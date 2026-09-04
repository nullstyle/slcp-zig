//! history.zig — quorum-authenticated registry checkpoint archive.
//!
//! The archive tree is untrusted shared storage. Under its network-id
//! namespace it contains canonical registry snapshots named by SHA-256,
//! fixed-width validator votes named by assertion digest and signer, and one
//! mutable latest-vote pointer per validator. The separate signing tree is
//! trusted local storage; immutable per-slot votes plus a monotonic high-water
//! vote prevent this validator from signing a rollback or equivocation.
//!
//! A vote signs SHA-256("REGISTRY-CKPT-V1" || network_id || slot_be ||
//! head_hash || snapshot_hash). Imported votes are evaluated only against the
//! caller-supplied, normalized quorum set. No quorum policy comes from the
//! archive.
//!
//! The fixed-width vote is 216 bytes: tag[16], network_id[32], slot[8]
//! big-endian, head_hash[32], snapshot_hash[32], signer[32], signature[64].
//! Files under `<archive>/<network-hex>/` are:
//! `snapshots/<snapshot-hash>.snap`,
//! `votes/<assertion-digest>-<signer>.vote`, and mutable
//! `latest/<signer>.vote`. Trusted files under
//! `<signing>/<network-hex>/` are immutable `votes/<slot>.vote` plus mutable
//! `high-water.vote`.
//! Every directory component below the configured roots is opened without
//! following symlinks and retained by handle; all object access is by a
//! generated basename with final-component no-follow. The parent directory of
//! each configured root must already exist. Device/inode identity and pinned
//! ancestor walks keep the archive disjoint from the signing root and, when
//! supplied, the caller's entire private-data root. Root and child creation,
//! both trusted signing fences, and archive publication are directory-fsync'd;
//! files also receive the platform's strongest available flush before and
//! after materialization. Archive history is therefore supported only on
//! Linux and macOS, where these directory barriers exist.
//! The archive also may not contain the caller-pinned validator-key parent.
//! Non-genesis legacy Snapshot V1 objects are local-restart inputs only and
//! are not eligible external checkpoints because they lack nomination context.
//!
//! Candidate discovery deliberately reads only the configured validators'
//! latest pointers, so work is bounded and no untrusted directory is scanned.
//! More than 16 distinct valid latest-pointer assertions is an availability
//! error rather than permission to do quadratic work or silently ignore a
//! possibly conflicting certificate.
//! This has an availability tradeoff: if every pointer that exposed an older
//! certificate advances to different, individually uncertified checkpoints,
//! that older certificate remains immutable but is no longer discoverable.

const std = @import("std");
const builtin = @import("builtin");
const slcp = @import("slcp");
const registry = @import("registry.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

extern "c" fn mkfifoat(dir_fd: std.posix.fd_t, path: [*:0]const u8, mode: std.c.mode_t) c_int;

const tag: *const [16]u8 = "REGISTRY-CKPT-V1";
const assertion_bytes = tag.len + 32 + 8 + 32 + 32;
const vote_bytes = assertion_bytes + 32 + 64;
const max_candidates = 16;
const max_name_bytes = 160;

pub const Config = struct {
    archive_dir: []const u8,
    signing_dir: []const u8,
    /// Caller-owned, already-open root containing all private node data. When
    /// supplied, the untrusted archive must be disjoint from this entire tree.
    private_data_root_dir: ?std.Io.Dir = null,
    /// Caller-owned, already-open parent of the validator key. The archive
    /// may live below a common ancestor, but it must not contain this parent
    /// (and therefore the key itself).
    private_key_parent_dir: ?std.Io.Dir = null,
    network_id: [32]u8,
    quorum: slcp.Quorum,
    signer_seed: [32]u8,
    checkpoint_every: u64 = 8,
};

pub const RecordStatus = enum {
    /// This slot is not a configured checkpoint boundary.
    not_due,
    /// This validator's vote was durably fenced and published. This does not
    /// imply that enough other validators have published for a quorum yet.
    published,
    /// This validator published its vote and the exact assertion now has a
    /// quorum under the caller-supplied quorum set.
    certified,
};

pub const Archive = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    snapshots_dir: std.Io.Dir,
    votes_dir: std.Io.Dir,
    latest_dir: std.Io.Dir,
    signing_dir: std.Io.Dir,
    signing_votes_dir: std.Io.Dir,
    network_id: [32]u8,
    quorum: slcp.core.qset.QuorumSetOwned,
    validators: []slcp.NodeId,
    signer_seed: [32]u8,
    signer_id: slcp.NodeId,
    checkpoint_every: u64,
    sync_directory: *const fn (std.Io.Dir) anyerror!void,
    sync_file: *const fn (std.Io, std.Io.File) anyerror!void,

    /// Opens network-scoped archive and signing roots and owns a normalized
    /// copy of `cfg.quorum`. The signer must be a member of that quorum set.
    pub fn open(gpa: std.mem.Allocator, io: std.Io, cfg: Config) !Archive {
        if (comptime !durabilitySupported(builtin.os.tag))
            return error.UnsupportedHistoryDurability;
        if (cfg.checkpoint_every == 0 or cfg.checkpoint_every > 16)
            return error.BadCheckpointInterval;

        var quorum = try cfg.quorum.toOwned(gpa);
        errdefer quorum.deinit(gpa);
        try slcp.core.qset.validateAndNormalize(gpa, &quorum);
        const signer_id = try slcp.core.crypto.publicKeyFromSeed(cfg.signer_seed);
        if (!slcp.core.qset.containsNode(&quorum, signer_id)) return error.SignerNotInQuorum;

        var validator_list: std.ArrayList(slcp.NodeId) = .empty;
        defer validator_list.deinit(gpa);
        try collectValidators(gpa, &quorum, &validator_list);
        std.mem.sort(slcp.NodeId, validator_list.items, {}, nodeLessThan);
        const validators = try validator_list.toOwnedSlice(gpa);
        errdefer gpa.free(validators);

        const no_follow: std.Io.Dir.CreateDirPathOpenOptions = .{
            .open_options = .{ .follow_symlinks = false },
        };
        const network_hex = registry.hex32(cfg.network_id);

        // Pin both configured roots before creating their network namespaces.
        // The optional private-data handle is already pinned by the caller;
        // reject any identity/ancestry overlap before putting shared objects
        // anywhere beneath the archive root.
        const archive_base = try openRoot(io, cfg.archive_dir, no_follow);
        defer archive_base.close(io);
        if (cfg.private_data_root_dir) |private_data_root| {
            if (try rootsOverlap(io, archive_base, private_data_root))
                return error.HistoryRootsOverlap;
        }
        if (cfg.private_key_parent_dir) |key_parent| {
            const archive_identity = try dirIdentity(archive_base);
            const key_parent_identity = try dirIdentity(key_parent);
            if (sameDirIdentity(archive_identity, key_parent_identity) or
                try isAncestorDir(io, archive_identity, key_parent))
                return error.HistoryRootsOverlap;
        }
        const signing_base = try openRoot(io, cfg.signing_dir, no_follow);
        defer signing_base.close(io);
        if (try rootsOverlap(io, archive_base, signing_base))
            return error.HistoryRootsOverlap;

        // Pin every untrusted namespace component to a directory handle. All
        // later operations use these handles plus generated basenames, so a
        // hostile rename/symlink swap cannot redirect I/O outside the archive.
        const archive_network = try archive_base.createDirPathOpen(io, &network_hex, no_follow);
        defer archive_network.close(io);
        try syncDir(archive_base);
        const snapshots_dir = try archive_network.createDirPathOpen(io, "snapshots", no_follow);
        errdefer snapshots_dir.close(io);
        const votes_dir = try archive_network.createDirPathOpen(io, "votes", no_follow);
        errdefer votes_dir.close(io);
        const latest_dir = try archive_network.createDirPathOpen(io, "latest", no_follow);
        errdefer latest_dir.close(io);
        try syncDir(archive_network);

        const signing_dir = try signing_base.createDirPathOpen(io, &network_hex, no_follow);
        errdefer signing_dir.close(io);
        try syncDir(signing_base);
        const signing_votes_dir = try signing_dir.createDirPathOpen(io, "votes", no_follow);
        errdefer signing_votes_dir.close(io);
        try syncDir(signing_dir);

        return .{
            .gpa = gpa,
            .io = io,
            .snapshots_dir = snapshots_dir,
            .votes_dir = votes_dir,
            .latest_dir = latest_dir,
            .signing_dir = signing_dir,
            .signing_votes_dir = signing_votes_dir,
            .network_id = cfg.network_id,
            .quorum = quorum,
            .validators = validators,
            .signer_seed = cfg.signer_seed,
            .signer_id = signer_id,
            .checkpoint_every = cfg.checkpoint_every,
            .sync_directory = syncDir,
            .sync_file = fullSync,
        };
    }

    pub fn deinit(self: *Archive) void {
        self.signing_votes_dir.close(self.io);
        self.signing_dir.close(self.io);
        self.latest_dir.close(self.io);
        self.votes_dir.close(self.io);
        self.snapshots_dir.close(self.io);
        self.quorum.deinit(self.gpa);
        self.gpa.free(self.validators);
        self.* = undefined;
    }

    /// Loads the highest discoverable quorum-certified state at or above the
    /// inclusive floor. Malformed/unavailable untrusted objects do not count;
    /// two discoverable certified assertions at one slot are a hard fork.
    pub fn loadLatest(self: *Archive, min_slot: u64) !?registry.State {
        var candidates: [max_candidates]Vote = undefined;
        var n_candidates: usize = 0;

        for (self.validators) |validator| {
            var name_buf: [max_name_bytes]u8 = undefined;
            const name = latestName(validator, &name_buf);
            const raw = try self.readUntrusted(self.latest_dir, name, vote_bytes);
            defer if (raw) |bytes| self.gpa.free(bytes);
            const vote = decodeVote(raw orelse continue) orelse continue;
            if (!std.mem.eql(u8, &vote.signer, &validator) or !self.validVote(&vote)) continue;
            if (vote.assertion.slot < min_slot) continue;
            const digest = vote.assertion.digest();
            var duplicate = false;
            for (candidates[0..n_candidates]) |known| {
                if (std.mem.eql(u8, &known.assertion.digest(), &digest)) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                if (n_candidates == candidates.len)
                    return error.TooManyCheckpointCandidates;
                candidates[n_candidates] = vote;
                n_candidates += 1;
            }
        }

        var best: ?registry.State = null;
        var certified: [max_candidates]Assertion = undefined;
        var n_certified: usize = 0;
        for (candidates[0..n_candidates]) |candidate| {
            if (!try self.isCertified(candidate.assertion)) continue;
            for (certified[0..n_certified]) |known| {
                if (known.slot == candidate.assertion.slot and !sameAssertion(known, candidate.assertion))
                    return error.CertifiedFork;
            }
            certified[n_certified] = candidate.assertion;
            n_certified += 1;

            const state = (try self.loadSnapshot(candidate.assertion)) orelse continue;
            if (best) |current| {
                if (state.head.slot < current.head.slot) continue;
            }
            best = state;
        }
        return best;
    }

    /// At checkpoint boundaries, validates the applied state, durably advances
    /// the trusted signing fence, then publishes the snapshot and local vote.
    pub fn recordApplied(self: *Archive, state: *const registry.State) !RecordStatus {
        if (state.head.slot == 0 or state.head.slot % self.checkpoint_every != 0) return .not_due;
        if (state.head.slot == std.math.maxInt(u64)) return error.CheckpointSlotOverflow;
        const last_set = state.last_set orelse return error.InvalidAppliedState;
        if (!std.mem.eql(u8, &state.network_id, &self.network_id) or
            !std.mem.eql(u8, &state.head.state_root, &state.stateRoot()) or
            !std.mem.eql(u8, &state.head.hash, &registry.headerHash(&state.head)) or
            !std.mem.eql(u8, &state.head.txset_hash, &last_set.hash()))
            return error.InvalidAppliedState;

        var snapshot_buf: [registry.snapshot_max_bytes]u8 = undefined;
        const snapshot = registry.writeSnapshot(state, &snapshot_buf);
        const assertion: Assertion = .{
            .network_id = self.network_id,
            .slot = state.head.slot,
            .head_hash = state.head.hash,
            .snapshot_hash = hash(snapshot),
        };
        const vote = Vote{
            .assertion = assertion,
            .signer = self.signer_id,
            .signature = try slcp.core.crypto.sign(self.signer_seed, assertion.digest()),
        };
        var vote_buf: [vote_bytes]u8 = undefined;
        encodeVote(vote, &vote_buf);

        // The trusted local files are the crash fence: no vote is published
        // until both the per-slot decision and the monotonic high-water mark
        // have reached stable storage.
        self.fence(vote, &vote_buf) catch |err| switch (err) {
            error.SigningFenceCorrupt,
            error.SigningEquivocation,
            error.SigningRollback,
            => |semantic| return semantic,
            // The same OS error can arise from trusted local custody or the
            // hostile shared archive. Preserve that boundary explicitly so
            // the process fails closed only when its signing fence could not
            // be durably advanced.
            else => return error.SigningFenceUnavailable,
        };

        var snapshot_name_buf: [max_name_bytes]u8 = undefined;
        try self.writeImmutable(self.snapshots_dir, snapshotName(assertion.snapshot_hash, &snapshot_name_buf), snapshot);
        try self.sync_directory(self.snapshots_dir);
        var vote_name_buf: [max_name_bytes]u8 = undefined;
        try self.writeImmutable(self.votes_dir, voteName(assertion.digest(), self.signer_id, &vote_name_buf), &vote_buf);
        try self.sync_directory(self.votes_dir);
        var latest_name_buf: [max_name_bytes]u8 = undefined;
        try self.writeAtomic(self.latest_dir, latestName(self.signer_id, &latest_name_buf), &vote_buf);
        try self.sync_directory(self.latest_dir);
        return if (try self.isCertified(assertion)) .certified else .published;
    }

    fn fence(self: *Archive, vote: Vote, bytes: *const [vote_bytes]u8) !void {
        const old_high = try self.readTrustedVote(self.signing_dir, "high-water.vote");
        if (old_high) |old| {
            if (old.assertion.slot > vote.assertion.slot) return error.SigningRollback;
            if (old.assertion.slot == vote.assertion.slot and !sameAssertion(old.assertion, vote.assertion))
                return error.SigningEquivocation;
        }

        var slot_name_buf: [max_name_bytes]u8 = undefined;
        const slot_name = slotName(vote.assertion.slot, &slot_name_buf);
        if (try self.readTrustedVote(self.signing_votes_dir, slot_name)) |old| {
            if (!sameAssertion(old.assertion, vote.assertion)) return error.SigningEquivocation;
        } else {
            try self.writeImmutable(self.signing_votes_dir, slot_name, bytes);
        }
        // Retry this barrier even when the name already exists: a previous
        // attempt may have materialized it but failed its directory sync.
        try self.sync_directory(self.signing_votes_dir);

        if (old_high == null or old_high.?.assertion.slot != vote.assertion.slot)
            try self.writeAtomic(self.signing_dir, "high-water.vote", bytes);
        // This barrier is likewise unconditional on retries and is the final
        // trusted fence before anything enters the shared archive.
        try self.sync_directory(self.signing_dir);
    }

    fn isCertified(self: *Archive, assertion: Assertion) !bool {
        if (!std.mem.eql(u8, &assertion.network_id, &self.network_id)) return false;
        const candidate_id = assertion.digest();
        return self.hasCertifiedSlice(&self.quorum, assertion, candidate_id);
    }

    fn hasCertifiedSlice(
        self: *Archive,
        quorum: *const slcp.core.qset.QuorumSetOwned,
        assertion: Assertion,
        candidate_id: [32]u8,
    ) !bool {
        var satisfied: u32 = 0;
        for (quorum.validators) |validator| {
            var name_buf: [max_name_bytes]u8 = undefined;
            const name = voteName(candidate_id, validator, &name_buf);
            const raw = try self.readUntrusted(self.votes_dir, name, vote_bytes);
            defer if (raw) |bytes| self.gpa.free(bytes);
            const vote = decodeVote(raw orelse continue) orelse continue;
            if (!std.mem.eql(u8, &vote.signer, &validator) or
                !sameAssertion(vote.assertion, assertion) or
                !self.validVote(&vote)) continue;
            satisfied += 1;
        }
        for (quorum.inner_sets) |*inner| {
            if (try self.hasCertifiedSlice(inner, assertion, candidate_id))
                satisfied += 1;
        }
        return satisfied >= quorum.threshold;
    }

    fn loadSnapshot(self: *Archive, assertion: Assertion) !?registry.State {
        var name_buf: [max_name_bytes]u8 = undefined;
        const name = snapshotName(assertion.snapshot_hash, &name_buf);
        const raw = try self.readUntrusted(self.snapshots_dir, name, registry.snapshot_max_bytes);
        defer if (raw) |bytes| self.gpa.free(bytes);
        const bytes = raw orelse return null;
        if (!std.mem.eql(u8, &hash(bytes), &assertion.snapshot_hash)) return null;
        const state = registry.readSnapshot(bytes) orelse return null;
        if (!std.mem.eql(u8, &state.network_id, &self.network_id) or
            state.head.slot != assertion.slot or
            !std.mem.eql(u8, &state.head.hash, &assertion.head_hash)) return null;
        // V1 remains a local restart format, where the journal can supply the
        // predecessor value. Never import it as an external checkpoint: main
        // must be able to install every authenticated state directly as V2,
        // including the exact command needed for next-slot nomination.
        if (state.head.slot > 0 and state.last_set == null) return null;
        return state;
    }

    fn validVote(self: *const Archive, vote: *const Vote) bool {
        // Membership is established by each caller's expected signer: archive
        // reads iterate the normalized, globally unique quorum tree (or its
        // flattened validator list), while trusted reads require
        // self.signer_id. Re-scanning the quorum tree here would turn
        // certificate verification from O(V) into O(V^2).
        return std.mem.eql(u8, &vote.assertion.network_id, &self.network_id) and
            vote.assertion.slot > 0 and
            vote.assertion.slot < std.math.maxInt(u64) and
            slcp.core.crypto.verify(vote.signer, vote.assertion.digest(), vote.signature);
    }

    fn readTrustedVote(self: *Archive, dir: std.Io.Dir, name: []const u8) !?Vote {
        const raw = self.readNoFollow(dir, name, vote_bytes) catch |err| switch (err) {
            error.FileNotFound => return null,
            error.StreamTooLong, error.SymLinkLoop, error.IsDir, error.NotRegularFile => return error.SigningFenceCorrupt,
            else => return err,
        };
        defer self.gpa.free(raw);
        if (raw.len != vote_bytes) return error.SigningFenceCorrupt;
        const vote = decodeVote(raw) orelse return error.SigningFenceCorrupt;
        if (!std.mem.eql(u8, &vote.signer, &self.signer_id) or !self.validVote(&vote))
            return error.SigningFenceCorrupt;
        return vote;
    }

    fn readUntrusted(self: *Archive, dir: std.Io.Dir, name: []const u8, max: usize) !?[]u8 {
        return self.readNoFollow(dir, name, max) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return null,
        };
    }

    fn readNoFollow(self: *Archive, dir: std.Io.Dir, name: []const u8, max: usize) ![]u8 {
        if (comptime !durabilitySupported(builtin.os.tag))
            return error.UnsupportedHistoryDurability;
        var flags: std.posix.O = .{ .ACCMODE = .RDONLY };
        flags.NONBLOCK = true;
        flags.NOFOLLOW = true;
        if (@hasField(std.posix.O, "CLOEXEC")) flags.CLOEXEC = true;
        if (@hasField(std.posix.O, "RESOLVE_BENEATH")) flags.RESOLVE_BENEATH = true;
        const fd = try std.posix.openat(dir.handle, name, flags, 0);
        var file: std.Io.File = .{
            .handle = fd,
            .flags = .{ .nonblocking = true },
        };
        defer file.close(self.io);
        const stat = try file.stat(self.io);
        if (stat.kind != .file) return error.NotRegularFile;
        var reader = file.reader(self.io, &.{});
        return reader.interface.allocRemaining(self.gpa, .limited(max + 1)) catch |err| switch (err) {
            error.ReadFailed => return reader.err.?,
            error.OutOfMemory, error.StreamTooLong => |e| return e,
        };
    }

    fn writeImmutable(self: *Archive, dir: std.Io.Dir, name: []const u8, bytes: []const u8) !void {
        if (self.readNoFollow(dir, name, bytes.len)) |old| {
            defer self.gpa.free(old);
            if (!std.mem.eql(u8, old, bytes)) return error.ImmutableFileConflict;
            return;
        } else |err| switch (err) {
            error.FileNotFound => {},
            error.StreamTooLong, error.SymLinkLoop, error.IsDir, error.NotRegularFile => return error.ImmutableFileConflict,
            else => return err,
        }

        var temp_buf: [max_name_bytes + 21]u8 = undefined;
        const temp = self.tempName(name, &temp_buf);
        var file = try dir.createFile(self.io, temp, .{
            .exclusive = true,
            .resolve_beneath = true,
        });
        var file_open = true;
        var temp_exists = true;
        defer if (file_open) file.close(self.io);
        defer if (temp_exists) dir.deleteFile(self.io, temp) catch {};
        try file.writeStreamingAll(self.io, bytes);
        try self.sync_file(self.io, file);
        dir.renamePreserve(temp, dir, name, self.io) catch |err| switch (err) {
            error.PathAlreadyExists => {
                const old = self.readNoFollow(dir, name, bytes.len) catch |read_err| switch (read_err) {
                    error.StreamTooLong, error.SymLinkLoop, error.IsDir, error.NotRegularFile => return error.ImmutableFileConflict,
                    else => return read_err,
                };
                defer self.gpa.free(old);
                if (!std.mem.eql(u8, old, bytes)) return error.ImmutableFileConflict;
                return;
            },
            else => return err,
        };
        temp_exists = false;
        try self.sync_file(self.io, file);
        file.close(self.io);
        file_open = false;
    }

    fn writeAtomic(self: *Archive, dir: std.Io.Dir, name: []const u8, bytes: []const u8) !void {
        var temp_buf: [max_name_bytes + 21]u8 = undefined;
        const temp = self.tempName(name, &temp_buf);
        var file = try dir.createFile(self.io, temp, .{
            .exclusive = true,
            .resolve_beneath = true,
        });
        var file_open = true;
        var temp_exists = true;
        defer if (file_open) file.close(self.io);
        defer if (temp_exists) dir.deleteFile(self.io, temp) catch {};
        try file.writeStreamingAll(self.io, bytes);
        try self.sync_file(self.io, file);
        try dir.rename(temp, dir, name, self.io);
        temp_exists = false;
        // As in the node store's compaction path, sync the renamed inode too:
        // the high-water signing fence must be stable before its vote can be
        // published into the untrusted archive.
        try self.sync_file(self.io, file);
        file.close(self.io);
        file_open = false;
    }

    fn tempName(self: *Archive, name: []const u8, out: *[max_name_bytes + 21]u8) []const u8 {
        var nonce: [8]u8 = undefined;
        self.io.random(&nonce);
        var nonce_hex: [16]u8 = undefined;
        writeHex(&nonce, &nonce_hex);
        return std.fmt.bufPrint(out, "{s}.tmp.{s}", .{ name, &nonce_hex }) catch unreachable;
    }
};

fn openRoot(io: std.Io, path: []const u8, options: std.Io.Dir.CreateDirPathOpenOptions) !std.Io.Dir {
    if (path.len == 0) return error.BadPathName;
    if (std.fs.path.isAbsolute(path) and std.mem.trim(u8, path, "/").len == 0)
        return error.BadPathName;
    const base = std.fs.path.basename(path);
    if (base.len == 0 or std.mem.eql(u8, base, ".") or std.mem.eql(u8, base, ".."))
        return error.BadPathName;
    const parent_path = std.fs.path.dirname(path) orelse ".";
    const cwd = std.Io.Dir.cwd();
    const parent = try cwd.openDir(io, parent_path, .{ .follow_symlinks = false });
    defer parent.close(io);
    const root = try parent.createDirPathOpen(io, base, options);
    errdefer root.close(io);
    try syncDir(parent);
    return root;
}

fn rootsOverlap(io: std.Io, a: std.Io.Dir, b: std.Io.Dir) !bool {
    const a_identity = try dirIdentity(a);
    const b_identity = try dirIdentity(b);
    if (sameDirIdentity(a_identity, b_identity)) return true;
    return try isAncestorDir(io, a_identity, b) or
        try isAncestorDir(io, b_identity, a);
}

const DirIdentity = struct {
    device: u64,
    inode: u64,
};

fn sameDirIdentity(a: DirIdentity, b: DirIdentity) bool {
    return a.device == b.device and a.inode == b.inode;
}

fn dirIdentity(dir: std.Io.Dir) !DirIdentity {
    if (comptime builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var stat: linux.Statx = std.mem.zeroes(linux.Statx);
        const rc = linux.statx(
            dir.handle,
            "",
            linux.AT.EMPTY_PATH,
            .{ .INO = true },
            &stat,
        );
        if (linux.errno(rc) != .SUCCESS) return error.RootIdentityFailed;
        if (!stat.mask.INO) return error.RootIdentityFailed;
        return .{
            .device = (@as(u64, stat.dev_major) << 32) | stat.dev_minor,
            .inode = stat.ino,
        };
    } else if (comptime builtin.os.tag == .macos) {
        while (true) {
            var stat: std.c.Stat = std.mem.zeroes(std.c.Stat);
            switch (std.c.errno(std.c.fstat(dir.handle, &stat))) {
                .SUCCESS => return .{
                    .device = @as(u32, @bitCast(stat.dev)),
                    .inode = stat.ino,
                },
                .INTR => {},
                else => return error.RootIdentityFailed,
            }
        }
    } else {
        return error.UnsupportedHistoryDurability;
    }
}

fn isAncestorDir(io: std.Io, ancestor: DirIdentity, descendant: std.Io.Dir) !bool {
    var current = try descendant.openDir(io, "..", .{ .follow_symlinks = false });
    defer current.close(io);

    while (true) {
        const current_identity = try dirIdentity(current);
        if (sameDirIdentity(ancestor, current_identity)) return true;

        const parent = try current.openDir(io, "..", .{ .follow_symlinks = false });
        const parent_identity = dirIdentity(parent) catch |err| {
            parent.close(io);
            return err;
        };
        if (sameDirIdentity(current_identity, parent_identity)) {
            parent.close(io);
            return false;
        }
        current.close(io);
        current = parent;
    }
}

fn syncDir(dir: std.Io.Dir) !void {
    if (comptime builtin.os.tag == .linux or builtin.os.tag == .macos) {
        if (std.c.fsync(dir.handle) != 0) return error.DirectorySyncFailed;
    }
}

fn durabilitySupported(os: std.Target.Os.Tag) bool {
    return os == .linux or os == .macos;
}

fn fullSync(io: std.Io, file: std.Io.File) !void {
    try file.sync(io);
    if (comptime builtin.os.tag == .macos) {
        if (std.c.fcntl(file.handle, std.posix.F.FULLFSYNC) < 0)
            return error.FullSyncFailed;
    }
}

const Assertion = struct {
    network_id: [32]u8,
    slot: u64,
    head_hash: [32]u8,
    snapshot_hash: [32]u8,

    fn digest(self: Assertion) [32]u8 {
        var bytes: [assertion_bytes]u8 = undefined;
        encodeAssertion(self, &bytes);
        return hash(&bytes);
    }
};

const Vote = struct {
    assertion: Assertion,
    signer: slcp.NodeId,
    signature: [64]u8,
};

fn encodeAssertion(assertion: Assertion, out: *[assertion_bytes]u8) void {
    var off: usize = 0;
    @memcpy(out[off..][0..tag.len], tag);
    off += tag.len;
    @memcpy(out[off..][0..32], &assertion.network_id);
    off += 32;
    std.mem.writeInt(u64, out[off..][0..8], assertion.slot, .big);
    off += 8;
    @memcpy(out[off..][0..32], &assertion.head_hash);
    off += 32;
    @memcpy(out[off..][0..32], &assertion.snapshot_hash);
}

fn encodeVote(vote: Vote, out: *[vote_bytes]u8) void {
    encodeAssertion(vote.assertion, out[0..assertion_bytes]);
    @memcpy(out[assertion_bytes..][0..32], &vote.signer);
    @memcpy(out[assertion_bytes + 32 ..][0..64], &vote.signature);
}

fn decodeVote(bytes: []const u8) ?Vote {
    if (bytes.len != vote_bytes or !std.mem.eql(u8, bytes[0..tag.len], tag)) return null;
    var off: usize = tag.len;
    const network_id = bytes[off..][0..32].*;
    off += 32;
    const slot = std.mem.readInt(u64, bytes[off..][0..8], .big);
    off += 8;
    const head_hash = bytes[off..][0..32].*;
    off += 32;
    const snapshot_hash = bytes[off..][0..32].*;
    off += 32;
    return .{
        .assertion = .{ .network_id = network_id, .slot = slot, .head_hash = head_hash, .snapshot_hash = snapshot_hash },
        .signer = bytes[off..][0..32].*,
        .signature = bytes[off + 32 ..][0..64].*,
    };
}

fn sameAssertion(a: Assertion, b: Assertion) bool {
    return a.slot == b.slot and
        std.mem.eql(u8, &a.network_id, &b.network_id) and
        std.mem.eql(u8, &a.head_hash, &b.head_hash) and
        std.mem.eql(u8, &a.snapshot_hash, &b.snapshot_hash);
}

fn hash(bytes: []const u8) [32]u8 {
    var h = Sha256.init(.{});
    h.update(bytes);
    return h.finalResult();
}

fn nodeLessThan(_: void, a: slcp.NodeId, b: slcp.NodeId) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

fn collectValidators(gpa: std.mem.Allocator, quorum: *const slcp.core.qset.QuorumSetOwned, out: *std.ArrayList(slcp.NodeId)) !void {
    try out.appendSlice(gpa, quorum.validators);
    for (quorum.inner_sets) |*inner| try collectValidators(gpa, inner, out);
}

fn snapshotName(snapshot_hash: [32]u8, out: *[max_name_bytes]u8) []const u8 {
    return std.fmt.bufPrint(out, "{s}.snap", .{&registry.hex32(snapshot_hash)}) catch unreachable;
}

fn voteName(candidate: [32]u8, signer: slcp.NodeId, out: *[max_name_bytes]u8) []const u8 {
    return std.fmt.bufPrint(out, "{s}-{s}.vote", .{
        &registry.hex32(candidate),
        &registry.hex32(signer),
    }) catch unreachable;
}

fn latestName(signer: slcp.NodeId, out: *[max_name_bytes]u8) []const u8 {
    return std.fmt.bufPrint(out, "{s}.vote", .{&registry.hex32(signer)}) catch unreachable;
}

fn slotName(slot: u64, out: *[max_name_bytes]u8) []const u8 {
    return std.fmt.bufPrint(out, "{d}.vote", .{slot}) catch unreachable;
}

fn writeHex(bytes: []const u8, out: []u8) void {
    std.debug.assert(out.len == bytes.len * 2);
    const hex = "0123456789abcdef";
    for (bytes, 0..) |byte, i| {
        out[i * 2] = hex[byte >> 4];
        out[i * 2 + 1] = hex[byte & 0x0f];
    }
}

const testing = std.testing;

fn testPath(tmp: *std.testing.TmpDir, io: std.Io, suffix: []const u8, buf: []u8) ![]const u8 {
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buf[0..try tmp.dir.realPath(io, &root_buf)];
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ root, suffix });
}

fn stateAt(network_id: [32]u8, slot: u64) registry.State {
    var state: registry.State = .{ .network_id = network_id };
    for (0..slot) |_| registry.apply(&state, &registry.TxSet.empty);
    return state;
}

fn overwriteTestFileAt(io: std.Io, dir: std.Io.Dir, name: []const u8, bytes: []const u8) !void {
    var file = try dir.createFile(io, name, .{ .resolve_beneath = true });
    defer file.close(io);
    try file.writeStreamingAll(io, bytes);
}

const TestDirSyncFault = struct {
    var target: ?std.Io.Dir.Handle = null;

    fn sync(dir: std.Io.Dir) !void {
        if (target != null and target.? == dir.handle)
            return error.InjectedDirectorySyncFailure;
        try syncDir(dir);
    }
};

const TestFileSyncFault = struct {
    var fail: bool = false;

    fn sync(io: std.Io, file: std.Io.File) !void {
        if (fail) return error.InjectedFileSyncFailure;
        try fullSync(io, file);
    }
};

test "history archive: crash-safe directory barriers have an explicit platform boundary" {
    try testing.expect(durabilitySupported(.linux));
    try testing.expect(durabilitySupported(.macos));
    try testing.expect(!durabilitySupported(.windows));
    try testing.expect(!durabilitySupported(.freebsd));
}

test "history archive: checkpoint cadence defaults to eight and is bounded by the answering window" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0x08);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = registry.networkId("history checkpoint cadence");
    const base: Config = .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
    };

    var zero = base;
    zero.checkpoint_every = 0;
    try testing.expectError(error.BadCheckpointInterval, Archive.open(gpa, io, zero));
    var seventeen = base;
    seventeen.checkpoint_every = 17;
    try testing.expectError(error.BadCheckpointInterval, Archive.open(gpa, io, seventeen));

    var archive = try Archive.open(gpa, io, base);
    defer archive.deinit();
    const one = stateAt(network_id, 1);
    try testing.expectEqual(RecordStatus.not_due, try archive.recordApplied(&one));
    const eight = stateAt(network_id, 8);
    try testing.expectEqual(RecordStatus.certified, try archive.recordApplied(&eight));
}

test "history archive: a persistently blocked checkpoint does not pin the signing fence" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0x18);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = registry.networkId("history skip blocked checkpoint");

    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 8,
    });
    defer archive.deinit();

    const eight = stateAt(network_id, 8);
    var snapshot_buf: [registry.snapshot_max_bytes]u8 = undefined;
    const snapshot = registry.writeSnapshot(&eight, &snapshot_buf);
    var name_buf: [max_name_bytes]u8 = undefined;
    const name = snapshotName(hash(snapshot), &name_buf);
    try overwriteTestFileAt(io, archive.snapshots_dir, name, "hostile immutable occupant");
    try testing.expectError(error.ImmutableFileConflict, archive.recordApplied(&eight));

    // Slot 8 is durably fenced even though its shared publication can never
    // succeed. Advancing to slot 16 remains safe and must restore this
    // validator's archive availability.
    const sixteen = stateAt(network_id, 16);
    try testing.expectEqual(RecordStatus.certified, try archive.recordApplied(&sixteen));
    const restored = (try archive.loadLatest(16)) orelse return error.ExpectedCertifiedCheckpoint;
    try testing.expectEqual(@as(u64, 16), restored.head.slot);
    try testing.expectEqualSlices(u8, &sixteen.head.hash, &restored.head.hash);
}

test "history archive: trusted signing custody must not overlap the untrusted archive" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var shared_buf: [std.fs.max_path_bytes]u8 = undefined;
    var alias_buf: [std.fs.max_path_bytes]u8 = undefined;
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var nested_buf: [std.fs.max_path_bytes]u8 = undefined;
    var trusted_buf: [std.fs.max_path_bytes]u8 = undefined;
    var nested_archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    const shared = try testPath(&tmp, io, "shared", &shared_buf);
    const canonical_alias = try testPath(&tmp, io, "shared/../shared", &alias_buf);
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const nested_signing = try testPath(&tmp, io, "archive/private-signing", &nested_buf);
    const trusted_path = try testPath(&tmp, io, "trusted", &trusted_buf);
    const nested_archive = try testPath(&tmp, io, "trusted/untrusted-archive", &nested_archive_buf);
    try tmp.dir.createDirPath(io, "trusted");
    const seed: [32]u8 = @splat(0x09);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = registry.networkId("history root separation");
    const quorum = slcp.Quorum.of(1, &.{id});

    const cases = [_][2][]const u8{
        .{ shared, shared },
        .{ shared, canonical_alias },
        .{ archive_path, nested_signing },
        .{ nested_archive, trusted_path },
    };
    for (cases) |paths| {
        if (Archive.open(gpa, io, .{
            .archive_dir = paths[0],
            .signing_dir = paths[1],
            .network_id = network_id,
            .quorum = quorum,
            .signer_seed = seed,
        })) |opened| {
            var archive = opened;
            archive.deinit();
            return error.ExpectedHistoryRootsOverlap;
        } else |err| try testing.expectEqual(error.HistoryRootsOverlap, err);
    }
}

test "history archive: a configured root may not be the filesystem root" {
    const no_follow: std.Io.Dir.CreateDirPathOpenOptions = .{
        .open_options = .{ .follow_symlinks = false },
    };
    try testing.expectError(error.BadPathName, openRoot(testing.io, "/", no_follow));
    try testing.expectError(error.BadPathName, openRoot(testing.io, "////", no_follow));
}

test "history archive: the untrusted archive must be disjoint from the entire private data root" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const seed: [32]u8 = @splat(0x0a);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = registry.networkId("history private data separation");
    const network_hex = registry.hex32(network_id);
    const cases = [_]struct {
        data_rel: []const u8,
        archive_rel: []const u8,
        signing_rel: []const u8,
    }{
        .{ .data_rel = "same", .archive_rel = "same", .signing_rel = "signing-0" },
        .{ .data_rel = "data-parent", .archive_rel = "data-parent/archive", .signing_rel = "signing-1" },
        .{ .data_rel = "archive-parent/private", .archive_rel = "archive-parent", .signing_rel = "signing-2" },
    };
    var archive_path_bufs: [cases.len][std.fs.max_path_bytes]u8 = undefined;
    var signing_path_bufs: [cases.len][std.fs.max_path_bytes]u8 = undefined;

    for (cases, 0..) |case, i| {
        try tmp.dir.createDirPath(io, case.data_rel);
        const private_data_root = try tmp.dir.openDir(io, case.data_rel, .{ .follow_symlinks = false });
        defer private_data_root.close(io);
        const archive_path = try testPath(&tmp, io, case.archive_rel, &archive_path_bufs[i]);
        const signing_path = try testPath(&tmp, io, case.signing_rel, &signing_path_bufs[i]);

        if (Archive.open(gpa, io, .{
            .archive_dir = archive_path,
            .signing_dir = signing_path,
            .private_data_root_dir = private_data_root,
            .network_id = network_id,
            .quorum = slcp.Quorum.of(1, &.{id}),
            .signer_seed = seed,
        })) |opened| {
            var archive = opened;
            archive.deinit();
            return error.ExpectedHistoryRootsOverlap;
        } else |err| try testing.expectEqual(error.HistoryRootsOverlap, err);

        // The overlap check happens before the archive's network namespace is
        // created, even when opening the archive root itself created its final
        // directory component.
        const archive_root = try std.Io.Dir.cwd().openDir(io, archive_path, .{ .follow_symlinks = false });
        defer archive_root.close(io);
        try testing.expectError(error.FileNotFound, archive_root.statFile(
            io,
            &network_hex,
            .{ .follow_symlinks = false },
        ));
    }
}

test "history archive: the untrusted archive may share a parent with, but cannot contain, the validator key" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "shared/keys");

    const key_parent = try tmp.dir.openDir(io, "shared/keys", .{ .follow_symlinks = false });
    defer key_parent.close(io);
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "shared", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing-contained-key", &signing_buf);
    const seed: [32]u8 = @splat(0x0b);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = registry.networkId("history key custody separation");

    try testing.expectError(error.HistoryRootsOverlap, Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .private_key_parent_dir = key_parent,
        .network_id = network_id,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
    }));

    // A common parent is normal: only the archive subtree is hostile, so a
    // sibling key is outside its custody boundary.
    var safe_archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var safe_signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const safe_archive = try testPath(&tmp, io, "safe-archive", &safe_archive_buf);
    const safe_signing = try testPath(&tmp, io, "safe-signing", &safe_signing_buf);
    var opened = try Archive.open(gpa, io, .{
        .archive_dir = safe_archive,
        .signing_dir = safe_signing,
        .private_key_parent_dir = tmp.dir,
        .network_id = network_id,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
    });
    opened.deinit();
}

test "history archive: a flat 2-of-3 checkpoint needs two distinct validator signatures" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var sign_a_buf: [std.fs.max_path_bytes]u8 = undefined;
    var sign_b_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const sign_a_path = try testPath(&tmp, io, "sign-a", &sign_a_buf);
    const sign_b_path = try testPath(&tmp, io, "sign-b", &sign_b_buf);

    const seeds = [3][32]u8{ @splat(0xa1), @splat(0xb2), @splat(0xc3) };
    const ids = [3][32]u8{
        try slcp.core.crypto.publicKeyFromSeed(seeds[0]),
        try slcp.core.crypto.publicKeyFromSeed(seeds[1]),
        try slcp.core.crypto.publicKeyFromSeed(seeds[2]),
    };
    const quorum = slcp.Quorum.of(2, &ids);
    const network_id = registry.networkId("history flat 2-of-3");
    const state = stateAt(network_id, 1);

    var a = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = sign_a_path,
        .network_id = network_id,
        .quorum = quorum,
        .signer_seed = seeds[0],
        .checkpoint_every = 1,
    });
    defer a.deinit();
    try testing.expectEqual(RecordStatus.published, try a.recordApplied(&state));
    try testing.expect((try a.loadLatest(1)) == null);

    var b = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = sign_b_path,
        .network_id = network_id,
        .quorum = quorum,
        .signer_seed = seeds[1],
        .checkpoint_every = 1,
    });
    defer b.deinit();
    try testing.expectEqual(RecordStatus.certified, try b.recordApplied(&state));

    const restored = (try a.loadLatest(1)) orelse return error.ExpectedCertifiedCheckpoint;
    try testing.expectEqual(@as(u64, 1), restored.head.slot);
    try testing.expectEqualSlices(u8, &state.head.hash, &restored.head.hash);
}

test "history archive: nested quorum satisfaction is not a flat signer count" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var sign_a_buf: [std.fs.max_path_bytes]u8 = undefined;
    var sign_b_buf: [std.fs.max_path_bytes]u8 = undefined;
    var sign_c_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const sign_a_path = try testPath(&tmp, io, "sign-a", &sign_a_buf);
    const sign_b_path = try testPath(&tmp, io, "sign-b", &sign_b_buf);
    const sign_c_path = try testPath(&tmp, io, "sign-c", &sign_c_buf);

    const seeds = [3][32]u8{ @splat(0x11), @splat(0x22), @splat(0x33) };
    const ids = [3][32]u8{
        try slcp.core.crypto.publicKeyFromSeed(seeds[0]),
        try slcp.core.crypto.publicKeyFromSeed(seeds[1]),
        try slcp.core.crypto.publicKeyFromSeed(seeds[2]),
    };
    const inner = [_]slcp.Quorum{slcp.Quorum.of(2, ids[1..3])};
    const quorum = slcp.Quorum{ .threshold = 2, .validators = ids[0..1], .inner_sets = &inner };
    const network_id = registry.networkId("history nested quorum");
    const state = stateAt(network_id, 1);

    var a = try Archive.open(gpa, io, .{ .archive_dir = archive_path, .signing_dir = sign_a_path, .network_id = network_id, .quorum = quorum, .signer_seed = seeds[0], .checkpoint_every = 1 });
    defer a.deinit();
    var b = try Archive.open(gpa, io, .{ .archive_dir = archive_path, .signing_dir = sign_b_path, .network_id = network_id, .quorum = quorum, .signer_seed = seeds[1], .checkpoint_every = 1 });
    defer b.deinit();
    var c = try Archive.open(gpa, io, .{ .archive_dir = archive_path, .signing_dir = sign_c_path, .network_id = network_id, .quorum = quorum, .signer_seed = seeds[2], .checkpoint_every = 1 });
    defer c.deinit();

    _ = try a.recordApplied(&state);
    _ = try b.recordApplied(&state);
    // Two flat signatures are not enough: the second root member is the
    // inner 2-of-2 set, which B alone does not satisfy.
    try testing.expect((try a.loadLatest(1)) == null);
    _ = try c.recordApplied(&state);
    try testing.expectEqual(@as(u64, 1), (try a.loadLatest(1)).?.head.slot);
}

test "history archive: candidate discovery fails closed beyond its linear-work cap" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    var seeds: [max_candidates + 1][32]u8 = undefined;
    var ids: [max_candidates + 1]slcp.NodeId = undefined;
    for (&seeds, &ids, 0..) |*seed, *id, i| {
        seed.* = @splat(@as(u8, @intCast(0xc0 + i)));
        id.* = try slcp.core.crypto.publicKeyFromSeed(seed.*);
    }
    const quorum = slcp.Quorum.of(max_candidates + 1, &ids);
    const network_id = registry.networkId("history candidate cap");

    for (seeds, 0..) |seed, i| {
        var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
        var suffix_buf: [32]u8 = undefined;
        const suffix = try std.fmt.bufPrint(&suffix_buf, "signing-{d}", .{i});
        const signing_path = try testPath(&tmp, io, suffix, &signing_buf);
        var writer = try Archive.open(gpa, io, .{
            .archive_dir = archive_path,
            .signing_dir = signing_path,
            .network_id = network_id,
            .quorum = quorum,
            .signer_seed = seed,
            .checkpoint_every = 1,
        });
        defer writer.deinit();
        const state = stateAt(network_id, i + 1);
        try testing.expectEqual(RecordStatus.published, try writer.recordApplied(&state));
    }

    var reader_signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const reader_signing = try testPath(&tmp, io, "signing-0", &reader_signing_buf);
    var reader = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = reader_signing,
        .network_id = network_id,
        .quorum = quorum,
        .signer_seed = seeds[0],
        .checkpoint_every = 1,
    });
    defer reader.deinit();
    try testing.expectError(error.TooManyCheckpointCandidates, reader.loadLatest(1));
}

test "history archive: bootstrap floor prevents rollback to an older valid checkpoint" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0x41);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = registry.networkId("history rollback floor");
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    defer archive.deinit();
    const state = stateAt(network_id, 3);
    _ = try archive.recordApplied(&state);
    try testing.expect((try archive.loadLatest(4)) == null);
    try testing.expectEqual(@as(u64, 3), (try archive.loadLatest(3)).?.head.slot);
}

test "history archive: durable signing fences reject same-slot equivocation and slot rollback" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0x51);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = registry.networkId("history signing fence");
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    defer archive.deinit();

    const one = stateAt(network_id, 1);
    _ = try archive.recordApplied(&one);
    archive.deinit();
    archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });

    var conflicting: registry.State = .{ .network_id = network_id };
    const source: registry.Key = @splat(0x61);
    const tx = registry.Tx.init(source, 1, .claim, "fork", "", registry.zero_key).?;
    var set: registry.TxSet = .{ .count = 1 };
    set.txs[0] = tx;
    registry.apply(&conflicting, &set);
    try testing.expectError(error.SigningEquivocation, archive.recordApplied(&conflicting));

    const two = stateAt(network_id, 2);
    _ = try archive.recordApplied(&two);
    try testing.expectError(error.SigningRollback, archive.recordApplied(&one));
}

test "history archive: duplicate, outsider, and misnamed votes do not satisfy 2-of-3" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var sign_a_buf: [std.fs.max_path_bytes]u8 = undefined;
    var sign_a_copy_buf: [std.fs.max_path_bytes]u8 = undefined;
    var sign_x_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const sign_a_path = try testPath(&tmp, io, "sign-a", &sign_a_buf);
    const sign_a_copy_path = try testPath(&tmp, io, "sign-a-copy", &sign_a_copy_buf);
    const sign_x_path = try testPath(&tmp, io, "sign-x", &sign_x_buf);
    const seeds = [4][32]u8{ @splat(0x71), @splat(0x72), @splat(0x73), @splat(0x7f) };
    const ids = [3]slcp.NodeId{
        try slcp.core.crypto.publicKeyFromSeed(seeds[0]),
        try slcp.core.crypto.publicKeyFromSeed(seeds[1]),
        try slcp.core.crypto.publicKeyFromSeed(seeds[2]),
    };
    const network_id = registry.networkId("history distinct signers");
    const quorum = slcp.Quorum.of(2, &ids);
    var a = try Archive.open(gpa, io, .{ .archive_dir = archive_path, .signing_dir = sign_a_path, .network_id = network_id, .quorum = quorum, .signer_seed = seeds[0], .checkpoint_every = 1 });
    defer a.deinit();
    var a_copy = try Archive.open(gpa, io, .{ .archive_dir = archive_path, .signing_dir = sign_a_copy_path, .network_id = network_id, .quorum = quorum, .signer_seed = seeds[0], .checkpoint_every = 1 });
    defer a_copy.deinit();
    try testing.expectError(error.SignerNotInQuorum, Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = sign_x_path,
        .network_id = network_id,
        .quorum = quorum,
        .signer_seed = seeds[3],
        .checkpoint_every = 1,
    }));
    const state = stateAt(network_id, 1);
    _ = try a.recordApplied(&state);
    _ = try a_copy.recordApplied(&state);
    try testing.expect((try a.loadLatest(1)) == null);

    var snapshot_buf: [registry.snapshot_max_bytes]u8 = undefined;
    const snapshot = registry.writeSnapshot(&state, &snapshot_buf);
    const assertion: Assertion = .{
        .network_id = network_id,
        .slot = state.head.slot,
        .head_hash = state.head.hash,
        .snapshot_hash = hash(snapshot),
    };
    const outsider_id = try slcp.core.crypto.publicKeyFromSeed(seeds[3]);
    const outsider_vote: Vote = .{
        .assertion = assertion,
        .signer = outsider_id,
        .signature = try slcp.core.crypto.sign(seeds[3], assertion.digest()),
    };
    var hostile_buf: [vote_bytes]u8 = undefined;
    encodeVote(outsider_vote, &hostile_buf);
    var b_name_buf: [max_name_bytes]u8 = undefined;
    const b_name = voteName(assertion.digest(), ids[1], &b_name_buf);
    try overwriteTestFileAt(io, a.votes_dir, b_name, &hostile_buf);
    try testing.expect((try a.loadLatest(1)) == null);

    // Even a valid member signature counts only in the filename belonging to
    // that exact member. A C vote planted under B's generated name is ignored.
    const misnamed_vote: Vote = .{
        .assertion = assertion,
        .signer = ids[2],
        .signature = try slcp.core.crypto.sign(seeds[2], assertion.digest()),
    };
    encodeVote(misnamed_vote, &hostile_buf);
    try overwriteTestFileAt(io, a.votes_dir, b_name, &hostile_buf);
    try testing.expect((try a.loadLatest(1)) == null);
}

test "history archive: snapshot hash and signed network/head bind imported state" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0x81);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = registry.networkId("history snapshot binding");
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    defer archive.deinit();
    const state = stateAt(network_id, 1);
    _ = try archive.recordApplied(&state);

    // Replace the object with a different snapshot that is internally
    // canonical and self-consistent. Its checksum, state root and head all
    // verify, but the old signed assertion names the original snapshot hash.
    var substitute: registry.State = .{ .network_id = network_id };
    const source: registry.Key = @splat(0x82);
    const tx = registry.Tx.init(source, 1, .claim, "substitute", "", registry.zero_key).?;
    var set: registry.TxSet = .{ .count = 1 };
    set.txs[0] = tx;
    registry.apply(&substitute, &set);
    var original_buf: [registry.snapshot_max_bytes]u8 = undefined;
    const original = registry.writeSnapshot(&state, &original_buf);
    var snapshot_name_buf: [max_name_bytes]u8 = undefined;
    const snapshot_name = snapshotName(hash(original), &snapshot_name_buf);
    var substitute_buf: [registry.snapshot_max_bytes]u8 = undefined;
    try overwriteTestFileAt(io, archive.snapshots_dir, snapshot_name, registry.writeSnapshot(&substitute, &substitute_buf));
    try testing.expect((try archive.loadLatest(1)) == null);

    // Restore the original object, then exercise hostile full-width votes.
    // Neither a foreign network nor a non-member can be smuggled through a
    // trusted validator's pointer path, even with a valid signature.
    try overwriteTestFileAt(io, archive.snapshots_dir, snapshot_name, original);
    var latest_name_buf: [max_name_bytes]u8 = undefined;
    const latest_name = latestName(id, &latest_name_buf);
    const foreign_assertion = Assertion{
        .network_id = registry.networkId("foreign assertion network"),
        .slot = 1,
        .head_hash = state.head.hash,
        .snapshot_hash = hash(original),
    };
    const foreign_vote = Vote{
        .assertion = foreign_assertion,
        .signer = id,
        .signature = try slcp.core.crypto.sign(seed, foreign_assertion.digest()),
    };
    var hostile_buf: [vote_bytes]u8 = undefined;
    encodeVote(foreign_vote, &hostile_buf);
    try archive.writeAtomic(archive.latest_dir, latest_name, &hostile_buf);
    try testing.expect((try archive.loadLatest(1)) == null);

    const correct_assertion = Assertion{
        .network_id = network_id,
        .slot = 1,
        .head_hash = state.head.hash,
        .snapshot_hash = hash(original),
    };
    var bad_signature = Vote{
        .assertion = correct_assertion,
        .signer = id,
        .signature = try slcp.core.crypto.sign(seed, correct_assertion.digest()),
    };
    bad_signature.signature[0] ^= 1;
    encodeVote(bad_signature, &hostile_buf);
    try archive.writeAtomic(archive.latest_dir, latest_name, &hostile_buf);
    try testing.expect((try archive.loadLatest(1)) == null);

    const outsider_seed: [32]u8 = @splat(0x83);
    const outsider_id = try slcp.core.crypto.publicKeyFromSeed(outsider_seed);
    const outsider_vote = Vote{
        .assertion = correct_assertion,
        .signer = outsider_id,
        .signature = try slcp.core.crypto.sign(outsider_seed, correct_assertion.digest()),
    };
    encodeVote(outsider_vote, &hostile_buf);
    try archive.writeAtomic(archive.latest_dir, latest_name, &hostile_buf);
    try testing.expect((try archive.loadLatest(1)) == null);

    // A valid member signature still cannot bless an assertion that names the
    // right snapshot but lies about its head.
    var wrong_head = state.head.hash;
    wrong_head[0] ^= 1;
    const assertion = Assertion{
        .network_id = network_id,
        .slot = 1,
        .head_hash = wrong_head,
        .snapshot_hash = hash(original),
    };
    const vote = Vote{
        .assertion = assertion,
        .signer = id,
        .signature = try slcp.core.crypto.sign(seed, assertion.digest()),
    };
    var vote_buf: [vote_bytes]u8 = undefined;
    encodeVote(vote, &vote_buf);
    var bad_vote_name_buf: [max_name_bytes]u8 = undefined;
    try archive.writeImmutable(archive.votes_dir, voteName(assertion.digest(), id, &bad_vote_name_buf), &vote_buf);
    try archive.writeAtomic(archive.latest_dir, latest_name, &vote_buf);
    try testing.expect((try archive.loadLatest(1)) == null);

    const wrong_network = stateAt(registry.networkId("other history network"), 1);
    try testing.expectError(error.InvalidAppliedState, archive.recordApplied(&wrong_network));

    var missing_context = state;
    missing_context.last_set = null;
    try testing.expectError(error.InvalidAppliedState, archive.recordApplied(&missing_context));

    var wrong_context = state;
    var other_set: registry.TxSet = .{ .count = 1 };
    other_set.txs[0] = registry.Tx.init(@splat(0x55), 1, .claim, "other", "", registry.zero_key).?;
    wrong_context.last_set = other_set;
    try testing.expectError(error.InvalidAppliedState, archive.recordApplied(&wrong_context));
}

test "history archive: legacy snapshots are local-restart only, never external checkpoints" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0x83);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = registry.networkId("history rejects V1 checkpoint");
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    defer archive.deinit();

    const state = stateAt(network_id, 1);
    var v2_buf: [registry.snapshot_max_bytes]u8 = undefined;
    const v2 = registry.writeSnapshot(&state, &v2_buf);
    const fixed_prefix = registry.snap_magic.len + 32 + 8 + 4 * 32;
    const set_len: usize = std.mem.readInt(u16, v2[fixed_prefix..][0..2], .big);
    const state_offset = fixed_prefix + 2 + set_len;
    var v1_buf: [registry.snapshot_max_bytes]u8 = undefined;
    @memcpy(v1_buf[0..registry.snap_magic_v1.len], registry.snap_magic_v1);
    @memcpy(v1_buf[registry.snap_magic_v1.len..fixed_prefix], v2[registry.snap_magic.len..fixed_prefix]);
    const state_len = v2.len - 32 - state_offset;
    @memcpy(v1_buf[fixed_prefix..][0..state_len], v2[state_offset..][0..state_len]);
    const body_end = fixed_prefix + state_len;
    const checksum = hash(v1_buf[0..body_end]);
    @memcpy(v1_buf[body_end..][0..32], &checksum);
    const v1 = v1_buf[0 .. body_end + 32];
    try testing.expect(registry.readSnapshot(v1).?.last_set == null);

    const assertion: Assertion = .{
        .network_id = network_id,
        .slot = state.head.slot,
        .head_hash = state.head.hash,
        .snapshot_hash = hash(v1),
    };
    var name_buf: [max_name_bytes]u8 = undefined;
    try archive.writeImmutable(archive.snapshots_dir, snapshotName(assertion.snapshot_hash, &name_buf), v1);
    try testing.expect((try archive.loadSnapshot(assertion)) == null);
}

test "history archive: torn untrusted pointer, snapshot, or vote is ignored" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0x91);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = registry.networkId("history torn archive files");
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    defer archive.deinit();
    const state = stateAt(network_id, 1);
    _ = try archive.recordApplied(&state);

    var latest_name_buf: [max_name_bytes]u8 = undefined;
    const latest_name = latestName(id, &latest_name_buf);
    try overwriteTestFileAt(io, archive.latest_dir, latest_name, "torn");
    try testing.expect((try archive.loadLatest(1)) == null);

    // Idempotent publication repairs only the mutable pointer.
    _ = try archive.recordApplied(&state);
    try testing.expect((try archive.loadLatest(1)) != null);
    var snapshot_buf: [registry.snapshot_max_bytes]u8 = undefined;
    const snapshot = registry.writeSnapshot(&state, &snapshot_buf);
    const assertion = Assertion{ .network_id = network_id, .slot = 1, .head_hash = state.head.hash, .snapshot_hash = hash(snapshot) };
    var snapshot_name_buf: [max_name_bytes]u8 = undefined;
    const snapshot_name = snapshotName(assertion.snapshot_hash, &snapshot_name_buf);
    try overwriteTestFileAt(io, archive.snapshots_dir, snapshot_name, "torn");
    try testing.expect((try archive.loadLatest(1)) == null);
    try overwriteTestFileAt(io, archive.snapshots_dir, snapshot_name, snapshot);
    try testing.expect((try archive.loadLatest(1)) != null);

    var vote_name_buf: [max_name_bytes]u8 = undefined;
    try overwriteTestFileAt(io, archive.votes_dir, voteName(assertion.digest(), id, &vote_name_buf), "torn");
    try testing.expect((try archive.loadLatest(1)) == null);
}

test "history archive: a torn trusted signing fence fails closed" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0x99);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = registry.networkId("history torn signing fence");
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    defer archive.deinit();
    const one = stateAt(network_id, 1);
    _ = try archive.recordApplied(&one);
    try overwriteTestFileAt(io, archive.signing_dir, "high-water.vote", "torn");
    const two = stateAt(network_id, 2);
    try testing.expectError(error.SigningFenceCorrupt, archive.recordApplied(&two));
}

test "history archive: each trusted directory barrier precedes shared publication" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const seed: [32]u8 = @splat(0x9a);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = registry.networkId("history directory barriers");
    const state = stateAt(network_id, 1);
    var snapshot_buf: [registry.snapshot_max_bytes]u8 = undefined;
    const snapshot = registry.writeSnapshot(&state, &snapshot_buf);

    // First fail the per-slot-vote directory fsync, then the high-water
    // directory fsync. Neither trusted failure may occur after a shared
    // object write. Finally fail the shared snapshot-directory barrier to
    // prove the identical low-level error retains availability semantics.
    for (0..3) |which| {
        var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
        var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
        var archive_suffix_buf: [32]u8 = undefined;
        var signing_suffix_buf: [32]u8 = undefined;
        const archive_suffix = try std.fmt.bufPrint(&archive_suffix_buf, "archive-{d}", .{which});
        const signing_suffix = try std.fmt.bufPrint(&signing_suffix_buf, "signing-{d}", .{which});
        const archive_path = try testPath(&tmp, io, archive_suffix, &archive_buf);
        const signing_path = try testPath(&tmp, io, signing_suffix, &signing_buf);
        var archive = try Archive.open(gpa, io, .{
            .archive_dir = archive_path,
            .signing_dir = signing_path,
            .network_id = network_id,
            .quorum = slcp.Quorum.of(1, &.{id}),
            .signer_seed = seed,
            .checkpoint_every = 1,
        });
        defer archive.deinit();
        archive.sync_directory = TestDirSyncFault.sync;
        TestDirSyncFault.target = switch (which) {
            0 => archive.signing_votes_dir.handle,
            1 => archive.signing_dir.handle,
            2 => archive.snapshots_dir.handle,
            else => unreachable,
        };
        defer TestDirSyncFault.target = null;

        if (which < 2) {
            try testing.expectError(error.SigningFenceUnavailable, archive.recordApplied(&state));
            var name_buf: [max_name_bytes]u8 = undefined;
            try testing.expectError(error.FileNotFound, archive.snapshots_dir.statFile(
                io,
                snapshotName(hash(snapshot), &name_buf),
                .{ .follow_symlinks = false },
            ));
        } else {
            try testing.expectError(error.InjectedDirectorySyncFailure, archive.recordApplied(&state));
        }
    }
}

test "history archive: a trusted file-sync failure precedes shared publication" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0x9b);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = registry.networkId("history file sync barrier");
    const state = stateAt(network_id, 1);

    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    defer archive.deinit();
    archive.sync_file = TestFileSyncFault.sync;
    TestFileSyncFault.fail = true;
    defer TestFileSyncFault.fail = false;

    try testing.expectError(error.SigningFenceUnavailable, archive.recordApplied(&state));
    try testing.expect((try archive.loadLatest(1)) == null);

    TestFileSyncFault.fail = false;
    try testing.expectEqual(RecordStatus.certified, try archive.recordApplied(&state));
    try testing.expectEqual(@as(u64, 1), (try archive.loadLatest(1)).?.head.slot);
}

test "history archive: two quorum-certified heads at one slot fail closed" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    var sign_bufs: [5][std.fs.max_path_bytes]u8 = undefined;
    var sign_paths: [5][]const u8 = undefined;
    for (&sign_paths, &sign_bufs, 0..) |*path, *buf, i| {
        var suffix_buf: [32]u8 = undefined;
        const suffix = try std.fmt.bufPrint(&suffix_buf, "sign-{d}", .{i});
        path.* = try testPath(&tmp, io, suffix, buf);
    }
    const seeds = [3][32]u8{ @splat(0xa1), @splat(0xa2), @splat(0xa3) };
    const ids = [3]slcp.NodeId{
        try slcp.core.crypto.publicKeyFromSeed(seeds[0]),
        try slcp.core.crypto.publicKeyFromSeed(seeds[1]),
        try slcp.core.crypto.publicKeyFromSeed(seeds[2]),
    };
    const network_id = registry.networkId("history certified fork");
    const quorum = slcp.Quorum.of(2, &ids);
    var ax = try Archive.open(gpa, io, .{ .archive_dir = archive_path, .signing_dir = sign_paths[0], .network_id = network_id, .quorum = quorum, .signer_seed = seeds[0], .checkpoint_every = 1 });
    defer ax.deinit();
    var bx = try Archive.open(gpa, io, .{ .archive_dir = archive_path, .signing_dir = sign_paths[1], .network_id = network_id, .quorum = quorum, .signer_seed = seeds[1], .checkpoint_every = 1 });
    defer bx.deinit();
    const x = stateAt(network_id, 1);
    _ = try ax.recordApplied(&x);
    _ = try bx.recordApplied(&x);

    // Simulate copied validator identities with independent trusted signing
    // directories: B and C attest a different, self-consistent head.
    var by = try Archive.open(gpa, io, .{ .archive_dir = archive_path, .signing_dir = sign_paths[2], .network_id = network_id, .quorum = quorum, .signer_seed = seeds[1], .checkpoint_every = 1 });
    defer by.deinit();
    var cy = try Archive.open(gpa, io, .{ .archive_dir = archive_path, .signing_dir = sign_paths[3], .network_id = network_id, .quorum = quorum, .signer_seed = seeds[2], .checkpoint_every = 1 });
    defer cy.deinit();
    var y: registry.State = .{ .network_id = network_id };
    const source: registry.Key = @splat(0xa9);
    const tx = registry.Tx.init(source, 1, .claim, "other-head", "", registry.zero_key).?;
    var set: registry.TxSet = .{ .count = 1 };
    set.txs[0] = tx;
    registry.apply(&y, &set);
    _ = try by.recordApplied(&y);
    _ = try cy.recordApplied(&y);

    // The signatures themselves are enough to prove a same-slot safety fork;
    // an attacker cannot suppress that hard failure by tearing one snapshot.
    var y_snapshot_buf: [registry.snapshot_max_bytes]u8 = undefined;
    const y_snapshot = registry.writeSnapshot(&y, &y_snapshot_buf);
    var y_snapshot_name_buf: [max_name_bytes]u8 = undefined;
    try overwriteTestFileAt(io, ax.snapshots_dir, snapshotName(hash(y_snapshot), &y_snapshot_name_buf), "torn");
    try testing.expectError(error.CertifiedFork, ax.loadLatest(1));
}

test "history archive: untrusted namespace directories may not be symlinks" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const seed: [32]u8 = @splat(0xb1);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = registry.networkId("history namespace symlinks");
    const network_hex = registry.hex32(network_id);
    const cases = [_]?[]const u8{ null, "snapshots", "votes", "latest" };
    var archive_path_bufs: [cases.len][std.fs.max_path_bytes]u8 = undefined;
    var signing_path_bufs: [cases.len][std.fs.max_path_bytes]u8 = undefined;
    var outside_path_bufs: [cases.len][std.fs.max_path_bytes]u8 = undefined;

    for (cases, 0..) |child, i| {
        var archive_rel_buf: [64]u8 = undefined;
        var signing_rel_buf: [64]u8 = undefined;
        var outside_rel_buf: [64]u8 = undefined;
        const archive_rel = try std.fmt.bufPrint(&archive_rel_buf, "archive-{d}", .{i});
        const signing_rel = try std.fmt.bufPrint(&signing_rel_buf, "signing-{d}", .{i});
        const outside_rel = try std.fmt.bufPrint(&outside_rel_buf, "outside-{d}", .{i});
        try tmp.dir.createDirPath(io, archive_rel);
        try tmp.dir.createDirPath(io, outside_rel);
        const archive_path = try testPath(&tmp, io, archive_rel, &archive_path_bufs[i]);
        const signing_path = try testPath(&tmp, io, signing_rel, &signing_path_bufs[i]);
        const outside_path = try testPath(&tmp, io, outside_rel, &outside_path_bufs[i]);

        var network_rel_buf: [160]u8 = undefined;
        const network_rel = try std.fmt.bufPrint(&network_rel_buf, "{s}/{s}", .{ archive_rel, &network_hex });
        if (child) |name| {
            try tmp.dir.createDirPath(io, network_rel);
            var link_rel_buf: [192]u8 = undefined;
            const link_rel = try std.fmt.bufPrint(&link_rel_buf, "{s}/{s}", .{ network_rel, name });
            try tmp.dir.symLink(io, outside_path, link_rel, .{ .is_directory = true });
        } else {
            try tmp.dir.symLink(io, outside_path, network_rel, .{ .is_directory = true });
        }

        if (Archive.open(gpa, io, .{
            .archive_dir = archive_path,
            .signing_dir = signing_path,
            .network_id = network_id,
            .quorum = slcp.Quorum.of(1, &.{id}),
            .signer_seed = seed,
            .checkpoint_every = 1,
        })) |opened| {
            var archive = opened;
            archive.deinit();
            return error.ExpectedUntrustedSymlinkRejection;
        } else |_| {}
    }
}

test "history archive: replacing an opened namespace with symlinks cannot redirect publication" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const seed: [32]u8 = @splat(0xb2);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = registry.networkId("history namespace replacement");
    const network_hex = registry.hex32(network_id);
    const state = stateAt(network_id, 1);
    var snapshot_buf: [registry.snapshot_max_bytes]u8 = undefined;
    const snapshot = registry.writeSnapshot(&state, &snapshot_buf);
    const assertion: Assertion = .{
        .network_id = network_id,
        .slot = 1,
        .head_hash = state.head.hash,
        .snapshot_hash = hash(snapshot),
    };
    const cases = [_]?[]const u8{ null, "snapshots", "votes", "latest" };
    var archive_path_bufs: [cases.len][std.fs.max_path_bytes]u8 = undefined;
    var signing_path_bufs: [cases.len][std.fs.max_path_bytes]u8 = undefined;
    var outside_path_bufs: [cases.len][std.fs.max_path_bytes]u8 = undefined;

    for (cases, 0..) |child, i| {
        var archive_rel_buf: [64]u8 = undefined;
        var signing_rel_buf: [64]u8 = undefined;
        var outside_rel_buf: [64]u8 = undefined;
        const archive_rel = try std.fmt.bufPrint(&archive_rel_buf, "archive-swap-{d}", .{i});
        const signing_rel = try std.fmt.bufPrint(&signing_rel_buf, "signing-swap-{d}", .{i});
        const outside_rel = try std.fmt.bufPrint(&outside_rel_buf, "outside-swap-{d}", .{i});
        const archive_path = try testPath(&tmp, io, archive_rel, &archive_path_bufs[i]);
        const signing_path = try testPath(&tmp, io, signing_rel, &signing_path_bufs[i]);
        const outside_path = try testPath(&tmp, io, outside_rel, &outside_path_bufs[i]);
        try tmp.dir.createDirPath(io, outside_rel);

        var archive = try Archive.open(gpa, io, .{
            .archive_dir = archive_path,
            .signing_dir = signing_path,
            .network_id = network_id,
            .quorum = slcp.Quorum.of(1, &.{id}),
            .signer_seed = seed,
            .checkpoint_every = 1,
        });
        defer archive.deinit();

        var network_rel_buf: [160]u8 = undefined;
        const network_rel = try std.fmt.bufPrint(&network_rel_buf, "{s}/{s}", .{ archive_rel, &network_hex });
        var target_rel_buf: [192]u8 = undefined;
        const target_rel = if (child) |name|
            try std.fmt.bufPrint(&target_rel_buf, "{s}/{s}", .{ network_rel, name })
        else
            network_rel;
        var real_rel_buf: [224]u8 = undefined;
        const real_rel = try std.fmt.bufPrint(&real_rel_buf, "{s}.real", .{target_rel});
        try tmp.dir.rename(target_rel, tmp.dir, real_rel, io);
        if (child == null) {
            try std.Io.Dir.cwd().createDirPath(io, outside_path);
            inline for (.{ "snapshots", "votes", "latest" }) |name| {
                var child_path_buf: [std.fs.max_path_bytes]u8 = undefined;
                const child_path = try std.fmt.bufPrint(&child_path_buf, "{s}/{s}", .{ outside_path, name });
                try std.Io.Dir.cwd().createDirPath(io, child_path);
            }
        }
        try tmp.dir.symLink(io, outside_path, target_rel, .{ .is_directory = true });

        try testing.expectEqual(RecordStatus.certified, try archive.recordApplied(&state));

        var escaped_rel_buf: [384]u8 = undefined;
        const escaped_rel = if (child == null or std.mem.eql(u8, child.?, "snapshots"))
            try std.fmt.bufPrint(&escaped_rel_buf, "{s}{s}{s}.snap", .{
                outside_rel,
                if (child == null) "/snapshots/" else "/",
                &registry.hex32(assertion.snapshot_hash),
            })
        else if (std.mem.eql(u8, child.?, "votes"))
            try std.fmt.bufPrint(&escaped_rel_buf, "{s}/{s}-{s}.vote", .{
                outside_rel,
                &registry.hex32(assertion.digest()),
                &registry.hex32(id),
            })
        else
            try std.fmt.bufPrint(&escaped_rel_buf, "{s}/{s}.vote", .{ outside_rel, &registry.hex32(id) });
        try testing.expectError(error.FileNotFound, tmp.dir.statFile(io, escaped_rel, .{ .follow_symlinks = false }));
    }
}

test "history archive: exact object symlinks are never followed" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0xb3);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = registry.networkId("history object symlinks");
    const state = stateAt(network_id, 1);
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    defer archive.deinit();
    _ = try archive.recordApplied(&state);
    try testing.expect((try archive.loadLatest(1)) != null);

    var snapshot_buf: [registry.snapshot_max_bytes]u8 = undefined;
    const snapshot = registry.writeSnapshot(&state, &snapshot_buf);
    const assertion: Assertion = .{
        .network_id = network_id,
        .slot = 1,
        .head_hash = state.head.hash,
        .snapshot_hash = hash(snapshot),
    };
    const dirs = [_]std.Io.Dir{ archive.snapshots_dir, archive.votes_dir, archive.latest_dir };
    var name_bufs: [3][max_name_bytes]u8 = undefined;
    const names = [3][]const u8{
        snapshotName(assertion.snapshot_hash, &name_bufs[0]),
        voteName(assertion.digest(), id, &name_bufs[1]),
        latestName(id, &name_bufs[2]),
    };

    for (dirs, names) |dir, name| {
        var real_buf: [max_name_bytes + 5]u8 = undefined;
        const real = try std.fmt.bufPrint(&real_buf, "{s}.real", .{name});
        try dir.rename(name, dir, real, io);
        try dir.symLink(io, real, name, .{});
        try testing.expect((try archive.loadLatest(1)) == null);
        try dir.deleteFile(io, name);
        try dir.rename(real, dir, name, io);
        try testing.expect((try archive.loadLatest(1)) != null);
    }
}

test "history archive: a FIFO object is rejected without blocking discovery" {
    if (comptime !durabilitySupported(builtin.os.tag)) return;
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0xb4);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = registry.networkId("history fifo object");
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    defer archive.deinit();

    var name_buf: [max_name_bytes]u8 = undefined;
    const name = latestName(id, &name_buf);
    var name_z_buf: [max_name_bytes + 1]u8 = undefined;
    @memcpy(name_z_buf[0..name.len], name);
    name_z_buf[name.len] = 0;
    const name_z: [:0]const u8 = name_z_buf[0..name.len :0];
    if (mkfifoat(archive.latest_dir.handle, name_z.ptr, 0o600) != 0)
        return error.TestFifoCreationFailed;
    try testing.expect((try archive.loadLatest(1)) == null);
}
