//! history.zig — quorum-authenticated replayable registry history.
//!
//! The archive tree is untrusted shared storage. Under its network-id
//! and `history-v1` namespaces it contains immutable ledger records, canonical
//! registry anchor snapshots, fixed-width validator tip votes, and one mutable
//! latest-vote pointer per validator. The separate signing tree is trusted
//! local storage; immutable per-slot votes plus a monotonic high-water vote
//! prevent this validator from signing a rollback or equivocation.
//!
//! A vote signs SHA-256("REGISTRY-HIST-V1" || network_id || tip slot/head ||
//! anchor cadence || anchor slot/head/snapshot hash). Imported votes are
//! evaluated only against the caller-supplied, normalized quorum set. No
//! quorum policy comes from the archive. Slot one and every cadence
//! boundary are deterministic anchor slots. On fresh non-genesis activation,
//! the existing base is not republished or treated as continuity-proven, even
//! when it occupies an anchor slot. Successor ledgers are recorded immediately;
//! attestation starts when a newly applied successor reaches the next anchor.
//! Ledger records contain no cadence or anchor metadata, so different writer
//! cadences produce identical content-addressed records.
//!
//! Files under `<archive>/<network-hex>/history-v1/` are:
//! `snapshots/<snapshot-hash>.snap`,
//! `votes/<assertion-digest>-<signer>.vote`, and mutable
//! `latest/<signer>.vote`, plus `ledgers/<head-hash>.ledger`. Trusted files
//! under `<signing>/<network-hex>/history-v1/` are an immutable cadence/epoch/
//! activation policy, immutable `votes/<slot>.vote`, mutable `high-water.vote`,
//! and a checksummed, crash-durable bounded outbox with explicit trusted boot
//! provenance.
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
//! Pre-E2c Snapshot V1/V2 objects are not eligible history anchors:
//! neither carries the versioned ledger value and close time required for
//! exact previous-value recovery. Snapshot V3 is the sole accepted format.
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

const tag: *const [16]u8 = "REGISTRY-HIST-V1";
const ledger_magic = "REGISTRY-LEDGER-V1\n";
const policy_magic = "REGISTRY-HISTORY-POLICY-V1\n";
const watermark_magic = "REGISTRY-HISTORY-WATERMARK-V1\n";
const boot_provenance_magic = "REGISTRY-HISTORY-BOOT-V1\n";
const boot_provenance_name = "boot-provenance";
const assertion_bytes = tag.len + 32 + 8 + 32 + 1 + 8 + 32 + 32;
const vote_bytes = assertion_bytes + 32 + 64;
const max_candidates = 16;
const max_backlog: u64 = 64;
const max_name_bytes = 160;
const ledger_fixed_bytes = ledger_magic.len + 32 + 8 + 8 + 4 * 32 + 2;
const ledger_max_bytes = ledger_fixed_bytes + registry.max_ledger_value_bytes + 32;
const policy_bytes = policy_magic.len + 32 + 8 + 1 + 8 + 32 + 32;
const watermark_bytes = watermark_magic.len + 32 + 8 + 32 + 32;
const boot_provenance_bytes = boot_provenance_magic.len + 32 + 8 + 32 + 32;

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
    genesis_close_time: u64,
    quorum: slcp.Quorum,
    signer_seed: [32]u8,
    checkpoint_every: u64 = 8,
};

pub const RecordStatus = enum {
    /// The canonical ledger was archived, but this signing tree has not yet
    /// published a continuity-proven anchor. A fresh non-genesis activation
    /// base is never republished as that anchor, even at slot 1 or an N-slot
    /// boundary; attestation starts when a newly applied successor reaches the
    /// next deterministic anchor.
    not_due,
    /// This validator's vote was durably fenced and published. This does not
    /// imply that enough other validators have published for a quorum yet.
    published,
    /// This validator published its vote and the exact assertion now has a
    /// quorum under the caller-supplied quorum set.
    certified,
};

pub const Recovery = struct {
    state: registry.State,
    anchor_slot: u64,
    /// Number of ledger records applied after the authenticated anchor.
    replayed_ledgers: u64,
};

const Watermark = struct {
    slot: u64,
    head_hash: [32]u8,
};

const Inflight = struct {
    state: registry.State,
    assertion: ?Assertion,
};

const RecoveredProof = struct {
    recovery: Recovery,
    assertion: Assertion,
};

pub const Archive = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    snapshots_dir: std.Io.Dir,
    ledgers_dir: std.Io.Dir,
    votes_dir: std.Io.Dir,
    latest_dir: std.Io.Dir,
    signing_dir: std.Io.Dir,
    signing_votes_dir: std.Io.Dir,
    outbox_dir: std.Io.Dir,
    network_id: [32]u8,
    genesis_close_time: u64,
    quorum: slcp.core.qset.QuorumSetOwned,
    validators: []slcp.NodeId,
    signer_seed: [32]u8,
    signer_id: slcp.NodeId,
    checkpoint_every: u64,
    policy_initialized: bool,
    activation: ?Watermark,
    adoption_pending: ?Watermark,
    boot_provenance: ?Watermark,
    admitted: ?Watermark,
    published: ?Watermark,
    stage_frontier: ?registry.State,
    publish_frontier: ?registry.State,
    publish_assertion: ?Assertion,
    fenced_pending: ?Assertion,
    ready: ?registry.State,
    inflight: ?Inflight,
    recovered_proof: ?RecoveredProof,
    mutex: std.Io.Mutex,
    sync_directory: *const fn (std.Io.Dir) anyerror!void,
    sync_file: *const fn (std.Io, std.Io.File) anyerror!void,

    /// Opens network-scoped archive and signing roots and owns a normalized
    /// copy of `cfg.quorum`. The signer must be a member of that quorum set.
    pub fn open(gpa: std.mem.Allocator, io: std.Io, cfg: Config) !Archive {
        if (comptime !durabilitySupported(builtin.os.tag))
            return error.UnsupportedHistoryDurability;
        if (cfg.checkpoint_every == 0 or cfg.checkpoint_every > 64)
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
        const archive_version = try archive_network.createDirPathOpen(io, "history-v1", no_follow);
        defer archive_version.close(io);
        try syncDir(archive_network);
        const snapshots_dir = try archive_version.createDirPathOpen(io, "snapshots", no_follow);
        errdefer snapshots_dir.close(io);
        const ledgers_dir = try archive_version.createDirPathOpen(io, "ledgers", no_follow);
        errdefer ledgers_dir.close(io);
        const votes_dir = try archive_version.createDirPathOpen(io, "votes", no_follow);
        errdefer votes_dir.close(io);
        const latest_dir = try archive_version.createDirPathOpen(io, "latest", no_follow);
        errdefer latest_dir.close(io);
        try syncDir(archive_version);

        const signing_network = try signing_base.createDirPathOpen(io, &network_hex, no_follow);
        defer signing_network.close(io);
        try syncDir(signing_base);
        const signing_dir = try signing_network.createDirPathOpen(io, "history-v1", no_follow);
        errdefer signing_dir.close(io);
        try syncDir(signing_network);
        const signing_votes_dir = try signing_dir.createDirPathOpen(io, "votes", no_follow);
        errdefer signing_votes_dir.close(io);
        const outbox_dir = try signing_dir.createDirPathOpen(io, "outbox", no_follow);
        errdefer outbox_dir.close(io);
        try syncDir(signing_dir);

        var archive: Archive = .{
            .gpa = gpa,
            .io = io,
            .snapshots_dir = snapshots_dir,
            .ledgers_dir = ledgers_dir,
            .votes_dir = votes_dir,
            .latest_dir = latest_dir,
            .signing_dir = signing_dir,
            .signing_votes_dir = signing_votes_dir,
            .outbox_dir = outbox_dir,
            .network_id = cfg.network_id,
            .genesis_close_time = cfg.genesis_close_time,
            .quorum = quorum,
            .validators = validators,
            .signer_seed = cfg.signer_seed,
            .signer_id = signer_id,
            .checkpoint_every = cfg.checkpoint_every,
            .policy_initialized = false,
            .activation = null,
            .adoption_pending = null,
            .boot_provenance = null,
            .admitted = null,
            .published = null,
            .stage_frontier = null,
            .publish_frontier = null,
            .publish_assertion = null,
            .fenced_pending = null,
            .ready = null,
            .inflight = null,
            .recovered_proof = null,
            .mutex = .init,
            .sync_directory = syncDir,
            .sync_file = fullSync,
        };
        try archive.loadPolicyAndWatermarks();
        return archive;
    }

    pub fn deinit(self: *Archive) void {
        if (self.stage_frontier) |*s| s.deinit(self.gpa);
        if (self.publish_frontier) |*s| s.deinit(self.gpa);
        if (self.ready) |*s| s.deinit(self.gpa);
        if (self.inflight) |*i| i.state.deinit(self.gpa);
        if (self.recovered_proof) |*proof| proof.recovery.state.deinit(self.gpa);
        self.outbox_dir.close(self.io);
        self.signing_votes_dir.close(self.io);
        self.signing_dir.close(self.io);
        self.latest_dir.close(self.io);
        self.votes_dir.close(self.io);
        self.ledgers_dir.close(self.io);
        self.snapshots_dir.close(self.io);
        self.quorum.deinit(self.gpa);
        self.gpa.free(self.validators);
        self.* = undefined;
    }

    /// Recovers the highest discoverable quorum-certified tip at or above the
    /// inclusive floor. Discovery is bounded by the configured validators and
    /// `max_candidates`; replay is bounded by signed `anchor_every - 1`.
    /// Malformed or unavailable shared objects cannot become state. Two
    /// discoverable certified assertions at one slot are a hard fork.
    pub fn recoverLatest(self: *Archive, min_slot: u64) !?Recovery {
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

        var best: ?RecoveredProof = null;
        var best_owned = true;
        defer {
            if (best_owned and best != null) {
                var b = best.?;
                b.recovery.state.deinit(self.gpa);
            }
        }
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

            var recovered = (try self.recoverAssertion(candidate.assertion)) orelse continue;
            if (best) |current| {
                if (recovered.state.head.slot < current.recovery.state.head.slot) {
                    recovered.state.deinit(self.gpa);
                    continue;
                }
                var superseded = current;
                superseded.recovery.state.deinit(self.gpa);
            }
            best = .{ .recovery = recovered, .assertion = candidate.assertion };
        }
        // The archive owns the retained proof; the caller gets a clone so
        // the two never share storage.
        if (best) |proof| {
            self.recovered_proof = proof; // moves the retained state in
            const out = try self.recovered_proof.?.recovery.state.clone(self.gpa);
            best_owned = false; // the archive owns it now
            return .{
                .state = out,
                .anchor_slot = proof.recovery.anchor_slot,
                .replayed_ledgers = proof.recovery.replayed_ledgers,
            };
        }
        self.recovered_proof = null;
        return null;
    }

    /// Compatibility wrapper for the E2c caller. New code should retain the
    /// recovery metadata returned by `recoverLatest`.
    pub fn loadLatest(self: *Archive, min_slot: u64) !?registry.State {
        return if (try self.recoverLatest(min_slot)) |recovered| recovered.state else null;
    }

    /// Establishes the trusted outbox frontier. A fresh history-v1 tree may
    /// adopt exactly one caller-supplied local base. Thereafter the base must
    /// match durable outbox state, unless it is the exact quorum-certified
    /// state most recently returned by `recoverLatest`.
    pub fn prepareFrontier(self: *Archive, base: *const registry.State) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        try self.validateState(base);
        if (self.stage_frontier) |*frontier| {
            if (sameDurableState(frontier, base)) return;
            const admitted = self.admitted orelse return error.HistoryOutboxCorrupt;
            const published = self.published orelse return error.HistoryOutboxCorrupt;
            if (admitted.slot == published.slot) {
                if (self.recovered_proof) |*proof| {
                    if (proof.recovery.state.head.slot > published.slot and
                        sameDurableState(base, &proof.recovery.state))
                    {
                        if (self.adoption_pending != null)
                            return error.HistoryAdoptionNotInstalled;
                        const target: Watermark = .{ .slot = base.head.slot, .head_hash = base.head.hash };
                        try self.beginCertifiedAdoption(target, base);
                        self.admitted = target;
                        self.published = target;
                        if (self.stage_frontier) |*s| s.deinit(self.gpa);
                        self.stage_frontier = try base.clone(self.gpa);
                        if (self.publish_frontier) |*s| s.deinit(self.gpa);
                        self.publish_frontier = try base.clone(self.gpa);
                        if (self.ready) |*s| s.deinit(self.gpa);
                        self.ready = null;
                        self.publish_assertion = if (proof.assertion.anchor_every == self.checkpoint_every)
                            proof.assertion
                        else
                            null;
                        self.fenced_pending = null;
                        return;
                    }
                }
            }
            if (try self.preparedBaseIsRepresented(base, published, admitted)) return;
            return error.HistoryFrontierMismatch;
        }
        if (!self.policy_initialized) {
            try self.initializePolicy(base);
        } else {
            try self.prepareExistingFrontier(base);
        }
    }

    /// Returns a trusted certified-adoption target that still must be written
    /// to the application's ordinary snapshot store, if one exists.
    pub fn pendingInstall(self: *Archive) !?registry.State {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const target = self.adoption_pending orelse return null;
        return try self.loadFrontierState(target);
    }

    /// Reports whether `state` has the exact durable semantics of the ordinary
    /// snapshot most recently confirmed as descending from certified history.
    pub fn hasTrustedBootProvenance(self: *Archive, state: *const registry.State) !bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const trusted = self.boot_provenance orelse return false;
        if (!watermarkMatchesState(trusted, state)) return false;
        const admitted = self.admitted orelse return error.HistoryOutboxCorrupt;
        const published = self.published orelse return error.HistoryOutboxCorrupt;
        var represented = try self.loadRepresentedState(trusted, published, admitted);
        defer represented.deinit(self.gpa);
        return sameDurableState(&represented, state);
    }

    /// Durably admits one exact successor without touching shared storage.
    /// This method is safe to call from the cadence thread while a worker is
    /// blocked in `recordApplied` on the hostile archive.
    pub fn stageApplied(self: *Archive, state: *const registry.State) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.adoption_pending != null) return error.HistoryAdoptionNotInstalled;
        const previous: *const registry.State = &(self.stage_frontier orelse return error.HistoryFrontierUnprepared);
        const admitted = self.admitted orelse return error.HistoryOutboxCorrupt;
        const published = self.published orelse return error.HistoryOutboxCorrupt;

        if (state.head.slot <= admitted.slot) {
            const durable = if (state.head.slot > published.slot)
                try self.loadStagedState(state.head.slot)
            else blk: {
                var name_buf: [max_name_bytes]u8 = undefined;
                break :blk try self.loadTrustedState(frontierName(state.head.hash, &name_buf));
            };
            if (!sameDurableState(&durable, state)) return error.HistoryOutboxStateMismatch;
            return;
        }
        if (state.head.slot <= admitted.slot or admitted.slot == std.math.maxInt(u64) or
            state.head.slot != admitted.slot + 1)
            return error.HistoryOutboxSequence;
        if (state.head.slot - published.slot > max_backlog)
            return error.HistoryBacklogFull;
        try self.validateSuccessor(previous, state, true);

        const snapshot = try registry.writeSnapshot(state, self.gpa);
        defer self.gpa.free(snapshot);
        var name_buf: [max_name_bytes]u8 = undefined;
        try self.writeTrustedImmutableFixed(
            self.outbox_dir,
            stagedName(state.head.slot, &name_buf),
            snapshot,
        );
        try self.sync_directory(self.outbox_dir);
        const next: Watermark = .{ .slot = state.head.slot, .head_hash = state.head.hash };
        try self.writeWatermark("admitted", next);
        try self.sync_directory(self.outbox_dir);
        self.admitted = next;
        if (self.stage_frontier) |*s| s.deinit(self.gpa);
        self.stage_frontier = try state.clone(self.gpa);
    }

    /// Confirms that the application has durably installed `state`. A pending
    /// certified adoption seeds trusted boot provenance before its marker is
    /// cleared. Existing provenance may advance through represented outbox
    /// successors; an exact cached certificate may seed an equal frontier.
    /// Without one of those trust roots, confirmation is intentionally a no-op.
    pub fn confirmInstalled(self: *Archive, state: *const registry.State) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        try self.validateState(state);
        const admitted = self.admitted orelse return error.HistoryOutboxCorrupt;
        const published = self.published orelse return error.HistoryOutboxCorrupt;
        if (self.adoption_pending) |target| {
            if (state.head.slot < target.slot) return error.HistoryAdoptionNotInstalled;
            if (state.head.slot > published.slot) return error.HistoryFrontierMismatch;
            if (!watermarkMatchesState(target, state)) return error.HistoryFrontierMismatch;
            if (!try self.stateIsRepresented(state, published, admitted))
                return error.HistoryFrontierMismatch;
            try self.advanceBootProvenance(state);
            try self.clearAdoptionMarker();
            return;
        }

        if (self.boot_provenance == null) {
            const proof = self.recovered_proof orelse return;
            if (!sameDurableState(&proof.recovery.state, state)) return;
        }
        if (!try self.stateIsRepresented(state, published, admitted))
            return error.HistoryFrontierMismatch;
        try self.advanceBootProvenance(state);
    }

    /// Returns the oldest unacknowledged durable state, or null when caught
    /// up. Snapshot V3 deliberately normalizes its transient result vector.
    pub fn nextStaged(self: *Archive) !?registry.State {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const admitted = self.admitted orelse return error.HistoryFrontierUnprepared;
        const published = self.published orelse return error.HistoryOutboxCorrupt;
        if (published.slot == admitted.slot) return null;
        if (published.slot == std.math.maxInt(u64)) return error.HistoryOutboxCorrupt;
        const state = try self.loadStagedState(published.slot + 1);
        const previous: *const registry.State = &(self.publish_frontier orelse return error.HistoryOutboxCorrupt);
        try self.validateSuccessor(previous, &state, false);
        if (self.ready) |*s| s.deinit(self.gpa);
        self.ready = try state.clone(self.gpa);
        return state;
    }

    /// Publishes the oldest staged state. No mutex is held across any shared
    /// archive operation; the cadence thread can continue filling the bounded
    /// trusted outbox while the shared filesystem is wedged.
    pub fn recordApplied(self: *Archive, state: *const registry.State) !RecordStatus {
        try self.validateState(state);
        const context = blk: {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (self.inflight != null) return error.HistoryAckRequired;
            const published = self.published orelse return error.HistoryFrontierUnprepared;
            if (published.slot == std.math.maxInt(u64) or state.head.slot != published.slot + 1)
                return error.HistoryOutboxSequence;
            const staged = self.ready orelse return error.HistoryStagedStateNotLoaded;
            if (!sameDurableState(&staged, state)) return error.HistoryOutboxStateMismatch;
            const previous: *const registry.State = &(self.publish_frontier orelse return error.HistoryOutboxCorrupt);
            break :blk .{
                .previous = previous,
                .prior_assertion = self.publish_assertion,
                .fenced_pending = self.fenced_pending,
                .published = published,
            };
        };
        try self.validateSuccessor(context.previous, state, false);

        const record: LedgerRecord = .{
            .network_id = self.network_id,
            .header = state.head,
            .value = state.last_value.?,
        };
        var ledger_buf: [ledger_max_bytes]u8 = undefined;
        const ledger = record.encode(&ledger_buf);
        var ledger_name_buf: [max_name_bytes]u8 = undefined;
        try self.writeImmutable(self.ledgers_dir, ledgerName(record.header.hash, &ledger_name_buf), ledger);
        try self.sync_directory(self.ledgers_dir);

        const anchor_slot = expectedAnchor(state.head.slot, self.checkpoint_every);
        var anchor_head_hash: [32]u8 = undefined;
        var anchor_snapshot_hash: [32]u8 = undefined;
        if (anchor_slot == state.head.slot) {
            const snapshot = try registry.writeSnapshot(state, self.gpa);
            defer self.gpa.free(snapshot);
            anchor_head_hash = state.head.hash;
            anchor_snapshot_hash = hash(snapshot);
            if (context.fenced_pending) |pending| {
                if (pending.slot != state.head.slot or
                    pending.anchor_every != self.checkpoint_every or
                    pending.anchor_slot != state.head.slot or
                    !std.mem.eql(u8, &pending.head_hash, &state.head.hash) or
                    !std.mem.eql(u8, &pending.anchor_head_hash, &anchor_head_hash) or
                    !std.mem.eql(u8, &pending.snapshot_hash, &anchor_snapshot_hash))
                    return error.SigningFenceCorrupt;
            }
            var snapshot_name_buf: [max_name_bytes]u8 = undefined;
            try self.writeImmutable(
                self.snapshots_dir,
                snapshotName(anchor_snapshot_hash, &snapshot_name_buf),
                snapshot,
            );
            try self.sync_directory(self.snapshots_dir);
        } else if (context.fenced_pending) |pending| {
            if (pending.slot != state.head.slot or
                !std.mem.eql(u8, &pending.head_hash, &state.head.hash) or
                pending.anchor_every != self.checkpoint_every or
                pending.anchor_slot != anchor_slot)
                return error.SigningFenceCorrupt;
            anchor_head_hash = pending.anchor_head_hash;
            anchor_snapshot_hash = pending.snapshot_hash;
        } else if (context.prior_assertion) |prior| {
            if (prior.anchor_every != self.checkpoint_every or prior.anchor_slot != anchor_slot)
                return error.HistoryAnchorInvalid;
            anchor_head_hash = prior.anchor_head_hash;
            anchor_snapshot_hash = prior.snapshot_hash;
        } else {
            try self.setInflight(context.published, state, null);
            return .not_due;
        }

        const assertion: Assertion = context.fenced_pending orelse .{
            .network_id = self.network_id,
            .slot = state.head.slot,
            .head_hash = state.head.hash,
            .anchor_every = @intCast(self.checkpoint_every),
            .anchor_slot = anchor_slot,
            .anchor_head_hash = anchor_head_hash,
            .snapshot_hash = anchor_snapshot_hash,
        };
        var recovered = (try self.recoverAssertion(assertion)) orelse
            return error.HistoryChainUnavailable;
        defer recovered.state.deinit(self.gpa);
        // `state` came from durable Snapshot V3 outbox bytes, which omit the
        // transient result vector. Admission already compared those results
        // before persistence; publication compares only durable semantics.
        if (!sameRecoveredState(&recovered.state, state, false))
            return error.HistoryTransitionInvalid;

        const vote = Vote{
            .assertion = assertion,
            .signer = self.signer_id,
            .signature = try slcp.core.crypto.sign(self.signer_seed, assertion.digest()),
        };
        var vote_buf: [vote_bytes]u8 = undefined;
        encodeVote(vote, &vote_buf);
        self.fence(vote, &vote_buf) catch |err| switch (err) {
            error.SigningFenceCorrupt,
            error.SigningEquivocation,
            error.SigningRollback,
            => |semantic| return semantic,
            else => return error.SigningFenceUnavailable,
        };

        var vote_name_buf: [max_name_bytes]u8 = undefined;
        try self.writeImmutable(self.votes_dir, voteName(assertion.digest(), self.signer_id, &vote_name_buf), &vote_buf);
        try self.sync_directory(self.votes_dir);
        var latest_name_buf: [max_name_bytes]u8 = undefined;
        try self.writeAtomic(self.latest_dir, latestName(self.signer_id, &latest_name_buf), &vote_buf);
        try self.sync_directory(self.latest_dir);
        const status: RecordStatus = if (try self.isCertified(assertion)) .certified else .published;
        try self.setInflight(context.published, state, assertion);
        return status;
    }

    /// Commits publication locally before deleting the staged object. Calling
    /// it twice for the same already-acknowledged slot is idempotent.
    pub fn ackStaged(self: *Archive, slot: u64) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const published = self.published orelse return error.HistoryFrontierUnprepared;
        if (slot == published.slot and self.inflight == null) return;
        if (published.slot == std.math.maxInt(u64) or slot != published.slot + 1)
            return error.HistoryOutboxSequence;
        const inflight: *const Inflight = &(self.inflight orelse return error.HistoryNotPublished);
        if (inflight.state.head.slot != slot) return error.HistoryOutboxSequence;

        const snapshot = try registry.writeSnapshot(&inflight.state, self.gpa);
        defer self.gpa.free(snapshot);
        var frontier_name_buf: [max_name_bytes]u8 = undefined;
        try self.writeTrustedImmutableFixed(
            self.outbox_dir,
            frontierName(inflight.state.head.hash, &frontier_name_buf),
            snapshot,
        );
        try self.sync_directory(self.outbox_dir);
        const next: Watermark = .{ .slot = slot, .head_hash = inflight.state.head.hash };
        try self.writeWatermark("published", next);
        try self.sync_directory(self.outbox_dir);

        var staged_name_buf: [max_name_bytes]u8 = undefined;
        self.outbox_dir.deleteFile(self.io, stagedName(slot, &staged_name_buf)) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return error.HistoryOutboxUnavailable,
        };
        try self.sync_directory(self.outbox_dir);
        self.published = next;
        if (self.publish_frontier) |*s| s.deinit(self.gpa);
        self.publish_frontier = inflight.state; // moves the inflight state
        if (inflight.assertion) |assertion| self.publish_assertion = assertion;
        if (self.fenced_pending) |pending| {
            if (pending.slot == slot) self.fenced_pending = null;
        }
        if (self.ready) |*s| s.deinit(self.gpa);
        self.ready = null;
        self.inflight = null; // its state moved into publish_frontier
    }

    fn loadPolicyAndWatermarks(self: *Archive) !void {
        var policy_buf: [policy_bytes]u8 = undefined;
        const raw = self.readTrustedFixed(self.signing_dir, "policy", &policy_buf) catch |err| switch (err) {
            error.FileNotFound => {
                if ((self.readBootProvenance() catch return error.HistoryOutboxCorrupt) != null)
                    return error.HistoryOutboxCorrupt;
                return;
            },
            else => return error.HistoryPolicyCorrupt,
        };
        const policy = decodePolicy(raw) orelse return error.HistoryPolicyCorrupt;
        if (!std.mem.eql(u8, &policy.network_id, &self.network_id) or
            policy.genesis_close_time != self.genesis_close_time or
            policy.anchor_every != self.checkpoint_every)
            return error.HistoryPolicyMismatch;
        self.policy_initialized = true;
        self.activation = policy.activation;
        self.admitted = self.readWatermark("admitted") catch return error.HistoryOutboxCorrupt;
        self.published = self.readWatermark("published") catch return error.HistoryOutboxCorrupt;
        self.adoption_pending = self.readWatermark("adoption") catch return error.HistoryOutboxCorrupt;
        self.boot_provenance = self.readBootProvenance() catch return error.HistoryOutboxCorrupt;
        const admitted = self.admitted orelse return error.HistoryOutboxCorrupt;
        const published = self.published orelse return error.HistoryOutboxCorrupt;
        if (self.loadFrontierState(policy.activation)) |probe| {
            var probe_state = probe;
            probe_state.deinit(self.gpa);
        } else |_| return error.HistoryOutboxCorrupt;
        if (published.slot > admitted.slot) return error.HistoryOutboxCorrupt;
        if (self.adoption_pending) |target| {
            if (!adoptionWatermarksReachable(target, published, admitted))
                return error.HistoryOutboxCorrupt;
        }
        if (admitted.slot - published.slot > max_backlog and self.adoption_pending == null)
            return error.HistoryOutboxCorrupt;
        if (self.boot_provenance) |trusted| {
            if (trusted.slot < policy.activation.slot) return error.HistoryOutboxCorrupt;
            if (self.loadRepresentedState(trusted, published, admitted)) |probe| {
                var probe_state = probe;
                probe_state.deinit(self.gpa);
            } else |_| return error.HistoryOutboxCorrupt;
            if (self.adoption_pending) |target| {
                if (trusted.slot > target.slot or
                    (trusted.slot == target.slot and !sameWatermark(trusted, target)))
                    return error.HistoryOutboxCorrupt;
            }
        }
    }

    fn initializePolicy(self: *Archive, base: *const registry.State) !void {
        const initial: Watermark = .{ .slot = base.head.slot, .head_hash = base.head.hash };
        const old_admitted = try self.readWatermark("admitted");
        const old_published = try self.readWatermark("published");
        inline for (.{ old_admitted, old_published }) |old| if (old) |watermark| {
            if (!sameWatermark(watermark, initial)) return error.HistoryActivationMismatch;
        };

        const snapshot = try registry.writeSnapshot(base, self.gpa);
        defer self.gpa.free(snapshot);
        var frontier_name_buf: [max_name_bytes]u8 = undefined;
        try self.writeTrustedImmutableFixed(
            self.outbox_dir,
            frontierName(base.head.hash, &frontier_name_buf),
            snapshot,
        );
        try self.sync_directory(self.outbox_dir);
        try self.writeWatermark("admitted", initial);
        try self.writeWatermark("published", initial);
        try self.sync_directory(self.outbox_dir);

        var policy_buf: [policy_bytes]u8 = undefined;
        encodePolicy(.{
            .network_id = self.network_id,
            .genesis_close_time = self.genesis_close_time,
            .anchor_every = @intCast(self.checkpoint_every),
            .activation = initial,
        }, &policy_buf);
        try self.writeTrustedImmutableFixed(self.signing_dir, "policy", &policy_buf);
        try self.sync_directory(self.signing_dir);
        self.policy_initialized = true;
        self.activation = initial;
        self.adoption_pending = null;
        self.boot_provenance = null;
        self.admitted = initial;
        self.published = initial;
        self.stage_frontier = try base.clone(self.gpa);
        self.publish_frontier = try base.clone(self.gpa);
        self.ready = null;
        try self.restorePublicationAssertions(initial, initial);
    }

    fn prepareExistingFrontier(self: *Archive, base: *const registry.State) !void {
        var admitted = self.admitted orelse return error.HistoryOutboxCorrupt;
        var published = self.published orelse return error.HistoryOutboxCorrupt;

        if (self.adoption_pending) |target| {
            if (!adoptionWatermarksReachable(target, published, admitted))
                return error.HistoryOutboxCorrupt;
            var target_name_buf: [max_name_bytes]u8 = undefined;
            var target_state = try self.loadOptionalTrustedState(frontierName(target.head_hash, &target_name_buf));
            defer if (target_state) |*t| t.deinit(self.gpa);
            if (target_state == null) {
                // `beginCertifiedAdoption` writes the trusted marker before
                // materializing its frontier. A crash in that first window
                // leaves both watermarks at the same old frontier and is the
                // only safe case in which the marker can be aborted.
                if (sameWatermark(admitted, published) and published.slot < target.slot) {
                    try self.clearAdoptionMarker();
                } else {
                    return error.HistoryOutboxCorrupt;
                }
            } else if (!watermarkMatchesState(target, &target_state.?)) {
                return error.HistoryOutboxCorrupt;
            } else {
                try self.finishCertifiedAdoption(target, &target_state.?);
                admitted = target;
                published = target;
            }
        }

        var published_state = try self.loadFrontierState(published);
        var published_owned = true;
        defer if (published_owned) published_state.deinit(self.gpa);
        var staged_state = try published_state.clone(self.gpa);
        var staged_owned = true;
        defer if (staged_owned) staged_state.deinit(self.gpa);
        var slot = published.slot;
        while (slot < admitted.slot) {
            slot += 1;
            var next = try self.loadStagedState(slot);
            try self.validateSuccessor(&staged_state, &next, false);
            staged_state.deinit(self.gpa);
            staged_state = next;
        }

        var represented = sameDurableState(base, &staged_state) or
            sameDurableState(base, &published_state);
        if (!represented and base.head.slot > published.slot and base.head.slot <= admitted.slot) {
            var pending = try self.loadStagedState(base.head.slot);
            defer pending.deinit(self.gpa);
            represented = sameDurableState(base, &pending);
        }
        if (!represented and base.head.slot <= published.slot) {
            var name_buf: [max_name_bytes]u8 = undefined;
            const ancestor = self.loadTrustedState(frontierName(base.head.hash, &name_buf)) catch null;
            if (ancestor) |state| {
                represented = sameDurableState(base, &state);
                var owned = state;
                owned.deinit(self.gpa);
            }
        }
        if (!represented) {
            const proof: *const RecoveredProof = &(self.recovered_proof orelse return error.HistoryFrontierMismatch);
            if (admitted.slot != published.slot or
                proof.recovery.state.head.slot <= published.slot or
                !sameDurableState(base, &proof.recovery.state))
                return error.HistoryFrontierMismatch;
            const target: Watermark = .{ .slot = base.head.slot, .head_hash = base.head.hash };
            try self.beginCertifiedAdoption(target, base);
            admitted = target;
            published = target;
            published_state.deinit(self.gpa);
            published_state = try base.clone(self.gpa);
            staged_state.deinit(self.gpa);
            staged_state = try base.clone(self.gpa);
        }

        self.admitted = admitted;
        self.published = published;
        if (self.stage_frontier) |*s| s.deinit(self.gpa);
        self.stage_frontier = staged_state;
        staged_owned = false; // moved into the archive
        if (self.publish_frontier) |*s| s.deinit(self.gpa);
        self.publish_frontier = published_state;
        published_owned = false; // moved into the archive
        if (self.ready) |*s| s.deinit(self.gpa);
        self.ready = null;
        try self.restorePublicationAssertions(published, admitted);
    }

    fn preparedBaseIsRepresented(
        self: *Archive,
        base: *const registry.State,
        published: Watermark,
        admitted: Watermark,
    ) !bool {
        if (base.head.slot > published.slot and base.head.slot <= admitted.slot) {
            const pending = try self.loadStagedState(base.head.slot);
            return sameDurableState(base, &pending);
        }
        if (base.head.slot <= published.slot) {
            var name_buf: [max_name_bytes]u8 = undefined;
            const ancestor = self.loadTrustedState(frontierName(base.head.hash, &name_buf)) catch return false;
            return sameDurableState(base, &ancestor);
        }
        return false;
    }

    fn beginCertifiedAdoption(self: *Archive, target: Watermark, state: *const registry.State) !void {
        var marker_buf: [watermark_bytes]u8 = undefined;
        encodeWatermark(self.network_id, target, &marker_buf);
        try self.writeTrustedImmutableFixed(self.outbox_dir, "adoption", &marker_buf);
        try self.sync_directory(self.outbox_dir);
        self.adoption_pending = target;
        const snapshot = try registry.writeSnapshot(state, self.gpa);
        defer self.gpa.free(snapshot);
        var name_buf: [max_name_bytes]u8 = undefined;
        try self.writeTrustedImmutableFixed(self.outbox_dir, frontierName(target.head_hash, &name_buf), snapshot);
        try self.sync_directory(self.outbox_dir);
        try self.finishCertifiedAdoption(target, state);
    }

    fn finishCertifiedAdoption(self: *Archive, target: Watermark, state: *const registry.State) !void {
        const admitted = self.admitted orelse return error.HistoryOutboxCorrupt;
        const published = self.published orelse return error.HistoryOutboxCorrupt;
        if (!watermarkMatchesState(target, state) or
            !adoptionWatermarksReachable(target, published, admitted))
            return error.HistoryOutboxCorrupt;
        const snapshot = try registry.writeSnapshot(state, self.gpa);
        defer self.gpa.free(snapshot);
        var name_buf: [max_name_bytes]u8 = undefined;
        try self.writeTrustedImmutableFixed(self.outbox_dir, frontierName(target.head_hash, &name_buf), snapshot);
        try self.sync_directory(self.outbox_dir);
        try self.writeWatermark("admitted", target);
        try self.sync_directory(self.outbox_dir);
        try self.writeWatermark("published", target);
        try self.sync_directory(self.outbox_dir);
    }

    fn clearAdoptionMarker(self: *Archive) !void {
        self.outbox_dir.deleteFile(self.io, "adoption") catch |err| switch (err) {
            error.FileNotFound => return error.HistoryOutboxCorrupt,
            else => return error.HistoryOutboxUnavailable,
        };
        try self.sync_directory(self.outbox_dir);
        self.adoption_pending = null;
    }

    fn restorePublicationAssertions(self: *Archive, published: Watermark, admitted: Watermark) !void {
        self.publish_assertion = null;
        self.fenced_pending = null;
        if (self.recovered_proof) |proof| {
            if (watermarkMatchesState(published, &proof.recovery.state) and
                proof.assertion.anchor_every == self.checkpoint_every)
                self.publish_assertion = proof.assertion;
        }
        const high = try self.readTrustedVote(self.signing_dir, "high-water.vote");
        if (high) |vote| {
            if (vote.assertion.slot <= published.slot and
                vote.assertion.anchor_every == self.checkpoint_every and
                expectedAnchor(published.slot +| 1, self.checkpoint_every) == vote.assertion.anchor_slot)
                self.publish_assertion = vote.assertion
            else if (published.slot != std.math.maxInt(u64) and
                vote.assertion.slot == published.slot + 1 and
                vote.assertion.slot <= admitted.slot)
            {
                if (vote.assertion.anchor_every != self.checkpoint_every)
                    return error.SigningFenceCorrupt;
                var staged = try self.loadStagedState(vote.assertion.slot);
                defer staged.deinit(self.gpa);
                if (!std.mem.eql(u8, &staged.head.hash, &vote.assertion.head_hash))
                    return error.SigningFenceCorrupt;
                self.fenced_pending = vote.assertion;
            } else if (vote.assertion.slot > published.slot) {
                return error.SigningFenceCorrupt;
            }
        }
    }

    fn setInflight(self: *Archive, expected: Watermark, state: *const registry.State, assertion: ?Assertion) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const published = self.published orelse return error.HistoryOutboxCorrupt;
        if (!sameWatermark(published, expected) or self.inflight != null)
            return error.HistoryPublisherRace;
        self.inflight = .{ .state = try state.clone(self.gpa), .assertion = assertion };
    }

    fn validateState(self: *const Archive, state: *const registry.State) !void {
        if (state.last_count > registry.max_txs or
            (state.last_value != null and state.last_value.?.txs.count > registry.max_txs))
            return error.InvalidAppliedState;
        const root = try state.stateRoot(self.gpa);
        if (!std.mem.eql(u8, &state.network_id, &self.network_id) or
            !std.mem.eql(u8, &state.head.state_root, &root) or
            !std.mem.eql(u8, &state.head.hash, &registry.headerHash(state.network_id, &state.head)) or
            !registry.closeTimeAtSlotOk(self.genesis_close_time, state.head.slot, state.head.close_time) or
            !hasExactLastValue(state))
            return error.InvalidAppliedState;
        if (state.head.slot == 0) {
            var genesis = try registry.State.genesis(self.network_id, self.genesis_close_time, self.gpa);
            defer genesis.deinit(self.gpa);
            if (!sameDurableState(&genesis, state)) return error.InvalidGenesisState;
        } else if (state.head.slot == std.math.maxInt(u64)) {
            return error.CheckpointSlotOverflow;
        }
    }

    fn validateSuccessor(
        self: *const Archive,
        previous: *const registry.State,
        state: *const registry.State,
        compare_results: bool,
    ) !void {
        try self.validateState(previous);
        try self.validateState(state);
        if (previous.head.slot == std.math.maxInt(u64) or
            state.head.slot != previous.head.slot + 1 or
            !std.mem.eql(u8, &state.head.prev_hash, &previous.head.hash))
            return error.HistoryTransitionInvalid;
        const value = state.last_value orelse return error.InvalidAppliedState;
        if (registry.validate(previous, &value, state.head.slot) != .valid)
            return error.HistoryTransitionInvalid;
        var rebuilt = try previous.clone(self.gpa);
        defer rebuilt.deinit(self.gpa);
        try registry.apply(&rebuilt, &value, self.gpa);
        if (!sameRecoveredState(&rebuilt, state, compare_results))
            return error.HistoryTransitionInvalid;
    }

    fn loadStagedState(self: *Archive, slot: u64) !registry.State {
        var name_buf: [max_name_bytes]u8 = undefined;
        return self.loadTrustedState(stagedName(slot, &name_buf));
    }

    fn loadFrontierState(self: *Archive, watermark: Watermark) !registry.State {
        var name_buf: [max_name_bytes]u8 = undefined;
        const state = try self.loadTrustedState(frontierName(watermark.head_hash, &name_buf));
        if (!watermarkMatchesState(watermark, &state)) return error.HistoryOutboxCorrupt;
        return state;
    }

    fn loadRepresentedState(
        self: *Archive,
        watermark: Watermark,
        published: Watermark,
        admitted: Watermark,
    ) !registry.State {
        if (watermark.slot > admitted.slot) return error.HistoryOutboxCorrupt;
        const state = if (watermark.slot > published.slot)
            try self.loadStagedState(watermark.slot)
        else
            try self.loadFrontierState(watermark);
        if (!watermarkMatchesState(watermark, &state)) return error.HistoryOutboxCorrupt;
        return state;
    }

    fn stateIsRepresented(
        self: *Archive,
        state: *const registry.State,
        published: Watermark,
        admitted: Watermark,
    ) !bool {
        if (state.head.slot > admitted.slot) return false;
        if (state.head.slot > published.slot) {
            var staged = try self.loadStagedState(state.head.slot);
            defer staged.deinit(self.gpa);
            return sameDurableState(&staged, state);
        }
        var name_buf: [max_name_bytes]u8 = undefined;
        var represented = (try self.loadOptionalTrustedState(frontierName(state.head.hash, &name_buf))) orelse
            return false;
        defer represented.deinit(self.gpa);
        return sameDurableState(&represented, state);
    }

    fn advanceBootProvenance(self: *Archive, state: *const registry.State) !void {
        const next: Watermark = .{ .slot = state.head.slot, .head_hash = state.head.hash };
        if (self.boot_provenance) |current| {
            if (next.slot < current.slot) return error.HistoryBootProvenanceRollback;
            if (next.slot == current.slot) {
                if (!sameWatermark(next, current)) return error.HistoryBootProvenanceConflict;
                // A previous attempt can leave the atomic rename visible but
                // fail before its directory barrier. Re-establish that barrier
                // before a caller may clear the certified-adoption marker.
                try self.sync_directory(self.outbox_dir);
                return;
            }
        }
        try self.writeBootProvenance(next);
        try self.sync_directory(self.outbox_dir);
        self.boot_provenance = next;
    }

    fn loadTrustedState(self: *Archive, name: []const u8) !registry.State {
        return (try self.loadOptionalTrustedState(name)) orelse return error.HistoryOutboxCorrupt;
    }

    fn loadOptionalTrustedState(self: *Archive, name: []const u8) !?registry.State {
        const raw = self.readTrustedAlloc(self.outbox_dir, name) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return error.HistoryOutboxCorrupt,
        };
        defer self.gpa.free(raw);
        var state = (try registry.readSnapshot(self.gpa, raw)) orelse return error.HistoryOutboxCorrupt;
        var kept = false;
        defer if (!kept) state.deinit(self.gpa);
        self.validateState(&state) catch return error.HistoryOutboxCorrupt;
        kept = true;
        return state;
    }

    /// The trusted-state read with a dynamic buffer: V4 snapshots have no
    /// fixed maximum, so the file is read into an allocation bounded by the
    /// registry's hostile-input read limit.
    fn readTrustedAlloc(self: *Archive, dir: std.Io.Dir, name: []const u8) ![]u8 {
        if (comptime !durabilitySupported(builtin.os.tag))
            return error.UnsupportedHistoryDurability;
        var flags: std.posix.O = .{ .ACCMODE = .RDONLY };
        flags.NONBLOCK = true;
        flags.NOFOLLOW = true;
        if (@hasField(std.posix.O, "CLOEXEC")) flags.CLOEXEC = true;
        if (@hasField(std.posix.O, "RESOLVE_BENEATH")) flags.RESOLVE_BENEATH = true;
        const fd = try std.posix.openat(dir.handle, name, flags, 0);
        var file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = true } };
        defer file.close(self.io);
        const stat = try file.stat(self.io);
        if (stat.kind != .file) return error.NotRegularFile;
        if (stat.size > registry.snapshot_read_limit) return error.HistoryOutboxCorrupt;
        const out = try self.gpa.alloc(u8, @intCast(stat.size));
        errdefer self.gpa.free(out);
        var off: usize = 0;
        while (off < out.len) {
            const n = try std.posix.read(fd, out[off..]);
            if (n == 0) return error.HistoryOutboxCorrupt; // shorter than its stat: torn
            off += n;
        }
        return out;
    }

    fn readWatermark(self: *Archive, name: []const u8) !?Watermark {
        var buf: [watermark_bytes]u8 = undefined;
        const raw = self.readTrustedFixed(self.outbox_dir, name, &buf) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return error.HistoryOutboxCorrupt,
        };
        return decodeWatermark(raw, self.network_id) orelse return error.HistoryOutboxCorrupt;
    }

    fn writeWatermark(self: *Archive, name: []const u8, watermark: Watermark) !void {
        var buf: [watermark_bytes]u8 = undefined;
        encodeWatermark(self.network_id, watermark, &buf);
        try self.writeAtomic(self.outbox_dir, name, &buf);
    }

    fn readBootProvenance(self: *Archive) !?Watermark {
        var buf: [boot_provenance_bytes]u8 = undefined;
        const raw = self.readTrustedFixed(self.outbox_dir, boot_provenance_name, &buf) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return error.HistoryOutboxCorrupt,
        };
        return decodeBootProvenance(raw, self.network_id) orelse return error.HistoryOutboxCorrupt;
    }

    fn writeBootProvenance(self: *Archive, watermark: Watermark) !void {
        var buf: [boot_provenance_bytes]u8 = undefined;
        encodeBootProvenance(self.network_id, watermark, &buf);
        try self.writeAtomic(self.outbox_dir, boot_provenance_name, &buf);
    }

    fn readTrustedFixed(self: *Archive, dir: std.Io.Dir, name: []const u8, out: []u8) ![]const u8 {
        if (comptime !durabilitySupported(builtin.os.tag))
            return error.UnsupportedHistoryDurability;
        var flags: std.posix.O = .{ .ACCMODE = .RDONLY };
        flags.NONBLOCK = true;
        flags.NOFOLLOW = true;
        if (@hasField(std.posix.O, "CLOEXEC")) flags.CLOEXEC = true;
        if (@hasField(std.posix.O, "RESOLVE_BENEATH")) flags.RESOLVE_BENEATH = true;
        const fd = try std.posix.openat(dir.handle, name, flags, 0);
        var file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = true } };
        defer file.close(self.io);
        const stat = try file.stat(self.io);
        if (stat.kind != .file) return error.NotRegularFile;
        var off: usize = 0;
        while (off < out.len) {
            const n = try std.posix.read(fd, out[off..]);
            if (n == 0) return out[0..off];
            off += n;
        }
        var extra: [1]u8 = undefined;
        if (try std.posix.read(fd, &extra) != 0) return error.StreamTooLong;
        return out;
    }

    fn writeTrustedImmutableFixed(self: *Archive, dir: std.Io.Dir, name: []const u8, bytes: []const u8) !void {
        const old_buf = try self.gpa.alloc(u8, bytes.len);
        defer self.gpa.free(old_buf);
        if (self.readTrustedFixed(dir, name, old_buf)) |old| {
            if (!std.mem.eql(u8, old, bytes)) return error.ImmutableFileConflict;
            return;
        } else |err| switch (err) {
            error.FileNotFound => {},
            error.StreamTooLong, error.SymLinkLoop, error.IsDir, error.NotRegularFile => return error.ImmutableFileConflict,
            else => return err,
        }

        var temp_buf: [max_name_bytes + 21]u8 = undefined;
        const temp = self.tempName(name, &temp_buf);
        var file = try dir.createFile(self.io, temp, .{ .exclusive = true, .resolve_beneath = true });
        var file_open = true;
        var temp_exists = true;
        defer if (file_open) file.close(self.io);
        defer if (temp_exists) dir.deleteFile(self.io, temp) catch {};
        try file.writeStreamingAll(self.io, bytes);
        try self.sync_file(self.io, file);
        dir.renamePreserve(temp, dir, name, self.io) catch |err| switch (err) {
            error.PathAlreadyExists => {
                const old = try self.readTrustedFixed(dir, name, old_buf[0..@min(old_buf.len, bytes.len)]);
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

    fn recoverAssertion(self: *Archive, assertion: Assertion) !?Recovery {
        if (!self.validAssertion(assertion)) return null;
        var current = (try self.loadLedger(assertion.head_hash)) orelse return null;
        if (!recordMatchesAssertion(&current, assertion)) return error.CertifiedHistoryInvalid;

        var replay_hashes: [63][32]u8 = undefined;
        var replay_count: usize = 0;
        while (current.header.slot > assertion.anchor_slot) {
            if (replay_count == replay_hashes.len) return error.CertifiedHistoryInvalid;
            replay_hashes[replay_count] = current.header.hash;
            replay_count += 1;
            const child = current;
            current = (try self.loadLedger(child.header.prev_hash)) orelse return null;
            if (current.header.slot == std.math.maxInt(u64) or
                current.header.slot + 1 != child.header.slot or
                !std.mem.eql(u8, &current.header.hash, &child.header.prev_hash))
                return error.HistoryTransitionInvalid;
        }
        if (current.header.slot != assertion.anchor_slot or
            !std.mem.eql(u8, &current.header.hash, &assertion.anchor_head_hash))
            return error.CertifiedHistoryInvalid;

        var state = (try self.loadAnchorSnapshot(assertion)) orelse return null;
        var state_owned = true;
        defer if (state_owned) state.deinit(self.gpa);
        if (!std.meta.eql(state.head, current.header) or
            state.last_value == null or
            !sameLedgerValue(&state.last_value.?, &current.value))
            return error.CertifiedHistoryInvalid;
        try self.validateState(&state);

        var i = replay_count;
        while (i > 0) {
            i -= 1;
            const next = (try self.loadLedger(replay_hashes[i])) orelse return null;
            if (next.header.slot != state.head.slot + 1 or
                !std.mem.eql(u8, &next.header.prev_hash, &state.head.hash))
                return error.HistoryTransitionInvalid;
            if (registry.validate(&state, &next.value, next.header.slot) != .valid)
                return error.HistoryTransitionInvalid;
            try registry.apply(&state, &next.value, self.gpa);
            if (!std.meta.eql(state.head, next.header) or
                state.last_value == null or
                !sameLedgerValue(&state.last_value.?, &next.value))
                return error.HistoryTransitionInvalid;
        }
        if (!std.mem.eql(u8, &state.head.hash, &assertion.head_hash))
            return error.CertifiedHistoryInvalid;
        state_owned = false; // ownership transfers to the caller
        return .{
            .state = state,
            .anchor_slot = assertion.anchor_slot,
            .replayed_ledgers = @intCast(replay_count),
        };
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

    fn loadAnchorSnapshot(self: *Archive, assertion: Assertion) !?registry.State {
        var name_buf: [max_name_bytes]u8 = undefined;
        const name = snapshotName(assertion.snapshot_hash, &name_buf);
        const raw = try self.readUntrusted(self.snapshots_dir, name, registry.snapshot_read_limit);
        defer if (raw) |bytes| self.gpa.free(bytes);
        const bytes = raw orelse return null;
        if (!std.mem.eql(u8, &hash(bytes), &assertion.snapshot_hash)) return null;
        var state = (try registry.readSnapshot(self.gpa, bytes)) orelse return null;
        if (!std.mem.eql(u8, &state.network_id, &self.network_id) or
            state.head.slot != assertion.anchor_slot or
            !std.mem.eql(u8, &state.head.hash, &assertion.anchor_head_hash)) return null;
        // Every external checkpoint must carry the exact value needed as the
        // next slot's previous-value context. Pre-E2c snapshots cannot supply
        // that value and are therefore never eligible for import.
        if (!hasExactLastValue(&state)) return null;
        return state;
    }

    // Kept as an internal test seam while the E2c adversarial snapshot cases
    // are expressed in terms of the new anchor-bearing assertion.
    fn loadSnapshot(self: *Archive, assertion: Assertion) !?registry.State {
        return self.loadAnchorSnapshot(assertion);
    }

    fn loadLedger(self: *Archive, head_hash: [32]u8) !?LedgerRecord {
        var name_buf: [max_name_bytes]u8 = undefined;
        const raw = try self.readUntrusted(
            self.ledgers_dir,
            ledgerName(head_hash, &name_buf),
            ledger_max_bytes,
        );
        defer if (raw) |bytes| self.gpa.free(bytes);
        const record = LedgerRecord.decode(raw orelse return null) orelse return null;
        if (!std.mem.eql(u8, &record.network_id, &self.network_id) or
            !std.mem.eql(u8, &record.header.hash, &head_hash)) return null;
        return record;
    }

    fn validAssertion(self: *const Archive, assertion: Assertion) bool {
        return std.mem.eql(u8, &assertion.network_id, &self.network_id) and
            assertion.slot > 0 and
            assertion.slot < std.math.maxInt(u64) and
            assertion.anchor_every > 0 and assertion.anchor_every <= 64 and
            assertion.anchor_slot == expectedAnchor(assertion.slot, assertion.anchor_every) and
            !allZero(&assertion.head_hash) and
            !allZero(&assertion.anchor_head_hash) and
            !allZero(&assertion.snapshot_hash);
    }

    fn validVote(self: *const Archive, vote: *const Vote) bool {
        // Membership is established by each caller's expected signer: archive
        // reads iterate the normalized, globally unique quorum tree (or its
        // flattened validator list), while trusted reads require
        // self.signer_id. Re-scanning the quorum tree here would turn
        // certificate verification from O(V) into O(V^2).
        return self.validAssertion(vote.assertion) and
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

const Policy = struct {
    network_id: [32]u8,
    genesis_close_time: u64,
    anchor_every: u8,
    activation: Watermark,
};

fn encodePolicy(policy: Policy, out: *[policy_bytes]u8) void {
    var off: usize = 0;
    @memcpy(out[off..][0..policy_magic.len], policy_magic);
    off += policy_magic.len;
    @memcpy(out[off..][0..32], &policy.network_id);
    off += 32;
    std.mem.writeInt(u64, out[off..][0..8], policy.genesis_close_time, .big);
    off += 8;
    out[off] = policy.anchor_every;
    off += 1;
    std.mem.writeInt(u64, out[off..][0..8], policy.activation.slot, .big);
    off += 8;
    @memcpy(out[off..][0..32], &policy.activation.head_hash);
    off += 32;
    const checksum = hash(out[0..off]);
    @memcpy(out[off..][0..32], &checksum);
}

fn decodePolicy(bytes: []const u8) ?Policy {
    if (bytes.len != policy_bytes or !std.mem.eql(u8, bytes[0..policy_magic.len], policy_magic))
        return null;
    const body_end = bytes.len - 32;
    if (!std.mem.eql(u8, &hash(bytes[0..body_end]), bytes[body_end..])) return null;
    var off: usize = policy_magic.len;
    const network_id = bytes[off..][0..32].*;
    off += 32;
    const genesis_close_time = std.mem.readInt(u64, bytes[off..][0..8], .big);
    off += 8;
    const anchor_every = bytes[off];
    off += 1;
    if (anchor_every == 0 or anchor_every > 64) return null;
    const activation_slot = std.mem.readInt(u64, bytes[off..][0..8], .big);
    off += 8;
    const activation_head_hash = bytes[off..][0..32].*;
    if (allZero(&activation_head_hash)) return null;
    return .{
        .network_id = network_id,
        .genesis_close_time = genesis_close_time,
        .anchor_every = anchor_every,
        .activation = .{ .slot = activation_slot, .head_hash = activation_head_hash },
    };
}

fn encodeWatermark(network_id: [32]u8, watermark: Watermark, out: *[watermark_bytes]u8) void {
    var off: usize = 0;
    @memcpy(out[off..][0..watermark_magic.len], watermark_magic);
    off += watermark_magic.len;
    @memcpy(out[off..][0..32], &network_id);
    off += 32;
    std.mem.writeInt(u64, out[off..][0..8], watermark.slot, .big);
    off += 8;
    @memcpy(out[off..][0..32], &watermark.head_hash);
    off += 32;
    const checksum = hash(out[0..off]);
    @memcpy(out[off..][0..32], &checksum);
}

fn decodeWatermark(bytes: []const u8, network_id: [32]u8) ?Watermark {
    if (bytes.len != watermark_bytes or
        !std.mem.eql(u8, bytes[0..watermark_magic.len], watermark_magic))
        return null;
    const body_end = bytes.len - 32;
    if (!std.mem.eql(u8, &hash(bytes[0..body_end]), bytes[body_end..])) return null;
    var off: usize = watermark_magic.len;
    if (!std.mem.eql(u8, bytes[off..][0..32], &network_id)) return null;
    off += 32;
    const slot = std.mem.readInt(u64, bytes[off..][0..8], .big);
    off += 8;
    const head_hash = bytes[off..][0..32].*;
    if (allZero(&head_hash)) return null;
    return .{ .slot = slot, .head_hash = head_hash };
}

fn encodeBootProvenance(
    network_id: [32]u8,
    watermark: Watermark,
    out: *[boot_provenance_bytes]u8,
) void {
    var off: usize = 0;
    @memcpy(out[off..][0..boot_provenance_magic.len], boot_provenance_magic);
    off += boot_provenance_magic.len;
    @memcpy(out[off..][0..32], &network_id);
    off += 32;
    std.mem.writeInt(u64, out[off..][0..8], watermark.slot, .big);
    off += 8;
    @memcpy(out[off..][0..32], &watermark.head_hash);
    off += 32;
    const checksum = hash(out[0..off]);
    @memcpy(out[off..][0..32], &checksum);
}

fn decodeBootProvenance(bytes: []const u8, network_id: [32]u8) ?Watermark {
    if (bytes.len != boot_provenance_bytes or
        !std.mem.eql(u8, bytes[0..boot_provenance_magic.len], boot_provenance_magic))
        return null;
    const body_end = bytes.len - 32;
    if (!std.mem.eql(u8, &hash(bytes[0..body_end]), bytes[body_end..])) return null;
    var off: usize = boot_provenance_magic.len;
    if (!std.mem.eql(u8, bytes[off..][0..32], &network_id)) return null;
    off += 32;
    const slot = std.mem.readInt(u64, bytes[off..][0..8], .big);
    off += 8;
    const head_hash = bytes[off..][0..32].*;
    if (allZero(&head_hash)) return null;
    return .{ .slot = slot, .head_hash = head_hash };
}

const LedgerRecord = struct {
    network_id: [32]u8,
    header: registry.Header,
    value: registry.LedgerValue,

    fn encode(self: *const LedgerRecord, out: []u8) []u8 {
        std.debug.assert(out.len >= ledger_max_bytes);
        var off: usize = 0;
        @memcpy(out[off..][0..ledger_magic.len], ledger_magic);
        off += ledger_magic.len;
        @memcpy(out[off..][0..32], &self.network_id);
        off += 32;
        std.mem.writeInt(u64, out[off..][0..8], self.header.slot, .big);
        off += 8;
        std.mem.writeInt(u64, out[off..][0..8], self.header.close_time, .big);
        off += 8;
        inline for (.{ &self.header.hash, &self.header.prev_hash, &self.header.txset_hash, &self.header.state_root }) |field| {
            @memcpy(out[off..][0..32], field);
            off += 32;
        }
        var value_buf: [registry.max_ledger_value_bytes]u8 = undefined;
        const value = self.value.encode(&value_buf);
        std.mem.writeInt(u16, out[off..][0..2], @intCast(value.len), .big);
        off += 2;
        @memcpy(out[off..][0..value.len], value);
        off += value.len;
        const checksum = hash(out[0..off]);
        @memcpy(out[off..][0..32], &checksum);
        off += 32;
        return out[0..off];
    }

    fn decode(bytes: []const u8) ?LedgerRecord {
        if (bytes.len < ledger_fixed_bytes + valueMinimumBytes() + 32 or
            bytes.len > ledger_max_bytes or
            !std.mem.eql(u8, bytes[0..ledger_magic.len], ledger_magic))
            return null;
        const body_end = bytes.len - 32;
        if (!std.mem.eql(u8, &hash(bytes[0..body_end]), bytes[body_end..])) return null;

        var off: usize = ledger_magic.len;
        const network_id = bytes[off..][0..32].*;
        off += 32;
        var header: registry.Header = .{};
        header.slot = std.mem.readInt(u64, bytes[off..][0..8], .big);
        off += 8;
        header.close_time = std.mem.readInt(u64, bytes[off..][0..8], .big);
        off += 8;
        header.hash = bytes[off..][0..32].*;
        off += 32;
        header.prev_hash = bytes[off..][0..32].*;
        off += 32;
        header.txset_hash = bytes[off..][0..32].*;
        off += 32;
        header.state_root = bytes[off..][0..32].*;
        off += 32;
        if (body_end < off + 2) return null;
        const value_len: usize = std.mem.readInt(u16, bytes[off..][0..2], .big);
        off += 2;
        if (value_len > registry.max_ledger_value_bytes or body_end != off + value_len)
            return null;
        const value_bytes = bytes[off..body_end];
        const value = registry.LedgerValue.decode(value_bytes) orelse return null;
        var canonical_buf: [registry.max_ledger_value_bytes]u8 = undefined;
        if (!std.mem.eql(u8, value.encode(&canonical_buf), value_bytes)) return null;
        if (header.slot == 0 or
            value.close_time != header.close_time or
            !std.mem.eql(u8, &header.txset_hash, &value.txs.hash()) or
            !std.mem.eql(u8, &header.hash, &registry.headerHash(network_id, &header)))
            return null;
        return .{
            .network_id = network_id,
            .header = header,
            .value = value,
        };
    }
};

fn valueMinimumBytes() usize {
    return registry.value_magic.len + 8 + 1;
}

const Assertion = struct {
    network_id: [32]u8,
    slot: u64,
    head_hash: [32]u8,
    anchor_every: u8 = 1,
    anchor_slot: u64 = 0,
    anchor_head_hash: [32]u8 = @splat(0),
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
    out[off] = assertion.anchor_every;
    off += 1;
    std.mem.writeInt(u64, out[off..][0..8], assertion.anchor_slot, .big);
    off += 8;
    @memcpy(out[off..][0..32], &assertion.anchor_head_hash);
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
    const anchor_every = bytes[off];
    off += 1;
    const anchor_slot = std.mem.readInt(u64, bytes[off..][0..8], .big);
    off += 8;
    const anchor_head_hash = bytes[off..][0..32].*;
    off += 32;
    const snapshot_hash = bytes[off..][0..32].*;
    off += 32;
    return .{
        .assertion = .{
            .network_id = network_id,
            .slot = slot,
            .head_hash = head_hash,
            .anchor_every = anchor_every,
            .anchor_slot = anchor_slot,
            .anchor_head_hash = anchor_head_hash,
            .snapshot_hash = snapshot_hash,
        },
        .signer = bytes[off..][0..32].*,
        .signature = bytes[off + 32 ..][0..64].*,
    };
}

fn sameAssertion(a: Assertion, b: Assertion) bool {
    return a.slot == b.slot and
        std.mem.eql(u8, &a.network_id, &b.network_id) and
        std.mem.eql(u8, &a.head_hash, &b.head_hash) and
        a.anchor_every == b.anchor_every and
        a.anchor_slot == b.anchor_slot and
        std.mem.eql(u8, &a.anchor_head_hash, &b.anchor_head_hash) and
        std.mem.eql(u8, &a.snapshot_hash, &b.snapshot_hash);
}

fn recordMatchesAssertion(record: *const LedgerRecord, assertion: Assertion) bool {
    return record.header.slot == assertion.slot and
        std.mem.eql(u8, &record.header.hash, &assertion.head_hash);
}

fn sameRecoveredState(a: *const registry.State, b: *const registry.State, compare_results: bool) bool {
    const durable_equal = std.mem.eql(u8, &a.network_id, &b.network_id) and
        std.meta.eql(a.head, b.head) and
        sameDurableState(a, b) and
        a.last_value != null and b.last_value != null and
        sameLedgerValue(&a.last_value.?, &b.last_value.?);
    if (!durable_equal) return false;
    // Snapshot V3 intentionally normalizes an anchor's transient result
    // vector to empty. Once at least one ledger is replayed, `apply` rebuilds
    // the tip's semantic results and they must match the offered state too.
    return !compare_results or
        (a.last_count == b.last_count and
            std.mem.eql(u8, std.mem.sliceAsBytes(a.lastResults()), std.mem.sliceAsBytes(b.lastResults())));
}

fn sameDurableState(a: *const registry.State, b: *const registry.State) bool {
    if (!std.mem.eql(u8, &a.network_id, &b.network_id) or
        !std.meta.eql(a.head, b.head) or
        a.accounts.items.len != b.accounts.items.len or a.names.items.len != b.names.items.len or
        !std.mem.eql(u8, std.mem.sliceAsBytes(a.accounts.items), std.mem.sliceAsBytes(b.accounts.items)) or
        !std.mem.eql(u8, std.mem.sliceAsBytes(a.names.items), std.mem.sliceAsBytes(b.names.items)))
        return false;
    if (a.last_value == null or b.last_value == null)
        return a.last_value == null and b.last_value == null;
    return sameLedgerValue(&a.last_value.?, &b.last_value.?);
}

fn expectedAnchor(slot: u64, anchor_every: u64) u64 {
    std.debug.assert(slot > 0 and anchor_every > 0 and anchor_every <= 64);
    if (slot < anchor_every) return 1;
    return slot - (slot % anchor_every);
}

fn sameWatermark(a: Watermark, b: Watermark) bool {
    return a.slot == b.slot and std.mem.eql(u8, &a.head_hash, &b.head_hash);
}

fn adoptionWatermarksReachable(target: Watermark, published: Watermark, admitted: Watermark) bool {
    // `beginCertifiedAdoption` starts only from a drained outbox, then writes
    // admitted and published to `target` in that order. These are the only
    // three states a crash can expose; accepting anything else could turn a
    // stale trusted marker into a durable rollback.
    return (sameWatermark(published, admitted) and published.slot < target.slot) or
        (published.slot < target.slot and sameWatermark(admitted, target)) or
        (sameWatermark(published, target) and sameWatermark(admitted, target));
}

fn watermarkMatchesState(watermark: Watermark, state: *const registry.State) bool {
    return watermark.slot == state.head.slot and
        std.mem.eql(u8, &watermark.head_hash, &state.head.hash);
}

fn sameLedgerValue(a: *const registry.LedgerValue, b: *const registry.LedgerValue) bool {
    var a_buf: [registry.max_ledger_value_bytes]u8 = undefined;
    var b_buf: [registry.max_ledger_value_bytes]u8 = undefined;
    return std.mem.eql(u8, a.encode(&a_buf), b.encode(&b_buf));
}

fn hash(bytes: []const u8) [32]u8 {
    var h = Sha256.init(.{});
    h.update(bytes);
    return h.finalResult();
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return false;
    return true;
}

fn hasExactLastValue(state: *const registry.State) bool {
    if (state.head.slot == 0) return state.last_value == null;
    const last_value = state.last_value orelse return false;
    return state.head.close_time == last_value.close_time and
        std.mem.eql(u8, &state.head.txset_hash, &last_value.txs.hash());
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

fn ledgerName(head_hash: [32]u8, out: *[max_name_bytes]u8) []const u8 {
    return std.fmt.bufPrint(out, "{s}.ledger", .{&registry.hex32(head_hash)}) catch unreachable;
}

fn stagedName(slot: u64, out: *[max_name_bytes]u8) []const u8 {
    return std.fmt.bufPrint(out, "staged-{d}.snap", .{slot}) catch unreachable;
}

fn frontierName(head_hash: [32]u8, out: *[max_name_bytes]u8) []const u8 {
    return std.fmt.bufPrint(out, "frontier-{s}.snap", .{&registry.hex32(head_hash)}) catch unreachable;
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
const test_genesis_close_time: u64 = 1_700_000_000;

fn testNetworkId(passphrase: []const u8) [32]u8 {
    return registry.networkId(passphrase, test_genesis_close_time);
}

test "history tip: V1 signing domain has a fixed digest and rejects checkpoint vote bytes" {
    const assertion: Assertion = .{
        .network_id = @splat(0x11),
        .slot = 0x0102030405060708,
        .head_hash = @splat(0x22),
        .anchor_every = 8,
        .anchor_slot = 0x1112131415161718,
        .anchor_head_hash = @splat(0x33),
        .snapshot_hash = @splat(0x44),
    };
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "7a5b05b8413534374fb2aa98575938d466c513e0e533a0015070a8b6fe152da1");
    try testing.expectEqualSlices(u8, &expected, &assertion.digest());

    var encoded: [vote_bytes]u8 = undefined;
    encodeVote(.{
        .assertion = assertion,
        .signer = @splat(0x44),
        .signature = @splat(0x55),
    }, &encoded);
    try testing.expectEqualStrings("REGISTRY-HIST-V1", encoded[0..tag.len]);

    var legacy = encoded;
    @memcpy(legacy[0..tag.len], "REGISTRY-CKPT-V2");
    try testing.expect(decodeVote(&legacy) == null);
}

test "history ledger: V1 record is canonical and binds its full header and exact value" {
    const gpa = testing.allocator;
    const network_id = testNetworkId("history ledger encoding");
    var state = try stateAt(gpa, network_id, 1);
    defer state.deinit(gpa);
    const record: LedgerRecord = .{
        .network_id = network_id,
        .header = state.head,
        .value = state.last_value.?,
    };
    var encoded_buf: [ledger_max_bytes + 1]u8 = undefined;
    const encoded = record.encode(encoded_buf[0..ledger_max_bytes]);
    const decoded = LedgerRecord.decode(encoded) orelse return error.ExpectedLedgerRecord;
    try testing.expectEqualStrings(ledger_magic, encoded[0..ledger_magic.len]);
    try testing.expectEqual(record.header, decoded.header);
    try testing.expect(sameLedgerValue(&record.value, &decoded.value));

    encoded_buf[encoded.len] = 0;
    try testing.expect(LedgerRecord.decode(encoded_buf[0 .. encoded.len + 1]) == null);

    var tampered = encoded_buf;
    tampered[encoded.len - 1] ^= 1;
    try testing.expect(LedgerRecord.decode(tampered[0..encoded.len]) == null);

    tampered = encoded_buf;
    const header_close_offset = ledger_magic.len + 32 + 8 + 32 + 32 + 8;
    tampered[header_close_offset + 7] ^= 1;
    const body_end = encoded.len - 32;
    const repaired = hash(tampered[0..body_end]);
    @memcpy(tampered[body_end..][0..32], &repaired);
    try testing.expect(LedgerRecord.decode(tampered[0..encoded.len]) == null);
}

fn testPath(tmp: *std.testing.TmpDir, io: std.Io, suffix: []const u8, buf: []u8) ![]const u8 {
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buf[0..try tmp.dir.realPath(io, &root_buf)];
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ root, suffix });
}

fn stateAt(gpa: std.mem.Allocator, network_id: [32]u8, slot: u64) !registry.State {
    var state = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    errdefer state.deinit(gpa);
    for (0..slot) |_| try applySet(gpa, &state, &registry.TxSet.empty);
    return state;
}

fn applySet(gpa: std.mem.Allocator, state: *registry.State, set: *const registry.TxSet) !void {
    const value: registry.LedgerValue = .{
        .close_time = state.head.close_time + 1,
        .txs = set.*,
    };
    try registry.apply(state, &value, gpa);
}

fn anchorAssertion(state: *const registry.State, snapshot: []const u8) Assertion {
    return .{
        .network_id = state.network_id,
        .slot = state.head.slot,
        .head_hash = state.head.hash,
        .anchor_slot = state.head.slot,
        .anchor_head_hash = state.head.hash,
        .snapshot_hash = hash(snapshot),
    };
}

fn recordAndAck(archive: *Archive, state: *const registry.State) !RecordStatus {
    if (archive.stage_frontier == null) {
        if (archive.policy_initialized) {
            const published = archive.published orelse return error.HistoryOutboxCorrupt;
            const durable = try archive.loadFrontierState(published);
            try archive.prepareFrontier(&durable);
        } else {
            var genesis = try registry.State.genesis(archive.network_id, archive.genesis_close_time, archive.gpa);
            defer genesis.deinit(archive.gpa);
            try archive.prepareFrontier(&genesis);
        }
    }
    try archive.stageApplied(state);
    var staged = (try archive.nextStaged()) orelse return error.ExpectedStagedState;
    defer staged.deinit(archive.gpa);
    if (staged.head.slot != state.head.slot) return error.UnexpectedStagedState;
    const status = try archive.recordApplied(&staged);
    try archive.ackStaged(staged.head.slot);
    return status;
}

test "history boot provenance: fresh activation is not independently trusted" {
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
    const network_id = testNetworkId("history untrusted fresh activation");
    const cfg: Config = .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 8,
    };
    var archive = try Archive.open(gpa, io, cfg);
    defer archive.deinit();

    var genesis = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    defer genesis.deinit(gpa);
    try archive.prepareFrontier(&genesis);
    try archive.confirmInstalled(&genesis);
    try testing.expect(!try archive.hasTrustedBootProvenance(&genesis));

    var one = try stateAt(gpa, network_id, 1);
    defer one.deinit(gpa);
    try archive.stageApplied(&one);
    try archive.confirmInstalled(&one);
    try testing.expect(!try archive.hasTrustedBootProvenance(&one));
    archive.deinit();

    archive = try Archive.open(gpa, io, cfg);
    try testing.expect(!try archive.hasTrustedBootProvenance(&genesis));
    try testing.expect(!try archive.hasTrustedBootProvenance(&one));
}

test "history boot provenance: certified install survives restart and advances on confirmation" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var writer_buf: [std.fs.max_path_bytes]u8 = undefined;
    var reader_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const writer_path = try testPath(&tmp, io, "writer", &writer_buf);
    const reader_path = try testPath(&tmp, io, "reader", &reader_buf);
    const seed: [32]u8 = @splat(0x42);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = testNetworkId("history durable boot provenance");
    const writer_cfg: Config = .{
        .archive_dir = archive_path,
        .signing_dir = writer_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 8,
    };
    var reader_cfg = writer_cfg;
    reader_cfg.signing_dir = reader_path;

    var genesis = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    defer genesis.deinit(gpa);
    var tip = genesis;
    var writer = try Archive.open(gpa, io, writer_cfg);
    for (0..3) |_| {
        try applySet(gpa, &tip, &registry.TxSet.empty);
        _ = try recordAndAck(&writer, &tip);
    }
    writer.deinit();

    var reader = try Archive.open(gpa, io, reader_cfg);
    try reader.prepareFrontier(&genesis);
    const recovered = (try reader.recoverLatest(tip.head.slot)) orelse
        return error.ExpectedCertifiedHistory;
    try reader.prepareFrontier(&recovered.state);
    try testing.expect(!try reader.hasTrustedBootProvenance(&recovered.state));
    try reader.confirmInstalled(&recovered.state);
    try testing.expect((try reader.pendingInstall()) == null);
    try testing.expect(try reader.hasTrustedBootProvenance(&recovered.state));
    reader.deinit();

    reader = try Archive.open(gpa, io, reader_cfg);
    try testing.expect(try reader.hasTrustedBootProvenance(&recovered.state));
    try reader.prepareFrontier(&recovered.state);
    var successor = recovered.state;
    try applySet(gpa, &successor, &registry.TxSet.empty);
    try reader.stageApplied(&successor);
    try testing.expect(try reader.hasTrustedBootProvenance(&recovered.state));
    try testing.expect(!try reader.hasTrustedBootProvenance(&successor));
    try reader.confirmInstalled(&successor);
    try testing.expect(!try reader.hasTrustedBootProvenance(&recovered.state));
    try testing.expect(try reader.hasTrustedBootProvenance(&successor));
    try testing.expectError(
        error.HistoryBootProvenanceRollback,
        reader.confirmInstalled(&recovered.state),
    );
    var unrepresented = successor;
    try applySet(gpa, &unrepresented, &registry.TxSet.empty);
    try testing.expectError(error.HistoryFrontierMismatch, reader.confirmInstalled(&unrepresented));
    reader.deinit();

    reader = try Archive.open(gpa, io, reader_cfg);
    try testing.expect(try reader.hasTrustedBootProvenance(&successor));
    try reader.prepareFrontier(&successor);
    var staged = (try reader.nextStaged()) orelse return error.ExpectedStagedState;
    defer staged.deinit(gpa);
    _ = try reader.recordApplied(&staged);
    try reader.ackStaged(staged.head.slot);
    try testing.expect(try reader.hasTrustedBootProvenance(&successor));
    reader.deinit();

    reader = try Archive.open(gpa, io, reader_cfg);
    defer reader.deinit();
    try testing.expect(try reader.hasTrustedBootProvenance(&successor));
}

test "history boot provenance: exact certified activation becomes trusted only on confirmation" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var writer_buf: [std.fs.max_path_bytes]u8 = undefined;
    var reader_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const writer_path = try testPath(&tmp, io, "writer", &writer_buf);
    const reader_path = try testPath(&tmp, io, "reader", &reader_buf);
    const seed: [32]u8 = @splat(0x43);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = testNetworkId("history exact certified activation provenance");
    const writer_cfg: Config = .{
        .archive_dir = archive_path,
        .signing_dir = writer_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 8,
    };
    var reader_cfg = writer_cfg;
    reader_cfg.signing_dir = reader_path;

    var one = try stateAt(gpa, network_id, 1);
    defer one.deinit(gpa);
    var writer = try Archive.open(gpa, io, writer_cfg);
    _ = try recordAndAck(&writer, &one);
    writer.deinit();

    var reader = try Archive.open(gpa, io, reader_cfg);
    try reader.prepareFrontier(&one);
    try testing.expect(!try reader.hasTrustedBootProvenance(&one));
    const recovered = (try reader.recoverLatest(1)) orelse
        return error.ExpectedCertifiedHistory;
    try reader.prepareFrontier(&recovered.state);
    try testing.expect(!try reader.hasTrustedBootProvenance(&one));
    try reader.confirmInstalled(&one);
    try testing.expect(try reader.hasTrustedBootProvenance(&one));
    reader.deinit();

    reader = try Archive.open(gpa, io, reader_cfg);
    defer reader.deinit();
    try testing.expect(try reader.hasTrustedBootProvenance(&one));
}

test "history boot provenance: crash after provenance write retains an idempotent adoption" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var writer_buf: [std.fs.max_path_bytes]u8 = undefined;
    var reader_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const writer_path = try testPath(&tmp, io, "writer", &writer_buf);
    const reader_path = try testPath(&tmp, io, "reader", &reader_buf);
    const seed: [32]u8 = @splat(0x44);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = testNetworkId("history boot provenance crash ordering");
    const writer_cfg: Config = .{
        .archive_dir = archive_path,
        .signing_dir = writer_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 8,
    };
    var reader_cfg = writer_cfg;
    reader_cfg.signing_dir = reader_path;
    var genesis = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    defer genesis.deinit(gpa);
    var one = try stateAt(gpa, network_id, 1);
    defer one.deinit(gpa);

    var writer = try Archive.open(gpa, io, writer_cfg);
    _ = try recordAndAck(&writer, &one);
    writer.deinit();

    var reader = try Archive.open(gpa, io, reader_cfg);
    try reader.prepareFrontier(&genesis);
    const recovered = (try reader.recoverLatest(1)) orelse
        return error.ExpectedCertifiedHistory;
    try reader.prepareFrontier(&recovered.state);
    reader.sync_directory = TestDirSyncFault.sync;
    {
        TestDirSyncFault.target = reader.outbox_dir.handle;
        defer TestDirSyncFault.target = null;
        try testing.expectError(error.InjectedDirectorySyncFailure, reader.confirmInstalled(&one));
    }
    try testing.expect((try reader.pendingInstall()) != null);
    reader.deinit();

    reader = try Archive.open(gpa, io, reader_cfg);
    try testing.expect(try reader.hasTrustedBootProvenance(&one));
    try reader.prepareFrontier(&genesis);
    try testing.expect((try reader.pendingInstall()) != null);

    // The first failed confirmation left the provenance rename visible but
    // without a successful directory barrier. A retry must re-establish that
    // barrier before it can delete the adoption marker. Fail that retry, then
    // model a crash that loses the earlier unbarriered provenance entry while
    // retaining the marker state visible at the last successful barrier.
    reader.sync_directory = TestDirSyncFault.sync;
    {
        TestDirSyncFault.target = reader.outbox_dir.handle;
        defer TestDirSyncFault.target = null;
        try testing.expectError(error.InjectedDirectorySyncFailure, reader.confirmInstalled(&one));
    }
    try reader.outbox_dir.deleteFile(io, boot_provenance_name);
    reader.deinit();

    reader = try Archive.open(gpa, io, reader_cfg);
    defer reader.deinit();
    try testing.expect(!try reader.hasTrustedBootProvenance(&one));
    try testing.expect((try reader.pendingInstall()) != null);
    try reader.prepareFrontier(&genesis);
    try reader.confirmInstalled(&one);
    try testing.expect((try reader.pendingInstall()) == null);
    try testing.expect(try reader.hasTrustedBootProvenance(&one));
}

test "history boot provenance: corrupt or unrepresented trusted watermark fails closed" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var malformed_buf: [std.fs.max_path_bytes]u8 = undefined;
    var unrepresented_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const malformed_path = try testPath(&tmp, io, "malformed", &malformed_buf);
    const unrepresented_path = try testPath(&tmp, io, "unrepresented", &unrepresented_buf);
    const seed: [32]u8 = @splat(0x45);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = testNetworkId("history corrupt boot provenance");
    const base: Config = .{
        .archive_dir = archive_path,
        .signing_dir = malformed_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 8,
    };
    var genesis = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    defer genesis.deinit(gpa);

    var archive = try Archive.open(gpa, io, base);
    try archive.prepareFrontier(&genesis);
    try overwriteTestFileAt(io, archive.outbox_dir, boot_provenance_name, "torn");
    archive.deinit();
    try testing.expectError(error.HistoryOutboxCorrupt, Archive.open(gpa, io, base));

    var unrepresented_cfg = base;
    unrepresented_cfg.signing_dir = unrepresented_path;
    archive = try Archive.open(gpa, io, unrepresented_cfg);
    try archive.prepareFrontier(&genesis);
    var encoded: [boot_provenance_bytes]u8 = undefined;
    encodeBootProvenance(network_id, .{ .slot = 1, .head_hash = @splat(0xa5) }, &encoded);
    try overwriteTestFileAt(io, archive.outbox_dir, boot_provenance_name, &encoded);
    archive.deinit();
    try testing.expectError(error.HistoryOutboxCorrupt, Archive.open(gpa, io, unrepresented_cfg));
}

test "history adoption: stale lower marker cannot roll durable watermarks backward" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0x46);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = testNetworkId("history stale adoption marker");
    const cfg: Config = .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 8,
    };

    var archive = try Archive.open(gpa, io, cfg);
    var one = try stateAt(gpa, network_id, 1);
    defer one.deinit(gpa);
    var two = try stateAt(gpa, network_id, 2);
    defer two.deinit(gpa);
    _ = try recordAndAck(&archive, &one);
    _ = try recordAndAck(&archive, &two);
    try archive.writeWatermark("adoption", .{ .slot = one.head.slot, .head_hash = one.head.hash });
    try archive.sync_directory(archive.outbox_dir);
    archive.deinit();

    try testing.expectError(error.HistoryOutboxCorrupt, Archive.open(gpa, io, cfg));
}

test "history archive: certified per-ledger tip replays a long outage without a live peer" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var sign_a_buf: [std.fs.max_path_bytes]u8 = undefined;
    var sign_b_buf: [std.fs.max_path_bytes]u8 = undefined;
    var sign_reader_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const sign_a_path = try testPath(&tmp, io, "sign-a", &sign_a_buf);
    const sign_b_path = try testPath(&tmp, io, "sign-b", &sign_b_buf);
    const sign_reader_path = try testPath(&tmp, io, "sign-reader", &sign_reader_buf);

    const seeds = [3][32]u8{ @splat(0x31), @splat(0x32), @splat(0x33) };
    const ids = [3]slcp.NodeId{
        try slcp.core.crypto.publicKeyFromSeed(seeds[0]),
        try slcp.core.crypto.publicKeyFromSeed(seeds[1]),
        try slcp.core.crypto.publicKeyFromSeed(seeds[2]),
    };
    const quorum = slcp.Quorum.of(2, &ids);
    const network_id = testNetworkId("history standalone replay");
    const cfg_a: Config = .{
        .archive_dir = archive_path,
        .signing_dir = sign_a_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = quorum,
        .signer_seed = seeds[0],
        .checkpoint_every = 64,
    };
    var cfg_b = cfg_a;
    cfg_b.signing_dir = sign_b_path;
    cfg_b.signer_seed = seeds[1];

    var a = try Archive.open(gpa, io, cfg_a);
    defer a.deinit();
    var b = try Archive.open(gpa, io, cfg_b);
    defer b.deinit();

    var state = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    defer state.deinit(gpa);
    var slot_34_hash: [32]u8 = undefined;
    for (1..36) |slot| {
        try applySet(gpa, &state, &registry.TxSet.empty);
        if (slot == 34) slot_34_hash = state.head.hash;
        _ = try recordAndAck(&a, &state);
        _ = try recordAndAck(&b, &state);
    }

    var cfg_reader = cfg_a;
    cfg_reader.signing_dir = sign_reader_path;
    cfg_reader.signer_seed = seeds[2];
    // Import geometry is signed by the writers, not imposed by this reader.
    cfg_reader.checkpoint_every = 8;
    var reader = try Archive.open(gpa, io, cfg_reader);
    defer reader.deinit();

    var recovered = (try reader.recoverLatest(35)) orelse return error.ExpectedCertifiedHistory;
    defer recovered.state.deinit(gpa);
    try testing.expectEqual(@as(u64, 35), recovered.state.head.slot);
    try testing.expectEqualSlices(u8, &state.head.hash, &recovered.state.head.hash);
    try testing.expectEqual(@as(u64, 1), recovered.anchor_slot);
    try testing.expectEqual(@as(u64, 34), recovered.replayed_ledgers);
    try testing.expect(sameLedgerValue(&state.last_value.?, &recovered.state.last_value.?));

    var ledger_name_buf: [max_name_bytes]u8 = undefined;
    try overwriteTestFileAt(io, reader.ledgers_dir, ledgerName(slot_34_hash, &ledger_name_buf), "torn");
    try testing.expect((try reader.recoverLatest(35)) == null);
}

test "history archive: every boundary is contiguous and replay remains bounded at sixty-four" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0x35);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = testNetworkId("history max replay geometry");
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 64,
    });
    defer archive.deinit();

    var one = try stateAt(gpa, network_id, 1);
    defer one.deinit(gpa);
    _ = try recordAndAck(&archive, &one);
    var eight = try stateAt(gpa, network_id, 8);
    defer eight.deinit(gpa);
    try testing.expectError(error.HistoryOutboxSequence, archive.recordApplied(&eight));

    var state = one;
    for (2..128) |slot| {
        try applySet(gpa, &state, &registry.TxSet.empty);
        try testing.expectEqual(@as(u64, slot), state.head.slot);
        _ = try recordAndAck(&archive, &state);
        if (slot == 63) {
            var recovered = (try archive.recoverLatest(63)) orelse return error.ExpectedCertifiedHistory;
            defer recovered.state.deinit(gpa);
            try testing.expectEqual(@as(u64, 1), recovered.anchor_slot);
            try testing.expectEqual(@as(u64, 62), recovered.replayed_ledgers);
        } else if (slot == 64) {
            var recovered = (try archive.recoverLatest(64)) orelse return error.ExpectedCertifiedHistory;
            defer recovered.state.deinit(gpa);
            try testing.expectEqual(@as(u64, 64), recovered.anchor_slot);
            try testing.expectEqual(@as(u64, 0), recovered.replayed_ledgers);
        } else if (slot == 127) {
            var recovered = (try archive.recoverLatest(127)) orelse return error.ExpectedCertifiedHistory;
            defer recovered.state.deinit(gpa);
            try testing.expectEqual(@as(u64, 64), recovered.anchor_slot);
            try testing.expectEqual(@as(u64, 63), recovered.replayed_ledgers);
        }
    }
}

test "history archive: slot one must extend the configured canonical genesis" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0x34);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = testNetworkId("history configured genesis");
    const wrong_g = test_genesis_close_time - 1;
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = wrong_g,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 8,
    });
    defer archive.deinit();
    var wrong_genesis = try registry.State.genesis(network_id, wrong_g, gpa);
    defer wrong_genesis.deinit(gpa);
    try archive.prepareFrontier(&wrong_genesis);
    var one = try stateAt(gpa, network_id, 1);
    defer one.deinit(gpa);
    try testing.expectError(error.HistoryTransitionInvalid, archive.stageApplied(&one));
}

test "history ledger: cadence is absent from canonical bytes and trusted policy is immutable" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var sign_8_buf: [std.fs.max_path_bytes]u8 = undefined;
    var sign_16_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const sign_8_path = try testPath(&tmp, io, "sign-8", &sign_8_buf);
    const sign_16_path = try testPath(&tmp, io, "sign-16", &sign_16_buf);
    const seed: [32]u8 = @splat(0x36);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = testNetworkId("history cadence-free ledger");
    const base: Config = .{
        .archive_dir = archive_path,
        .signing_dir = sign_8_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 8,
    };
    var cfg_16 = base;
    cfg_16.signing_dir = sign_16_path;
    cfg_16.checkpoint_every = 16;
    var a = try Archive.open(gpa, io, base);
    defer a.deinit();
    var b = try Archive.open(gpa, io, cfg_16);
    defer b.deinit();
    var state = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    defer state.deinit(gpa);
    for (1..18) |_| {
        try applySet(gpa, &state, &registry.TxSet.empty);
        _ = try recordAndAck(&a, &state);
        _ = try recordAndAck(&b, &state);
    }

    // Reopening the same trusted signing tree with another cadence cannot
    // reinterpret either its fence or its outbox.
    a.deinit();
    var mismatch = base;
    mismatch.checkpoint_every = 16;
    try testing.expectError(error.HistoryPolicyMismatch, Archive.open(gpa, io, mismatch));
    mismatch = base;
    mismatch.genesis_close_time -= 1;
    try testing.expectError(error.HistoryPolicyMismatch, Archive.open(gpa, io, mismatch));
    a = try Archive.open(gpa, io, base);
}

test "history outbox: restart accepts pending and published snapshot ancestors" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0x37);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = testNetworkId("history outbox ancestors");
    const cfg: Config = .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 8,
    };
    var genesis = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    defer genesis.deinit(gpa);
    var one = try stateAt(gpa, network_id, 1);
    defer one.deinit(gpa);
    var two = try stateAt(gpa, network_id, 2);
    defer two.deinit(gpa);

    var archive = try Archive.open(gpa, io, cfg);
    try archive.prepareFrontier(&genesis);
    try archive.stageApplied(&one);
    try archive.stageApplied(&two);
    archive.deinit();

    archive = try Archive.open(gpa, io, cfg);
    try archive.prepareFrontier(&one); // ordinary snapshot at P+1
    try archive.stageApplied(&one); // journal re-delivery is exact/idempotent
    try archive.stageApplied(&two);
    var pending_one = (try archive.nextStaged()) orelse return error.ExpectedStagedState;
    defer pending_one.deinit(gpa);
    _ = try recordAndAck(&archive, &pending_one);
    var pending_two = (try archive.nextStaged()) orelse return error.ExpectedStagedState;
    defer pending_two.deinit(gpa);
    _ = try recordAndAck(&archive, &pending_two);
    archive.deinit();

    archive = try Archive.open(gpa, io, cfg);
    try archive.prepareFrontier(&genesis); // local snapshot lags published P+2
    try archive.stageApplied(&one);
    try archive.stageApplied(&two);
    archive.deinit();
}

test "history outbox: missing trusted pending state and backlog overflow fail closed" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0x38);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = testNetworkId("history outbox corruption");
    const cfg: Config = .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 64,
    };
    var genesis = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    defer genesis.deinit(gpa);
    var archive = try Archive.open(gpa, io, cfg);
    try archive.prepareFrontier(&genesis);
    var state = genesis;
    for (1..65) |_| {
        try applySet(gpa, &state, &registry.TxSet.empty);
        try archive.stageApplied(&state);
    }
    try applySet(gpa, &state, &registry.TxSet.empty);
    try testing.expectError(error.HistoryBacklogFull, archive.stageApplied(&state));
    var name_buf: [max_name_bytes]u8 = undefined;
    try archive.outbox_dir.deleteFile(io, stagedName(34, &name_buf));
    archive.deinit();

    archive = try Archive.open(gpa, io, cfg);
    defer archive.deinit();
    try testing.expectError(error.HistoryOutboxCorrupt, archive.prepareFrontier(&genesis));
}

test "history archive: recordApplied validates the immediate predecessor at an anchor" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0x39);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = testNetworkId("history anchor predecessor");
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 8,
    });
    defer archive.deinit();
    for (1..8) |slot| {
        var state = try stateAt(gpa, network_id, slot);
        defer state.deinit(gpa);
        _ = try recordAndAck(&archive, &state);
    }
    var eight = try stateAt(gpa, network_id, 8);
    defer eight.deinit(gpa);
    try archive.stageApplied(&eight);
    _ = try archive.nextStaged();
    // This private-seam corruption models an implementation that tries to
    // treat slot 8 as an independent snapshot reset. Publication must still
    // reject it before signing.
    archive.publish_frontier = try stateAt(gpa, network_id, 6);
    try testing.expectError(error.HistoryTransitionInvalid, archive.recordApplied(&eight));
}

test "history outbox: a fenced pending non-anchor is retried identically after restart" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0x3a);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = testNetworkId("history fenced pending retry");
    const cfg: Config = .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 8,
    };
    var one = try stateAt(gpa, network_id, 1);
    defer one.deinit(gpa);
    var two = try stateAt(gpa, network_id, 2);
    defer two.deinit(gpa);
    var archive = try Archive.open(gpa, io, cfg);
    _ = try recordAndAck(&archive, &one);
    try archive.stageApplied(&two);
    var pending = (try archive.nextStaged()) orelse return error.ExpectedStagedState;
    defer pending.deinit(gpa);
    try testing.expectEqual(RecordStatus.certified, try archive.recordApplied(&pending));
    const fenced = (try archive.readTrustedVote(archive.signing_dir, "high-water.vote")) orelse
        return error.ExpectedSigningFence;
    var name_buf: [max_name_bytes]u8 = undefined;
    try archive.votes_dir.deleteFile(io, voteName(fenced.assertion.digest(), id, &name_buf));
    try archive.latest_dir.deleteFile(io, latestName(id, &name_buf));
    archive.deinit();

    archive = try Archive.open(gpa, io, cfg);
    defer archive.deinit();
    try archive.prepareFrontier(&one);
    var retry = (try archive.nextStaged()) orelse return error.ExpectedStagedState;
    defer retry.deinit(gpa);
    try testing.expectEqual(RecordStatus.certified, try archive.recordApplied(&retry));
    try archive.ackStaged(2);
    try testing.expectEqual(@as(u64, 2), (try archive.recoverLatest(2)).?.state.head.slot);
}

test "history outbox: transaction results are validated before admission but not persisted" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0x3e);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = testNetworkId("history transient outbox results");
    const cfg: Config = .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 8,
    };
    var state = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    defer state.deinit(gpa);
    try applySet(gpa, &state, &registry.TxSet.empty);
    var archive = try Archive.open(gpa, io, cfg);
    _ = try recordAndAck(&archive, &state);

    var tx = registry.Tx.init(id, 1, .claim, "durable", "", registry.zero_key).?;
    try tx.sign(seed, network_id);
    var set: registry.TxSet = .{ .count = 1 };
    set.txs[0] = tx;
    try applySet(gpa, &state, &set);
    try testing.expectEqual(@as(u8, 1), state.last_count);
    try archive.stageApplied(&state);
    archive.deinit();

    archive = try Archive.open(gpa, io, cfg);
    defer archive.deinit();
    var one = try stateAt(gpa, network_id, 1);
    defer one.deinit(gpa);
    try archive.prepareFrontier(&one);
    var staged = (try archive.nextStaged()) orelse return error.ExpectedStagedState;
    defer staged.deinit(gpa);
    try testing.expectEqual(@as(u8, 0), staged.last_count);
    try testing.expectEqual(RecordStatus.certified, try archive.recordApplied(&staged));
    try archive.ackStaged(2);
    var recovered = (try archive.recoverLatest(2)) orelse return error.ExpectedCertifiedHistory;
    defer recovered.state.deinit(gpa);
    try testing.expectEqual(@as(u8, 1), recovered.state.last_count);
    try testing.expectEqual(registry.Result.ok, recovered.state.lastResults()[0]);
}

test "history outbox: drain may be followed by adoption of newer certified history" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var sign_a_buf: [std.fs.max_path_bytes]u8 = undefined;
    var sign_b_buf: [std.fs.max_path_bytes]u8 = undefined;
    var sign_c_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const sign_a = try testPath(&tmp, io, "sign-a", &sign_a_buf);
    const sign_b = try testPath(&tmp, io, "sign-b", &sign_b_buf);
    const sign_c = try testPath(&tmp, io, "sign-c", &sign_c_buf);
    const seeds = [3][32]u8{ @splat(0x3b), @splat(0x3c), @splat(0x3d) };
    const ids = [3]slcp.NodeId{
        try slcp.core.crypto.publicKeyFromSeed(seeds[0]),
        try slcp.core.crypto.publicKeyFromSeed(seeds[1]),
        try slcp.core.crypto.publicKeyFromSeed(seeds[2]),
    };
    const network_id = testNetworkId("history adopt after drain");
    const base: Config = .{
        .archive_dir = archive_path,
        .signing_dir = sign_a,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(2, &ids),
        .signer_seed = seeds[0],
        .checkpoint_every = 8,
    };
    var cfg_b = base;
    cfg_b.signing_dir = sign_b;
    cfg_b.signer_seed = seeds[1];
    var cfg_c = base;
    cfg_c.signing_dir = sign_c;
    cfg_c.signer_seed = seeds[2];
    var a = try Archive.open(gpa, io, base);
    defer a.deinit();
    var b = try Archive.open(gpa, io, cfg_b);
    defer b.deinit();
    var c = try Archive.open(gpa, io, cfg_c);
    defer c.deinit();
    var genesis = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    defer genesis.deinit(gpa);
    try a.prepareFrontier(&genesis);
    var one = try stateAt(gpa, network_id, 1);
    defer one.deinit(gpa);
    var two = try stateAt(gpa, network_id, 2);
    defer two.deinit(gpa);
    try a.stageApplied(&one);
    try a.stageApplied(&two);

    var remote = genesis;
    for (1..6) |_| {
        try applySet(gpa, &remote, &registry.TxSet.empty);
        _ = try recordAndAck(&b, &remote);
        _ = try recordAndAck(&c, &remote);
    }
    while (try a.nextStaged()) |pending| {
        _ = try a.recordApplied(&pending);
        try a.ackStaged(pending.head.slot);
    }
    var recovered = (try a.recoverLatest(5)) orelse return error.ExpectedCertifiedHistory;
    defer recovered.state.deinit(gpa);
    try testing.expectEqual(@as(u64, 5), recovered.state.head.slot);
    try a.prepareFrontier(&recovered.state);
    try testing.expect((try a.nextStaged()) == null);
    try a.confirmInstalled(&recovered.state);

    // Advance the remote certificate again, then model a crash after the
    // adoption marker and admitted watermark but before published advances.
    for (6..8) |_| {
        try applySet(gpa, &remote, &registry.TxSet.empty);
        _ = try recordAndAck(&b, &remote);
        _ = try recordAndAck(&c, &remote);
    }
    var seven = (try a.recoverLatest(7)) orelse return error.ExpectedCertifiedHistory;
    defer seven.state.deinit(gpa);
    const target: Watermark = .{ .slot = seven.state.head.slot, .head_hash = seven.state.head.hash };
    try a.writeWatermark("adoption", target);
    try a.sync_directory(a.outbox_dir);
    const adopted_snapshot = try registry.writeSnapshot(&seven.state, gpa);
    defer gpa.free(adopted_snapshot);
    var adopted_name_buf: [max_name_bytes]u8 = undefined;
    try a.writeTrustedImmutableFixed(
        a.outbox_dir,
        frontierName(target.head_hash, &adopted_name_buf),
        adopted_snapshot,
    );
    try a.sync_directory(a.outbox_dir);
    try a.writeWatermark("admitted", target);
    try a.sync_directory(a.outbox_dir);
    try applySet(gpa, &remote, &registry.TxSet.empty); // latest proof U advances beyond marker T
    _ = try recordAndAck(&b, &remote);
    _ = try recordAndAck(&c, &remote);
    a.deinit();

    a = try Archive.open(gpa, io, base);
    var newer = (try a.recoverLatest(8)) orelse return error.ExpectedCertifiedHistory;
    defer newer.state.deinit(gpa);
    try a.prepareFrontier(&recovered.state); // represented local snapshot at 5
    try testing.expectEqual(@as(u64, 7), a.published.?.slot);
    try testing.expectEqual(@as(u64, 7), (try a.pendingInstall()).?.head.slot);
    var eight = try stateAt(gpa, network_id, 8);
    defer eight.deinit(gpa);
    try testing.expectError(error.HistoryAdoptionNotInstalled, a.stageApplied(&eight));
    try a.confirmInstalled(&seven.state);
    try a.prepareFrontier(&newer.state);
    try a.confirmInstalled(&newer.state);
    var nine = try stateAt(gpa, network_id, 9);
    defer nine.deinit(gpa);
    try a.stageApplied(&nine);
    try testing.expectEqual(@as(u64, 9), (try a.nextStaged()).?.head.slot);
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

test "history archive: anchor cadence defaults to eight and is bounded at sixty-four" {
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
    const network_id = testNetworkId("history checkpoint cadence");
    const base: Config = .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
    };

    var zero = base;
    zero.checkpoint_every = 0;
    try testing.expectError(error.BadCheckpointInterval, Archive.open(gpa, io, zero));
    var sixty_five = base;
    sixty_five.checkpoint_every = 65;
    try testing.expectError(error.BadCheckpointInterval, Archive.open(gpa, io, sixty_five));

    var archive = try Archive.open(gpa, io, base);
    defer archive.deinit();
    var one = try stateAt(gpa, network_id, 1);
    defer one.deinit(gpa);
    try testing.expectEqual(RecordStatus.certified, try recordAndAck(&archive, &one));
    for (2..9) |slot| {
        var state = try stateAt(gpa, network_id, slot);
        defer state.deinit(gpa);
        try testing.expectEqual(RecordStatus.certified, try recordAndAck(&archive, &state));
    }
}

test "history archive: recordApplied requires the exact last ledger value time and transaction hash" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0x19);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = testNetworkId("history exact last value");
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    defer archive.deinit();

    var canonical = try stateAt(gpa, network_id, 1);
    defer canonical.deinit(gpa);

    var missing = canonical;
    missing.last_value = null;
    try testing.expectError(error.InvalidAppliedState, archive.recordApplied(&missing));

    var wrong_value_time = canonical;
    wrong_value_time.last_value.?.close_time += 1;
    try testing.expectError(error.InvalidAppliedState, archive.recordApplied(&wrong_value_time));

    var wrong_head_time = canonical;
    wrong_head_time.head.close_time += 1;
    wrong_head_time.head.hash = registry.headerHash(network_id, &wrong_head_time.head);
    try testing.expectError(error.InvalidAppliedState, archive.recordApplied(&wrong_head_time));

    var wrong_txs = canonical;
    wrong_txs.last_value.?.txs = .{ .count = 1 };
    wrong_txs.last_value.?.txs.txs[0] = registry.Tx.init(
        @splat(0x55),
        1,
        .claim,
        "other",
        "",
        registry.zero_key,
    ).?;
    try testing.expectError(error.InvalidAppliedState, archive.recordApplied(&wrong_txs));

    try testing.expectEqual(RecordStatus.certified, try recordAndAck(&archive, &canonical));
}

test "history archive: a blocked anchor remains the oldest durable outbox item" {
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
    const network_id = testNetworkId("history skip blocked checkpoint");

    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 8,
    });
    defer archive.deinit();

    var one = try stateAt(gpa, network_id, 1);
    defer one.deinit(gpa);
    _ = try recordAndAck(&archive, &one);
    for (2..8) |slot| {
        var state = try stateAt(gpa, network_id, slot);
        defer state.deinit(gpa);
        _ = try recordAndAck(&archive, &state);
    }
    var eight = try stateAt(gpa, network_id, 8);
    defer eight.deinit(gpa);
    const snapshot = try registry.writeSnapshot(&eight, gpa);
    defer gpa.free(snapshot);
    var name_buf: [max_name_bytes]u8 = undefined;
    const name = snapshotName(hash(snapshot), &name_buf);
    try overwriteTestFileAt(io, archive.snapshots_dir, name, "hostile immutable occupant");
    try archive.stageApplied(&eight);
    _ = try archive.nextStaged();
    try testing.expectError(error.ImmutableFileConflict, archive.recordApplied(&eight));
    var pending = (try archive.nextStaged()) orelse return error.ExpectedStagedState;
    defer pending.deinit(gpa);
    try testing.expectEqual(@as(u64, 8), pending.head.slot);
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
    const network_id = testNetworkId("history root separation");
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
            .genesis_close_time = test_genesis_close_time,
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
    const network_id = testNetworkId("history private data separation");
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
            .genesis_close_time = test_genesis_close_time,
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
    const network_id = testNetworkId("history key custody separation");

    try testing.expectError(error.HistoryRootsOverlap, Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .private_key_parent_dir = key_parent,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
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
        .genesis_close_time = test_genesis_close_time,
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
    const network_id = testNetworkId("history flat 2-of-3");
    var state = try stateAt(gpa, network_id, 1);
    defer state.deinit(gpa);

    var a = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = sign_a_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = quorum,
        .signer_seed = seeds[0],
        .checkpoint_every = 1,
    });
    defer a.deinit();
    try testing.expectEqual(RecordStatus.published, try recordAndAck(&a, &state));
    try testing.expect((try a.loadLatest(1)) == null);

    var b = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = sign_b_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = quorum,
        .signer_seed = seeds[1],
        .checkpoint_every = 1,
    });
    defer b.deinit();
    try testing.expectEqual(RecordStatus.certified, try recordAndAck(&b, &state));

    var restored = (try a.loadLatest(1)) orelse return error.ExpectedCertifiedCheckpoint;
    defer restored.deinit(gpa);
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
    const network_id = testNetworkId("history nested quorum");
    var state = try stateAt(gpa, network_id, 1);
    defer state.deinit(gpa);

    var a = try Archive.open(gpa, io, .{ .archive_dir = archive_path, .signing_dir = sign_a_path, .network_id = network_id, .genesis_close_time = test_genesis_close_time, .quorum = quorum, .signer_seed = seeds[0], .checkpoint_every = 1 });
    defer a.deinit();
    var b = try Archive.open(gpa, io, .{ .archive_dir = archive_path, .signing_dir = sign_b_path, .network_id = network_id, .genesis_close_time = test_genesis_close_time, .quorum = quorum, .signer_seed = seeds[1], .checkpoint_every = 1 });
    defer b.deinit();
    var c = try Archive.open(gpa, io, .{ .archive_dir = archive_path, .signing_dir = sign_c_path, .network_id = network_id, .genesis_close_time = test_genesis_close_time, .quorum = quorum, .signer_seed = seeds[2], .checkpoint_every = 1 });
    defer c.deinit();

    _ = try recordAndAck(&a, &state);
    _ = try recordAndAck(&b, &state);
    // Two flat signatures are not enough: the second root member is the
    // inner 2-of-2 set, which B alone does not satisfy.
    try testing.expect((try a.loadLatest(1)) == null);
    _ = try recordAndAck(&c, &state);
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
    const network_id = testNetworkId("history candidate cap");

    for (seeds, 0..) |seed, i| {
        var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
        var suffix_buf: [32]u8 = undefined;
        const suffix = try std.fmt.bufPrint(&suffix_buf, "signing-{d}", .{i});
        const signing_path = try testPath(&tmp, io, suffix, &signing_buf);
        var writer = try Archive.open(gpa, io, .{
            .archive_dir = archive_path,
            .signing_dir = signing_path,
            .network_id = network_id,
            .genesis_close_time = test_genesis_close_time,
            .quorum = quorum,
            .signer_seed = seed,
            .checkpoint_every = 1,
        });
        defer writer.deinit();
        var base = try stateAt(gpa, network_id, i);
        defer base.deinit(gpa);
        try writer.prepareFrontier(&base);
        var state = try stateAt(gpa, network_id, i + 1);
        defer state.deinit(gpa);
        try testing.expectEqual(RecordStatus.published, try recordAndAck(&writer, &state));
    }

    var reader_signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const reader_signing = try testPath(&tmp, io, "signing-0", &reader_signing_buf);
    var reader = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = reader_signing,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
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
    const network_id = testNetworkId("history rollback floor");
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    defer archive.deinit();
    var state = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    defer state.deinit(gpa);
    for (1..4) |slot| {
        state = try stateAt(gpa, network_id, slot);
        _ = try recordAndAck(&archive, &state);
    }
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
    const network_id = testNetworkId("history signing fence");
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    defer archive.deinit();

    var one = try stateAt(gpa, network_id, 1);
    defer one.deinit(gpa);
    _ = try recordAndAck(&archive, &one);
    archive.deinit();
    archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });

    var conflicting = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    defer conflicting.deinit(gpa);
    const source: registry.Key = @splat(0x61);
    const tx = registry.Tx.init(source, 1, .claim, "fork", "", registry.zero_key).?;
    var set: registry.TxSet = .{ .count = 1 };
    set.txs[0] = tx;
    try applySet(gpa, &conflicting, &set);
    try testing.expectError(error.HistoryOutboxSequence, archive.recordApplied(&conflicting));

    var two = try stateAt(gpa, network_id, 2);
    defer two.deinit(gpa);
    _ = try recordAndAck(&archive, &two);
    try testing.expectError(error.HistoryOutboxSequence, archive.recordApplied(&one));
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
    const network_id = testNetworkId("history distinct signers");
    const quorum = slcp.Quorum.of(2, &ids);
    var a = try Archive.open(gpa, io, .{ .archive_dir = archive_path, .signing_dir = sign_a_path, .network_id = network_id, .genesis_close_time = test_genesis_close_time, .quorum = quorum, .signer_seed = seeds[0], .checkpoint_every = 1 });
    defer a.deinit();
    var a_copy = try Archive.open(gpa, io, .{ .archive_dir = archive_path, .signing_dir = sign_a_copy_path, .network_id = network_id, .genesis_close_time = test_genesis_close_time, .quorum = quorum, .signer_seed = seeds[0], .checkpoint_every = 1 });
    defer a_copy.deinit();
    try testing.expectError(error.SignerNotInQuorum, Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = sign_x_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = quorum,
        .signer_seed = seeds[3],
        .checkpoint_every = 1,
    }));
    var state = try stateAt(gpa, network_id, 1);
    defer state.deinit(gpa);
    _ = try recordAndAck(&a, &state);
    _ = try recordAndAck(&a_copy, &state);
    try testing.expect((try a.loadLatest(1)) == null);

    const snapshot = try registry.writeSnapshot(&state, gpa);
    defer gpa.free(snapshot);
    const assertion = anchorAssertion(&state, snapshot);
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
    const network_id = testNetworkId("history snapshot binding");
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    defer archive.deinit();
    var state = try stateAt(gpa, network_id, 1);
    defer state.deinit(gpa);
    _ = try recordAndAck(&archive, &state);

    // Replace the object with a different snapshot that is internally
    // canonical and self-consistent. Its checksum, state root and head all
    // verify, but the old signed assertion names the original snapshot hash.
    var substitute = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    defer substitute.deinit(gpa);
    const source: registry.Key = @splat(0x82);
    const tx = registry.Tx.init(source, 1, .claim, "substitute", "", registry.zero_key).?;
    var set: registry.TxSet = .{ .count = 1 };
    set.txs[0] = tx;
    try applySet(gpa, &substitute, &set);
    const original = try registry.writeSnapshot(&state, gpa);
    defer gpa.free(original);
    var snapshot_name_buf: [max_name_bytes]u8 = undefined;
    const snapshot_name = snapshotName(hash(original), &snapshot_name_buf);
    const substitute_bytes = try registry.writeSnapshot(&substitute, gpa);
    defer gpa.free(substitute_bytes);
    try overwriteTestFileAt(io, archive.snapshots_dir, snapshot_name, substitute_bytes);
    try testing.expect((try archive.loadLatest(1)) == null);

    // Restore the original object, then exercise hostile full-width votes.
    // Neither a foreign network nor a non-member can be smuggled through a
    // trusted validator's pointer path, even with a valid signature.
    try overwriteTestFileAt(io, archive.snapshots_dir, snapshot_name, original);
    var latest_name_buf: [max_name_bytes]u8 = undefined;
    const latest_name = latestName(id, &latest_name_buf);
    const foreign_assertion = Assertion{
        .network_id = testNetworkId("foreign assertion network"),
        .slot = 1,
        .head_hash = state.head.hash,
        .anchor_slot = 1,
        .anchor_head_hash = state.head.hash,
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

    const correct_assertion = anchorAssertion(&state, original);
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
        .anchor_slot = 1,
        .anchor_head_hash = wrong_head,
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

    var wrong_network = try stateAt(gpa, testNetworkId("other history network"), 1);
    defer wrong_network.deinit(gpa);
    try testing.expectError(error.InvalidAppliedState, archive.recordApplied(&wrong_network));

    var missing_context = state;
    missing_context.last_value = null;
    try testing.expectError(error.InvalidAppliedState, archive.recordApplied(&missing_context));

    var wrong_context = state;
    var other_set: registry.TxSet = .{ .count = 1 };
    other_set.txs[0] = registry.Tx.init(@splat(0x55), 1, .claim, "other", "", registry.zero_key).?;
    wrong_context.last_value.?.txs = other_set;
    try testing.expectError(error.InvalidAppliedState, archive.recordApplied(&wrong_context));
}

test "history archive: pre-E2c snapshot versions are never external checkpoints" {
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
    const network_id = testNetworkId("history rejects pre-E2c checkpoint");
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    defer archive.deinit();

    var state = try stateAt(gpa, network_id, 1);
    defer state.deinit(gpa);
    const current = try registry.writeSnapshot(&state, gpa);
    defer gpa.free(current);
    var legacy_buf = try gpa.dupe(u8, current);
    defer gpa.free(legacy_buf);
    const legacy_magic = "REGISTRY-SNAP-V2\n";
    comptime std.debug.assert(legacy_magic.len == registry.snap_magic.len);
    @memcpy(legacy_buf[0..legacy_magic.len], legacy_magic);
    const body_end = current.len - 32;
    const checksum = hash(legacy_buf[0..body_end]);
    @memcpy(legacy_buf[body_end..][0..32], &checksum);
    const legacy = legacy_buf[0..current.len];
    try testing.expect((try registry.readSnapshot(gpa, legacy)) == null);

    const assertion = anchorAssertion(&state, legacy);
    var name_buf: [max_name_bytes]u8 = undefined;
    try archive.writeImmutable(archive.snapshots_dir, snapshotName(assertion.snapshot_hash, &name_buf), legacy);
    try testing.expect((try archive.loadSnapshot(assertion)) == null);
}

test "history archive: imported snapshots bind the last value close time and transaction hash" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0x84);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = testNetworkId("history last value snapshot binding");
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    defer archive.deinit();

    const fixed_prefix = registry.snap_magic.len + 32 + 8 + 8 + 4 * 32;
    const value_offset = fixed_prefix + 2;

    var empty = try stateAt(gpa, network_id, 1);
    defer empty.deinit(gpa);
    const time_snapshot = try registry.writeSnapshot(&empty, gpa);
    defer gpa.free(time_snapshot);
    time_snapshot[value_offset + registry.value_magic.len + 7] ^= 1;
    var body_end = time_snapshot.len - 32;
    var checksum = hash(time_snapshot[0..body_end]);
    @memcpy(time_snapshot[body_end..][0..32], &checksum);
    const tampered_time = time_snapshot[0..time_snapshot.len];
    const time_value_len: usize = std.mem.readInt(u16, time_snapshot[fixed_prefix..][0..2], .big);
    try testing.expect(registry.LedgerValue.decode(time_snapshot[value_offset..][0..time_value_len]) != null);
    const time_assertion = anchorAssertion(&empty, tampered_time);
    var name_buf: [max_name_bytes]u8 = undefined;
    try archive.writeImmutable(
        archive.snapshots_dir,
        snapshotName(time_assertion.snapshot_hash, &name_buf),
        tampered_time,
    );
    try testing.expect((try archive.loadSnapshot(time_assertion)) == null);

    var with_tx = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    defer with_tx.deinit(gpa);
    var txs: registry.TxSet = .{ .count = 1 };
    txs.txs[0] = registry.Tx.init(@splat(0x85), 1, .claim, "bound", "", registry.zero_key).?;
    try applySet(gpa, &with_tx, &txs);
    const tx_bytes = try registry.writeSnapshot(&with_tx, gpa);
    defer gpa.free(tx_bytes);
    var tx_snapshot = try gpa.dupe(u8, tx_bytes);
    defer gpa.free(tx_snapshot);
    const first_signature = value_offset + registry.value_magic.len + 8 + 1 + registry.unsigned_tx_bytes;
    tx_snapshot[first_signature] ^= 1;
    body_end = tx_snapshot.len - 32;
    checksum = hash(tx_snapshot[0..body_end]);
    @memcpy(tx_snapshot[body_end..][0..32], &checksum);
    const tampered_tx = tx_snapshot[0..tx_snapshot.len];
    const tx_value_len: usize = std.mem.readInt(u16, tx_snapshot[fixed_prefix..][0..2], .big);
    try testing.expect(registry.LedgerValue.decode(tx_snapshot[value_offset..][0..tx_value_len]) != null);
    const tx_assertion = anchorAssertion(&with_tx, tampered_tx);
    try archive.writeImmutable(
        archive.snapshots_dir,
        snapshotName(tx_assertion.snapshot_hash, &name_buf),
        tampered_tx,
    );
    try testing.expect((try archive.loadSnapshot(tx_assertion)) == null);
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
    const network_id = testNetworkId("history torn archive files");
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    defer archive.deinit();
    var state = try stateAt(gpa, network_id, 1);
    defer state.deinit(gpa);
    _ = try recordAndAck(&archive, &state);

    var latest_name_buf: [max_name_bytes]u8 = undefined;
    const latest_name = latestName(id, &latest_name_buf);
    try overwriteTestFileAt(io, archive.latest_dir, latest_name, "torn");
    try testing.expect((try archive.loadLatest(1)) == null);

    // A subsequent publication repairs the mutable pointer.
    var state_two = try stateAt(gpa, network_id, 2);
    defer state_two.deinit(gpa);
    _ = try recordAndAck(&archive, &state_two);
    try testing.expect((try archive.loadLatest(2)) != null);
    const snapshot = try registry.writeSnapshot(&state_two, gpa);
    defer gpa.free(snapshot);
    const assertion = anchorAssertion(&state_two, snapshot);
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
    const network_id = testNetworkId("history torn signing fence");
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    defer archive.deinit();
    var one = try stateAt(gpa, network_id, 1);
    defer one.deinit(gpa);
    _ = try recordAndAck(&archive, &one);
    var two = try stateAt(gpa, network_id, 2);
    defer two.deinit(gpa);
    try archive.stageApplied(&two);
    _ = try archive.nextStaged();
    try overwriteTestFileAt(io, archive.signing_dir, "high-water.vote", "torn");
    try testing.expectError(error.SigningFenceCorrupt, archive.recordApplied(&two));
}

test "history archive: a V1 trusted signing fence fails closed during migration" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try testPath(&tmp, io, "archive", &archive_buf);
    const signing_path = try testPath(&tmp, io, "signing", &signing_buf);
    const seed: [32]u8 = @splat(0x98);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = testNetworkId("history V1 signing fence");
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    defer archive.deinit();

    var state = try stateAt(gpa, network_id, 1);
    defer state.deinit(gpa);
    const snapshot = try registry.writeSnapshot(&state, gpa);
    defer gpa.free(snapshot);
    const assertion = anchorAssertion(&state, snapshot);
    var genesis = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    defer genesis.deinit(gpa);
    try archive.prepareFrontier(&genesis);
    try archive.stageApplied(&state);
    _ = try archive.nextStaged();
    var legacy: [vote_bytes]u8 = undefined;
    encodeVote(.{
        .assertion = assertion,
        .signer = id,
        .signature = try slcp.core.crypto.sign(seed, assertion.digest()),
    }, &legacy);
    @memcpy(legacy[0..tag.len], "REGISTRY-CKPT-V1");
    try overwriteTestFileAt(io, archive.signing_dir, "high-water.vote", &legacy);

    try testing.expectError(error.SigningFenceCorrupt, archive.recordApplied(&state));
    try testing.expect((try archive.loadLatest(1)) == null);
}

test "history archive: each trusted directory barrier precedes shared publication" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const seed: [32]u8 = @splat(0x9a);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = testNetworkId("history directory barriers");
    var state = try stateAt(gpa, network_id, 1);
    defer state.deinit(gpa);
    const snapshot = try registry.writeSnapshot(&state, gpa);
    defer gpa.free(snapshot);

    // First fail the per-slot-vote directory fsync, then the high-water
    // directory fsync. Ledger and anchor objects deliberately precede the
    // fence, but neither trusted failure may publish a shared vote or latest
    // pointer. Finally fail the shared snapshot-directory barrier.
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
            .genesis_close_time = test_genesis_close_time,
            .quorum = slcp.Quorum.of(1, &.{id}),
            .signer_seed = seed,
            .checkpoint_every = 1,
        });
        defer archive.deinit();
        var genesis = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
        defer genesis.deinit(gpa);
        try archive.prepareFrontier(&genesis);
        try archive.stageApplied(&state);
        _ = try archive.nextStaged();
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
            _ = try archive.snapshots_dir.statFile(
                io,
                snapshotName(hash(snapshot), &name_buf),
                .{ .follow_symlinks = false },
            );
            const assertion = anchorAssertion(&state, snapshot);
            try testing.expectError(error.FileNotFound, archive.votes_dir.statFile(
                io,
                voteName(assertion.digest(), id, &name_buf),
                .{ .follow_symlinks = false },
            ));
            try testing.expectError(error.FileNotFound, archive.latest_dir.statFile(
                io,
                latestName(id, &name_buf),
                .{ .follow_symlinks = false },
            ));
        } else {
            try testing.expectError(error.InjectedDirectorySyncFailure, archive.recordApplied(&state));
        }
    }
}

test "history archive: a shared object file-sync failure precedes signing" {
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
    const network_id = testNetworkId("history file sync barrier");
    var state = try stateAt(gpa, network_id, 1);
    defer state.deinit(gpa);

    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    defer archive.deinit();
    var genesis = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    defer genesis.deinit(gpa);
    try archive.prepareFrontier(&genesis);
    try archive.stageApplied(&state);
    _ = try archive.nextStaged();
    archive.sync_file = TestFileSyncFault.sync;
    TestFileSyncFault.fail = true;
    defer TestFileSyncFault.fail = false;

    try testing.expectError(error.InjectedFileSyncFailure, archive.recordApplied(&state));
    try testing.expect((try archive.loadLatest(1)) == null);

    TestFileSyncFault.fail = false;
    try testing.expectEqual(RecordStatus.certified, try recordAndAck(&archive, &state));
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
    const network_id = testNetworkId("history certified fork");
    const quorum = slcp.Quorum.of(2, &ids);
    var ax = try Archive.open(gpa, io, .{ .archive_dir = archive_path, .signing_dir = sign_paths[0], .network_id = network_id, .genesis_close_time = test_genesis_close_time, .quorum = quorum, .signer_seed = seeds[0], .checkpoint_every = 1 });
    defer ax.deinit();
    var bx = try Archive.open(gpa, io, .{ .archive_dir = archive_path, .signing_dir = sign_paths[1], .network_id = network_id, .genesis_close_time = test_genesis_close_time, .quorum = quorum, .signer_seed = seeds[1], .checkpoint_every = 1 });
    defer bx.deinit();
    var x = try stateAt(gpa, network_id, 1);
    defer x.deinit(gpa);
    _ = try recordAndAck(&ax, &x);
    _ = try recordAndAck(&bx, &x);

    // Simulate copied validator identities with independent trusted signing
    // directories: B and C attest a different, self-consistent head.
    var by = try Archive.open(gpa, io, .{ .archive_dir = archive_path, .signing_dir = sign_paths[2], .network_id = network_id, .genesis_close_time = test_genesis_close_time, .quorum = quorum, .signer_seed = seeds[1], .checkpoint_every = 1 });
    defer by.deinit();
    var cy = try Archive.open(gpa, io, .{ .archive_dir = archive_path, .signing_dir = sign_paths[3], .network_id = network_id, .genesis_close_time = test_genesis_close_time, .quorum = quorum, .signer_seed = seeds[2], .checkpoint_every = 1 });
    defer cy.deinit();
    var y = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    defer y.deinit(gpa);
    const fork_seed: [32]u8 = @splat(0xa9);
    const source = try slcp.core.crypto.publicKeyFromSeed(fork_seed);
    var tx = registry.Tx.init(source, 1, .claim, "other-head", "", registry.zero_key).?;
    try tx.sign(fork_seed, network_id);
    var set: registry.TxSet = .{ .count = 1 };
    set.txs[0] = tx;
    try applySet(gpa, &y, &set);
    _ = try recordAndAck(&by, &y);
    _ = try recordAndAck(&cy, &y);

    // The signatures themselves are enough to prove a same-slot safety fork;
    // an attacker cannot suppress that hard failure by tearing one snapshot.
    const y_snapshot = try registry.writeSnapshot(&y, gpa);
    defer gpa.free(y_snapshot);
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
    const network_id = testNetworkId("history namespace symlinks");
    const network_hex = registry.hex32(network_id);
    const cases = [_]?[]const u8{
        null,
        "history-v1",
        "history-v1/snapshots",
        "history-v1/ledgers",
        "history-v1/votes",
        "history-v1/latest",
    };
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
            var parent_rel_buf: [192]u8 = undefined;
            const parent_rel = if (std.fs.path.dirname(name)) |parent|
                try std.fmt.bufPrint(&parent_rel_buf, "{s}/{s}", .{ network_rel, parent })
            else
                network_rel;
            try tmp.dir.createDirPath(io, parent_rel);
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
            .genesis_close_time = test_genesis_close_time,
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
    const network_id = testNetworkId("history namespace replacement");
    const network_hex = registry.hex32(network_id);
    var state = try stateAt(gpa, network_id, 1);
    defer state.deinit(gpa);
    const snapshot = try registry.writeSnapshot(&state, gpa);
    defer gpa.free(snapshot);
    const assertion = anchorAssertion(&state, snapshot);
    const cases = [_]?[]const u8{
        null,
        "history-v1",
        "history-v1/snapshots",
        "history-v1/ledgers",
        "history-v1/votes",
        "history-v1/latest",
    };
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
            .genesis_close_time = test_genesis_close_time,
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
        try tmp.dir.symLink(io, outside_path, target_rel, .{ .is_directory = true });

        try testing.expectEqual(RecordStatus.certified, try recordAndAck(&archive, &state));

        var escaped_rel_buf: [384]u8 = undefined;
        const prefix = if (child == null)
            "history-v1/snapshots"
        else if (std.mem.eql(u8, child.?, "history-v1"))
            "snapshots"
        else
            "";
        const escaped_rel = if (child == null or
            std.mem.eql(u8, child.?, "history-v1") or
            std.mem.endsWith(u8, child.?, "/snapshots"))
            try std.fmt.bufPrint(&escaped_rel_buf, "{s}/{s}{s}{s}.snap", .{
                outside_rel,
                prefix,
                if (prefix.len == 0) "" else "/",
                &registry.hex32(assertion.snapshot_hash),
            })
        else if (std.mem.endsWith(u8, child.?, "/ledgers"))
            try std.fmt.bufPrint(&escaped_rel_buf, "{s}/{s}.ledger", .{
                outside_rel,
                &registry.hex32(state.head.hash),
            })
        else if (std.mem.endsWith(u8, child.?, "/votes"))
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
    const network_id = testNetworkId("history object symlinks");
    var state = try stateAt(gpa, network_id, 1);
    defer state.deinit(gpa);
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    defer archive.deinit();
    _ = try recordAndAck(&archive, &state);
    try testing.expect((try archive.loadLatest(1)) != null);

    const snapshot = try registry.writeSnapshot(&state, gpa);
    defer gpa.free(snapshot);
    const assertion = anchorAssertion(&state, snapshot);
    const dirs = [_]std.Io.Dir{ archive.snapshots_dir, archive.ledgers_dir, archive.votes_dir, archive.latest_dir };
    var name_bufs: [4][max_name_bytes]u8 = undefined;
    const names = [4][]const u8{
        snapshotName(assertion.snapshot_hash, &name_bufs[0]),
        ledgerName(state.head.hash, &name_bufs[1]),
        voteName(assertion.digest(), id, &name_bufs[2]),
        latestName(id, &name_bufs[3]),
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
    const network_id = testNetworkId("history fifo object");
    var archive = try Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
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
