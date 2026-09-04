//! main.zig — the `registry` process (docs/examples-roadmap.md E1–E2d:
//! persistence, flooding, authenticated history replay, cadence, and
//! CLI). `registry node …` runs one validator: the typed node from
//! app.zig, the RPC server from rpc.zig, the snapshot file, and the cadence
//! loop that turns the pending queue into proposals. `submit`, `get`,
//! `account` and `head` are the client verbs: they talk to a node's RPC.

const std = @import("std");
const builtin = @import("builtin");
const slcp = @import("slcp");
const registry = @import("registry.zig");
const app = @import("app.zig");
const history = @import("history.zig");
const rpc = @import("rpc.zig");

const default_rpc = "127.0.0.1:7412";
const gossip_drain_per_tick: usize = 64;
const gossip_reflood_ms: u64 = 1_000;

/// Stack-lived adapter from registry admission to the node's Experimental
/// application-message transport. A periodic reflood retries any best-effort
/// send that cannot make progress now.
const GossipPublisher = struct {
    node: *slcp.Node,

    fn publisher(self: *@This()) rpc.Publisher {
        return .{ .ctx = self, .publishFn = publish };
    }

    fn publish(ctx: *anyopaque, bytes: []const u8) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.node.publishAppMessage(bytes) catch {};
    }
};

const usage =
    \\registry — a replicated name registry on slcp (examples/registry)
    \\
    \\  registry node --network <passphrase> --genesis-close-time <unix-seconds>
    \\                --key <file> --data-dir <dir> --quorum <json>
    \\                --listen <port> --rpc <port> [--peer host:port]...
    \\                [--min-slot-ms 1000] [--heartbeat-ms 3000]
    \\                [--proposal-clock-offset-s 0]
    \\                [--history-dir <dir> [--checkpoint-every 8] [--history-min-slot 0]]
    \\  registry submit --key <file> [--rpc ip:port] claim <name>
    \\  registry submit --key <file> [--rpc ip:port] set <name> <value>
    \\  registry submit --key <file> [--rpc ip:port] transfer <name> <hex64>
    \\  registry submit --key <file> [--rpc ip:port] release <name>
    \\  registry get [--rpc ip:port] <name>
    \\  registry account [--rpc ip:port] <hex64>
    \\  registry head [--rpc ip:port]
    \\
    \\--rpc defaults to 127.0.0.1:7412. Key files are slcp seeds (`slcp key new file.key`).
    \\Names are [a-z0-9-], 1..32 bytes; values up to 64 bytes.
    \\Exit codes: 0 ok · 1 refused or failed · 2 usage · 3 the node fell behind a gap it cannot recover.
    \\
;

pub fn main(init: std.process.Init) !void {
    var it = std.process.Args.Iterator.init(init.minimal.args);
    _ = it.next(); // argv[0]
    var args: std.ArrayList([]const u8) = .empty;
    defer args.deinit(init.gpa);
    while (it.next()) |arg| try args.append(init.gpa, arg);

    var out_buf: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &out_buf);
    const code = run(init, args.items, &out.interface) catch |err| blk: {
        std.debug.print("registry: {t}\n", .{err});
        break :blk @as(u8, 1);
    };
    out.interface.flush() catch {};
    std.process.exit(code);
}

fn run(init: std.process.Init, args: []const []const u8, out: *std.Io.Writer) !u8 {
    if (args.len == 0) return usageError("missing verb");
    const verb = args[0];
    if (eql(verb, "--help") or eql(verb, "-h") or eql(verb, "help")) {
        try out.writeAll(usage);
        return 0;
    }
    if (eql(verb, "node")) return runNode(init, args[1..]);
    if (eql(verb, "submit")) return runSubmit(init, args[1..], out);
    if (eql(verb, "get") or eql(verb, "account") or eql(verb, "head")) return runQuery(init, verb, args[1..], out);
    return usageError("unknown verb");
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn usageError(msg: []const u8) u8 {
    std.debug.print("registry: {s}\n\n{s}", .{ msg, usage });
    return 2;
}

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

const Flags = struct {
    network: ?[]const u8 = null,
    /// Required network anchor: POSIX/Unix seconds, leap seconds ignored.
    genesis_close_time: ?u64 = null,
    key: ?[]const u8 = null,
    data_dir: ?[]const u8 = null,
    quorum: ?[]const u8 = null,
    listen: ?u16 = null,
    /// `--rpc` is a port for `node`, an `ip:port` spec for the client verbs.
    rpc_port: ?u16 = null,
    rpc: []const u8 = default_rpc,
    min_slot_ms: u64 = registry.min_slot_ms,
    heartbeat_ms: u64 = registry.heartbeat_ms,
    /// Test/operations clock injection. It affects only this node's proposal;
    /// deterministic validation never reads it or the local wall clock.
    proposal_clock_offset_s: i64 = 0,
    /// A shared, untrusted archive. Validator attestations authenticate its
    /// contents; the local signing fence lives under `data_dir` instead.
    history_dir: ?[]const u8 = null,
    checkpoint_every: u64 = 8,
    history_min_slot: u64 = 0,
    history_policy_set: bool = false,
    peers: std.ArrayList([]const u8) = .empty,
    positional: std.ArrayList([]const u8) = .empty,

    fn deinit(self: *Flags, gpa: std.mem.Allocator) void {
        self.peers.deinit(gpa);
        self.positional.deinit(gpa);
    }
};

const FlagError = error{ UnknownFlag, MissingValue, EmptyNetwork, BadPort, BadMillis, BadGenesisCloseTime, BadClockOffset, BadCheckpointInterval, BadSlot } || std.mem.Allocator.Error;

fn parseFlags(gpa: std.mem.Allocator, args: []const []const u8, node_mode: bool) FlagError!Flags {
    var f: Flags = .{};
    errdefer f.deinit(gpa);
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (!std.mem.startsWith(u8, arg, "--")) {
            try f.positional.append(gpa, arg);
            continue;
        }
        const name = arg[2..];
        if (i + 1 >= args.len) return error.MissingValue;
        i += 1;
        const value = args[i];
        if (eql(name, "network")) {
            if (value.len == 0) return error.EmptyNetwork;
            f.network = value;
        } else if (eql(name, "genesis-close-time")) {
            f.genesis_close_time = std.fmt.parseInt(u64, value, 10) catch return error.BadGenesisCloseTime;
            if (f.genesis_close_time.? == std.math.maxInt(u64)) return error.BadGenesisCloseTime;
        } else if (eql(name, "key")) {
            f.key = value;
        } else if (eql(name, "data-dir")) {
            f.data_dir = value;
        } else if (eql(name, "quorum")) {
            f.quorum = value;
        } else if (eql(name, "listen")) {
            f.listen = std.fmt.parseInt(u16, value, 10) catch return error.BadPort;
            if (f.listen.? == 0) return error.BadPort;
        } else if (eql(name, "rpc")) {
            if (node_mode) {
                f.rpc_port = std.fmt.parseInt(u16, value, 10) catch return error.BadPort;
                if (f.rpc_port.? == 0) return error.BadPort;
            } else {
                f.rpc = value;
            }
        } else if (eql(name, "peer")) {
            try f.peers.append(gpa, value);
        } else if (eql(name, "min-slot-ms")) {
            f.min_slot_ms = std.fmt.parseInt(u64, value, 10) catch return error.BadMillis;
        } else if (eql(name, "heartbeat-ms")) {
            f.heartbeat_ms = std.fmt.parseInt(u64, value, 10) catch return error.BadMillis;
            if (f.heartbeat_ms == 0) return error.BadMillis;
        } else if (eql(name, "proposal-clock-offset-s")) {
            f.proposal_clock_offset_s = std.fmt.parseInt(i64, value, 10) catch return error.BadClockOffset;
        } else if (eql(name, "history-dir")) {
            if (value.len == 0) return error.MissingValue;
            f.history_dir = value;
        } else if (eql(name, "checkpoint-every")) {
            f.checkpoint_every = std.fmt.parseInt(u64, value, 10) catch return error.BadCheckpointInterval;
            if (f.checkpoint_every == 0 or f.checkpoint_every > 64) return error.BadCheckpointInterval;
            f.history_policy_set = true;
        } else if (eql(name, "history-min-slot")) {
            f.history_min_slot = std.fmt.parseInt(u64, value, 10) catch return error.BadSlot;
            f.history_policy_set = true;
        } else {
            return error.UnknownFlag;
        }
    }
    return f;
}

fn flagsOrUsage(gpa: std.mem.Allocator, args: []const []const u8, node_mode: bool) ?Flags {
    return parseFlags(gpa, args, node_mode) catch |err| {
        _ = usageError(switch (err) {
            error.UnknownFlag => "unknown flag",
            error.MissingValue => "a flag is missing its value",
            error.EmptyNetwork => "--network must be a non-empty passphrase unique to this registry network",
            error.BadPort => "a port must be a number in 1..65535",
            error.BadMillis => "--min-slot-ms / --heartbeat-ms take milliseconds (heartbeat > 0)",
            error.BadGenesisCloseTime => "--genesis-close-time must be a Unix-seconds integer below 18446744073709551615",
            error.BadClockOffset => "--proposal-clock-offset-s must be a signed seconds integer",
            error.BadCheckpointInterval => "--checkpoint-every must be a number in 1..64",
            error.BadSlot => "--history-min-slot must be a non-negative slot number",
            error.OutOfMemory => "out of memory",
        });
        return null;
    };
}

// ---------------------------------------------------------------------------
// registry node
// ---------------------------------------------------------------------------

/// How long without an applied slot before the node loop says so.
const stall_warn_ms: u64 = 60_000;
const history_retry_ms: u64 = 1_000;

/// Failures in the trusted signing fence, the state-to-be-signed, or the
/// authenticated archive view are safety failures. Ordinary shared-storage
/// errors are availability failures: consensus continues while publication
/// retries in the background.
fn historyFailureIsFatal(err: anyerror) bool {
    return err == error.InvalidAppliedState or
        err == error.InvalidGenesisState or
        err == error.SigningFenceCorrupt or
        err == error.SigningFenceUnavailable or
        err == error.SigningEquivocation or
        err == error.SigningRollback or
        err == error.CheckpointSlotOverflow or
        err == error.CertifiedFork or
        err == error.CertifiedHistoryInvalid or
        err == error.HistoryAckRequired or
        err == error.HistoryActivationMismatch or
        err == error.HistoryAdoptionNotInstalled or
        err == error.HistoryAnchorInvalid or
        err == error.HistoryBacklogFull or
        err == error.HistoryBootProvenanceConflict or
        err == error.HistoryBootProvenanceRollback or
        err == error.HistoryFrontierMismatch or
        err == error.HistoryFrontierUnprepared or
        err == error.HistoryNotPublished or
        err == error.HistoryOutboxCorrupt or
        err == error.HistoryOutboxSequence or
        err == error.HistoryOutboxStateMismatch or
        err == error.HistoryOutboxUnavailable or
        err == error.HistoryPolicyCorrupt or
        err == error.HistoryPolicyMismatch or
        err == error.HistoryPublisherRace or
        err == error.HistoryStagedStateNotLoaded or
        err == error.HistoryTransitionInvalid or
        err == error.OutOfMemory;
}

fn nowMs(io: std.Io) u64 {
    const ns = std.Io.Clock.now(.awake, io).nanoseconds;
    return @intCast(@divTrunc(ns, std.time.ns_per_ms));
}

/// Unix/POSIX whole seconds, ignoring leap seconds. This is called only when
/// constructing this validator's own proposal; received values and replay
/// are checked exclusively against deterministic ledger state.
fn wallSeconds(io: std.Io) u64 {
    const ns = std.Io.Clock.now(.real, io).nanoseconds;
    if (ns <= 0) return 0;
    const seconds = @divFloor(ns, std.time.ns_per_s);
    return std.math.cast(u64, seconds) orelse std.math.maxInt(u64);
}

fn shiftedWallSeconds(seconds: u64, offset: i64) u64 {
    const shifted = @as(i128, seconds) + @as(i128, offset);
    if (shifted <= 0) return 0;
    if (shifted >= std.math.maxInt(u64)) return std.math.maxInt(u64);
    return @intCast(shifted);
}

fn readSnapshotFile(io: std.Io, dir: std.Io.Dir, gpa: std.mem.Allocator) !?registry.State {
    const bytes = dir.readFileAlloc(io, "snapshot", gpa, .limited(registry.snapshot_read_limit)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer gpa.free(bytes);
    const state = (try registry.readSnapshot(gpa, bytes)) orelse return error.SnapshotCorrupt;
    return state;
}

fn fullSync(io: std.Io, file: std.Io.File) !void {
    try file.sync(io);
    if (comptime builtin.os.tag == .macos) {
        if (std.c.fcntl(file.handle, std.posix.F.FULLFSYNC) < 0)
            return error.FullSyncFailed;
    }
}

fn syncDirectory(dir: std.Io.Dir) !void {
    if (comptime builtin.os.tag == .linux or builtin.os.tag == .macos) {
        if (std.c.fsync(dir.handle) != 0) return error.DirectorySyncFailed;
    }
}

/// Create/open the final data-directory component through an already-existing
/// parent and make that directory entry durable. History mode needs this
/// fence before it can publish a vote whose trusted signing state lives under
/// the data directory.
fn openDurableDataDir(
    io: std.Io,
    path: []const u8,
    sync_parent: *const fn (std.Io.Dir) anyerror!void,
) !std.Io.Dir {
    if (path.len == 0) return error.BadPathName;
    const base = std.fs.path.basename(path);
    if (base.len == 0 or std.mem.eql(u8, base, ".") or std.mem.eql(u8, base, "..") or
        (base.len == 1 and base[0] == std.fs.path.sep))
        return error.BadPathName;
    const parent_path = std.fs.path.dirname(path) orelse ".";
    const cwd = std.Io.Dir.cwd();
    const parent = try cwd.openDir(io, parent_path, .{ .follow_symlinks = false });
    defer parent.close(io);
    const dir = try parent.createDirPathOpen(io, base, .{
        .open_options = .{ .follow_symlinks = false },
    });
    errdefer dir.close(io);
    try sync_parent(parent);
    return dir;
}

/// Unnamed/random temp → write + full sync → atomic replacement →
/// directory sync. A history vote is attempted only after this returns.
fn writeSnapshotFile(io: std.Io, dir: std.Io.Dir, gpa: std.mem.Allocator, state: *const registry.State) !void {
    const bytes = try registry.writeSnapshot(state, gpa);
    defer gpa.free(bytes);
    var af = try dir.createFileAtomic(io, "snapshot", .{ .replace = true });
    defer af.deinit(io);
    try af.file.writeStreamingAll(io, bytes);
    try fullSync(io, af.file);
    try af.replace(io);
    try syncDirectory(dir);
}

const BootSource = enum { genesis, local_snapshot, history, history_outbox, trusted_local };

const BootSelection = struct {
    state: registry.State,
    source: BootSource,
    /// The default `1` lets Node resume its own journal. A recovered history tip
    /// is different: its exact successor declares the older journal prefix
    /// permanently out of scope.
    start_slot: u64,
};

const BootSelectionError = error{
    SnapshotWrongNetwork,
    SnapshotWrongGenesisCloseTime,
    HistoryCheckpointWrongNetwork,
    HistoryCheckpointWrongGenesisCloseTime,
    HistoryCheckpointConflict,
    HistoryCheckpointAtMaxSlot,
    HistoryFloorUnavailable,
};

/// Choose between locally persisted state and an independently authenticated
/// history tip. `min_slot` is an operator's anti-rollback policy, not a search
/// hint: if nothing reaches it, boot must fail instead of quietly starting
/// from older state.
///
/// Ownership: both candidate states move IN and are freed unless they move
/// OUT inside the returned selection. `authenticated` is a CLONE of the
/// caller's recovery state (the recovery outlives the call), so freeing it
/// here on any non-selected exit is safe.
fn selectBootState(
    gpa: std.mem.Allocator,
    network_id: [32]u8,
    genesis_close_time: u64,
    local: ?registry.State,
    authenticated: ?registry.State,
    min_slot: u64,
) (BootSelectionError || std.mem.Allocator.Error)!BootSelection {
    var leftover_local = local;
    defer if (leftover_local) |*s| s.deinit(gpa);
    var leftover_auth = authenticated;
    defer if (leftover_auth) |*s| s.deinit(gpa);

    if (leftover_local) |*state| {
        if (!std.mem.eql(u8, &state.network_id, &network_id)) return error.SnapshotWrongNetwork;
        if (!registry.closeTimeAtSlotOk(genesis_close_time, state.head.slot, state.head.close_time))
            return error.SnapshotWrongGenesisCloseTime;
    }
    if (leftover_auth) |*state| {
        if (!std.mem.eql(u8, &state.network_id, &network_id)) return error.HistoryCheckpointWrongNetwork;
        if (!registry.closeTimeAtSlotOk(genesis_close_time, state.head.slot, state.head.close_time))
            return error.HistoryCheckpointWrongGenesisCloseTime;
        if (state.head.slot < min_slot) return error.HistoryFloorUnavailable;
    }

    const local_eligible = if (leftover_local) |*s| s.head.slot >= min_slot else false;

    if (leftover_auth) |*checkpoint| {
        if (local_eligible) {
            const snapshot = &leftover_local.?;
            if (snapshot.head.slot == checkpoint.head.slot and
                !std.mem.eql(u8, &snapshot.head.hash, &checkpoint.head.hash))
                return error.HistoryCheckpointConflict;
            if (snapshot.head.slot > checkpoint.head.slot) {
                const chosen = leftover_local.?;
                leftover_local = null;
                return .{ .state = chosen, .source = .local_snapshot, .start_slot = 1 };
            }
        }
        const successor = std.math.add(u64, checkpoint.head.slot, 1) catch
            return error.HistoryCheckpointAtMaxSlot;
        const chosen = leftover_auth.?;
        leftover_auth = null;
        return .{ .state = chosen, .source = .history, .start_slot = successor };
    }

    if (local_eligible) {
        const chosen = leftover_local.?;
        leftover_local = null;
        return .{ .state = chosen, .source = .local_snapshot, .start_slot = 1 };
    }
    if (min_slot != 0) return error.HistoryFloorUnavailable;
    return .{ .state = try registry.State.genesis(network_id, genesis_close_time, gpa), .source = .genesis, .start_slot = 1 };
}

/// A trusted local adoption marker is an unfinished install transaction, so
/// it outranks any newer proof visible in mutable shared storage. The ordinary
/// anti-rollback floor still applies to the chosen state.
fn selectHistoryBootState(
    gpa: std.mem.Allocator,
    network_id: [32]u8,
    genesis_close_time: u64,
    local: ?registry.State,
    authenticated: ?registry.State,
    pending_install: ?registry.State,
    min_slot: u64,
) (BootSelectionError || std.mem.Allocator.Error)!BootSelection {
    var pending = pending_install;
    defer if (pending) |*s| s.deinit(gpa);
    var auth = authenticated;
    defer if (auth) |*s| s.deinit(gpa);

    // The candidate moves into selectBootState (which frees it unless it
    // moves into the selection); forget it here so the defers above never
    // free a state that function already owns.
    const used_pending = pending != null;
    const candidate: ?registry.State = if (used_pending) pending.? else auth;
    if (used_pending) pending = null else auth = null;
    var selected = try selectBootState(
        gpa,
        network_id,
        genesis_close_time,
        local,
        candidate,
        min_slot,
    );
    if (used_pending and selected.source == .history)
        selected.source = .history_outbox;
    return selected;
}

/// Create an AppNode at an already selected application frontier. A history
/// checkpoint may overlap a locally durable journal tail; retrying from the
/// ordinary journal start is safe only because AppNode revalidates that the
/// retained tail is the exact continuation of the selected state.
fn createBootNode(
    gpa: std.mem.Allocator,
    io: std.Io,
    base_options: app.Node.Options,
    selected: BootSelection,
) !*app.Node {
    var options = base_options;
    options.start_slot = selected.start_slot;
    return app.Node.create(gpa, io, options, selected.state) catch |err| {
        if ((selected.source == .history or
            selected.source == .history_outbox or
            selected.source == .trusted_local) and
            err == error.StartSlotBehindJournal)
        {
            std.debug.print("registry node: authenticated history tip slot {d} overlaps a newer local journal; verifying that journal as its continuation\n", .{selected.state.head.slot});
            options.start_slot = 1;
            return app.Node.create(gpa, io, options, selected.state);
        }
        return err;
    };
}

/// Drain the synchronous journal replay that `AppNode.create` queued before
/// returning. The caller must do this before publishing application state to
/// RPC or installing a replacement snapshot: `initial` can be older than the
/// Node journal when the previous process crashed between those two durable
/// writes.
fn drainBootReplay(
    node: *app.Node,
    gpa: std.mem.Allocator,
    initial: *const registry.State,
    history_archive: ?*history.Archive,
) !registry.State {
    var ready = try initial.clone(gpa);
    var owned = true;
    defer if (owned) ready.deinit(gpa);
    while (try node.waitApplied(.{ .timeout_ms = 0 })) |applied| {
        const successor = std.math.add(u64, ready.head.slot, 1) catch
            return error.BootReplayDiscontinuity;
        if (applied.slot != successor or applied.obs.head.slot != applied.slot)
            return error.BootReplayDiscontinuity;
        // The node's journal is already durable. Admit every replayed state
        // to the trusted history outbox before allowing the ordinary snapshot
        // to catch up, exactly as the live cadence path does. The observation
        // (an owned clone from the engine thread) becomes the ready state.
        if (history_archive) |archive| try stageBootHistory(archive, gpa, &applied.obs);
        ready.deinit(gpa);
        ready = applied.obs;
    }
    owned = false;
    return ready;
}

/// Complete one already-staged publication. The shared archive phase and the
/// trusted acknowledgement phase stay explicit so only the former may be
/// retried as an availability failure by the background worker.
fn publishStagedHistory(archive: *history.Archive, state: *const registry.State) !history.RecordStatus {
    const status = try archive.recordApplied(state);
    try archive.ackStaged(state.head.slot);
    return status;
}

fn logHistoryStatus(status: history.RecordStatus, state: *const registry.State) void {
    switch (status) {
        .not_due => {},
        .published => {
            const head_hex = registry.hex32(state.head.hash);
            std.debug.print("history tip slot {d} signed head={s}\n", .{ state.head.slot, &head_hex });
        },
        .certified => {
            const head_hex = registry.hex32(state.head.hash);
            std.debug.print("history tip slot {d} signed head={s}\n", .{ state.head.slot, &head_hex });
            std.debug.print("history tip slot {d} certified head={s}\n", .{ state.head.slot, &head_hex });
        },
    }
}

/// Startup has no worker yet. Drain previously admitted history before boot
/// selection adopts a newer certified frontier; otherwise a full or older
/// pending outbox could make every restart repeat the same refusal.
fn drainStartupHistory(archive: *history.Archive, gpa: std.mem.Allocator) !void {
    while (try archive.nextStaged()) |staged| {
        var state = staged;
        defer state.deinit(gpa);
        const status = try publishStagedHistory(archive, &state);
        logHistoryStatus(status, &state);
    }
}

const LatestHistoryBoot = struct {
    selected: BootSelection,
    recovery: ?history.Recovery,
};

/// Once Archive accepts a selected local snapshot as represented by its
/// trusted frontier, preserve that external-state provenance for AppNode.
/// This is derived again on every restart, so clearing a completed adoption
/// marker cannot turn T back into an ordinary snapshot that needs a retained
/// journal predecessor.
fn prepareHistoryBoot(archive: *history.Archive, selected: *BootSelection) !void {
    try archive.prepareFrontier(&selected.state);
    if (selected.source == .local_snapshot and
        try archive.hasTrustedBootProvenance(&selected.state))
    {
        selected.source = .trusted_local;
        selected.start_slot = std.math.add(u64, selected.state.head.slot, 1) catch
            return error.HistoryCheckpointAtMaxSlot;
    }
}

/// Reconcile the ordered outbox, recover the newest independently certified
/// state no older than `installed`, and prepare that final frontier. This is
/// intentionally called again after a pending adoption T is confirmed: T is
/// the crash-safe install transaction, not necessarily the best available
/// point from which to join the live network.
fn selectLatestHistoryBoot(
    archive: *history.Archive,
    gpa: std.mem.Allocator,
    network_id: [32]u8,
    genesis_close_time: u64,
    installed: *const registry.State,
    min_slot: u64,
) !LatestHistoryBoot {
    try drainStartupHistory(archive, gpa);
    const floor = @max(min_slot, installed.head.slot);
    const recovery = try archive.recoverLatest(floor);
    // The recovery owns its state; selection works on an owned clone so the
    // recovery can outlive it (the caller reports its anchor slot).
    const authenticated = if (recovery) |*rec| try rec.state.clone(gpa) else null;
    var selected = try selectHistoryBootState(
        gpa,
        network_id,
        genesis_close_time,
        try installed.clone(gpa),
        authenticated,
        null,
        min_slot,
    );
    // `installed` originated at trusted history T, even when no newer U is
    // currently discoverable. `prepareHistoryBoot` preserves the explicit
    // successor handoff; createBootNode still rechecks a later journal tail.
    try prepareHistoryBoot(archive, &selected);
    return .{ .selected = selected, .recovery = recovery };
}

/// Journal recovery can expose one state beyond an outbox that was full when
/// the previous process stopped. Free the oldest durable slot synchronously
/// and retry admission instead of reproducing that permanent startup wedge.
fn stageBootHistory(archive: *history.Archive, gpa: std.mem.Allocator, state: *const registry.State) !void {
    while (true) {
        archive.stageApplied(state) catch |err| switch (err) {
            error.HistoryBacklogFull => {
                var oldest = (try archive.nextStaged()) orelse
                    return error.HistoryOutboxCorrupt;
                defer oldest.deinit(gpa);
                const status = try publishStagedHistory(archive, &oldest);
                logHistoryStatus(status, &oldest);
                continue;
            },
            else => return err,
        };
        return;
    }
}

const HistoryPublicationFailure = struct {
    slot: u64,
    err: anyerror,
};

/// Wakeup and fatal-error channel for the history worker. Applied states do
/// not live here: `Archive.stageApplied` has already placed them in the
/// checksummed, fsync'd trusted outbox before this signal is sent.
const HistoryWakeup = struct {
    io: std.Io,
    mu: std.Io.Mutex = .init,
    changed: std.Io.Condition = .init,
    generation: u64 = 0,
    fatal: ?HistoryPublicationFailure = null,
    stopping: bool = false,

    fn init(io: std.Io) HistoryWakeup {
        return .{ .io = io };
    }

    fn accepting(self: *HistoryWakeup) bool {
        const io = self.io;
        self.mu.lockUncancelable(io);
        defer self.mu.unlock(io);
        return !self.stopping and self.fatal == null;
    }

    fn notify(self: *HistoryWakeup) !void {
        const io = self.io;
        self.mu.lockUncancelable(io);
        defer self.mu.unlock(io);
        if (self.stopping or self.fatal != null) return error.HistoryPublisherStopped;
        self.generation +%= 1;
        self.changed.signal(io);
    }

    /// Wait after observing an empty outbox. The generation check closes the
    /// race where a producer stages and signals between `nextStaged` and the
    /// worker taking this lock.
    fn waitForChange(self: *HistoryWakeup, observed: *u64) bool {
        const io = self.io;
        self.mu.lockUncancelable(io);
        defer self.mu.unlock(io);
        while (!self.stopping and self.fatal == null and self.generation == observed.*) {
            self.changed.waitUncancelable(io, &self.mu);
        }
        observed.* = self.generation;
        return !self.stopping and self.fatal == null;
    }

    /// Shared archive availability failures retry in place. Stop signals wake
    /// this bounded delay promptly; newly staged successors do not overtake
    /// the failed durable head.
    fn waitForRetry(self: *HistoryWakeup) bool {
        const io = self.io;
        self.mu.lockUncancelable(io);
        defer self.mu.unlock(io);
        const retry_deadline_ns = std.Io.Clock.now(.awake, io).nanoseconds +
            @as(i96, history_retry_ms) * std.time.ns_per_ms;
        while (!self.stopping and self.fatal == null) {
            const now_ns = std.Io.Clock.now(.awake, io).nanoseconds;
            if (now_ns >= retry_deadline_ns) break;
            const deadline: std.Io.Clock.Timestamp = .{
                .raw = .{ .nanoseconds = retry_deadline_ns },
                .clock = .awake,
            };
            self.changed.waitTimeout(io, &self.mu, .{ .deadline = deadline }) catch {};
        }
        return !self.stopping and self.fatal == null;
    }

    fn latchFatal(self: *HistoryWakeup, slot: u64, err: anyerror) void {
        const io = self.io;
        self.mu.lockUncancelable(io);
        defer self.mu.unlock(io);
        if (self.fatal == null) self.fatal = .{ .slot = slot, .err = err };
        self.stopping = true;
        self.changed.broadcast(io);
    }

    fn fatalFailure(self: *HistoryWakeup) ?HistoryPublicationFailure {
        const io = self.io;
        self.mu.lockUncancelable(io);
        defer self.mu.unlock(io);
        return self.fatal;
    }

    fn stop(self: *HistoryWakeup) void {
        const io = self.io;
        self.mu.lockUncancelable(io);
        self.stopping = true;
        self.changed.broadcast(io);
        self.mu.unlock(io);
    }
};

/// The cadence loop durably stages exact successor states in the trusted
/// outbox. This worker alone publishes its oldest entry to shared history and
/// advances the durable published watermark; hostile shared I/O therefore
/// cannot make a successor overtake a failed ledger.
const HistoryPublisher = struct {
    gpa: std.mem.Allocator,
    archive: history.Archive,
    wakeup: HistoryWakeup,
    thread: std.Thread,

    fn start(gpa: std.mem.Allocator, io: std.Io, archive: history.Archive) !*HistoryPublisher {
        const self = try gpa.create(HistoryPublisher);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .archive = archive,
            .wakeup = .init(io),
            .thread = undefined,
        };
        self.thread = try std.Thread.spawn(.{}, HistoryPublisher.run, .{self});
        return self;
    }

    fn offer(self: *HistoryPublisher, ledger: registry.State) !void {
        if (!self.wakeup.accepting()) return error.HistoryPublisherStopped;
        try self.archive.stageApplied(&ledger);
        try self.wakeup.notify();
    }

    fn fatalFailure(self: *HistoryPublisher) ?HistoryPublicationFailure {
        return self.wakeup.fatalFailure();
    }

    /// Called only after the ordinary application snapshot is durable. Once
    /// certified provenance exists, this advances its crash-safe boot point
    /// across exact states already admitted to the ordered outbox.
    fn confirmSnapshot(self: *HistoryPublisher, state: *const registry.State) !void {
        try self.archive.confirmInstalled(state);
    }

    fn deinit(self: *HistoryPublisher) void {
        self.wakeup.stop();
        self.thread.join();
        self.archive.deinit();
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    fn run(self: *HistoryPublisher) void {
        var observed_generation: u64 = 0;
        while (true) {
            if (!self.wakeup.accepting()) return;
            const staged = self.archive.nextStaged() catch |err| {
                self.wakeup.latchFatal(0, err);
                return;
            };
            const ledger = staged orelse {
                if (!self.wakeup.waitForChange(&observed_generation)) return;
                continue;
            };
            const status = self.archive.recordApplied(&ledger) catch |err| {
                if (historyFailureIsFatal(err)) {
                    self.wakeup.latchFatal(ledger.head.slot, err);
                    return;
                }
                std.debug.print("registry history: cannot publish ledger slot {d}: {t}; consensus continues and ordered publication will retry\n", .{ ledger.head.slot, err });
                if (!self.wakeup.waitForRetry()) return;
                continue;
            };
            self.archive.ackStaged(ledger.head.slot) catch |err| {
                // This mutates only the trusted outbox and its watermarks; an
                // uncertain acknowledgement is a local safety failure.
                self.wakeup.latchFatal(ledger.head.slot, err);
                return;
            };
            logHistoryStatus(status, &ledger);
        }
    }
};

/// A post-start fatal path must not unwind through an unbounded publisher
/// join: a native NFS/FUSE syscall may be uninterruptible. Drain RPC handlers,
/// stop the consensus node, then let process exit tear down the isolated worker.
fn stopNodeAndExit(server: *rpc.Server, node: *app.Node, node_needs_deinit: *bool, code: u8) noreturn {
    // RPC handlers hold a publisher pointer into the Node. Drain them before
    // freeing that target; process.exit skips the ordinary server defer.
    server.stop();
    if (node_needs_deinit.*) {
        node.deinit();
        node_needs_deinit.* = false;
    }
    std.process.exit(code);
}

fn runNode(init: std.process.Init, args: []const []const u8) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    var f = flagsOrUsage(gpa, args, true) orelse return 2;
    defer f.deinit(gpa);
    const network = f.network orelse return usageError("--network is required");
    const genesis_close_time = f.genesis_close_time orelse return usageError("--genesis-close-time is required");
    const key_path = f.key orelse return usageError("--key is required");
    const data_dir = f.data_dir orelse return usageError("--data-dir is required");
    const quorum_path = f.quorum orelse return usageError("--quorum is required");
    const listen = f.listen orelse return usageError("--listen is required");
    const rpc_port = f.rpc_port orelse return usageError("--rpc is required");
    if (f.positional.items.len != 0) return usageError("unexpected argument");
    if (f.history_dir == null and f.history_policy_set)
        return usageError("--checkpoint-every / --history-min-slot require --history-dir");

    // The quorum spec: a JSON file (docs/quorum-recipes.md), linted at create.
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const qbytes = std.Io.Dir.cwd().readFileAlloc(io, quorum_path, gpa, .limited(1 << 20)) catch |err| {
        std.debug.print("registry node: cannot read --quorum {s}: {t}\n", .{ quorum_path, err });
        return 1;
    };
    defer gpa.free(qbytes);
    const quorum = slcp.Quorum.fromJson(arena.allocator(), qbytes) catch |err| {
        std.debug.print("registry node: --quorum {s} is not a quorum spec ({t}); see docs/quorum-recipes.md\n", .{ quorum_path, err });
        return 1;
    };

    // Identity: the same seed file the node loads (minted 0600 when absent).
    const kp = slcp.keys.loadOrCreate(io, key_path) catch |err| {
        std.debug.print("registry node: cannot load or create --key {s}: {t}\n", .{ key_path, err });
        return 1;
    };
    var key_parent_dir: ?std.Io.Dir = null;
    defer if (key_parent_dir) |parent| parent.close(io);
    if (f.history_dir != null) {
        const key_stat = std.Io.Dir.cwd().statFile(io, key_path, .{ .follow_symlinks = false }) catch |err| {
            std.debug.print("registry node: cannot pin --key {s} for history custody checks: {t}\n", .{ key_path, err });
            return 1;
        };
        if (key_stat.kind != .file) {
            std.debug.print("registry node: --key {s} must be a regular file, not a symlink or special file, when --history-dir is enabled\n", .{key_path});
            return 1;
        }
        const key_parent_path = std.fs.path.dirname(key_path) orelse ".";
        key_parent_dir = std.Io.Dir.cwd().openDir(io, key_parent_path, .{ .follow_symlinks = false }) catch |err| {
            std.debug.print("registry node: cannot pin the parent of --key {s} for history custody checks: {t}\n", .{ key_path, err });
            return 1;
        };
    }

    // Boot state: prefer a newer quorum-authenticated replayed history tip,
    // otherwise resume the local snapshot (or genesis for a fresh node).
    const nid = registry.networkId(network, genesis_close_time);
    const descriptor_buf = try gpa.alloc(u8, registry.tag_net.len + 8 + network.len);
    defer gpa.free(descriptor_buf);
    const network_descriptor = registry.networkDescriptor(genesis_close_time, network, descriptor_buf);
    const dir = if (f.history_dir != null)
        openDurableDataDir(io, data_dir, syncDirectory) catch |err| {
            std.debug.print("registry node: cannot durably create --data-dir {s}: {t}; in history mode its immediate parent must already exist on durable storage\n", .{ data_dir, err });
            return 1;
        }
    else
        std.Io.Dir.cwd().createDirPathOpen(io, data_dir, .{}) catch |err| {
            std.debug.print("registry node: cannot create --data-dir {s}: {t}\n", .{ data_dir, err });
            return 1;
        };
    defer dir.close(io);

    var local_snapshot = readSnapshotFile(io, dir, gpa) catch |err| {
        std.debug.print("registry node: {s}/snapshot: {t} — keep this node stopped until the local snapshot is repaired or removed under operator control\n", .{ data_dir, err });
        return 1;
    };
    if (local_snapshot) |*snap| {
        if (!std.mem.eql(u8, &snap.network_id, &nid)) {
            std.debug.print("registry node: {s}/snapshot belongs to another --network; use a fresh --data-dir\n", .{data_dir});
            return 1;
        }
        // Validate G before this local slot is used as the archive lookup
        // floor. `selectBootState` repeats the check at the install boundary.
        if (!registry.closeTimeAtSlotOk(genesis_close_time, snap.head.slot, snap.head.close_time)) {
            std.debug.print("registry node: the local snapshot's slot/close_time is outside the interval anchored by --genesis-close-time {d}; keep this node stopped and restore a snapshot from this network epoch\n", .{genesis_close_time});
            return 1;
        }
    }

    var history_archive: ?history.Archive = null;
    defer if (history_archive) |*archive| archive.deinit();
    var authenticated_recovery: ?history.Recovery = null;
    defer if (authenticated_recovery) |*r| r.deinit(gpa);
    var authenticated: ?registry.State = null;
    defer if (authenticated) |*s| s.deinit(gpa);
    var pending_install: ?registry.State = null;
    if (f.history_dir) |archive_dir| {
        const signing_dir = try std.fmt.allocPrint(gpa, "{s}/history-signing", .{data_dir});
        defer gpa.free(signing_dir);
        history_archive = history.Archive.open(gpa, io, .{
            .archive_dir = archive_dir,
            .signing_dir = signing_dir,
            .private_data_root_dir = dir,
            .private_key_parent_dir = key_parent_dir,
            .network_id = nid,
            .genesis_close_time = genesis_close_time,
            .quorum = quorum,
            .signer_seed = kp.seed,
            .checkpoint_every = f.checkpoint_every,
        }) catch |err| {
            if (err == error.SignerNotInQuorum) {
                std.debug.print("registry node: history requires this validator ({s}) to appear explicitly in --quorum; automatic self-inclusion is disabled\n", .{&registry.hex32(kp.public_key)});
            } else {
                std.debug.print("registry node: cannot open --history-dir {s}: {t}\n", .{ archive_dir, err });
            }
            return 1;
        };

        // Reconcile the private outbox before consulting mutable shared
        // history. In particular, a certified adoption marker is a trusted
        // local install obligation: it must participate in boot selection
        // before --history-min-slot is enforced, and a newer shared proof
        // must not replace it until this exact state reaches `snapshot`.
        var genesis_base: ?registry.State = null;
        defer if (genesis_base) |*g| g.deinit(gpa);
        const local_history_base: *const registry.State = if (local_snapshot) |*snap|
            snap
        else base: {
            genesis_base = try registry.State.genesis(nid, genesis_close_time, gpa);
            break :base &genesis_base.?;
        };
        history_archive.?.prepareFrontier(local_history_base) catch |err| {
            std.debug.print("registry node: cannot prepare the durable history outbox at local slot {d}: {t}; keep this node stopped\n", .{ local_history_base.head.slot, err });
            return 1;
        };
        pending_install = history_archive.?.pendingInstall() catch |err| {
            std.debug.print("registry node: cannot read the trusted pending history installation: {t}; keep this node stopped\n", .{err});
            return 1;
        };
        if (pending_install == null) {
            // Finish older admitted work before a newer shared certificate
            // can move the outbox frontier.
            drainStartupHistory(&history_archive.?, gpa) catch |err| {
                std.debug.print("registry node: cannot finish the durable history backlog before boot: {t}; keep this node stopped and restore shared archive availability\n", .{err});
                return 1;
            };
            const floor = @max(f.history_min_slot, local_history_base.head.slot);
            authenticated_recovery = history_archive.?.recoverLatest(floor) catch |err| {
                std.debug.print("registry node: cannot authenticate and replay a history tip at or above slot {d} in {s}: {t}\n", .{ floor, archive_dir, err });
                return 1;
            };
            // The recovery owns its state; selection consumes a clone.
            authenticated = if (authenticated_recovery) |*recovered| try recovered.state.clone(gpa) else null;
        }
    }

    // The three candidates move into the selection; it frees the losers and
    // owns the winner from here to the end of boot.
    var selected = selectHistoryBootState(
        gpa,
        nid,
        genesis_close_time,
        local_snapshot,
        authenticated,
        pending_install,
        f.history_min_slot,
    ) catch |err| {
        switch (err) {
            error.SnapshotWrongGenesisCloseTime => std.debug.print("registry node: the local snapshot's slot/close_time is outside the interval anchored by --genesis-close-time {d}; keep this node stopped and restore a snapshot from this network epoch\n", .{genesis_close_time}),
            error.HistoryCheckpointWrongGenesisCloseTime => std.debug.print("registry node: the authenticated history tip's slot/close_time is outside the interval anchored by --genesis-close-time {d}; keep this node stopped\n", .{genesis_close_time}),
            error.HistoryCheckpointConflict => std.debug.print("registry node: the authenticated history tip and local snapshot claim different heads at the same slot; keep this node stopped\n", .{}),
            error.HistoryFloorUnavailable => std.debug.print("registry node: no local snapshot or authenticated history tip reaches --history-min-slot {d}; refusing an anti-rollback downgrade\n", .{f.history_min_slot}),
            else => std.debug.print("registry node: cannot select boot state: {t}\n", .{err}),
        }
        return 1;
    };
    // The moved-in optionals are consumed; clear them so the scope defers
    // never free a state the selection already owns.
    if (local_snapshot != null) local_snapshot = null;
    if (authenticated != null) authenticated = null;
    if (pending_install != null) pending_install = null;
    defer selected.state.deinit(gpa);
    if (history_archive) |*archive| {
        prepareHistoryBoot(archive, &selected) catch |err| {
            std.debug.print("registry node: cannot adopt the selected history frontier at slot {d}: {t}; keep this node stopped\n", .{ selected.state.head.slot, err });
            return 1;
        };
    }

    const slcp_dir = try std.fmt.allocPrint(gpa, "{s}/slcp", .{data_dir});
    defer gpa.free(slcp_dir);

    var diag: slcp.node.Diagnostic = .{};
    const node_options: app.Node.Options = .{
        // Registry schema and genesis time are part of the raw SLCP signing
        // domain too, so old nodes cannot enter this network and merely stall.
        .network = network_descriptor,
        .key_file = key_path,
        // `kp` also signs history assertions. Bind Node's later key-file read
        // to that exact identity so a path swap cannot split the two roles.
        .node_id = kp.public_key,
        .listen_port = listen,
        .peers = f.peers.items,
        .quorum = quorum,
        .include_self = f.history_dir == null,
        .data_dir = slcp_dir,
        .max_value_bytes = registry.max_value_bytes,
        // Intentionally omit `answering_window_slots`: this example uses the
        // Node default of 16 for bounded live-peer catch-up and its
        // authenticated archive for longer outages.
        .start_slot = selected.start_slot,
        .diagnostic = &diag,
    };

    if (pending_install != null) {
        // A previous process crashed after trusting certified T but before
        // completing T's ordinary snapshot installation. Validate and finish
        // that transaction on an isolated listener first. Only then may this
        // boot consult shared storage for a newer U; otherwise replacing T's
        // marker is unsafe, while joining live consensus from T+1 can strand
        // a node already beyond reachable peers' retained coverage.
        if (selected.source != .history_outbox) {
            std.debug.print("registry node: trusted pending history did not select its exact install frontier; keep this node stopped\n", .{});
            return 1;
        }
        var isolated_options = node_options;
        isolated_options.listen_port = 0;
        isolated_options.peers = &.{};
        const validation_node = createBootNode(gpa, io, isolated_options, selected) catch |err| {
            std.debug.print("registry node: cannot validate trusted pending history against the local journal ({t}): {s}\n", .{ err, diag.message() });
            return 1;
        };
        defer validation_node.deinit();

        writeSnapshotFile(io, dir, gpa, &selected.state) catch |err| {
            std.debug.print("registry node: cannot install trusted pending history in {s}/snapshot: {t}; stopping\n", .{ data_dir, err });
            return 1;
        };
        history_archive.?.confirmInstalled(&selected.state) catch |err| {
            std.debug.print("registry node: cannot confirm trusted pending history slot {d}: {t}; keep this node stopped\n", .{ selected.state.head.slot, err });
            return 1;
        };
        var installed = drainBootReplay(validation_node, gpa, &selected.state, &history_archive.?) catch |err| {
            if (err == error.NodeHalted) {
                std.debug.print("registry node: halted while validating trusted pending history against the local journal; see the log above\n", .{});
            } else {
                std.debug.print("registry node: the local journal does not continue trusted pending history slot {d} one slot at a time ({t}); keep this node stopped\n", .{ selected.state.head.slot, err });
            }
            return 1;
        };
        defer installed.deinit(gpa);
        if (installed.head.slot > selected.state.head.slot) {
            writeSnapshotFile(io, dir, gpa, &installed) catch |err| {
                std.debug.print("registry node: cannot install the journal continuation in {s}/snapshot: {t}; stopping\n", .{ data_dir, err });
                return 1;
            };
        }
        history_archive.?.confirmInstalled(&installed) catch |err| {
            std.debug.print("registry node: cannot preserve trusted boot provenance at journal slot {d}: {t}; keep this node stopped\n", .{ installed.head.slot, err });
            return 1;
        };
        std.debug.print("history install resumed from trusted outbox tip {d}\n", .{selected.state.head.slot});

        // Publication of any journal continuation is reconciled before the
        // second adoption, preserving one ordered outbox frontier. The old
        // selected state and the old recovery are freed as their
        // replacements take ownership.
        const latest = selectLatestHistoryBoot(
            &history_archive.?,
            gpa,
            nid,
            genesis_close_time,
            &installed,
            f.history_min_slot,
        ) catch |err| {
            std.debug.print("registry node: cannot reconcile or select final history after installing trusted slot {d} in {s}: {t}; keep this node stopped\n", .{ installed.head.slot, f.history_dir.?, err });
            return 1;
        };
        if (authenticated_recovery) |*old| old.deinit(gpa);
        authenticated_recovery = latest.recovery;
        selected.state.deinit(gpa);
        selected = latest.selected;
        pending_install = null;
    }

    const node = createBootNode(gpa, io, node_options, selected) catch |err| {
        std.debug.print("registry node: cannot start ({t}): {s}\n", .{ err, diag.message() });
        return 1;
    };
    var node_needs_deinit = true;
    defer if (node_needs_deinit) node.deinit();

    // The generic Node retains no application payloads until the application
    // asks for one. Opt in before RPC admission or the cadence loop can race
    // with an already-connected peer's first transaction flood.
    if (node.raw().waitAppMessage(.{ .timeout_ms = 0 })) |message| {
        node.raw().allocator().free(message);
    }
    // A certified adoption remains explicitly pending until AppNode accepts
    // its recovery boundary and the exact selected state is also durable in
    // the ordinary snapshot. Only then may journal successors enter the
    // outbox; this makes every crash point choose either the old installed
    // state or the trusted adopted state, never an unrepresented middle.
    if (selected.source == .history or selected.source == .history_outbox) {
        writeSnapshotFile(io, dir, gpa, &selected.state) catch |err| {
            std.debug.print("registry node: cannot install recovered state in {s}/snapshot: {t}; stopping\n", .{ data_dir, err });
            return 1;
        };
    }
    if (history_archive) |*archive| {
        archive.confirmInstalled(&selected.state) catch |err| {
            std.debug.print("registry node: cannot confirm the selected history installation at slot {d}: {t}; keep this node stopped\n", .{ selected.state.head.slot, err });
            return 1;
        };
    }
    // Node recovery is synchronous, but AppNode exposes the resulting state
    // copies through its queue. Drain those copies before RPC can observe the
    // initial history/local snapshot. This closes the crash window where the
    // consensus journal is durably ahead of the application snapshot.
    const boot_history: ?*history.Archive = if (history_archive) |*archive| archive else null;
    const ready_state = drainBootReplay(node, gpa, &selected.state, boot_history) catch |err| {
        if (err == error.NodeHalted) {
            std.debug.print("registry node: halted while recovering the local journal; see the log above\n", .{});
        } else {
            std.debug.print("registry node: the recovered journal does not continue boot slot {d} one slot at a time ({t}); keep this node stopped\n", .{ selected.state.head.slot, err });
        }
        return 1;
    };
    const replayed_boot = ready_state.head.slot > selected.state.head.slot;

    // Only after AppNode accepts the recovered-state/start-slot pair and any local
    // continuation may the replacement snapshot become durable. A failed
    // create leaves prior state intact; a successful replay persists its
    // newest state, never the stale history anchor that preceded it.
    if (replayed_boot) {
        writeSnapshotFile(io, dir, gpa, &ready_state) catch |err| {
            std.debug.print("registry node: cannot install recovered state in {s}/snapshot: {t}; stopping\n", .{ data_dir, err });
            return 1;
        };
    }
    if (history_archive) |*archive| {
        archive.confirmInstalled(&ready_state) catch |err| {
            std.debug.print("registry node: cannot preserve trusted boot provenance at recovered slot {d}: {t}; keep this node stopped\n", .{ ready_state.head.slot, err });
            return 1;
        };
    }
    if (replayed_boot) {
        std.debug.print("registry node: local journal advanced boot state from slot {d} through slot {d} before RPC startup\n", .{ selected.state.head.slot, ready_state.head.slot });
    }
    if (selected.source == .history) {
        const recovered = authenticated_recovery orelse unreachable;
        std.debug.print("history replay anchor {d} through tip {d} ({d} ledgers)\n", .{
            recovered.anchor_slot,
            recovered.state.head.slot,
            recovered.replayed_ledgers,
        });
    } else if (selected.source == .history_outbox) {
        std.debug.print("history install resumed from trusted outbox tip {d}\n", .{selected.state.head.slot});
    }

    // Startup archive discovery and backlog reconciliation are synchronous.
    // The archive moves into the publisher only after every other fallible
    // startup gate: once its worker can enter hostile shared I/O, ordinary
    // error unwinding must never wait on an uninterruptible syscall.
    var history_publisher: ?*HistoryPublisher = null;
    defer {
        // A shared filesystem syscall may be uninterruptible. Stop consensus
        // and close its listener before waiting for that worker, so a process
        // reporting "stopping" can never remain a live validator merely
        // because publication cleanup is delayed.
        if (node_needs_deinit) {
            node.deinit();
            node_needs_deinit = false;
        }
        if (history_publisher) |publisher| publisher.deinit();
    }
    var publisher = GossipPublisher{ .node = node.raw() };
    var shared = rpc.Shared{ .io = io, .state = ready_state, .publisher = publisher.publisher() };
    const server = rpc.Server.start(gpa, io, &shared, rpc_port) catch |err| {
        std.debug.print("registry node: cannot bind the rpc port 127.0.0.1:{d}: {t}\n", .{ rpc_port, err });
        return 1;
    };
    defer server.stop();

    if (history_archive) |archive| {
        history_publisher = HistoryPublisher.start(gpa, io, archive) catch |err| {
            std.debug.print("registry node: cannot start the history publisher: {t}\n", .{err});
            return 1;
        };
        history_archive = null;
    }

    const boot_source = switch (selected.source) {
        .genesis => "genesis",
        .local_snapshot => "the snapshot",
        .history => "history replay",
        .history_outbox => "trusted history",
        .trusted_local => "a trusted local history frontier",
    };
    std.debug.print("registry: node {s} listening on port {d}; {d} peer(s); data in {s}; starting from {s} at slot {d} close_time={d}\n", .{
        &registry.hex32(kp.public_key), node.raw().boundPort(), f.peers.items.len, data_dir, boot_source, selected.state.head.slot, selected.state.head.close_time,
    });
    std.debug.print("registry: limits: {d} txs per set, {d} pending, unbounded accounts and names; busy slots every >= {d} ms, idle heartbeat every {d} ms\n", .{
        registry.max_txs, registry.max_pending, f.min_slot_ms, f.heartbeat_ms,
    });
    std.debug.print("registry: rpc listening on 127.0.0.1:{d}\n", .{server.port});
    if (f.history_dir) |archive_dir| {
        std.debug.print("registry: authenticated history in {s}; snapshot anchor every {d} slots; anti-rollback floor {d}\n", .{
            archive_dir, f.checkpoint_every, f.history_min_slot,
        });
    }

    // The cadence loop (§3.9): after every applied slot, refresh the shared
    // copy, prune the queue, persist, and propose once for the next slot —
    // right away when transactions are pending, else at the heartbeat.
    var last_close = nowMs(io);
    var proposed = false;
    // No per-peer retained-coverage signal explains whether a quiet node lacks
    // quorum or cannot obtain a missing slot. Say something every minute.
    var next_stall_warn = nowMs(io) + stall_warn_ms;
    var next_gossip_reflood = nowMs(io) + gossip_reflood_ms;
    while (true) {
        const item = node.waitApplied(.{ .timeout_ms = 100 }) catch |err| switch (err) {
            error.NodeHalted => {
                if (node.haltError()) |e| {
                    std.debug.print("registry node: the node halted: {t}; see the log above\n", .{e});
                } else {
                    std.debug.print("registry node: the node halted; see the log above\n", .{});
                }
                stopNodeAndExit(server, node, &node_needs_deinit, 1);
            },
        };
        if (history_publisher) |history_worker| {
            if (history_worker.fatalFailure()) |failure| {
                std.debug.print("registry node: refusing unsafe history publication for slot {d}: {t}; stopping\n", .{ failure.slot, failure.err });
                stopNodeAndExit(server, node, &node_needs_deinit, 1);
            }
        }
        if (item) |a| {
            if (a.slot != a.obs.head.slot) {
                // The native node abandoned a delivery gap under its local
                // slot horizon (roadmap §2.1 gap 2): `apply` skipped the set
                // (it does not fit this state) and the header stayed put.
                // Stop at once — `exit`, not a return through `deinit`, so
                // the engine thread applies nothing more meanwhile.
                if (f.history_dir != null) {
                    std.debug.print("registry node: applied slot {d} but the state's header is at slot {d}: its local answering horizon expired before it obtained the missing slots from reachable peers. Exiting with code 3; restart from a certified history tip at or beyond the gap.\n", .{ a.slot, a.obs.head.slot });
                } else {
                    std.debug.print("registry node: applied slot {d} but the state's header is at slot {d}: its local answering horizon expired before it obtained the missing slots from reachable peers. Exiting with code 3; configure authenticated history or rejoin only when the whole network starts over.\n", .{ a.slot, a.obs.head.slot });
                }
                std.process.exit(3);
            }
            // In history mode the trusted, ordered outbox is the first
            // application-level durable write after AppNode's journal. A
            // crash before the ordinary snapshot is repaired by journal
            // replay, while a crash afterward can never erase this ledger
            // from the publication backlog.
            if (history_publisher) |history_worker| {
                history_worker.offer(a.obs) catch |err| {
                    std.debug.print("registry node: cannot durably stage history ledger slot {d}: {t}; stopping before history can skip a ledger\n", .{ a.slot, err });
                    stopNodeAndExit(server, node, &node_needs_deinit, 1);
                };
            }
            writeSnapshotFile(io, dir, gpa, &a.obs) catch |err| {
                std.debug.print("registry node: cannot write {s}/snapshot: {t}; stopping (a node that cannot persist must stop)\n", .{ data_dir, err });
                stopNodeAndExit(server, node, &node_needs_deinit, 1);
            };
            if (history_publisher) |history_worker| {
                history_worker.confirmSnapshot(&a.obs) catch |err| {
                    std.debug.print("registry node: cannot preserve trusted boot provenance at slot {d}: {t}; stopping\n", .{ a.slot, err });
                    stopNodeAndExit(server, node, &node_needs_deinit, 1);
                };
            }
            // RPC only observes the new head once both application durability
            // barriers above have completed.
            shared.lock();
            shared.state = a.obs;
            shared.prune();
            shared.unlock();
            var ok: usize = 0;
            for (a.obs.lastResults()) |r| {
                if (r == .ok) ok += 1;
            }
            const head_hex = registry.hex32(a.obs.head.hash);
            std.debug.print("slot {d}: close_time={d} txs={d} ok={d} head={s}\n", .{ a.slot, a.obs.head.close_time, a.obs.last_count, ok, head_hex[0..16] });
            last_close = nowMs(io);
            next_stall_warn = last_close + stall_warn_ms;
            proposed = false;
        }

        // Keep hostile or simply busy peers from starving application and
        // consensus progress: each tick consumes at most 64 owned messages.
        // Shared.admit is the same trust boundary used by localhost RPC.
        for (0..gossip_drain_per_tick) |_| {
            const message = node.raw().waitAppMessage(.{ .timeout_ms = 0 }) orelse break;
            defer node.raw().allocator().free(message);
            _ = shared.admit(message);
        }

        const now = nowMs(io);
        if (now >= next_gossip_reflood) {
            _ = shared.refloodPending();
            next_gossip_reflood = now + gossip_reflood_ms;
        }
        if (now >= next_stall_warn) {
            if (f.history_dir != null) {
                std.debug.print("registry node: no slot applied for {d} s — either the network has no quorum, or needed retained statements are not arriving from reachable peers; in the latter case restart this process after a certified history tip covering the gap is available\n", .{(nowMs(io) -| last_close) / 1000});
            } else {
                std.debug.print("registry node: no slot applied for {d} s — either the network has no quorum, or needed retained statements are not arriving from reachable peers; configure authenticated history for long-outage recovery, or use a fresh --data-dir only when the whole network starts over\n", .{(nowMs(io) -| last_close) / 1000});
            }
            next_stall_warn = now + stall_warn_ms;
        }
        if (!proposed) {
            const since = now -| last_close;
            var value: ?registry.LedgerValue = null;
            shared.lock();
            if (registry.nominationDue(shared.n_pending > 0, since, f.min_slot_ms, f.heartbeat_ms)) {
                const proposal_time = shiftedWallSeconds(wallSeconds(io), f.proposal_clock_offset_s);
                value = registry.proposal(&shared.state, shared.pendingSlice(), proposal_time);
            }
            shared.unlock();
            if (value) |v| {
                node.propose(v) catch |err| {
                    std.debug.print("registry node: propose failed: {t}\n", .{err});
                };
                proposed = true;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// registry submit
// ---------------------------------------------------------------------------

/// The message and exit code for a client verb whose RPC request failed:
/// a malformed `--rpc` is a usage error (2), an unreachable node is 1.
fn rpcFailure(verb: []const u8, spec: []const u8, err: anyerror) u8 {
    if (err == error.BadRpcSpec) {
        std.debug.print("registry {s}: --rpc must be ip:port — an IPv4 or IPv6 literal with a port, not a hostname (got {s})\n", .{ verb, spec });
        return 2;
    }
    std.debug.print("registry {s}: cannot reach the node at {s}: {t}\n", .{ verb, spec, err });
    return 1;
}

fn runSubmit(init: std.process.Init, args: []const []const u8, out: *std.Io.Writer) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    var f = flagsOrUsage(gpa, args, false) orelse return 2;
    defer f.deinit(gpa);
    const key_path = f.key orelse return usageError("--key is required");
    const pos = f.positional.items;
    if (pos.len < 2) return usageError("submit needs an operation and a name");
    const op: registry.Op = if (eql(pos[0], "claim")) .claim else if (eql(pos[0], "set")) .set else if (eql(pos[0], "transfer")) .transfer else if (eql(pos[0], "release")) .release else return usageError("operation must be claim | set | transfer | release");
    const name = pos[1];
    var value: []const u8 = "";
    var to: registry.Key = registry.zero_key;
    switch (op) {
        .set => {
            if (pos.len != 3) return usageError("set <name> <value>");
            value = pos[2];
        },
        .transfer => {
            if (pos.len != 3) return usageError("transfer <name> <hex64>");
            to = registry.parseKey(pos[2]) orelse return usageError("the transfer target must be a 64-hex public key");
        },
        .claim, .release => if (pos.len != 2) return usageError("claim/release take only a name"),
    }

    const kp = slcp.keys.load(io, key_path) catch |err| {
        std.debug.print("registry submit: cannot load --key {s}: {t}\n", .{ key_path, err });
        return 1;
    };

    // The node tells us the network id and the next seq for this key.
    var buf: [rpc.max_line]u8 = undefined;
    const head = rpc.request(io, f.rpc, "head", &buf) catch |err| return rpcFailure("submit", f.rpc, err);
    const nid = registry.parseKey(rpc.field(head, "network") orelse "") orelse {
        std.debug.print("registry submit: unexpected head reply: {s}\n", .{head});
        return 1;
    };
    var line_buf: [rpc.max_line]u8 = undefined;
    const acct_req = try std.fmt.bufPrint(&line_buf, "account {s}", .{&registry.hex32(kp.public_key)});
    const acct = rpc.request(io, f.rpc, acct_req, &buf) catch |err| return rpcFailure("submit", f.rpc, err);
    const next = std.fmt.parseInt(u64, rpc.field(acct, "next") orelse "", 10) catch {
        std.debug.print("registry submit: unexpected account reply: {s}\n", .{acct});
        return 1;
    };

    var tx = registry.Tx.init(kp.public_key, next, op, name, value, to) orelse
        return usageError("bad name or value (names are [a-z0-9-], 1..32 bytes; values up to 64 bytes)");
    tx.sign(kp.seed, nid) catch |err| {
        std.debug.print("registry submit: cannot sign: {t}\n", .{err});
        return 1;
    };
    var enc: [registry.tx_bytes]u8 = undefined;
    tx.encode(&enc);
    const hex = std.fmt.bytesToHex(enc, .lower);
    const req = try std.fmt.bufPrint(&line_buf, "submit {s}", .{&hex});
    const resp = rpc.request(io, f.rpc, req, &buf) catch |err| return rpcFailure("submit", f.rpc, err);
    try out.print("{s}\n", .{resp});
    return if (std.mem.startsWith(u8, resp, "ok")) 0 else 1;
}

// ---------------------------------------------------------------------------
// registry get | account | head
// ---------------------------------------------------------------------------

fn runQuery(init: std.process.Init, verb: []const u8, args: []const []const u8, out: *std.Io.Writer) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    var f = flagsOrUsage(gpa, args, false) orelse return 2;
    defer f.deinit(gpa);
    const pos = f.positional.items;
    var line_buf: [rpc.max_line]u8 = undefined;
    const req = if (eql(verb, "head")) blk: {
        if (pos.len != 0) return usageError("head takes no argument");
        break :blk "head";
    } else blk: {
        if (pos.len != 1) return usageError(if (eql(verb, "get")) "get <name>" else "account <hex64>");
        break :blk try std.fmt.bufPrint(&line_buf, "{s} {s}", .{ verb, pos[0] });
    };
    var buf: [rpc.max_line]u8 = undefined;
    const resp = rpc.request(io, f.rpc, req, &buf) catch |err| return rpcFailure(verb, f.rpc, err);
    try out.print("{s}\n", .{resp});
    return if (std.mem.startsWith(u8, resp, "err")) 1 else 0;
}

test {
    _ = app;
}

const testing = std.testing;
const test_genesis_close_time: u64 = 1_700_000_000;

fn testNetworkId(passphrase: []const u8) [32]u8 {
    return registry.networkId(passphrase, test_genesis_close_time);
}

fn testGenesis(passphrase: []const u8, gpa: std.mem.Allocator) !registry.State {
    return registry.State.genesis(testNetworkId(passphrase), test_genesis_close_time, gpa);
}

fn advanceEmpty(state: *registry.State, gpa: std.mem.Allocator) !void {
    const value = registry.proposal(state, &.{}, state.head.close_time + 1).?;
    try registry.apply(state, &value, gpa);
}

test "registry main: history snapshot cadence has a bounded replay span" {
    var parsed = try parseFlags(testing.allocator, &.{
        "--genesis-close-time",      "1700000000",
        "--proposal-clock-offset-s", "-30",
        "--history-dir",             "/shared/history",
        "--checkpoint-every",        "64",
        "--history-min-slot",        "240",
    }, true);
    defer parsed.deinit(testing.allocator);
    try testing.expectEqualStrings("/shared/history", parsed.history_dir.?);
    try testing.expectEqual(test_genesis_close_time, parsed.genesis_close_time.?);
    try testing.expectEqual(@as(i64, -30), parsed.proposal_clock_offset_s);
    try testing.expectEqual(@as(u64, 64), parsed.checkpoint_every);
    try testing.expectEqual(@as(u64, 240), parsed.history_min_slot);

    try testing.expectError(error.BadCheckpointInterval, parseFlags(testing.allocator, &.{ "--checkpoint-every", "0" }, true));
    try testing.expectError(error.BadCheckpointInterval, parseFlags(testing.allocator, &.{ "--checkpoint-every", "65" }, true));
    try testing.expectError(error.BadSlot, parseFlags(testing.allocator, &.{ "--history-min-slot", "not-a-slot" }, true));
    try testing.expectError(error.BadGenesisCloseTime, parseFlags(testing.allocator, &.{ "--genesis-close-time", "18446744073709551615" }, true));
    try testing.expectError(error.BadClockOffset, parseFlags(testing.allocator, &.{ "--proposal-clock-offset-s", "fast" }, true));
    try testing.expectError(error.EmptyNetwork, parseFlags(testing.allocator, &.{ "--network", "" }, true));
}

test "registry main: proposal clock offsets saturate without affecting cadence time" {
    try testing.expectEqual(@as(u64, 70), shiftedWallSeconds(100, -30));
    try testing.expectEqual(@as(u64, 0), shiftedWallSeconds(10, -30));
    try testing.expectEqual(std.math.maxInt(u64), shiftedWallSeconds(std.math.maxInt(u64) - 5, 30));
}

test "registry main: boot selection prefers authenticated history and treats its floor as absolute" {
    const gpa = testing.allocator;
    const nid = testNetworkId("registry main history selection");
    var local: registry.State = .{ .network_id = nid };
    local.head.slot = 10;
    local.head.close_time = test_genesis_close_time + 10;
    local.head.hash = @splat(0x10);
    var checkpoint = local;
    checkpoint.head.slot = 11;
    checkpoint.head.close_time = test_genesis_close_time + 11;
    checkpoint.head.hash = @splat(0x11);

    const newer = try selectBootState(gpa, nid, test_genesis_close_time, local, checkpoint, 0);
    try testing.expectEqual(BootSource.history, newer.source);
    try testing.expectEqual(@as(u64, 12), newer.start_slot);

    const local_newer = try selectBootState(gpa, nid, test_genesis_close_time, checkpoint, local, 0);
    try testing.expectEqual(BootSource.local_snapshot, local_newer.source);
    try testing.expectEqual(@as(u64, 1), local_newer.start_slot);

    const equal = try selectBootState(gpa, nid, test_genesis_close_time, checkpoint, checkpoint, checkpoint.head.slot);
    try testing.expectEqual(BootSource.history, equal.source);
    try testing.expectEqual(@as(u64, 12), equal.start_slot);

    var fork = checkpoint;
    fork.head.hash = @splat(0xff);
    try testing.expectError(error.HistoryCheckpointConflict, selectBootState(gpa, nid, test_genesis_close_time, checkpoint, fork, 0));
    try testing.expectError(error.HistoryFloorUnavailable, selectBootState(gpa, nid, test_genesis_close_time, local, null, 11));
}

test "registry main: pending history install outranks a newer shared tip before floor enforcement" {
    const gpa = testing.allocator;
    const nid = testNetworkId("registry main pending install selection");
    var local: registry.State = .{ .network_id = nid };
    local.head.slot = 5;
    local.head.close_time = test_genesis_close_time + 5;
    local.head.hash = @splat(0x05);
    var pending = local;
    pending.head.slot = 7;
    pending.head.close_time = test_genesis_close_time + 7;
    pending.head.hash = @splat(0x07);
    var shared = pending;
    shared.head.slot = 9;
    shared.head.close_time = test_genesis_close_time + 9;
    shared.head.hash = @splat(0x09);

    const selected = try selectHistoryBootState(
        gpa,
        nid,
        test_genesis_close_time,
        local,
        shared,
        pending,
        6,
    );
    try testing.expectEqual(BootSource.history_outbox, selected.source);
    try testing.expectEqual(@as(u64, 7), selected.state.head.slot);
    try testing.expectEqual(@as(u64, 8), selected.start_slot);

    // The operator cannot silently skip an unfinished trusted install even
    // when mutable shared storage currently advertises a newer certificate.
    try testing.expectError(error.HistoryFloorUnavailable, selectHistoryBootState(
        gpa,
        nid,
        test_genesis_close_time,
        local,
        shared,
        pending,
        8,
    ));
}

test "registry main: fresh history activation does not grant external boot provenance" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buf[0..try tmp.dir.realPath(io, &root_buf)];
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    var journal_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try std.fmt.bufPrint(&archive_buf, "{s}/archive", .{root});
    const signing_path = try std.fmt.bufPrint(&signing_buf, "{s}/signing", .{root});
    const journal_path = try std.fmt.bufPrint(&journal_buf, "{s}/empty-journal", .{root});
    const seed: [32]u8 = @splat(0xe0);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_name = "registry fresh history activation provenance";
    const network_id = testNetworkId(network_name);
    var archive = try history.Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 8,
    });
    defer archive.deinit();

    var local = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    for (0..7) |_| try advanceEmpty(&local, gpa);
    var selected: BootSelection = .{
        .state = local,
        .source = .local_snapshot,
        .start_slot = 1,
    };
    try prepareHistoryBoot(&archive, &selected);
    try testing.expectEqual(BootSource.local_snapshot, selected.source);
    try testing.expectEqual(@as(u64, 1), selected.start_slot);
    try testing.expect(!try archive.hasTrustedBootProvenance(&local));

    var descriptor_buf: [160]u8 = undefined;
    const descriptor = registry.networkDescriptor(
        test_genesis_close_time,
        network_name,
        &descriptor_buf,
    );
    var diag: slcp.node.Diagnostic = .{};
    try testing.expectError(error.InitialSlotOutsideJournal, createBootNode(gpa, io, .{
        .network = descriptor,
        .secret_seed = seed,
        .listen_port = 0,
        .peers = &.{},
        .quorum = slcp.Quorum.of(1, &.{id}),
        .include_self = false,
        .data_dir = journal_path,
        .max_value_bytes = registry.max_value_bytes,
        .diagnostic = &diag,
    }, selected));
}

test "registry main: confirmed pending install is followed by fresh recovery before network boot" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buf[0..try tmp.dir.realPath(io, &root_buf)];
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var sign_a_buf: [std.fs.max_path_bytes]u8 = undefined;
    var sign_b_buf: [std.fs.max_path_bytes]u8 = undefined;
    var sign_c_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try std.fmt.bufPrint(&archive_buf, "{s}/archive", .{root});
    const sign_a = try std.fmt.bufPrint(&sign_a_buf, "{s}/sign-a", .{root});
    const sign_b = try std.fmt.bufPrint(&sign_b_buf, "{s}/sign-b", .{root});
    const sign_c = try std.fmt.bufPrint(&sign_c_buf, "{s}/sign-c", .{root});
    const seeds = [3][32]u8{ @splat(0xe1), @splat(0xe2), @splat(0xe3) };
    const ids = [3]slcp.NodeId{
        try slcp.core.crypto.publicKeyFromSeed(seeds[0]),
        try slcp.core.crypto.publicKeyFromSeed(seeds[1]),
        try slcp.core.crypto.publicKeyFromSeed(seeds[2]),
    };
    const network_name = "registry two-phase history startup";
    const network_id = testNetworkId(network_name);
    const config_a: history.Config = .{
        .archive_dir = archive_path,
        .signing_dir = sign_a,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(2, &ids),
        .signer_seed = seeds[0],
        .checkpoint_every = 8,
    };
    var config_b = config_a;
    config_b.signing_dir = sign_b;
    config_b.signer_seed = seeds[1];
    var config_c = config_a;
    config_c.signing_dir = sign_c;
    config_c.signer_seed = seeds[2];
    const genesis = try registry.State.genesis(network_id, test_genesis_close_time, gpa);

    // Initialize A's private outbox at the old local snapshot frontier.
    {
        var a = try history.Archive.open(gpa, io, config_a);
        defer a.deinit();
        try a.prepareFrontier(&genesis);
    }

    const Publisher = struct {
        fn publish(archive: *history.Archive, state: *const registry.State) !void {
            try archive.stageApplied(state);
            const staged = (try archive.nextStaged()) orelse
                return error.ExpectedStagedHistory;
            _ = try publishStagedHistory(archive, &staged);
        }
    };
    var b = try history.Archive.open(gpa, io, config_b);
    defer b.deinit();
    var c = try history.Archive.open(gpa, io, config_c);
    defer c.deinit();
    try b.prepareFrontier(&genesis);
    try c.prepareFrontier(&genesis);

    // Two independent validators certify T at slot 7.
    var remote = genesis;
    for (0..7) |_| {
        try advanceEmpty(&remote, gpa);
        try Publisher.publish(&b, &remote);
        try Publisher.publish(&c, &remote);
    }
    const expected_t = remote;

    // A adopts T, then crashes before the ordinary snapshot transaction.
    {
        var a = try history.Archive.open(gpa, io, config_a);
        defer a.deinit();
        try a.prepareFrontier(&genesis);
        const recovered_t = (try a.recoverLatest(expected_t.head.slot)) orelse
            return error.ExpectedCertifiedHistory;
        try testing.expectEqual(expected_t.head.slot, recovered_t.state.head.slot);
        try testing.expectEqualSlices(u8, &expected_t.head.hash, &recovered_t.state.head.hash);
        try a.prepareFrontier(&recovered_t.state);
        try testing.expectEqual(expected_t.head.slot, (try a.pendingInstall()).?.head.slot);
    }

    // While A is stopped, shared history advances more than two full cadence
    // intervals beyond T. This models a tip beyond this binary's default live
    // answering window.
    for (7..40) |_| {
        try advanceEmpty(&remote, gpa);
        try Publisher.publish(&b, &remote);
        try Publisher.publish(&c, &remote);
    }
    const expected_u = remote;

    // Restart first selects and durably installs the trusted T, never the
    // newer mutable shared tip. Crash once more before confirmation.
    {
        var a = try history.Archive.open(gpa, io, config_a);
        defer a.deinit();
        try a.prepareFrontier(&genesis);
        const pending_t = (try a.pendingInstall()) orelse
            return error.ExpectedPendingHistoryInstall;
        var first = try selectHistoryBootState(
            gpa,
            network_id,
            test_genesis_close_time,
            genesis,
            expected_u,
            pending_t,
            5,
        );
        try prepareHistoryBoot(&a, &first);
        try testing.expectEqual(BootSource.history_outbox, first.source);
        try testing.expectEqual(expected_t.head.slot, first.state.head.slot);
        try writeSnapshotFile(io, tmp.dir, gpa, &first.state);
    }

    const installed_t = (try readSnapshotFile(io, tmp.dir, gpa)) orelse
        return error.SnapshotMissing;
    try testing.expectEqual(expected_t.head.slot, installed_t.head.slot);
    try testing.expectEqualSlices(u8, &expected_t.head.hash, &installed_t.head.hash);

    // The marker survives the snapshot-before-confirm crash. Confirm T, then
    // crash at the other edge of that transaction before consulting shared
    // history again.
    {
        var a = try history.Archive.open(gpa, io, config_a);
        defer a.deinit();
        try a.prepareFrontier(&installed_t);
        try testing.expectEqual(expected_t.head.slot, (try a.pendingInstall()).?.head.slot);
        try a.confirmInstalled(&installed_t);
        try testing.expect((try a.pendingInstall()) == null);
    }

    // Withhold the mutable latest pointers after T commits. The fallback must
    // retain authenticated-history provenance and its exact T+1 handoff; an
    // empty local journal is allowed to accept that externally proved state.
    var latest_b_name_buf: [96]u8 = undefined;
    var latest_c_name_buf: [96]u8 = undefined;
    const latest_b_name = try std.fmt.bufPrint(&latest_b_name_buf, "{s}.vote", .{&registry.hex32(ids[1])});
    const latest_c_name = try std.fmt.bufPrint(&latest_c_name_buf, "{s}.vote", .{&registry.hex32(ids[2])});
    var latest_dir_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const latest_dir_path = try std.fmt.bufPrint(
        &latest_dir_path_buf,
        "archive/{s}/history-v1/latest",
        .{&registry.hex32(network_id)},
    );
    const latest_dir = try tmp.dir.openDir(io, latest_dir_path, .{});
    defer latest_dir.close(io);
    const latest_b_bytes = try latest_dir.readFileAlloc(io, latest_b_name, gpa, .limited(4 * 1024));
    defer gpa.free(latest_b_bytes);
    const latest_c_bytes = try latest_dir.readFileAlloc(io, latest_c_name, gpa, .limited(4 * 1024));
    defer gpa.free(latest_c_bytes);
    try latest_dir.deleteFile(io, latest_b_name);
    try latest_dir.deleteFile(io, latest_c_name);
    {
        var a = try history.Archive.open(gpa, io, config_a);
        defer a.deinit();
        try a.prepareFrontier(&installed_t);
        const withheld = try selectLatestHistoryBoot(
            &a,
            gpa,
            network_id,
            test_genesis_close_time,
            &installed_t,
            5,
        );
        try testing.expect(withheld.recovery == null);
        try testing.expectEqual(BootSource.trusted_local, withheld.selected.source);
        try testing.expectEqual(installed_t.head.slot, withheld.selected.state.head.slot);
        try testing.expectEqual(installed_t.head.slot + 1, withheld.selected.start_slot);

        var descriptor_buf: [128]u8 = undefined;
        const descriptor = registry.networkDescriptor(
            test_genesis_close_time,
            network_name,
            &descriptor_buf,
        );
        var empty_journal_buf: [std.fs.max_path_bytes]u8 = undefined;
        const empty_journal_path = try std.fmt.bufPrint(&empty_journal_buf, "{s}/empty-journal", .{root});
        var diag: slcp.node.Diagnostic = .{};
        const validation_node = try createBootNode(gpa, io, .{
            .network = descriptor,
            .secret_seed = seeds[0],
            .listen_port = 0,
            .peers = &.{},
            .quorum = slcp.Quorum.of(2, &ids),
            .include_self = false,
            .data_dir = empty_journal_path,
            .max_value_bytes = registry.max_value_bytes,
            .diagnostic = &diag,
        }, withheld.selected);
        validation_node.deinit();
    }

    // Make the same certified U discoverable again. The next call must not
    // cache the previous absence: it performs a genuinely fresh recovery.
    try latest_dir.writeFile(io, .{ .sub_path = latest_b_name, .data = latest_b_bytes });
    try latest_dir.writeFile(io, .{ .sub_path = latest_c_name, .data = latest_c_bytes });

    var final_selection: BootSelection = undefined;
    {
        var a = try history.Archive.open(gpa, io, config_a);
        defer a.deinit();
        try a.prepareFrontier(&installed_t);
        try testing.expect((try a.pendingInstall()) == null);

        // This is the pre-network startup seam: after T is confirmed it must
        // perform a new shared recovery, select U, and prepare U's own durable
        // install marker before the real peer-bearing AppNode is constructed.
        const latest = try selectLatestHistoryBoot(
            &a,
            gpa,
            network_id,
            test_genesis_close_time,
            &installed_t,
            5,
        );
        final_selection = latest.selected;
        try testing.expect(latest.recovery != null);
        try testing.expectEqual(BootSource.history, final_selection.source);
        try testing.expectEqual(expected_u.head.slot, final_selection.state.head.slot);
        try testing.expectEqualSlices(u8, &expected_u.head.hash, &final_selection.state.head.hash);
        try testing.expectEqual(expected_u.head.slot + 1, final_selection.start_slot);
        try testing.expectEqual(expected_u.head.slot, (try a.pendingInstall()).?.head.slot);
    }

    // A crash after choosing U but before its ordinary snapshot is also
    // recoverable solely from the trusted marker installed by the seam.
    {
        var a = try history.Archive.open(gpa, io, config_a);
        defer a.deinit();
        try a.prepareFrontier(&installed_t);
        const pending_u = (try a.pendingInstall()) orelse
            return error.ExpectedPendingHistoryInstall;
        try testing.expectEqual(final_selection.state.head.slot, pending_u.head.slot);
        try testing.expectEqualSlices(u8, &final_selection.state.head.hash, &pending_u.head.hash);
        try writeSnapshotFile(io, tmp.dir, gpa, &pending_u);
        try a.confirmInstalled(&pending_u);
        try testing.expect((try a.pendingInstall()) == null);
    }

    const installed_u = (try readSnapshotFile(io, tmp.dir, gpa)) orelse
        return error.SnapshotMissing;
    try testing.expectEqual(expected_u.head.slot, installed_u.head.slot);
    try testing.expectEqualSlices(u8, &expected_u.head.hash, &installed_u.head.hash);
}

test "registry main: boot selection rejects a local genesis from a different close-time epoch" {
    const gpa = testing.allocator;
    const nid = testNetworkId("registry main local genesis epoch");
    const wrong_genesis = try registry.State.genesis(nid, test_genesis_close_time + 1, gpa);
    try testing.expectError(
        error.SnapshotWrongGenesisCloseTime,
        selectBootState(gpa, nid, test_genesis_close_time, wrong_genesis, null, 0),
    );
}

test "registry main: boot selection rejects history outside the cumulative close-time epoch" {
    const gpa = testing.allocator;
    const nid = testNetworkId("registry main history close-time epoch");
    var checkpoint = try registry.State.genesis(nid, test_genesis_close_time, gpa);
    checkpoint.head.slot = 2;
    checkpoint.head.close_time = test_genesis_close_time + 1;
    try testing.expectError(
        error.HistoryCheckpointWrongGenesisCloseTime,
        selectBootState(gpa, nid, test_genesis_close_time, null, checkpoint, 0),
    );
}

test "registry main: a history-free empty boot preserves genesis behavior" {
    const gpa = testing.allocator;
    const nid = testNetworkId("registry main genesis selection");
    const selected = try selectBootState(gpa, nid, test_genesis_close_time, null, null, 0);
    try testing.expectEqual(BootSource.genesis, selected.source);
    try testing.expectEqual(@as(u64, 0), selected.state.head.slot);
    try testing.expectEqual(@as(u64, 1), selected.start_slot);
    try testing.expectEqualSlices(u8, &nid, &selected.state.network_id);
    try testing.expectEqual(test_genesis_close_time, selected.state.head.close_time);
    try testing.expectEqualSlices(u8, &registry.headerHash(nid, &selected.state.head), &selected.state.head.hash);
}

test "registry main: a missing snapshot cannot replay a compacted journal" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];
    const network = "registry main compacted journal without snapshot";
    const network_id = testNetworkId(network);
    var descriptor_buf: [128]u8 = undefined;
    const descriptor = registry.networkDescriptor(test_genesis_close_time, network, &descriptor_buf);
    const seed: [32]u8 = @splat(0xb1);
    const id = try registry.publicKeyOf(seed);
    var diag: slcp.node.Diagnostic = .{};

    var encoded_buf: [registry.max_ledger_value_bytes]u8 = undefined;
    const encoded = (registry.LedgerValue{
        .close_time = test_genesis_close_time + 49,
        .txs = .empty,
    }).encode(&encoded_buf);
    {
        var store = try slcp.store.Store.open(gpa, io, data_dir);
        defer store.deinit();
        try store.appendExternalized(49, encoded);
    }

    const boot_state = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    if (app.Node.create(gpa, io, .{
        .network = descriptor,
        .secret_seed = seed,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .include_self = false,
        .listen_port = 0,
        .data_dir = data_dir,
        .max_value_bytes = registry.max_value_bytes,
        .diagnostic = &diag,
    }, boot_state)) |node| {
        node.deinit();
        return error.ExpectedCompactedJournalRejection;
    } else |err| {
        try testing.expectEqual(error.InitialSlotOutsideJournal, err);
        try testing.expect(std.mem.indexOf(u8, diag.message(), "slots 49..49") != null);
        try testing.expect(std.mem.indexOf(u8, diag.message(), "did not go live") != null);
    }
}

test "registry main: the E2c descriptor rejects a pre-E2c data directory" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var data_dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = data_dir_buf[0..try tmp.dir.realPath(io, &data_dir_buf)];
    const network = "registry main hard epoch";
    const network_id = testNetworkId(network);
    var descriptor_buf: [128]u8 = undefined;
    const descriptor = registry.networkDescriptor(test_genesis_close_time, network, &descriptor_buf);
    const seed: [32]u8 = @splat(0xb2);
    const id = try registry.publicKeyOf(seed);
    var diag: slcp.node.Diagnostic = .{};
    const boot_state = try registry.State.genesis(network_id, test_genesis_close_time, gpa);

    // The legacy registry passed the human passphrase directly to Node.
    const legacy = try app.Node.create(gpa, io, .{
        .network = network,
        .secret_seed = seed,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .include_self = false,
        .listen_port = 0,
        .data_dir = data_dir,
        .max_value_bytes = registry.max_value_bytes,
        .diagnostic = &diag,
    }, boot_state);
    legacy.deinit();

    if (app.Node.create(gpa, io, .{
        .network = descriptor,
        .secret_seed = seed,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .include_self = false,
        .listen_port = 0,
        .data_dir = data_dir,
        .max_value_bytes = registry.max_value_bytes,
        .diagnostic = &diag,
    }, boot_state)) |unexpected| {
        unexpected.deinit();
        return error.ExpectedHardNetworkEpoch;
    } else |err| try testing.expectEqual(error.DataDirOtherNetwork, err);
}

test "registry main: a legacy transaction-set journal fails closed if the network guard is bypassed" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var data_dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = data_dir_buf[0..try tmp.dir.realPath(io, &data_dir_buf)];
    const network = "registry main legacy journal";
    const network_id = testNetworkId(network);
    var descriptor_buf: [128]u8 = undefined;
    const descriptor = registry.networkDescriptor(test_genesis_close_time, network, &descriptor_buf);
    const seed: [32]u8 = @splat(0xb3);
    const id = try registry.publicKeyOf(seed);
    var diag: slcp.node.Diagnostic = .{};
    const boot_state = try registry.State.genesis(network_id, test_genesis_close_time, gpa);

    // Establish current network identity, then inject bytes written by the
    // pre-E2c TxSet codec to isolate the value-format migration check.
    const current = try app.Node.create(gpa, io, .{
        .network = descriptor,
        .secret_seed = seed,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .include_self = false,
        .listen_port = 0,
        .data_dir = data_dir,
        .max_value_bytes = registry.max_value_bytes,
        .diagnostic = &diag,
    }, boot_state);
    current.deinit();
    var old_buf: [registry.max_set_bytes]u8 = undefined;
    {
        var store = try slcp.store.Store.open(gpa, io, data_dir);
        defer store.deinit();
        try store.appendExternalized(1, registry.TxSet.empty.encode(&old_buf));
    }

    try testing.expectError(error.UndecodableExternalizedValue, app.Node.create(gpa, io, .{
        .network = descriptor,
        .secret_seed = seed,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .include_self = false,
        .listen_port = 0,
        .data_dir = data_dir,
        .max_value_bytes = registry.max_value_bytes,
        .diagnostic = &diag,
    }, boot_state));
}

test "registry main: snapshot replacement does not follow a planted temp or final symlink" {
    const gpa = testing.allocator;
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var outside = try tmp.dir.createFile(io, "outside", .{});
    try outside.writeStreamingAll(io, "sentinel");
    outside.close(io);
    try tmp.dir.symLink(io, "outside", "snapshot", .{});
    // The old implementation used this predictable name and would truncate
    // its target before the rename.
    try tmp.dir.symLink(io, "outside", "snapshot.tmp", .{});

    var state = try testGenesis("registry main snapshot atomic", gpa);
    try advanceEmpty(&state, gpa);
    try writeSnapshotFile(io, tmp.dir, gpa, &state);

    const sentinel = try tmp.dir.readFileAlloc(io, "outside", testing.allocator, .limited(32));
    defer testing.allocator.free(sentinel);
    try testing.expectEqualStrings("sentinel", sentinel);
    try testing.expectEqual(std.Io.File.Kind.file, (try tmp.dir.statFile(io, "snapshot", .{ .follow_symlinks = false })).kind);
    const restored = (try readSnapshotFile(io, tmp.dir, testing.allocator)).?;
    try testing.expectEqualSlices(u8, &state.head.hash, &restored.head.hash);
}

const DataDirSyncProbe = struct {
    var calls: usize = 0;
    var fail: bool = false;

    fn sync(dir: std.Io.Dir) !void {
        calls += 1;
        if (fail) return error.InjectedDirectorySyncFailure;
        try syncDirectory(dir);
    }
};

test "registry main: history data-dir creation is fenced in its existing parent" {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "parent");
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buf[0..try tmp.dir.realPath(io, &root_buf)];
    var data_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_path = try std.fmt.bufPrint(&data_buf, "{s}/parent/node", .{root});

    DataDirSyncProbe.calls = 0;
    DataDirSyncProbe.fail = true;
    try testing.expectError(error.InjectedDirectorySyncFailure, openDurableDataDir(io, data_path, DataDirSyncProbe.sync));
    try testing.expectEqual(@as(usize, 1), DataDirSyncProbe.calls);

    DataDirSyncProbe.fail = false;
    const dir = try openDurableDataDir(io, data_path, DataDirSyncProbe.sync);
    defer dir.close(io);
    try testing.expectEqual(@as(usize, 2), DataDirSyncProbe.calls);
    try testing.expectEqual(std.Io.File.Kind.directory, (try tmp.dir.statFile(io, "parent/node", .{ .follow_symlinks = false })).kind);

    var nested_buf: [std.fs.max_path_bytes]u8 = undefined;
    const nested = try std.fmt.bufPrint(&nested_buf, "{s}/missing/parent/node", .{root});
    try testing.expectError(error.FileNotFound, openDurableDataDir(io, nested, DataDirSyncProbe.sync));
}

test "registry main: only history safety failures are process-fatal" {
    try testing.expect(historyFailureIsFatal(error.InvalidAppliedState));
    try testing.expect(historyFailureIsFatal(error.InvalidGenesisState));
    try testing.expect(historyFailureIsFatal(error.SigningFenceCorrupt));
    try testing.expect(historyFailureIsFatal(error.SigningFenceUnavailable));
    try testing.expect(historyFailureIsFatal(error.SigningEquivocation));
    try testing.expect(historyFailureIsFatal(error.SigningRollback));
    try testing.expect(historyFailureIsFatal(error.CheckpointSlotOverflow));
    try testing.expect(historyFailureIsFatal(error.CertifiedFork));
    try testing.expect(historyFailureIsFatal(error.CertifiedHistoryInvalid));
    try testing.expect(historyFailureIsFatal(error.HistoryBootProvenanceConflict));
    try testing.expect(historyFailureIsFatal(error.HistoryBootProvenanceRollback));
    try testing.expect(historyFailureIsFatal(error.HistoryOutboxCorrupt));
    try testing.expect(historyFailureIsFatal(error.HistoryOutboxSequence));
    try testing.expect(historyFailureIsFatal(error.HistoryPolicyMismatch));
    try testing.expect(historyFailureIsFatal(error.HistoryTransitionInvalid));
    // A hostile shared archive can pre-create a content-addressed path. It
    // may deny history availability, but must not halt consensus.
    try testing.expect(!historyFailureIsFatal(error.ImmutableFileConflict));
    try testing.expect(!historyFailureIsFatal(error.FileNotFound));
    try testing.expect(!historyFailureIsFatal(error.AccessDenied));
}

const PublisherSigningFenceFault = struct {
    var target: ?std.Io.Dir.Handle = null;

    fn sync(dir: std.Io.Dir) !void {
        if (target != null and target.? == dir.handle)
            return error.InjectedDirectorySyncFailure;
        try syncDirectory(dir);
    }
};

test "registry main: the publisher latches trusted fence I/O as fatal" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buf[0..try tmp.dir.realPath(io, &root_buf)];
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try std.fmt.bufPrint(&archive_buf, "{s}/archive", .{root});
    const signing_path = try std.fmt.bufPrint(&signing_buf, "{s}/signing", .{root});
    const seed: [32]u8 = @splat(0xd1);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = testNetworkId("registry publisher trusted fence failure");
    var archive = try history.Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    var archive_live = true;
    defer if (archive_live) archive.deinit();
    PublisherSigningFenceFault.target = archive.signing_votes_dir.handle;
    defer PublisherSigningFenceFault.target = null;
    archive.sync_directory = PublisherSigningFenceFault.sync;

    var state = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    try archive.prepareFrontier(&state);
    const publisher = try HistoryPublisher.start(gpa, io, archive);
    archive_live = false;
    defer publisher.deinit();
    try advanceEmpty(&state, gpa);
    try publisher.offer(state);

    const deadline = nowMs(io) + 5_000;
    var failure: ?HistoryPublicationFailure = null;
    while (failure == null and nowMs(io) < deadline) {
        failure = publisher.fatalFailure();
        if (failure == null) std.Io.sleep(io, .fromMilliseconds(1), .awake) catch {};
    }
    const latched = failure orelse return error.HistoryFailureNotLatched;
    try testing.expectEqual(@as(u64, 1), latched.slot);
    try testing.expectEqual(error.SigningFenceUnavailable, latched.err);
}

test "registry main: the publisher drains a crash-durable outbox without a new offer" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buf[0..try tmp.dir.realPath(io, &root_buf)];
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try std.fmt.bufPrint(&archive_buf, "{s}/archive", .{root});
    const signing_path = try std.fmt.bufPrint(&signing_buf, "{s}/signing", .{root});
    const seed: [32]u8 = @splat(0xd2);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = testNetworkId("registry publisher durable outbox restart");
    const cfg: history.Config = .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 8,
    };

    const genesis = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    var one = genesis;
    try advanceEmpty(&one, gpa);
    var before_crash = try history.Archive.open(gpa, io, cfg);
    try before_crash.prepareFrontier(&genesis);
    try before_crash.stageApplied(&one);
    before_crash.deinit();

    var resumed = try history.Archive.open(gpa, io, cfg);
    var resumed_live = true;
    defer if (resumed_live) resumed.deinit();
    try resumed.prepareFrontier(&genesis);
    const publisher = try HistoryPublisher.start(gpa, io, resumed);
    resumed_live = false;
    var publisher_live = true;
    defer if (publisher_live) publisher.deinit();

    const deadline = nowMs(io) + 5_000;
    var drained = false;
    while (nowMs(io) < deadline) {
        if (publisher.fatalFailure()) |failure| return failure.err;
        if (try publisher.archive.nextStaged() == null) {
            drained = true;
            break;
        }
        std.Io.sleep(io, .fromMilliseconds(1), .awake) catch {};
    }
    try testing.expect(drained);
    publisher.deinit();
    publisher_live = false;

    var verifier = try history.Archive.open(gpa, io, cfg);
    defer verifier.deinit();
    const recovered = (try verifier.recoverLatest(1)) orelse
        return error.ExpectedCertifiedHistory;
    try testing.expectEqual(@as(u64, 1), recovered.state.head.slot);
    try testing.expectEqualSlices(u8, &one.head.hash, &recovered.state.head.hash);
}

test "registry main: startup frees durable capacity for a journal-only successor" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buf[0..try tmp.dir.realPath(io, &root_buf)];
    var archive_buf: [std.fs.max_path_bytes]u8 = undefined;
    var signing_buf: [std.fs.max_path_bytes]u8 = undefined;
    const archive_path = try std.fmt.bufPrint(&archive_buf, "{s}/archive", .{root});
    const signing_path = try std.fmt.bufPrint(&signing_buf, "{s}/signing", .{root});
    const seed: [32]u8 = @splat(0xd3);
    const id = try slcp.core.crypto.publicKeyFromSeed(seed);
    const network_id = testNetworkId("registry full outbox journal successor");
    var archive = try history.Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .genesis_close_time = test_genesis_close_time,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 64,
    });
    defer archive.deinit();

    const genesis = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    try archive.prepareFrontier(&genesis);
    var state = genesis;
    for (0..64) |_| {
        try advanceEmpty(&state, gpa);
        try archive.stageApplied(&state);
    }
    var journal_only = state;
    try advanceEmpty(&journal_only, gpa);
    try testing.expectError(error.HistoryBacklogFull, archive.stageApplied(&journal_only));

    try stageBootHistory(&archive, gpa, &journal_only);
    const oldest = (try archive.nextStaged()) orelse return error.ExpectedLedgerRecord;
    try testing.expectEqual(@as(u64, 2), oldest.head.slot);
}

test "registry main: a checkpoint can resume the journal after the snapshot write crash window" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = root_buf[0..try tmp.dir.realPath(io, &root_buf)];
    const network = "registry main checkpoint journal overlap";
    const network_id = testNetworkId(network);
    var descriptor_buf: [128]u8 = undefined;
    const descriptor = registry.networkDescriptor(test_genesis_close_time, network, &descriptor_buf);
    const seed: [32]u8 = @splat(0xc1);
    const id = try registry.publicKeyOf(seed);
    var diag: slcp.node.Diagnostic = .{};

    var checkpoint: registry.State = undefined;
    var after: registry.State = undefined;
    const boot_state = try registry.State.genesis(network_id, test_genesis_close_time, gpa);
    {
        const original = try app.Node.create(gpa, io, .{
            .network = descriptor,
            .secret_seed = seed,
            .quorum = slcp.Quorum.of(1, &.{id}),
            .include_self = false,
            .listen_port = 0,
            .data_dir = data_dir,
            .max_value_bytes = registry.max_value_bytes,
            .diagnostic = &diag,
        }, boot_state);
        defer original.deinit();
        try original.propose(registry.proposal(&boot_state, &.{}, test_genesis_close_time + 1).?);
        checkpoint = (try original.waitApplied(.{ .timeout_ms = 5_000 })).?.obs;
        try original.propose(registry.proposal(&checkpoint, &.{}, checkpoint.head.close_time + 1).?);
        after = (try original.waitApplied(.{ .timeout_ms = 5_000 })).?.obs;
    }

    // Model a crash after the Node journal durably recorded slot 2 but before
    // main replaced its slot-1 application snapshot.
    const checkpoint_state = checkpoint;
    try testing.expectError(error.StartSlotBehindJournal, app.Node.create(gpa, io, .{
        .network = descriptor,
        .secret_seed = seed,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .include_self = false,
        .listen_port = 0,
        .data_dir = data_dir,
        .max_value_bytes = registry.max_value_bytes,
        .start_slot = checkpoint.head.slot + 1,
        .diagnostic = &diag,
    }, checkpoint_state));

    const resumed = try app.Node.create(gpa, io, .{
        .network = descriptor,
        .secret_seed = seed,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .include_self = false,
        .listen_port = 0,
        .data_dir = data_dir,
        .max_value_bytes = registry.max_value_bytes,
        .diagnostic = &diag,
    }, checkpoint_state);
    defer resumed.deinit();
    const ready = try drainBootReplay(resumed, gpa, &checkpoint, null);
    try testing.expectEqual(@as(u64, 2), ready.head.slot);
    try testing.expectEqualSlices(u8, &after.head.hash, &ready.head.hash);
    try testing.expectEqual(after.head.close_time, ready.head.close_time);
    var after_value_buf: [registry.max_ledger_value_bytes]u8 = undefined;
    var ready_value_buf: [registry.max_ledger_value_bytes]u8 = undefined;
    try testing.expectEqualSlices(u8, after.last_value.?.encode(&after_value_buf), ready.last_value.?.encode(&ready_value_buf));

    // The process installs the replay-complete state before it exposes RPC.
    // Persisting the stale checkpoint here would resurrect slot 1 on the next
    // restart even though the Node journal had already reached slot 2.
    try writeSnapshotFile(io, tmp.dir, gpa, &ready);
    const installed = (try readSnapshotFile(io, tmp.dir, gpa)) orelse return error.SnapshotMissing;
    try testing.expectEqual(@as(u64, 2), installed.head.slot);
    try testing.expectEqualSlices(u8, &after.head.hash, &installed.head.hash);
    try testing.expectEqual(after.head.close_time, installed.head.close_time);
}
