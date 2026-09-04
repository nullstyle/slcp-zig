//! main.zig — the `registry` process (docs/examples-roadmap.md E1–E2b:
//! persistence, flooding, authenticated checkpoint recovery, cadence, and
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
    \\  registry node --network <passphrase> --key <file> --data-dir <dir> --quorum <json>
    \\                --listen <port> --rpc <port> [--peer host:port]...
    \\                [--min-slot-ms 1000] [--heartbeat-ms 3000]
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
    key: ?[]const u8 = null,
    data_dir: ?[]const u8 = null,
    quorum: ?[]const u8 = null,
    listen: ?u16 = null,
    /// `--rpc` is a port for `node`, an `ip:port` spec for the client verbs.
    rpc_port: ?u16 = null,
    rpc: []const u8 = default_rpc,
    min_slot_ms: u64 = registry.min_slot_ms,
    heartbeat_ms: u64 = registry.heartbeat_ms,
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

const FlagError = error{ UnknownFlag, MissingValue, BadPort, BadMillis, BadCheckpointInterval, BadSlot } || std.mem.Allocator.Error;

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
            f.network = value;
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
        } else if (eql(name, "history-dir")) {
            if (value.len == 0) return error.MissingValue;
            f.history_dir = value;
        } else if (eql(name, "checkpoint-every")) {
            f.checkpoint_every = std.fmt.parseInt(u64, value, 10) catch return error.BadCheckpointInterval;
            if (f.checkpoint_every == 0 or f.checkpoint_every > 16) return error.BadCheckpointInterval;
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
            error.BadPort => "a port must be a number in 1..65535",
            error.BadMillis => "--min-slot-ms / --heartbeat-ms take milliseconds (heartbeat > 0)",
            error.BadCheckpointInterval => "--checkpoint-every must be a number in 1..16",
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
        err == error.SigningFenceCorrupt or
        err == error.SigningFenceUnavailable or
        err == error.SigningEquivocation or
        err == error.SigningRollback or
        err == error.CheckpointSlotOverflow or
        err == error.CertifiedFork;
}

fn nowMs(io: std.Io) u64 {
    const ns = std.Io.Clock.now(.awake, io).nanoseconds;
    return @intCast(@divTrunc(ns, std.time.ns_per_ms));
}

fn readSnapshotFile(io: std.Io, dir: std.Io.Dir, gpa: std.mem.Allocator) !?registry.State {
    const bytes = dir.readFileAlloc(io, "snapshot", gpa, .limited(registry.snapshot_max_bytes + 1)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer gpa.free(bytes);
    return registry.readSnapshot(bytes) orelse error.SnapshotCorrupt;
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
fn writeSnapshotFile(io: std.Io, dir: std.Io.Dir, state: *const registry.State) !void {
    var buf: [registry.snapshot_max_bytes]u8 = undefined;
    const bytes = registry.writeSnapshot(state, &buf);
    var af = try dir.createFileAtomic(io, "snapshot", .{ .replace = true });
    defer af.deinit(io);
    try af.file.writeStreamingAll(io, bytes);
    try fullSync(io, af.file);
    try af.replace(io);
    try syncDirectory(dir);
}

const BootSource = enum { genesis, local_snapshot, history };

const BootSelection = struct {
    state: registry.State,
    source: BootSource,
    /// The default `1` lets Node resume its own journal. A history checkpoint
    /// is different: its exact successor declares the older journal prefix
    /// permanently out of scope.
    start_slot: u64,
};

const BootSelectionError = error{
    SnapshotWrongNetwork,
    HistoryCheckpointWrongNetwork,
    HistoryCheckpointConflict,
    HistoryCheckpointAtMaxSlot,
    HistoryFloorUnavailable,
};

/// Choose between locally persisted state and an independently authenticated
/// checkpoint. `min_slot` is an operator's anti-rollback policy, not a search
/// hint: if nothing reaches it, boot must fail instead of quietly starting
/// from older state.
fn selectBootState(
    network_id: [32]u8,
    local: ?registry.State,
    authenticated: ?registry.State,
    min_slot: u64,
) BootSelectionError!BootSelection {
    if (local) |state| {
        if (!std.mem.eql(u8, &state.network_id, &network_id)) return error.SnapshotWrongNetwork;
    }
    if (authenticated) |state| {
        if (!std.mem.eql(u8, &state.network_id, &network_id)) return error.HistoryCheckpointWrongNetwork;
        if (state.head.slot < min_slot) return error.HistoryFloorUnavailable;
    }

    const eligible_local: ?registry.State = if (local) |state|
        if (state.head.slot >= min_slot) state else null
    else
        null;

    if (authenticated) |checkpoint| {
        if (eligible_local) |snapshot| {
            if (snapshot.head.slot == checkpoint.head.slot and
                !std.mem.eql(u8, &snapshot.head.hash, &checkpoint.head.hash))
                return error.HistoryCheckpointConflict;
            if (snapshot.head.slot > checkpoint.head.slot) {
                return .{ .state = snapshot, .source = .local_snapshot, .start_slot = 1 };
            }
        }
        const successor = std.math.add(u64, checkpoint.head.slot, 1) catch
            return error.HistoryCheckpointAtMaxSlot;
        return .{ .state = checkpoint, .source = .history, .start_slot = successor };
    }

    if (eligible_local) |snapshot|
        return .{ .state = snapshot, .source = .local_snapshot, .start_slot = 1 };
    if (min_slot != 0) return error.HistoryFloorUnavailable;
    return .{ .state = .{ .network_id = network_id }, .source = .genesis, .start_slot = 1 };
}

/// Drain the synchronous journal replay that `AppNode.create` queued before
/// returning. The caller must do this before publishing application state to
/// RPC or installing a replacement snapshot: `initial` can be older than the
/// Node journal when the previous process crashed between those two durable
/// writes.
fn drainBootReplay(node: *app.Node, initial: registry.State) !registry.State {
    var ready = initial;
    while (try node.waitApplied(.{ .timeout_ms = 0 })) |applied| {
        const successor = std.math.add(u64, ready.head.slot, 1) catch
            return error.BootReplayDiscontinuity;
        if (applied.slot != successor or applied.state.head.slot != applied.slot)
            return error.BootReplayDiscontinuity;
        ready = applied.state;
    }
    return ready;
}

const HistoryPublicationFailure = struct {
    slot: u64,
    err: anyerror,
};

/// The producer/consumer seam between the cadence loop and shared history.
/// It owns at most one waiting checkpoint; the worker's currently active
/// checkpoint is outside the lock, so even a wedged archive operation cannot
/// make `offer` wait for shared storage.
const HistoryMailbox = struct {
    const RequeueResult = union(enum) {
        retry,
        superseded: u64,
        stopped,
    };

    io: std.Io,
    mu: std.Io.Mutex = .init,
    changed: std.Io.Condition = .init,
    pending: ?registry.State = null,
    /// Highest slot ever accepted from the cadence loop. This keeps a failed
    /// older publication from being restored over a newer pending one.
    newest_slot: u64 = 0,
    retry_slot: ?u64 = null,
    retry_deadline_ns: i96 = 0,
    fatal: ?HistoryPublicationFailure = null,
    stopping: bool = false,

    fn init(io: std.Io) HistoryMailbox {
        return .{ .io = io };
    }

    /// Keep only the newest due checkpoint awaiting publication. Returns the
    /// slot evicted from the one-element mailbox, if any. The active worker
    /// never holds `mu` while touching the archive.
    fn offer(self: *HistoryMailbox, next: registry.State) ?u64 {
        const io = self.io;
        self.mu.lockUncancelable(io);
        defer self.mu.unlock(io);
        if (self.stopping or self.fatal != null or next.head.slot <= self.newest_slot)
            return null;

        const replaced = if (self.pending) |old| old.head.slot else null;
        self.pending = next;
        self.newest_slot = next.head.slot;
        // A new checkpoint supersedes any retry deadline attached to the old
        // mailbox occupant and should be attempted immediately.
        self.retry_slot = null;
        self.changed.signal(io);
        return replaced;
    }

    /// Wait for the next checkpoint or shutdown. Availability retries sleep
    /// on the condition variable so a newer offer wakes and supersedes them.
    fn take(self: *HistoryMailbox) ?registry.State {
        const io = self.io;
        self.mu.lockUncancelable(io);
        defer self.mu.unlock(io);

        while (!self.stopping) {
            const pending = self.pending orelse {
                self.changed.waitUncancelable(io, &self.mu);
                continue;
            };
            if (self.retry_slot != null and self.retry_slot.? == pending.head.slot) {
                const now_ns = std.Io.Clock.now(.awake, io).nanoseconds;
                if (now_ns < self.retry_deadline_ns) {
                    const deadline: std.Io.Clock.Timestamp = .{
                        .raw = .{ .nanoseconds = self.retry_deadline_ns },
                        .clock = .awake,
                    };
                    self.changed.waitTimeout(io, &self.mu, .{ .deadline = deadline }) catch {};
                    continue;
                }
            }
            self.pending = null;
            self.retry_slot = null;
            return pending;
        }
        return null;
    }

    /// Restore an availability-failed checkpoint for a delayed retry unless a
    /// newer offer arrived while the worker was in shared/trusted storage.
    fn requeueAvailabilityFailure(self: *HistoryMailbox, checkpoint: registry.State) RequeueResult {
        const io = self.io;
        self.mu.lockUncancelable(io);
        defer self.mu.unlock(io);
        if (self.stopping) return .stopped;
        if (self.newest_slot > checkpoint.head.slot)
            return .{ .superseded = self.newest_slot };

        self.pending = checkpoint;
        self.retry_slot = checkpoint.head.slot;
        self.retry_deadline_ns = std.Io.Clock.now(.awake, io).nanoseconds +
            @as(i96, history_retry_ms) * std.time.ns_per_ms;
        self.changed.signal(io);
        return .retry;
    }

    fn latchFatal(self: *HistoryMailbox, slot: u64, err: anyerror) void {
        const io = self.io;
        self.mu.lockUncancelable(io);
        defer self.mu.unlock(io);
        if (self.fatal == null) self.fatal = .{ .slot = slot, .err = err };
        self.pending = null;
        self.stopping = true;
        self.changed.broadcast(io);
    }

    fn fatalFailure(self: *HistoryMailbox) ?HistoryPublicationFailure {
        const io = self.io;
        self.mu.lockUncancelable(io);
        defer self.mu.unlock(io);
        return self.fatal;
    }

    fn stop(self: *HistoryMailbox) void {
        const io = self.io;
        self.mu.lockUncancelable(io);
        self.stopping = true;
        self.changed.broadcast(io);
        self.mu.unlock(io);
    }
};

/// Sole post-startup owner of the archive and its trusted signing fence. The
/// cadence loop only copies a bounded State into `mailbox`; all filesystem
/// access, including retries, happens on this native worker thread.
const HistoryPublisher = struct {
    gpa: std.mem.Allocator,
    archive: history.Archive,
    mailbox: HistoryMailbox,
    thread: std.Thread,

    fn start(gpa: std.mem.Allocator, io: std.Io, archive: history.Archive) !*HistoryPublisher {
        const self = try gpa.create(HistoryPublisher);
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .archive = archive,
            .mailbox = .init(io),
            .thread = undefined,
        };
        self.thread = try std.Thread.spawn(.{}, HistoryPublisher.run, .{self});
        return self;
    }

    fn offer(self: *HistoryPublisher, checkpoint: registry.State) void {
        if (self.mailbox.offer(checkpoint)) |old_slot| {
            std.debug.print("registry history: checkpoint slot {d} supersedes queued slot {d}\n", .{ checkpoint.head.slot, old_slot });
        }
    }

    fn fatalFailure(self: *HistoryPublisher) ?HistoryPublicationFailure {
        return self.mailbox.fatalFailure();
    }

    fn deinit(self: *HistoryPublisher) void {
        self.mailbox.stop();
        self.thread.join();
        self.archive.deinit();
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    fn run(self: *HistoryPublisher) void {
        while (self.mailbox.take()) |checkpoint| {
            const status = self.archive.recordApplied(&checkpoint) catch |err| {
                if (historyFailureIsFatal(err)) {
                    self.mailbox.latchFatal(checkpoint.head.slot, err);
                    return;
                }
                switch (self.mailbox.requeueAvailabilityFailure(checkpoint)) {
                    .retry => std.debug.print("registry history: cannot publish checkpoint slot {d}: {t}; consensus continues and publication will retry\n", .{ checkpoint.head.slot, err }),
                    .superseded => |newer_slot| std.debug.print("registry history: checkpoint slot {d} supersedes availability-blocked slot {d}\n", .{ newer_slot, checkpoint.head.slot }),
                    .stopped => return,
                }
                continue;
            };
            switch (status) {
                .not_due => {},
                .published => {
                    const head_hex = registry.hex32(checkpoint.head.hash);
                    std.debug.print("history checkpoint slot {d} signed head={s}\n", .{ checkpoint.head.slot, head_hex[0..16] });
                },
                .certified => {
                    const head_hex = registry.hex32(checkpoint.head.hash);
                    std.debug.print("history checkpoint slot {d} signed head={s}\n", .{ checkpoint.head.slot, head_hex[0..16] });
                    std.debug.print("history checkpoint slot {d} certified head={s}\n", .{ checkpoint.head.slot, head_hex[0..16] });
                },
            }
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

    // Boot state: prefer a newer quorum-authenticated history checkpoint,
    // otherwise resume the local snapshot (or genesis for a fresh node).
    const nid = registry.networkId(network);
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

    const local_snapshot = readSnapshotFile(io, dir, gpa) catch |err| {
        std.debug.print("registry node: {s}/snapshot: {t} — keep this node stopped until the local snapshot is repaired or removed under operator control\n", .{ data_dir, err });
        return 1;
    };
    if (local_snapshot) |snap| {
        if (!std.mem.eql(u8, &snap.network_id, &nid)) {
            std.debug.print("registry node: {s}/snapshot belongs to another --network; use a fresh --data-dir\n", .{data_dir});
            return 1;
        }
    }

    var history_archive: ?history.Archive = null;
    defer if (history_archive) |*archive| archive.deinit();
    var authenticated: ?registry.State = null;
    if (f.history_dir) |archive_dir| {
        const signing_dir = try std.fmt.allocPrint(gpa, "{s}/history-signing", .{data_dir});
        defer gpa.free(signing_dir);
        history_archive = history.Archive.open(gpa, io, .{
            .archive_dir = archive_dir,
            .signing_dir = signing_dir,
            .private_data_root_dir = dir,
            .private_key_parent_dir = key_parent_dir,
            .network_id = nid,
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
        const floor = @max(f.history_min_slot, if (local_snapshot) |snap| snap.head.slot else 0);
        authenticated = history_archive.?.loadLatest(floor) catch |err| {
            std.debug.print("registry node: cannot authenticate a history checkpoint at or above slot {d} in {s}: {t}\n", .{ floor, archive_dir, err });
            return 1;
        };
    }

    const selected = selectBootState(nid, local_snapshot, authenticated, f.history_min_slot) catch |err| {
        switch (err) {
            error.HistoryCheckpointConflict => std.debug.print("registry node: the authenticated history checkpoint and local snapshot claim different heads at the same slot; keep this node stopped\n", .{}),
            error.HistoryFloorUnavailable => std.debug.print("registry node: no local snapshot or authenticated history checkpoint reaches --history-min-slot {d}; refusing an anti-rollback downgrade\n", .{f.history_min_slot}),
            else => std.debug.print("registry node: cannot select boot state: {t}\n", .{err}),
        }
        return 1;
    };
    app.boot = .{ .state = selected.state, .slot = selected.state.head.slot };

    const slcp_dir = try std.fmt.allocPrint(gpa, "{s}/slcp", .{data_dir});
    defer gpa.free(slcp_dir);

    var diag: slcp.node.Diagnostic = .{};
    var node_options: app.Node.Options = .{
        .network = network,
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
        .start_slot = selected.start_slot,
        .diagnostic = &diag,
    };
    const node = app.Node.create(gpa, io, node_options) catch |err| retry: {
        // Crash window: Node persists an externalized slot before the main
        // loop persists its resulting application snapshot. If a history
        // checkpoint at C is therefore paired with a local journal already
        // beyond C, its explicit C+1 start is intentionally rejected. Retry
        // with the same authenticated state and ordinary journal resumption;
        // AppNode will accept only when the retained tail continues C.
        if (selected.source == .history and err == error.StartSlotBehindJournal) {
            std.debug.print("registry node: authenticated checkpoint slot {d} overlaps a newer local journal; verifying that journal as its continuation\n", .{selected.state.head.slot});
            node_options.start_slot = 1;
            break :retry app.Node.create(gpa, io, node_options) catch |retry_err| {
                std.debug.print("registry node: cannot continue authenticated checkpoint through the local journal ({t}): {s}\n", .{ retry_err, diag.message() });
                return 1;
            };
        }
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
    // Node recovery is synchronous, but AppNode exposes the resulting state
    // copies through its queue. Drain those copies before RPC can observe the
    // initial checkpoint/snapshot. This closes the crash window where the
    // consensus journal is durably ahead of the application snapshot.
    const ready_state = drainBootReplay(node, selected.state) catch |err| {
        if (err == error.NodeHalted) {
            std.debug.print("registry node: halted while recovering the local journal; see the log above\n", .{});
        } else {
            std.debug.print("registry node: the recovered journal does not continue boot slot {d} one slot at a time ({t}); keep this node stopped\n", .{ selected.state.head.slot, err });
        }
        return 1;
    };
    const replayed_boot = ready_state.head.slot > selected.state.head.slot;

    // Only after AppNode accepts the checkpoint/start-slot pair and any local
    // continuation may the replacement snapshot become durable. A failed
    // create leaves prior state intact; a successful replay persists its
    // newest state, never the stale checkpoint that preceded it.
    if (selected.source == .history or replayed_boot) {
        writeSnapshotFile(io, dir, &ready_state) catch |err| {
            std.debug.print("registry node: cannot install recovered state in {s}/snapshot: {t}; stopping\n", .{ data_dir, err });
            return 1;
        };
    }
    if (replayed_boot) {
        std.debug.print("registry node: local journal advanced boot state from slot {d} through slot {d} before RPC startup\n", .{ selected.state.head.slot, ready_state.head.slot });
    }

    // Startup archive discovery is synchronous because it selects the boot
    // state. Once recovery is complete, move the archive into its sole worker
    // owner so neither shared nor trusted history I/O can stall consensus,
    // RPC, gossip, or ordinary snapshot persistence.
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
    if (history_archive) |archive| {
        history_publisher = HistoryPublisher.start(gpa, io, archive) catch |err| {
            std.debug.print("registry node: cannot start the history publisher: {t}\n", .{err});
            return 1;
        };
        history_archive = null;
    }

    var publisher = GossipPublisher{ .node = node.raw() };
    var shared = rpc.Shared{ .io = io, .state = ready_state, .publisher = publisher.publisher() };
    const server = rpc.Server.start(gpa, io, &shared, rpc_port) catch |err| {
        std.debug.print("registry node: cannot bind the rpc port 127.0.0.1:{d}: {t}\n", .{ rpc_port, err });
        return 1;
    };
    defer server.stop();

    const boot_source = switch (selected.source) {
        .genesis => "genesis",
        .local_snapshot => "the snapshot",
        .history => "history checkpoint",
    };
    std.debug.print("registry: node {s} listening on port {d}; {d} peer(s); data in {s}; starting from {s} at slot {d}\n", .{
        &registry.hex32(kp.public_key), node.raw().boundPort(), f.peers.items.len, data_dir, boot_source, selected.state.head.slot,
    });
    std.debug.print("registry: limits: {d} txs per set, {d} accounts, {d} names, {d} pending; busy slots every >= {d} ms, idle heartbeat every {d} ms\n", .{
        registry.max_txs, registry.max_accounts, registry.max_names, registry.max_pending, f.min_slot_ms, f.heartbeat_ms,
    });
    std.debug.print("registry: rpc listening on 127.0.0.1:{d}\n", .{server.port});
    if (f.history_dir) |archive_dir| {
        std.debug.print("registry: authenticated history in {s}; checkpoint every {d} slots; anti-rollback floor {d}\n", .{
            archive_dir, f.checkpoint_every, f.history_min_slot,
        });
    }

    // The cadence loop (§3.9): after every applied slot, refresh the shared
    // copy, prune the queue, persist, and propose once for the next slot —
    // right away when transactions are pending, else at the heartbeat.
    var last_close = nowMs(io);
    var proposed = false;
    // A node that fell more than ~80 slots behind (the library's 64-slot
    // hold window plus its 16-slot answering window) is not told so: the
    // statements it needs are dropped silently. Say something every minute.
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
            if (a.slot != a.state.head.slot) {
                // Delivered a slot past a gap the library could not answer
                // (roadmap §2.1 gap 2): `apply` skipped the set (it does
                // not fit this state) and the header stayed put. Stop at
                // once — `exit`, not a return through `deinit`, so the
                // engine thread applies nothing more meanwhile.
                if (f.history_dir != null) {
                    std.debug.print("registry node: applied slot {d} but the state's header is at slot {d}: this process crossed a gap outside live history. Exiting with code 3; restart it from a recent certified checkpoint whose successor is still inside a peer's answering window.\n", .{ a.slot, a.state.head.slot });
                } else {
                    std.debug.print("registry node: applied slot {d} but the state's header is at slot {d}: this node missed slots the peers have already compacted. Exiting with code 3; configure authenticated history or rejoin only when the whole network starts over.\n", .{ a.slot, a.state.head.slot });
                }
                std.process.exit(3);
            }
            shared.lock();
            shared.state = a.state;
            shared.prune();
            shared.unlock();
            writeSnapshotFile(io, dir, &a.state) catch |err| {
                std.debug.print("registry node: cannot write {s}/snapshot: {t}; stopping (a node that cannot persist must stop)\n", .{ data_dir, err });
                stopNodeAndExit(server, node, &node_needs_deinit, 1);
            };
            // The ordinary snapshot is durable before the state enters the
            // one-element history mailbox. Publication and all retry I/O are
            // owned by the worker, so this cadence loop remains live even if
            // the shared archive or trusted signing storage stalls.
            if (history_publisher) |history_worker| {
                if (a.slot % f.checkpoint_every == 0)
                    history_worker.offer(a.state);
            }
            var ok: usize = 0;
            for (a.state.lastResults()) |r| {
                if (r == .ok) ok += 1;
            }
            const head_hex = registry.hex32(a.state.head.hash);
            std.debug.print("slot {d}: txs={d} ok={d} head={s}\n", .{ a.slot, a.state.last_count, ok, head_hex[0..16] });
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
                std.debug.print("registry node: no slot applied for {d} s — either the network has no quorum, or this process fell beyond live history; in the latter case stop and restart it only after a recent certified checkpoint is available inside a peer's answering window\n", .{(nowMs(io) -| last_close) / 1000});
            } else {
                std.debug.print("registry node: no slot applied for {d} s — either the network has no quorum, or this node fell beyond live history; configure authenticated history for catch-up, or use a fresh --data-dir only when the whole network starts over\n", .{(nowMs(io) -| last_close) / 1000});
            }
            next_stall_warn = now + stall_warn_ms;
        }
        if (!proposed) {
            const since = now -| last_close;
            var set: ?registry.TxSet = null;
            shared.lock();
            if (registry.nominationDue(shared.n_pending > 0, since, f.min_slot_ms, f.heartbeat_ms)) {
                set = registry.proposal(&shared.state, shared.pendingSlice());
            }
            shared.unlock();
            if (set) |s| {
                node.propose(s) catch |err| {
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

test "registry main: history flags parse and checkpoint cadence is bounded by the answering window" {
    var parsed = try parseFlags(testing.allocator, &.{
        "--history-dir",      "/shared/history",
        "--checkpoint-every", "16",
        "--history-min-slot", "240",
    }, true);
    defer parsed.deinit(testing.allocator);
    try testing.expectEqualStrings("/shared/history", parsed.history_dir.?);
    try testing.expectEqual(@as(u64, 16), parsed.checkpoint_every);
    try testing.expectEqual(@as(u64, 240), parsed.history_min_slot);

    try testing.expectError(error.BadCheckpointInterval, parseFlags(testing.allocator, &.{ "--checkpoint-every", "0" }, true));
    try testing.expectError(error.BadCheckpointInterval, parseFlags(testing.allocator, &.{ "--checkpoint-every", "17" }, true));
    try testing.expectError(error.BadSlot, parseFlags(testing.allocator, &.{ "--history-min-slot", "not-a-slot" }, true));
}

test "registry main: boot selection prefers authenticated history and treats its floor as absolute" {
    const nid = registry.networkId("registry main history selection");
    var local: registry.State = .{ .network_id = nid };
    local.head.slot = 10;
    local.head.hash = @splat(0x10);
    var checkpoint = local;
    checkpoint.head.slot = 11;
    checkpoint.head.hash = @splat(0x11);

    const newer = try selectBootState(nid, local, checkpoint, 0);
    try testing.expectEqual(BootSource.history, newer.source);
    try testing.expectEqual(@as(u64, 12), newer.start_slot);

    const local_newer = try selectBootState(nid, checkpoint, local, 0);
    try testing.expectEqual(BootSource.local_snapshot, local_newer.source);
    try testing.expectEqual(@as(u64, 1), local_newer.start_slot);

    const equal = try selectBootState(nid, checkpoint, checkpoint, checkpoint.head.slot);
    try testing.expectEqual(BootSource.history, equal.source);
    try testing.expectEqual(@as(u64, 12), equal.start_slot);

    var fork = checkpoint;
    fork.head.hash = @splat(0xff);
    try testing.expectError(error.HistoryCheckpointConflict, selectBootState(nid, checkpoint, fork, 0));
    try testing.expectError(error.HistoryFloorUnavailable, selectBootState(nid, local, null, 11));
}

test "registry main: a history-free empty boot preserves genesis behavior" {
    const nid = registry.networkId("registry main genesis selection");
    const selected = try selectBootState(nid, null, null, 0);
    try testing.expectEqual(BootSource.genesis, selected.source);
    try testing.expectEqual(@as(u64, 0), selected.state.head.slot);
    try testing.expectEqual(@as(u64, 1), selected.start_slot);
    try testing.expectEqualSlices(u8, &nid, &selected.state.network_id);
}

test "registry main: a missing snapshot cannot replay a compacted journal" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];
    const network = "registry main compacted journal without snapshot";
    const network_id = registry.networkId(network);
    const seed: [32]u8 = @splat(0xb1);
    const id = try registry.publicKeyOf(seed);
    var diag: slcp.node.Diagnostic = .{};
    defer app.boot = .{ .state = .{}, .slot = 0 };

    var encoded_buf: [registry.max_set_bytes]u8 = undefined;
    const encoded = registry.TxSet.empty.encode(&encoded_buf);
    {
        var store = try slcp.store.Store.open(gpa, io, data_dir);
        defer store.deinit();
        try store.appendExternalized(49, encoded);
    }

    app.boot = .{ .state = .{ .network_id = network_id }, .slot = 0 };
    if (app.Node.create(gpa, io, .{
        .network = network,
        .secret_seed = seed,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .include_self = false,
        .listen_port = 0,
        .data_dir = data_dir,
        .max_value_bytes = registry.max_value_bytes,
        .diagnostic = &diag,
    })) |node| {
        node.deinit();
        return error.ExpectedCompactedJournalRejection;
    } else |err| {
        try testing.expectEqual(error.InitialSlotOutsideJournal, err);
        try testing.expect(std.mem.indexOf(u8, diag.message(), "slots 49..49") != null);
        try testing.expect(std.mem.indexOf(u8, diag.message(), "did not go live") != null);
    }
}

test "registry main: snapshot replacement does not follow a planted temp or final symlink" {
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

    var state: registry.State = .{ .network_id = registry.networkId("registry main snapshot atomic") };
    registry.apply(&state, &registry.TxSet.empty);
    try writeSnapshotFile(io, tmp.dir, &state);

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
    try testing.expect(historyFailureIsFatal(error.SigningFenceCorrupt));
    try testing.expect(historyFailureIsFatal(error.SigningFenceUnavailable));
    try testing.expect(historyFailureIsFatal(error.SigningEquivocation));
    try testing.expect(historyFailureIsFatal(error.SigningRollback));
    try testing.expect(historyFailureIsFatal(error.CheckpointSlotOverflow));
    try testing.expect(historyFailureIsFatal(error.CertifiedFork));
    // A hostile shared archive can pre-create a content-addressed path. It
    // may deny history availability, but must not halt consensus.
    try testing.expect(!historyFailureIsFatal(error.ImmutableFileConflict));
    try testing.expect(!historyFailureIsFatal(error.FileNotFound));
    try testing.expect(!historyFailureIsFatal(error.AccessDenied));
}

const PublisherSigningFenceFault = struct {
    fn sync(_: std.Io.Dir) !void {
        return error.InjectedDirectorySyncFailure;
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
    const network_id = registry.networkId("registry publisher trusted fence failure");
    var archive = try history.Archive.open(gpa, io, .{
        .archive_dir = archive_path,
        .signing_dir = signing_path,
        .network_id = network_id,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .signer_seed = seed,
        .checkpoint_every = 1,
    });
    var archive_live = true;
    defer if (archive_live) archive.deinit();
    archive.sync_directory = PublisherSigningFenceFault.sync;

    const publisher = try HistoryPublisher.start(gpa, io, archive);
    archive_live = false;
    defer publisher.deinit();
    var state: registry.State = .{ .network_id = network_id };
    registry.apply(&state, &registry.TxSet.empty);
    publisher.offer(state);

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

test "registry main: an availability-blocked checkpoint is coalesced to the newest due state" {
    const nid = registry.networkId("registry main checkpoint coalescing");
    var eight: registry.State = .{ .network_id = nid };
    for (0..8) |_| registry.apply(&eight, &registry.TxSet.empty);
    var sixteen = eight;
    for (8..16) |_| registry.apply(&sixteen, &registry.TxSet.empty);

    var mailbox = HistoryMailbox.init(testing.io);
    defer mailbox.stop();
    try testing.expect(mailbox.offer(eight) == null);
    try testing.expectEqual(@as(u64, 8), mailbox.offer(sixteen).?);
    const pending = mailbox.take().?;
    try testing.expectEqual(@as(u64, 16), pending.head.slot);
    try testing.expectEqualSlices(u8, &sixteen.head.hash, &pending.head.hash);
}

test "registry main: a newer checkpoint supersedes an active publication after availability failure" {
    const nid = registry.networkId("registry main active history supersession");
    var eight: registry.State = .{ .network_id = nid };
    for (0..8) |_| registry.apply(&eight, &registry.TxSet.empty);
    var sixteen = eight;
    for (8..16) |_| registry.apply(&sixteen, &registry.TxSet.empty);

    var mailbox = HistoryMailbox.init(testing.io);
    defer mailbox.stop();
    try testing.expect(mailbox.offer(eight) == null);
    const active = mailbox.take().?;
    try testing.expectEqual(@as(u64, 8), active.head.slot);
    try testing.expect(mailbox.offer(sixteen) == null);
    switch (mailbox.requeueAvailabilityFailure(active)) {
        .superseded => |slot| try testing.expectEqual(@as(u64, 16), slot),
        else => return error.ExpectedHistoryCheckpointSupersession,
    }
    try testing.expectEqual(@as(u64, 16), mailbox.take().?.head.slot);
}

const SlowHistoryMailboxConsumer = struct {
    mailbox: *HistoryMailbox,
    first_slot: std.atomic.Value(u64) = .init(0),
    release: std.atomic.Value(bool) = .init(false),
    second_slot: std.atomic.Value(u64) = .init(0),

    fn run(self: *@This()) void {
        const first = self.mailbox.take() orelse return;
        self.first_slot.store(first.head.slot, .release);
        while (!self.release.load(.acquire)) std.Thread.yield() catch {};
        const second = self.mailbox.take() orelse return;
        self.second_slot.store(second.head.slot, .release);
    }
};

test "registry main: a slow history consumer does not block offers and sees only the newest queued checkpoint" {
    const io = testing.io;
    const nid = registry.networkId("registry main slow history consumer");
    var eight: registry.State = .{ .network_id = nid };
    for (0..8) |_| registry.apply(&eight, &registry.TxSet.empty);
    var sixteen = eight;
    for (8..16) |_| registry.apply(&sixteen, &registry.TxSet.empty);
    var twenty_four = sixteen;
    for (16..24) |_| registry.apply(&twenty_four, &registry.TxSet.empty);

    var mailbox = HistoryMailbox.init(io);
    var consumer = SlowHistoryMailboxConsumer{ .mailbox = &mailbox };
    try testing.expect(mailbox.offer(eight) == null);
    var thread: ?std.Thread = try std.Thread.spawn(.{}, SlowHistoryMailboxConsumer.run, .{&consumer});
    defer {
        consumer.release.store(true, .release);
        mailbox.stop();
        if (thread) |t| t.join();
    }

    const wait_deadline = nowMs(io) + 5_000;
    while (consumer.first_slot.load(.acquire) == 0 and nowMs(io) < wait_deadline)
        std.Io.sleep(io, .fromMilliseconds(1), .awake) catch {};
    try testing.expectEqual(@as(u64, 8), consumer.first_slot.load(.acquire));

    // The consumer is deliberately held outside the mailbox, modeling a
    // blocked archive syscall. Producers can still replace the sole queued
    // element without waiting for it.
    try testing.expect(mailbox.offer(sixteen) == null);
    try testing.expectEqual(@as(u64, 16), mailbox.offer(twenty_four).?);
    consumer.release.store(true, .release);
    thread.?.join();
    thread = null;
    try testing.expectEqual(@as(u64, 24), consumer.second_slot.load(.acquire));
}

test "registry main: a checkpoint can resume the journal after the snapshot write crash window" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = root_buf[0..try tmp.dir.realPath(io, &root_buf)];
    const network = "registry main checkpoint journal overlap";
    const network_id = registry.networkId(network);
    const seed: [32]u8 = @splat(0xc1);
    const id = try registry.publicKeyOf(seed);
    var diag: slcp.node.Diagnostic = .{};
    defer app.boot = .{ .state = .{}, .slot = 0 };

    var checkpoint: registry.State = undefined;
    var after: registry.State = undefined;
    app.boot = .{ .state = .{ .network_id = network_id }, .slot = 0 };
    {
        const original = try app.Node.create(gpa, io, .{
            .network = network,
            .secret_seed = seed,
            .quorum = slcp.Quorum.of(1, &.{id}),
            .include_self = false,
            .listen_port = 0,
            .data_dir = data_dir,
            .max_value_bytes = registry.max_value_bytes,
            .diagnostic = &diag,
        });
        defer original.deinit();
        try original.propose(registry.TxSet.empty);
        checkpoint = (try original.waitApplied(.{ .timeout_ms = 5_000 })).?.state;
        try original.propose(registry.TxSet.empty);
        after = (try original.waitApplied(.{ .timeout_ms = 5_000 })).?.state;
    }

    // Model a crash after the Node journal durably recorded slot 2 but before
    // main replaced its slot-1 application snapshot.
    app.boot = .{ .state = checkpoint, .slot = checkpoint.head.slot };
    try testing.expectError(error.StartSlotBehindJournal, app.Node.create(gpa, io, .{
        .network = network,
        .secret_seed = seed,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .include_self = false,
        .listen_port = 0,
        .data_dir = data_dir,
        .max_value_bytes = registry.max_value_bytes,
        .start_slot = checkpoint.head.slot + 1,
        .diagnostic = &diag,
    }));

    const resumed = try app.Node.create(gpa, io, .{
        .network = network,
        .secret_seed = seed,
        .quorum = slcp.Quorum.of(1, &.{id}),
        .include_self = false,
        .listen_port = 0,
        .data_dir = data_dir,
        .max_value_bytes = registry.max_value_bytes,
        .diagnostic = &diag,
    });
    defer resumed.deinit();
    const ready = try drainBootReplay(resumed, checkpoint);
    try testing.expectEqual(@as(u64, 2), ready.head.slot);
    try testing.expectEqualSlices(u8, &after.head.hash, &ready.head.hash);

    // The process installs the replay-complete state before it exposes RPC.
    // Persisting the stale checkpoint here would resurrect slot 1 on the next
    // restart even though the Node journal had already reached slot 2.
    try writeSnapshotFile(io, tmp.dir, &ready);
    const installed = (try readSnapshotFile(io, tmp.dir, gpa)) orelse return error.SnapshotMissing;
    try testing.expectEqual(@as(u64, 2), installed.head.slot);
    try testing.expectEqualSlices(u8, &after.head.hash, &installed.head.hash);
}
