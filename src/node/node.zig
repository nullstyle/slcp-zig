//! The omakase Node (design §11.2, bytes-level surface). Wraps the sans-io
//! engine in a real, threaded, crash-safe node.
//!
//! Threading model (single-threaded engine contract preserved):
//!   * ONE engine thread owns `core.engine.Engine`. Every engine call happens
//!     there. It pulls `Input`s from a mutex+condvar queue, feeds exactly one,
//!     then drains ALL effects before the next (the engine's §5.3 contract).
//!   * Overlay reader threads, the timer wheel, and `propose` push Inputs onto
//!     that queue. They never touch the engine directly.
//!   * Effect dispatch runs on the engine thread: persist→store (fsync),
//!     broadcast/forward→overlay, arm/cancel→timer wheel, externalized→store +
//!     the app delivery queue + proposal advance + GC.
//!
//! Restart (§10) happens synchronously in `create`, BEFORE the engine thread
//! starts and BEFORE the overlay binds: recover own.log, replay each latest
//! record as `restore_own_envelope` (rebuilding state; the engine re-emits
//! broadcast which we capture into `own_latest` for on-connect catch-up, never
//! lost because no peers exist yet). A corrupt own.log forces watcher mode
//! (safe superset of the §10 bounded fallback: a watcher never emits, so it
//! can never emit stale-vs-self).

const std = @import("std");
const core = @import("slcp-core");

const wire = @import("wire.zig");
const overlay_mod = @import("overlay.zig");
const timers_mod = @import("timers.zig");
const store_mod = @import("store.zig");
const keys_mod = @import("keys.zig");
const lint_report = @import("lint_report.zig");

const engine = core.engine;
const crypto = core.crypto;
const qset = core.qset;
const gen_slcp = core.gen.slcp;
const canonical = core.canonical;
const MessageBuilder = core.capnpc.message.MessageBuilder;

const log = std.log.scoped(.slcp_node);

/// GC window: keep 16 externalized slots answerable to laggards (§10).
const purge_window: u64 = 16;

/// Anti-entropy period (§9.2 host policy; see the resync_thread field).
const resync_interval_ms: u64 = 3_000;

/// M6:example logs — cadence of the "waiting for peers" reminder.
const peers_waiting_reminder_ms: u64 = 60_000;

/// A relative-duration Io.Timeout in milliseconds (this Zig's condvar API).
/// Public: `AppNode.waitApplied` reuses it.
pub fn msTimeout(ms: u64) std.Io.Timeout {
    return .{ .duration = .{ .raw = std.Io.Duration.fromMilliseconds(@intCast(ms)), .clock = .awake } };
}

/// Every way `create` can refuse to start, one member per misconfiguration
/// (design §11.2 / plan R18). Each site writes a one-paragraph message that
/// names the offending value and says what to do into `Options.diagnostic`
/// (or `std.log.scoped(.slcp_create).err` when none is given); `explain`
/// is the static, value-free fallback text.
pub const CreateError = error{
    NetworkPassphraseEmpty,
    NoIdentity,
    ConflictingIdentity,
    WatcherHasIdentity,
    IdentityMismatch,
    KeyFileBad,
    KeyFileDirMissing,
    KeyFileAccessDenied,
    KeyFileIoFailed,
    MaxValueBytesOutOfRange,
    StartSlotZero,
    StartSlotBehindJournal,
    BadPeerSpec,
    DuplicatePeer,
    PeerIsSelf,
    QuorumEmpty,
    QuorumThresholdOutOfRange,
    QuorumDuplicateNode,
    QuorumTooDeep,
    QuorumTooManyValidators,
    UnsafeQuorum,
    DataDirEmpty,
    DataDirNotADirectory,
    DataDirAccessDenied,
    DataDirUnusable,
    DataDirOtherNetwork,
    DataDirOtherNode,
    DataDirBusy,
    ListenPortInUse,
    ListenPortPrivileged,
    ListenFailed,
    ThreadSpawnFailed,
    EngineFailed,
} || std.mem.Allocator.Error;

/// Alias kept for one release (M5 spelling).
pub const Error = CreateError;

pub const ProposeError = error{ WatcherCannotPropose, ValueEmpty, ValueTooLarge } || std.mem.Allocator.Error;

/// Static, value-free explanation of a `CreateError` — the fallback when the
/// caller did not pass a `Diagnostic`. Non-empty and unique per member (the
/// exhaustive switch keeps it covering every member).
pub fn explain(err: CreateError) []const u8 {
    return explainCreateError(err);
}

fn explainCreateError(err: CreateError) []const u8 {
    return switch (err) {
        error.NetworkPassphraseEmpty => ".network is empty; set it to a passphrase unique to your application (it becomes the networkId).",
        error.NoIdentity => "no identity: set .key_file (created on first run) or .secret_seed, or .watcher = true for a node that only follows.",
        error.ConflictingIdentity => ".key_file and .secret_seed are both set; provide one identity source.",
        error.WatcherHasIdentity => ".watcher = true but a signing identity (.secret_seed / .key_file) is set; a watcher never signs.",
        error.IdentityMismatch => ".node_id is not the public key of the given seed / key file; drop .node_id (it is derived) or fix the seed.",
        error.KeyFileBad => ".key_file is not a 32-byte raw seed; restore the original file or move it aside to mint a new identity.",
        error.KeyFileDirMissing => ".key_file's directory does not exist; create the directory first (slcp creates the file, not its parent).",
        error.KeyFileAccessDenied => ".key_file cannot be read or created (permission denied); fix the permissions or choose another path.",
        error.KeyFileIoFailed => ".key_file could not be read or created (I/O error); check the path and the filesystem.",
        error.MaxValueBytesOutOfRange => ".max_value_bytes is outside [1, 65536]; pick the largest value your app will ever propose.",
        error.StartSlotZero => ".start_slot is 0 but slots start at 1; drop it (default 1).",
        error.StartSlotBehindJournal => ".start_slot is at or below the journal high-water mark in .data_dir; drop it (the node resumes after the journal) or use a fresh data_dir.",
        error.BadPeerSpec => "a .peers entry is not host:port (IPv4/IPv6 literal or hostname, port 1..65535).",
        error.DuplicatePeer => "a .peers entry is listed twice; list each peer once.",
        error.PeerIsSelf => "a .peers entry is this node's own listen address; list only the OTHER nodes.",
        error.QuorumEmpty => ".quorum has no members; list the validators (slcp.Quorum.twoThirdsOf is the blessed default).",
        error.QuorumThresholdOutOfRange => "a .quorum level's threshold is outside [1, member count].",
        error.QuorumDuplicateNode => ".quorum lists the same validator more than once.",
        error.QuorumTooDeep => ".quorum nests deeper than the wire limit (4 levels); flatten it.",
        error.QuorumTooManyValidators => ".quorum names more than 255 validators; trim or group them.",
        error.UnsafeQuorum => ".quorum is below a majority (a fork machine); raise the threshold or set .allow_unsafe_quorum = true to start anyway.",
        error.DataDirEmpty => ".data_dir is empty; set it to a directory this node owns (created on first run).",
        error.DataDirNotADirectory => ".data_dir exists but is not a directory.",
        error.DataDirAccessDenied => ".data_dir cannot be created or opened (permission denied).",
        error.DataDirUnusable => ".data_dir cannot be used (I/O error); check the path, the filesystem and free space.",
        error.DataDirOtherNetwork => ".data_dir was created for a different network; use a fresh data_dir per network, or fix .network.",
        error.DataDirOtherNode => ".data_dir belongs to another node's key; restore the original key file or start a fresh data_dir.",
        error.DataDirBusy => ".data_dir is held by another live slcp node (its lock file is locked); one identity must never run twice — stop the other process, or give this node its own data_dir.",
        error.ListenPortInUse => ".listen_port is already in use on this machine; stop the other process or pick another port.",
        error.ListenPortPrivileged => ".listen_port is a privileged port (< 1024) this process may not bind; use a port >= 1024.",
        error.ListenFailed => "the listener could not be bound (socket error); check the port and the network stack.",
        error.ThreadSpawnFailed => "cannot start the engine/overlay threads; the process is out of threads or memory.",
        error.EngineFailed => "the consensus engine could not be initialized; please report this with your options.",
        error.OutOfMemory => "out of memory while creating the node.",
    };
}

/// Where `create` writes its one-paragraph failure message. Stack-sized;
/// a message longer than the buffer is truncated and ends with "…".
pub const Diagnostic = struct {
    buf: [1024]u8 = undefined,
    len: usize = 0,

    pub fn message(self: *const Diagnostic) []const u8 {
        return self.buf[0..self.len];
    }

    /// Overwrite the message. Public so `AppNode.create` can report its own
    /// members (`CommandExceedsMaxValueBytes`, …) through the same buffer.
    pub fn set(self: *Diagnostic, comptime fmt: []const u8, args: anytype) void {
        var w: std.Io.Writer = .fixed(&self.buf);
        w.print(fmt, args) catch {
            const ellipsis = "…";
            var keep = @min(w.end, self.buf.len - ellipsis.len);
            // Do not split a UTF-8 sequence.
            while (keep > 0 and (self.buf[keep] & 0xC0) == 0x80) keep -= 1;
            @memcpy(self.buf[keep..][0..ellipsis.len], ellipsis);
            self.len = keep + ellipsis.len;
            return;
        };
        self.len = w.end;
    }
};

const create_log = std.log.scoped(.slcp_create);

/// Record the failure message (into `diag`, else the create log) and hand
/// back the error for `return`.
fn fail(diag: ?*Diagnostic, err: CreateError, comptime fmt: []const u8, args: anytype) CreateError {
    var local: Diagnostic = .{};
    const d = diag orelse &local;
    d.set(fmt, args);
    if (diag == null) create_log.err("{s}", .{d.message()});
    return err;
}

/// One externalized slot, delivered to the app. `value` is owned by the
/// caller after `waitExternalized` returns — free it with `node.allocator()`.
pub const Externalized = struct {
    slot: u64,
    value: []u8,
};

/// Engine-thread delivery (design §8.5 "where apply runs"). When set, every
/// externalized slot goes to `on_externalized` INSTEAD of the
/// `waitExternalized` queue — on the engine thread, after the journal
/// append, before the next input reaches the engine — so a typed `apply`
/// and the driver's `validate` read the same state without a lock.
/// Delivery is strictly slot-ascending on every path, including the
/// journal-tail replay inside `create` (where the hook runs on the creating
/// thread, before any thread starts). `value` is borrowed for the call.
///
/// An error from `on_externalized` is an invariant break (the app cannot
/// consume a value the network already agreed on): inside `create` the node
/// refuses to start (`EngineFailed`, the error named in the diagnostic);
/// at runtime the node logs loudly and latches inert (§10 discipline), then
/// calls `on_failed` exactly once. `on_failed` also fires for every other
/// latch (a failed write-ahead append, an engine fault), so the app can
/// stop waiting.
pub const DeliveryHook = struct {
    ctx: *anyopaque,
    on_externalized: *const fn (ctx: *anyopaque, slot: u64, value: []const u8) anyerror!void,
    on_failed: *const fn (ctx: *anyopaque, err: anyerror) void,
};

const Quorum = core.quorum.Quorum;

pub const Options = struct {
    /// Passphrase → networkId (domain separation). Must be non-empty.
    network: []const u8,
    /// Identity: EITHER `.key_file` (loaded, or minted on first run) OR
    /// `.secret_seed`; `.node_id` is optional and, when given, must be the
    /// public key of that seed. A `.watcher` has no signing identity.
    node_id: ?[32]u8 = null,
    secret_seed: ?[32]u8 = null,
    key_file: ?[]const u8 = null,
    /// The quorum spec (§12). Borrowed; deep-copied, validated, normalized
    /// and linted at `create`. The local node is added to the top level when
    /// absent (see `include_self`).
    quorum: Quorum,
    /// Auto-add this node to the top-level validators when it is absent
    /// from the whole tree (info log). `false` opts out (warning log).
    include_self: bool = true,
    /// Start even when the lint reports ERRORs (sub-majority threshold).
    /// The errors are still logged.
    allow_unsafe_quorum: bool = false,
    /// TCP port to listen on; 0 = ephemeral (see `boundPort`).
    listen_port: u16,
    /// "host:port" strings to dial: IPv4/IPv6 literal (`[v6]:port`) or hostname.
    peers: []const []const u8 = &.{},
    /// Directory for the write-ahead logs and the identity marker; created
    /// on first run, then bound to this network + key.
    data_dir: []const u8,
    /// No key, ephemeral nodeId, never signs, never proposes (§11).
    watcher: bool = false,
    strict_canonical: bool = true,
    /// Largest value `propose` accepts; [1, 65536].
    max_value_bytes: u32 = 4096,
    /// First slot to nominate proposals for (default 1). Must be above the
    /// journal high-water mark of an existing data_dir.
    start_slot: u64 = 1,
    /// Application driver; null → the omakase default (§8.4).
    driver: ?core.driver.Driver = null,
    /// Engine-thread delivery hook; null → the `waitExternalized` queue.
    /// `AppNode` supplies its own (§8.5); bytes-level apps rarely need it.
    delivery: ?DeliveryHook = null,
    /// Receives the failure message when `create` errors.
    diagnostic: ?*Diagnostic = null,
};

const SlotOwn = struct {
    nom: ?[]u8 = null,
    ballot: ?[]u8 = null,

    fn free(self: *SlotOwn, gpa: std.mem.Allocator) void {
        if (self.nom) |b| gpa.free(b);
        if (self.ballot) |b| gpa.free(b);
        self.* = .{};
    }
};

const InputItem = struct {
    input: engine.Input,
    source_peer: ?usize,
};

/// Mutex+condvar FIFO of pending engine inputs. Payloads are owned; the engine
/// thread frees them after `pushInput` (which copies what it keeps).
/// This Zig's sync primitives live under std.Io and take `io` on every call
/// (cancellation is a no-op on our raw std.Thread workers, so the
/// *Uncancelable variants are used to avoid the error union).
const InputQueue = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    mu: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    items: std.ArrayList(InputItem) = .empty,
    head: usize = 0,
    closed: bool = false,

    fn push(self: *InputQueue, item: InputItem) void {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        if (self.closed) {
            var in = item.input;
            core.host_codec.freeInput(self.gpa, &in);
            return;
        }
        self.items.append(self.gpa, item) catch {
            // OOM enqueuing: drop the input (freeing it) rather than crash;
            // the engine degrades, it does not corrupt.
            var in = item.input;
            core.host_codec.freeInput(self.gpa, &in);
            log.err("input queue OOM; dropped one input", .{});
            return;
        };
        self.cond.signal(self.io);
    }

    /// Block for the next item; null once closed and drained.
    fn pop(self: *InputQueue) ?InputItem {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        while (self.head >= self.items.items.len and !self.closed) self.cond.waitUncancelable(self.io, &self.mu);
        if (self.head >= self.items.items.len) return null;
        const it = self.items.items[self.head];
        self.head += 1;
        if (self.head == self.items.items.len) {
            self.items.clearRetainingCapacity();
            self.head = 0;
        }
        return it;
    }

    fn close(self: *InputQueue) void {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        self.closed = true;
        self.cond.broadcast(self.io);
    }

    fn deinit(self: *InputQueue) void {
        for (self.items.items[self.head..]) |*it| core.host_codec.freeInput(self.gpa, &it.input);
        self.items.deinit(self.gpa);
        self.* = undefined;
    }
};

pub const Node = struct {
    gpa: std.mem.Allocator,
    io: std.Io,

    network_id: [32]u8,
    node_id: [32]u8,
    local_qset_hash: [32]u8,
    watcher: bool,

    eng: engine.Engine,
    q: InputQueue,
    store: store_mod.Store,
    wheel: timers_mod.Wheel,
    ov: overlay_mod.Overlay,

    engine_thread: ?std.Thread = null,
    failed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// False during synchronous restart replay (before the overlay binds);
    /// true once the node is serving the network. Effect dispatch suppresses
    /// network sends while false — restore rebroadcasts only need to populate
    /// `own_latest` for on-connect catch-up, and there are no peers yet.
    /// Set once (create thread) before the engine thread spawns; the spawn is
    /// the happens-before edge, so a plain bool is safe.
    live: bool = false,
    /// Engine-thread-only scratch: the source peer of the input being drained,
    /// used to exclude the origin from `forward_envelope` relays.
    cur_source: ?usize = null,

    own_mu: std.Io.Mutex = .init,
    own_latest: std.AutoHashMapUnmanaged(u64, SlotOwn) = .empty,

    prop_mu: std.Io.Mutex = .init,
    current_slot: u64,
    last_ext_value: []u8, // owned; empty slice initially
    proposal_queue: std.ArrayList([]u8) = .empty,
    nominating: bool = false,

    ext_mu: std.Io.Mutex = .init,
    ext_cond: std.Io.Condition = .init,
    ext_queue: std.ArrayList(Externalized) = .empty,
    ext_closed: bool = false,
    /// `Options.delivery`: when set, `deliverSlot` calls it instead of
    /// queueing for `waitExternalized`. Read on the engine thread (and on
    /// the creating thread during the journal-tail replay).
    delivery: ?DeliveryHook,

    /// Engine-thread-only: out-of-order externalizations awaiting their turn
    /// (values owned), and the next slot to hand the app (§11.2 ordering).
    pending_ext: std.AutoHashMapUnmanaged(u64, []u8) = .empty,
    next_deliver: u64,
    /// Engine-thread-only: the delivered frontier at the last successful log
    /// compaction. Compaction runs whenever the frontier enters a new
    /// 64-slot bucket past this (§10 "every 64 delivered slots") — tracked
    /// rather than tested with `frontier % 64 == 0`, because one drain can
    /// step over a boundary when out-of-order catch-up slots are buffered.
    last_compact_frontier: u64 = 0,
    /// Slots below this are purged; the timer wheel drops stale fires for
    /// them (read on the wheel thread).
    purge_floor: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// qset hashes this node actually asked the network for (bounded).
    /// Guards the on-disk qset cache: unsolicited qset frames are still fed
    /// to the engine (it validates + bounds its own memory cache) but are
    /// never persisted — otherwise any peer could fill the disk (review
    /// finding, §9.1 trust model).
    qset_mu: std.Io.Mutex = .init,
    req_qsets: std.AutoHashMapUnmanaged([32]u8, void) = .empty,

    /// Node-owned copies of the peer dial specs. The overlay's dialer threads
    /// re-parse these on every reconnect for the node's whole lifetime, so
    /// borrowing the caller's slices would be a use-after-free footgun (it
    /// WAS one — an e2e dialer crashed parsing a freed string).
    peer_specs: [][]u8 = &.{},

    /// `Options.max_value_bytes`: `propose` rejects larger values up front
    /// (`ValueTooLarge`) instead of letting the engine drop them silently.
    max_value_bytes: u32,

    /// Anti-entropy thread (§9.2 host policy): every `resync_interval_ms` it
    /// re-floods our latest own envelopes for live slots + getSlotState(0).
    /// The engine (faithfully to stellar-core) only emits when its state
    /// CHANGES — so after a partition heals with connections intact, or after
    /// message loss, two quiescent sides would otherwise wait on each other
    /// forever. Periodic re-flooding is the liveness backstop; receivers dedup
    /// via engine freshness, so there is no relay amplification.
    resync_thread: ?std.Thread = null,
    resync_stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    // M6:example logs — hobbyist-facing connectivity counters. `peers_live`
    // is the number of Hello-complete connections right now (up minus down;
    // a pair of nodes that dial EACH OTHER holds two — one per direction —
    // so a full 3-node mesh shows up to 4), `peer_downs` counts on_peer_down
    // events. Both feed only log lines and tests; no protocol decision reads
    // them.
    peers_live: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    peer_downs: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn allocator(self: *Node) std.mem.Allocator {
        return self.gpa;
    }

    // -------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------

    /// Build and start a node. Fail-fast: every misconfiguration is checked
    /// in a fixed order (passphrase → identity → limits → peers → quorum →
    /// data_dir → engine → store/recovery → listener → threads) and reported
    /// as ONE `CreateError` member with a message in `options.diagnostic`.
    pub fn create(gpa: std.mem.Allocator, io: std.Io, options: Options) CreateError!*Node {
        const opts = options;
        const diag = opts.diagnostic;

        // ---- passphrase ----
        if (opts.network.len == 0) {
            return fail(diag, error.NetworkPassphraseEmpty, ".network is empty; set it to a passphrase unique to your application, e.g. \"my-counter-app v1\" (it becomes the networkId, which partitions your network from every other slcp network).", .{});
        }
        const network_id = crypto.networkIdFromPassphrase(opts.network);

        // ---- identity ----
        var node_id: [32]u8 = undefined;
        var secret_seed: ?[32]u8 = null;
        if (opts.watcher) {
            if (opts.secret_seed != null) {
                return fail(diag, error.WatcherHasIdentity, ".watcher = true but .secret_seed is set; a watcher never signs — drop .secret_seed (and .key_file), or set .watcher = false to validate with that identity.", .{});
            }
            if (opts.key_file) |path| {
                return fail(diag, error.WatcherHasIdentity, ".watcher = true but .key_file = \"{s}\" is set; a watcher never signs — drop .key_file (and .secret_seed), or set .watcher = false to validate with that key.", .{path});
            }
            if (opts.node_id) |n| {
                node_id = n;
            } else {
                const kp = keys_mod.ephemeral(io) catch |e| {
                    return fail(diag, error.EngineFailed, "cannot draw OS entropy for the watcher's ephemeral node id: {t}; the system's secure random source is unavailable.", .{e});
                };
                node_id = kp.public_key;
            }
        } else if (opts.secret_seed != null and opts.key_file != null) {
            return fail(diag, error.ConflictingIdentity, ".key_file = \"{s}\" and .secret_seed are both set; provide ONE identity source (drop .secret_seed to use the key file, or drop .key_file to use the seed).", .{opts.key_file.?});
        } else if (opts.secret_seed) |seed| {
            const derived = crypto.publicKeyFromSeed(seed) catch |e| {
                return fail(diag, error.EngineFailed, ".secret_seed is not a usable Ed25519 seed ({t}); use 32 random bytes (slcp key new <file> mints one).", .{e});
            };
            if (opts.node_id) |n| {
                if (!std.mem.eql(u8, &n, &derived)) {
                    return fail(diag, error.IdentityMismatch, ".node_id {s} is not the public key of .secret_seed (which derives {s}); drop .node_id (it is derived from the seed) or fix the seed.", .{ &std.fmt.bytesToHex(n, .lower), &std.fmt.bytesToHex(derived, .lower) });
                }
            }
            node_id = derived;
            secret_seed = seed;
        } else if (opts.key_file) |path| {
            const kp = try loadKeyFile(io, path, diag);
            if (opts.node_id) |n| {
                if (!std.mem.eql(u8, &n, &kp.public_key)) {
                    return fail(diag, error.IdentityMismatch, ".node_id {s} is not the public key of .key_file \"{s}\" (which holds {s}); drop .node_id (it is derived from the key file) or point .key_file at the right file.", .{ &std.fmt.bytesToHex(n, .lower), path, &std.fmt.bytesToHex(kp.public_key, .lower) });
                }
            }
            node_id = kp.public_key;
            secret_seed = kp.seed;
        } else if (opts.node_id) |n| {
            return fail(diag, error.NoIdentity, ".node_id {s} alone cannot sign; add the matching .secret_seed or .key_file, or set .watcher = true for a node that only follows.", .{&std.fmt.bytesToHex(n, .lower)});
        } else {
            return fail(diag, error.NoIdentity, "no identity: set .key_file (e.g. \"slcp.key\" — created on first run, then reused) or .secret_seed, or set .watcher = true for a node that only follows.", .{});
        }
        const node_hex = std.fmt.bytesToHex(node_id, .lower);

        // ---- limits ----
        if (opts.max_value_bytes < 1 or opts.max_value_bytes > 65536) {
            return fail(diag, error.MaxValueBytesOutOfRange, ".max_value_bytes {d} is outside [1, 65536]; pick the largest value your app will ever propose (the default is 4096).", .{opts.max_value_bytes});
        }
        if (opts.start_slot == 0) {
            return fail(diag, error.StartSlotZero, ".start_slot is 0 but slots start at 1; drop .start_slot (default 1) or set it to the first slot this node should nominate.", .{});
        }

        // ---- peer specs ----
        for (opts.peers, 0..) |spec, i| {
            overlay_mod.validatePeerSpec(spec) catch |e| {
                const why: []const u8 = switch (e) {
                    error.MissingPort => "no port",
                    error.EmptyHost => "empty host",
                    error.BadPort => "port must be 1..65535",
                    error.BadHost => "host is neither an IP literal nor a valid hostname",
                };
                return fail(diag, error.BadPeerSpec, ".peers[{d}] = \"{s}\" is not host:port ({s}); use \"a.example.com:7311\", \"10.0.0.2:7311\" or \"[2001:db8::2]:7311\".", .{ i, spec, why });
            };
            for (opts.peers[0..i], 0..) |prev, j| {
                if (std.mem.eql(u8, prev, spec)) {
                    return fail(diag, error.DuplicatePeer, ".peers[{d}] = \"{s}\" repeats .peers[{d}]; list each peer once.", .{ i, spec, j });
                }
            }
            if (opts.listen_port != 0) {
                const hp = overlay_mod.parseHostPort(spec) catch unreachable; // validated above
                if (hp.port == opts.listen_port and isLoopbackHost(hp.host)) {
                    return fail(diag, error.PeerIsSelf, ".peers[{d}] = \"{s}\" is this node's own listen address; list only the OTHER nodes.", .{ i, spec });
                }
            }
        }

        // ---- quorum ----
        if (opts.quorum.memberCount() == 0) {
            return fail(diag, error.QuorumEmpty, ".quorum has no members (threshold {d} of 0); list the validators, e.g. slcp.Quorum.twoThirdsOf(&.{{ pk_a, pk_b, pk_c }}).", .{opts.quorum.threshold});
        }
        var owned = try opts.quorum.toOwned(gpa);
        var owned_live = true;
        errdefer if (owned_live) owned.deinit(gpa);
        if (!opts.watcher and !opts.quorum.containsNode(node_id)) {
            if (opts.include_self) {
                const grown = try gpa.realloc(owned.validators, owned.validators.len + 1);
                grown[grown.len - 1] = node_id;
                owned.validators = grown;
                create_log.info("added self {s} to the top-level quorum", .{&node_hex});
            } else {
                var wbuf: [512]u8 = undefined;
                var w: std.Io.Writer = .fixed(&wbuf);
                lint_report.writeSelfAbsent(&w, node_id) catch {};
                create_log.warn("{s}", .{std.mem.trimEnd(u8, w.buffered(), "\n")});
            }
        }
        // Structural checks on the owned tree, in the order the messages
        // are most useful; `validateAndNormalize` is the authority and its
        // errors map 1:1 to the same members as a fallback.
        if (lint_report.firstBadThreshold(&owned)) |bad| {
            return fail(diag, error.QuorumThresholdOutOfRange, ".quorum threshold {d} is outside [1, {d}] for a level with {d} members; use slcp.Quorum.twoThirdsOf (the blessed default) or a threshold within range.", .{ bad.threshold, bad.members, bad.members });
        }
        if (try lint_report.firstDuplicate(gpa, &owned)) |dup| {
            return fail(diag, error.QuorumDuplicateNode, ".quorum lists validator {s} more than once; each node appears once in the whole tree.", .{&std.fmt.bytesToHex(dup, .lower)});
        }
        if (lint_report.depth(&owned) > qset.max_depth) {
            return fail(diag, error.QuorumTooDeep, ".quorum nests {d} levels deep but the wire limit is {d}; flatten the inner sets (orgs one level down is the usual shape).", .{ lint_report.depth(&owned), qset.max_depth });
        }
        if (lint_report.totalValidators(&owned) > qset.max_total_validators) {
            return fail(diag, error.QuorumTooManyValidators, ".quorum names {d} validators but the wire limit is {d}; group them into inner sets or trim the list.", .{ lint_report.totalValidators(&owned), qset.max_total_validators });
        }
        qset.validateAndNormalize(gpa, &owned) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.EmptyQuorumSet => return fail(diag, error.QuorumEmpty, ".quorum has a level with no members; every level needs at least one validator or inner set.", .{}),
            error.ThresholdOutOfRange => return fail(diag, error.QuorumThresholdOutOfRange, ".quorum has a level whose threshold is outside [1, member count]; use slcp.Quorum.twoThirdsOf (the blessed default).", .{}),
            error.DuplicateNode => return fail(diag, error.QuorumDuplicateNode, ".quorum lists a validator more than once; each node appears once in the whole tree.", .{}),
            error.DepthExceeded => return fail(diag, error.QuorumTooDeep, ".quorum nests deeper than the wire limit of {d} levels; flatten the inner sets.", .{qset.max_depth}),
            error.TooManyValidators => return fail(diag, error.QuorumTooManyValidators, ".quorum names more than {d} validators; group them into inner sets or trim the list.", .{qset.max_total_validators}),
            else => return fail(diag, error.EngineFailed, ".quorum could not be normalized: {t}; please report this with your quorum spec.", .{e}),
        };
        const findings = try qset.lint(gpa, &owned); // OOM only
        defer gpa.free(findings);
        for (findings) |f| {
            if (f.level != .err) continue;
            if (!opts.allow_unsafe_quorum) {
                const n = f.members;
                const t = f.threshold;
                const two_thirds = std.math.divCeil(u32, 2 * n, 3) catch unreachable;
                return fail(diag, error.UnsafeQuorum, ".quorum is unsafe: {d}-of-{d} is below a majority, so two disjoint \"quorums\" can form inside your own slice (a fork machine); use a threshold of at least {d} (slcp.Quorum.twoThirdsOf gives {d}), or set .allow_unsafe_quorum = true to start anyway.", .{ t, n, n / 2 + 1, two_thirds });
            }
        }
        for (findings) |f| {
            var wbuf: [512]u8 = undefined;
            var w: std.Io.Writer = .fixed(&wbuf);
            lint_report.writeFinding(&w, f, &owned) catch {};
            const line = std.mem.trimEnd(u8, w.buffered(), "\n");
            // Both at warn: an ERROR finding only reaches this loop when
            // the operator set `.allow_unsafe_quorum = true`, i.e. accepted
            // it knowingly (and the test runner fails any test that logs at
            // err level).
            switch (f.level) {
                .err => create_log.warn("{s} (.allow_unsafe_quorum = true: starting anyway)", .{line}),
                .warning => create_log.warn("{s}", .{line}),
            }
        }
        // Hash + framed form (for getQset answering) BEFORE the engine takes
        // ownership of the tree.
        const local_hash = qset.hashNormalized(gpa, &owned) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return fail(diag, error.EngineFailed, ".quorum could not be hashed: {t}; please report this with your quorum spec.", .{e}),
        };
        const framed_local = ownedQsetToFramed(gpa, &owned) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return fail(diag, error.EngineFailed, ".quorum could not be encoded: {t}; please report this with your quorum spec.", .{e}),
        };
        defer gpa.free(framed_local);

        // ---- data_dir ----
        if (opts.data_dir.len == 0) {
            return fail(diag, error.DataDirEmpty, ".data_dir is empty; set it to a directory this node owns, e.g. \"slcp-data\" (created on first run).", .{});
        }
        try checkDataDir(io, opts.data_dir, network_id, node_id, opts.watcher, diag);

        // ---- engine ----
        var limits = core.limits.Limits{};
        limits.max_value_bytes = opts.max_value_bytes;
        const cfg = engine.Config{
            .network_id = network_id,
            .node_id = node_id,
            .secret_seed = secret_seed,
            .quorum_set = owned,
            .strict_canonical = opts.strict_canonical,
            .limits = limits,
        };
        const drv = opts.driver orelse core.driver.Driver.default();

        const self = try gpa.create(Node);
        errdefer gpa.destroy(self);

        self.* = .{
            .gpa = gpa,
            .io = io,
            .network_id = cfg.network_id,
            .node_id = node_id,
            .local_qset_hash = local_hash,
            .watcher = opts.watcher or secret_seed == null,
            .eng = undefined,
            .q = .{ .gpa = gpa, .io = io },
            .store = undefined,
            .wheel = undefined,
            .ov = undefined,
            .current_slot = opts.start_slot,
            .next_deliver = opts.start_slot,
            .last_ext_value = &.{},
            .delivery = opts.delivery,
            .max_value_bytes = opts.max_value_bytes,
        };

        // Engine.init does NOT free cfg.quorum_set on failure; we still own
        // it until this succeeds.
        self.eng = engine.Engine.init(gpa, cfg, drv) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return fail(diag, error.EngineFailed, "the consensus engine could not be initialized: {t}; this is a bug in slcp or an exotic limit — please report it with your options.", .{e}),
        };
        owned_live = false;
        errdefer self.eng.deinit();

        // ---- store + recovery ----
        self.store = store_mod.Store.open(gpa, io, opts.data_dir) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Busy => return fail(diag, error.DataDirBusy, ".data_dir \"{s}\" is in use by another live slcp node (the lock file {s}/lock is held); one identity must never run twice — stop the other process, or point this node at its own data_dir.", .{ opts.data_dir, opts.data_dir }),
            else => return fail(diag, error.DataDirUnusable, ".data_dir \"{s}\" cannot be used: the logs could not be opened ({t}); check the path, the filesystem and free space.", .{ opts.data_dir, e }),
        };
        errdefer self.store.deinit();

        // Cache our own qset on disk so getQset can answer it after restart.
        self.store.putQset(local_hash, framed_local);

        self.wheel = timers_mod.Wheel.init(gpa, io, onTimerFire, self);

        // Own the peer specs: the overlay's dialers re-parse them on every
        // reconnect for the node's lifetime; never borrow the caller's.
        self.peer_specs = try gpa.alloc([]u8, opts.peers.len);
        var specs_done: usize = 0;
        errdefer {
            for (self.peer_specs[0..specs_done]) |s| gpa.free(s);
            gpa.free(self.peer_specs);
        }
        for (opts.peers, 0..) |p, i| {
            self.peer_specs[i] = try gpa.dupe(u8, p);
            specs_done += 1;
        }

        self.ov = try overlay_mod.Overlay.init(gpa, io, .{
            .listen_port = opts.listen_port,
            .peers = self.peer_specs,
            .network_id_prefix = self.network_id[0..8].*,
            .node_id = node_id,
        }, .{
            .ctx = self,
            .on_recv = onRecv,
            .on_peer_up = onPeerUp,
            .on_peer_down = onPeerDown, // M6:example logs
        });

        // ---- Restart recovery (§10), synchronous, pre-threads ----
        var rec = self.store.recover(gpa) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return fail(diag, error.DataDirUnusable, ".data_dir \"{s}\" cannot be used: the logs could not be read back ({t}); check the filesystem, or move the directory aside to start fresh.", .{ opts.data_dir, e }),
        };
        defer store_mod.Store.deinitRecovery(gpa, &rec);

        if (opts.start_slot > 1) {
            if (rec.externalized_hwm) |hwm| {
                if (opts.start_slot <= hwm) {
                    return fail(diag, error.StartSlotBehindJournal, ".start_slot {d} is at or below the journal high-water mark {d} in {s}; drop .start_slot (the node resumes at {d}) or use a fresh data_dir.", .{ opts.start_slot, hwm, opts.data_dir, hwm + 1 });
                }
            }
        }

        self.wheel.start() catch |e| { // arms during restore are honored
            return fail(diag, error.ThreadSpawnFailed, "cannot start the engine/overlay thread: {t}.", .{e});
        };
        errdefer self.wheel.stop();

        if (rec.torn_tail_repaired) {
            // The ROUTINE crash artifact (power loss mid-append): the store
            // truncated the torn record; the valid prefix is fully trusted
            // (§10: persist precedes broadcast, so a torn final record was
            // never sent). The node stays a validator.
            log.warn("torn log tail repaired on recovery (normal after a crash)", .{});
        }
        if (rec.own_log_corrupt and !self.watcher) {
            log.err("own.log integrity failure — falling back to WATCHER mode " ++
                "for the node's lifetime (safe: a watcher never emits, so it " ++
                "cannot emit stale-vs-self). Slots up to the externalized " ++
                "high-water mark + 1 were at risk.", .{});
            // Rebuild the engine as a watcher (secret_seed cleared). The old
            // engine owns a normalized qset clone; give the new one a fresh
            // clone.
            const qs_clone = try qset.clone(gpa, &self.eng.cfg.quorum_set);
            self.eng.deinit();
            var wcfg = cfg;
            wcfg.secret_seed = null;
            wcfg.quorum_set = qs_clone;
            self.eng = engine.Engine.init(gpa, wcfg, drv) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return fail(diag, error.EngineFailed, "the consensus engine could not be re-initialized in watcher mode: {t}; please report this.", .{e}),
            };
            self.watcher = true;
        }

        // Order matters (M6 S3; the M5 order was restore → frontier → tail):
        //   1. the delivery frontier comes from the journal high-water mark
        //      FIRST, so nothing the own.log restore below can emit for a
        //      journaled slot is ever handed to the app out of order;
        //   2. the journal tail is replayed through `deliverSlot` — the same
        //      chokepoint the engine thread uses — in ascending slot order
        //      (a delivery hook sees it here, synchronously, before any
        //      thread exists);
        //   3. THEN the own.log restore rebuilds protocol state.
        // Resume proposal slot past the highest externalized slot on disk.
        if (rec.externalized_hwm) |hwm| {
            if (hwm + 1 > self.current_slot) self.current_slot = hwm + 1;
            // Consensus delivery resumes after the journal high-water mark.
            if (hwm + 1 > self.next_deliver) self.next_deliver = hwm + 1;
        }
        // §10: externalized.log is the app-visible journal. A crash can land
        // between journal append and app consumption, so REPLAY the (compaction
        // -bounded) journal tail into the app stream — the app dedups by slot
        // (the §10 contract). Without this, journaled-but-unconsumed values
        // would be silently lost across a restart (review finding).
        for (rec.ext_tail) |r| {
            const v = try gpa.dupe(u8, r.value);
            self.deliverSlot(r.slot, v) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return fail(diag, error.EngineFailed, ".delivery hook refused journaled slot {d} of {s} during restart replay: {t}; the app cannot consume a value the network already agreed on, so the node will not start.", .{ r.slot, opts.data_dir, e }),
            };
        }
        if (!rec.own_log_corrupt) {
            for (rec.own_latest) |r| {
                self.applyInput(.{
                    .input = .{ .restore_own_envelope = .{ .bytes = try gpa.dupe(u8, r.envelope) } },
                    .source_peer = null,
                });
            }
        }

        // ---- Go live ----
        self.ov.start() catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.AddressInUse => return fail(diag, error.ListenPortInUse, ".listen_port {d} is already in use on this machine (another slcp node, or a stale process); stop it or pick a different port.", .{opts.listen_port}),
            error.AccessDenied => {
                if (opts.listen_port < 1024) {
                    return fail(diag, error.ListenPortPrivileged, ".listen_port {d} is a privileged port (< 1024) and this process may not bind it; use a port >= 1024 (7311 is the docs' default).", .{opts.listen_port});
                }
                return fail(diag, error.ListenFailed, "cannot listen on .listen_port {d}: AccessDenied; a sandbox or firewall policy refuses the bind.", .{opts.listen_port});
            },
            error.ThreadSpawnFailed => return fail(diag, error.ThreadSpawnFailed, "cannot start the engine/overlay thread: {t}.", .{e}),
            else => return fail(diag, error.ListenFailed, "cannot listen on .listen_port {d}: {t}; check the port and the network stack.", .{ opts.listen_port, e }),
        };
        errdefer self.ov.stop();
        // M6:example logs — the first line a hobbyist looks for.
        create_log.info("node {s} listening on port {d}; dialing {d} peer(s)", .{ &std.fmt.bytesToHex(node_id, .lower), self.ov.boundPort(), self.peer_specs.len });

        self.live = true; // dispatch may now emit to the network
        self.engine_thread = std.Thread.spawn(.{}, engineLoop, .{self}) catch |e| {
            return fail(diag, error.ThreadSpawnFailed, "cannot start the engine/overlay thread: {t}.", .{e});
        };
        // If the SECOND spawn fails, the unwind must join the engine thread
        // BEFORE the earlier errdefers tear down the store/engine/overlay it
        // is actively using (and before gpa.destroy frees the queue it is
        // parked on) — review finding: spawn-failure UAF.
        errdefer {
            self.q.close();
            if (self.engine_thread) |t| t.join();
        }
        self.resync_thread = std.Thread.spawn(.{}, resyncLoop, .{self}) catch |e| {
            return fail(diag, error.ThreadSpawnFailed, "cannot start the engine/overlay thread: {t}.", .{e});
        };
        return self;
    }

    /// Static explanation of a `CreateError` (the module-level `explain`).
    pub const explain = explainCreateError;

    /// Resolve `.key_file`: load it, or mint it on first run — never both
    /// silently. Every failure is mapped to a specific `KeyFile*` member.
    fn loadKeyFile(io: std.Io, path: []const u8, diag: ?*Diagnostic) CreateError!keys_mod.KeyPair {
        if (keys_mod.load(io, path)) |kp| {
            // The mint ceremony writes 0600; a file copied in by cp/scp or
            // restored under umask 022 arrives 0644 and would otherwise be
            // accepted in silence (S8 finding). Warn, do not refuse: the
            // seed is still this node's identity and a running deployment
            // must keep starting — the operator fixes the mode.
            if (keys_mod.modeOf(io, path)) |mode| {
                if (keys_mod.modeTooOpen(mode)) {
                    create_log.warn(".key_file \"{s}\" is mode 0{o}: readable by group/other, not the 0600 slcp mints; run `chmod 600 {s}`", .{ path, mode, path });
                }
            } else |_| {}
            return kp;
        } else |err| switch (err) {
            error.FileNotFound => {
                const kp = keys_mod.createNew(io, path) catch |cerr| switch (cerr) {
                    error.FileNotFound => return fail(diag, error.KeyFileDirMissing, ".key_file \"{s}\": its directory does not exist; create the directory first (slcp creates the key file, not its parent).", .{path}),
                    error.AccessDenied, error.PermissionDenied => return fail(diag, error.KeyFileAccessDenied, ".key_file \"{s}\" cannot be created (permission denied); fix the directory permissions or point .key_file somewhere this user can write.", .{path}),
                    error.KeyFileExists => {
                        // Raced with another creator: the file is there now.
                        return keys_mod.load(io, path) catch |e2| {
                            return fail(diag, error.KeyFileIoFailed, ".key_file \"{s}\" appeared while being created but could not be read: {t}.", .{ path, e2 });
                        };
                    },
                    else => return fail(diag, error.KeyFileIoFailed, ".key_file \"{s}\" could not be created: {t}; check the path and the filesystem.", .{ path, cerr }),
                };
                create_log.info("created new key file {s} (public key {s})", .{ path, &std.fmt.bytesToHex(kp.public_key, .lower) });
                return kp;
            },
            error.BadKeyFile => {
                const size: u64 = if (std.Io.Dir.cwd().statFile(io, path, .{})) |st| st.size else |_| 0;
                return fail(diag, error.KeyFileBad, ".key_file \"{s}\" holds {d} bytes, not the 32-byte raw seed slcp writes; restore the original file, or move it aside to mint a new identity on the next start.", .{ path, size });
            },
            error.AccessDenied, error.PermissionDenied => return fail(diag, error.KeyFileAccessDenied, ".key_file \"{s}\" cannot be read (permission denied); fix the file permissions or point .key_file somewhere this user can read.", .{path}),
            error.IsDir => return fail(diag, error.KeyFileBad, ".key_file \"{s}\" is a directory, not a 32-byte raw seed file; point .key_file at the key file itself.", .{path}),
            else => return fail(diag, error.KeyFileIoFailed, ".key_file \"{s}\" could not be read: {t}; check the path and the filesystem.", .{ path, err }),
        }
    }

    /// The identity-marker line format (§10 data_dir layout, M6):
    /// `slcp-identity-v1\n<hex16 of networkId[0..8]>\n<hex64 node_id>\n`.
    const identity_header = "slcp-identity-v1";
    const identity_file = "identity";

    /// Create/open `data_dir` and bind it to this network + key through the
    /// `identity` marker: written on first create, compared afterwards. A
    /// watcher skips the node comparison (its id is ephemeral).
    fn checkDataDir(io: std.Io, data_dir: []const u8, network_id: [32]u8, node_id: [32]u8, watcher: bool, diag: ?*Diagnostic) CreateError!void {
        var dir = std.Io.Dir.cwd().createDirPathOpen(io, data_dir, .{}) catch |e| switch (e) {
            error.NotDir => return fail(diag, error.DataDirNotADirectory, ".data_dir \"{s}\" exists but is not a directory (the path or one of its components is a regular file); point .data_dir at a directory or remove the file.", .{data_dir}),
            error.AccessDenied, error.PermissionDenied => return fail(diag, error.DataDirAccessDenied, ".data_dir \"{s}\" cannot be created or opened (permission denied); fix the permissions or pick a directory this user can write.", .{data_dir}),
            else => return fail(diag, error.DataDirUnusable, ".data_dir \"{s}\" cannot be used: {t}; check the path, the filesystem and free space.", .{ data_dir, e }),
        };
        defer dir.close(io);

        const net_hex = std.fmt.bytesToHex(network_id[0..8].*, .lower);
        const node_hex = std.fmt.bytesToHex(node_id, .lower);
        var expect_buf: [128]u8 = undefined;
        const expected = std.fmt.bufPrint(&expect_buf, identity_header ++ "\n{s}\n{s}\n", .{ &net_hex, &node_hex }) catch unreachable;

        var have_buf: [256]u8 = undefined;
        if (dir.openFile(io, identity_file, .{})) |opened| {
            var f = opened;
            defer f.close(io);
            const n = f.readPositionalAll(io, &have_buf, 0) catch |e| {
                return fail(diag, error.DataDirUnusable, ".data_dir \"{s}\": the identity marker could not be read ({t}); check the filesystem.", .{ data_dir, e });
            };
            var lines = std.mem.splitScalar(u8, have_buf[0..n], '\n');
            const header = lines.next() orelse "";
            const have_net = lines.next() orelse "";
            const have_node = lines.next() orelse "";
            if (!std.mem.eql(u8, header, identity_header) or have_net.len != 16 or have_node.len != 64) {
                return fail(diag, error.DataDirUnusable, ".data_dir \"{s}\": the identity marker ({s}/{s}) is malformed; if this data_dir really belongs to this node, delete that file and it will be rewritten.", .{ data_dir, data_dir, identity_file });
            }
            if (!std.mem.eql(u8, have_net, &net_hex)) {
                return fail(diag, error.DataDirOtherNetwork, ".data_dir {s} was created for a different network (id prefix {s}, this node's is {s}); use a fresh data_dir per network, or fix .network.", .{ data_dir, have_net, &net_hex });
            }
            if (!watcher and !std.mem.eql(u8, have_node, &node_hex)) {
                return fail(diag, error.DataDirOtherNode, ".data_dir {s} belongs to node {s} but this node is {s}; a data_dir is bound to one key — restore the original key file or start a fresh data_dir.", .{ data_dir, have_node, &node_hex });
            }
        } else |e| switch (e) {
            error.FileNotFound => {
                var f = dir.createFile(io, identity_file, .{}) catch |ce| switch (ce) {
                    error.AccessDenied, error.PermissionDenied => return fail(diag, error.DataDirAccessDenied, ".data_dir \"{s}\" is not writable (permission denied); fix the permissions or pick a directory this user can write.", .{data_dir}),
                    else => return fail(diag, error.DataDirUnusable, ".data_dir \"{s}\" cannot be used: the identity marker could not be created ({t}); check the filesystem and free space.", .{ data_dir, ce }),
                };
                defer f.close(io);
                f.writeStreamingAll(io, expected) catch |we| {
                    return fail(diag, error.DataDirUnusable, ".data_dir \"{s}\" cannot be used: the identity marker could not be written ({t}); check the filesystem and free space.", .{ data_dir, we });
                };
                f.sync(io) catch {};
            },
            error.AccessDenied, error.PermissionDenied => return fail(diag, error.DataDirAccessDenied, ".data_dir \"{s}\" is not readable (permission denied); fix the permissions or pick a directory this user can use.", .{data_dir}),
            else => return fail(diag, error.DataDirUnusable, ".data_dir \"{s}\" cannot be used: the identity marker could not be opened ({t}); check the filesystem.", .{ data_dir, e }),
        }
    }

    /// `PeerIsSelf` host test: 127.0.0.0/8, `::1`, or `localhost`.
    fn isLoopbackHost(host: []const u8) bool {
        if (std.ascii.eqlIgnoreCase(host, "localhost")) return true;
        const addr = std.Io.net.IpAddress.parse(host, 1) catch return false;
        return switch (addr) {
            .ip4 => |a| a.bytes[0] == 127,
            .ip6 => |a| blk: {
                var v6_loopback: [16]u8 = @splat(0);
                v6_loopback[15] = 1;
                break :blk std.mem.eql(u8, &a.bytes, &v6_loopback);
            },
        };
    }

    pub fn deinit(self: *Node) void {
        // The resync thread touches own_mu and the overlay — stop it first.
        self.resync_stop.store(true, .release);
        if (self.resync_thread) |t| t.join();

        // Wake any app thread blocked in waitExternalized so it returns null.
        self.ext_mu.lockUncancelable(self.io);
        self.ext_closed = true;
        self.ext_cond.broadcast(self.io);
        self.ext_mu.unlock(self.io);

        // Order matters. Close the queue and JOIN the engine thread first, so
        // no effect dispatch can touch the overlay/wheel/store after we start
        // tearing them down. During this final drain the overlay and wheel are
        // still live (safe to call); external producers (overlay readers, the
        // wheel) may still push, but push-after-close just frees the input.
        self.q.close();
        if (self.engine_thread) |t| t.join();

        // Now nothing dispatches. Stop the producers and free the sinks.
        self.ov.stop();
        self.wheel.stop();
        self.ov.deinit();
        self.wheel.deinit();

        // Dialer threads (the peer-spec readers) were joined in ov.stop().
        for (self.peer_specs) |s| self.gpa.free(s);
        self.gpa.free(self.peer_specs);

        self.q.deinit();
        self.store.deinit();
        self.eng.deinit();

        {
            var it = self.own_latest.iterator();
            while (it.next()) |e| e.value_ptr.free(self.gpa);
            self.own_latest.deinit(self.gpa);
        }
        for (self.proposal_queue.items) |v| self.gpa.free(v);
        self.proposal_queue.deinit(self.gpa);
        if (self.last_ext_value.len > 0) self.gpa.free(self.last_ext_value);
        for (self.ext_queue.items) |e| self.gpa.free(e.value);
        self.ext_queue.deinit(self.gpa);
        {
            var it = self.pending_ext.valueIterator();
            while (it.next()) |v| self.gpa.free(v.*);
            self.pending_ext.deinit(self.gpa);
        }
        self.req_qsets.deinit(self.gpa);

        const gpa = self.gpa;
        self.* = undefined;
        gpa.destroy(self);
    }

    // -------------------------------------------------------------------
    // App surface
    // -------------------------------------------------------------------

    /// Queue `value` to be nominated for the next available slot (§11).
    /// Watchers cannot propose; empty and oversized (> `max_value_bytes`)
    /// values are rejected up front rather than dropped by the engine.
    pub fn propose(self: *Node, value: []const u8) ProposeError!void {
        if (self.watcher) return error.WatcherCannotPropose;
        if (value.len == 0) return error.ValueEmpty;
        if (value.len > self.max_value_bytes) return error.ValueTooLarge;
        const copy = try self.gpa.dupe(u8, value);
        self.prop_mu.lockUncancelable(self.io);
        self.proposal_queue.append(self.gpa, copy) catch |e| {
            self.gpa.free(copy);
            self.prop_mu.unlock(self.io);
            return e;
        };
        self.prop_mu.unlock(self.io);
        self.maybeStartNomination();
    }

    pub const WaitOptions = struct {
        /// null = block until the next externalization or shutdown.
        timeout_ms: ?u64 = null,
    };

    /// Block for the next externalized slot in order. Returns null on timeout
    /// or shutdown. The returned `value` is owned by the caller.
    pub fn waitExternalized(self: *Node, wopts: WaitOptions) ?Externalized {
        self.ext_mu.lockUncancelable(self.io);
        defer self.ext_mu.unlock(self.io);
        while (self.ext_queue.items.len == 0 and !self.ext_closed) {
            if (wopts.timeout_ms) |ms| {
                self.ext_cond.waitTimeout(self.io, &self.ext_mu, msTimeout(ms)) catch return null;
            } else {
                self.ext_cond.waitUncancelable(self.io, &self.ext_mu);
            }
        }
        if (self.ext_queue.items.len == 0) return null;
        return self.ext_queue.orderedRemove(0);
    }

    /// Observability snapshot (racy counters). `.failed` is true when EITHER
    /// the engine latched (§7.2 DriverFault/EngineFailed) or the node itself
    /// went inert (`markFailed`: a hook refusal, a failed write-ahead append,
    /// a buffering OOM) — a halted node must not report itself healthy.
    pub fn stats(self: *Node) engine.Stats {
        var s = self.eng.stats();
        s.failed = s.failed or self.failed.load(.acquire);
        return s;
    }

    pub fn boundPort(self: *Node) u16 {
        return self.ov.boundPort();
    }

    // -------------------------------------------------------------------
    // Engine thread
    // -------------------------------------------------------------------

    const EmitTarget = union(enum) { all, one: usize, except: usize };

    /// Envelope-emit chokepoint. The engine's latest maps can hold ZERO-FRAME
    /// placeholder self-records (the lagger path — see nomination.zig's
    /// placeholderNomStored / ballot.zig's zero-frame self placeholders),
    /// whose bytes are deliberately empty and MUST NOT go on the wire — the
    /// engine contract says the host skips zero-length frames. This is that
    /// skip, for every envelope-bearing send path.
    fn emitEnvelope(self: *Node, comptime site: []const u8, target: EmitTarget, bytes: []const u8) void {
        if (bytes.len == 0) {
            log.debug("skipping zero-frame placeholder envelope at {s}", .{site});
            return;
        }
        switch (target) {
            .all => self.ov.broadcast(.{ .envelope = bytes }),
            .one => |id| self.ov.send(id, .{ .envelope = bytes }),
            .except => |id| self.ov.broadcastExcept(id, .{ .envelope = bytes }),
        }
    }

    fn engineLoop(self: *Node) void {
        while (self.q.pop()) |item| {
            self.applyInput(item);
        }
    }

    /// Anti-entropy loop (own thread): re-flood our latest own envelopes for
    /// live slots + getSlotState(0) every resync_interval_ms. Sleeps in short
    /// ticks so deinit joins promptly.
    fn resyncLoop(self: *Node) void {
        const tick_ms: u64 = 250;
        var since_ms: u64 = 0;
        // M6:example logs — while fewer connections are live than peers are
        // configured, remind (at most once per 60 s) that a quorum is needed.
        var waiting_ms: u64 = 0;
        while (!self.resync_stop.load(.acquire)) {
            std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(@intCast(tick_ms)), .awake) catch {};
            since_ms += tick_ms;
            const live = self.peers_live.load(.acquire);
            if (live < self.peer_specs.len) {
                waiting_ms += tick_ms;
                if (waiting_ms >= peers_waiting_reminder_ms) {
                    waiting_ms = 0;
                    log.info("{d} live connection(s) to {d} configured peer(s) — consensus needs a quorum; waiting", .{ live, self.peer_specs.len });
                }
            } else {
                waiting_ms = 0;
            }
            if (since_ms < resync_interval_ms) continue;
            since_ms = 0;
            if (self.failed.load(.acquire)) continue;

            // Borrow envelopes under own_mu; the overlay copies on enqueue.
            self.own_mu.lockUncancelable(self.io);
            var it = self.own_latest.iterator();
            while (it.next()) |e| {
                if (e.value_ptr.nom) |b| self.emitEnvelope("resync-nom", .all, b);
                if (e.value_ptr.ballot) |b| self.emitEnvelope("resync-ballot", .all, b);
            }
            self.own_mu.unlock(self.io);
            self.ov.broadcast(.{ .get_slot_state = 0 });
        }
    }

    /// Feed one input and drain all its effects (engine thread only).
    fn applyInput(self: *Node, item_in: InputItem) void {
        var item = item_in;
        if (self.failed.load(.acquire)) {
            // Inert: consume and free inputs without touching the engine.
            core.host_codec.freeInput(self.gpa, &item.input);
            return;
        }
        self.cur_source = item.source_peer;
        self.eng.pushInput(item.input) catch |err| {
            core.host_codec.freeInput(self.gpa, &item.input);
            self.markFailed(err);
            return;
        };
        core.host_codec.freeInput(self.gpa, &item.input);
        while (self.eng.popEffect()) |eff| {
            // A dispatch that trips markFailed (a failed write-ahead append)
            // must suppress every LATER effect of this input — most
            // importantly the broadcast paired with a failed persist (§10:
            // never send what is not durable). The remaining effects are
            // still committed so their payloads are freed.
            if (!self.failed.load(.acquire)) self.dispatch(eff);
            self.eng.commitEffect();
        }
        self.cur_source = null;
    }

    /// Latch the node inert: no further inputs are applied, no further
    /// effects dispatched, and app waiters are woken (waitExternalized
    /// returns null). §10: a node that cannot persist MUST NOT keep talking —
    /// going silent is safe; broadcasting unpersisted statements is Byzantine
    /// after the next crash.
    fn markFailed(self: *Node, err: anyerror) void {
        if (!self.failed.swap(true, .seq_cst)) {
            log.err("node failed: {s} — going inert (§10 write-ahead discipline)", .{@errorName(err)});
            self.ext_mu.lockUncancelable(self.io);
            self.ext_closed = true;
            self.ext_cond.broadcast(self.io);
            self.ext_mu.unlock(self.io);
            // Exactly once, after the latch: the hook's waiters stop too.
            if (self.delivery) |h| h.on_failed(h.ctx, err);
        }
    }

    fn dispatch(self: *Node, eff: *const engine.Effect) void {
        switch (eff.*) {
            .persist_own_envelope => |sb| {
                // CRITICAL invariant (§5.3/§10): this append+fsync must
                // complete before the paired broadcast_envelope may be sent.
                // On failure the node goes inert — applyInput then suppresses
                // the rest of this input's effects, including that broadcast.
                self.store.appendOwn(sb.slot, sb.bytes) catch |e| {
                    log.err("own.log append failed: {s}", .{@errorName(e)});
                    self.markFailed(e);
                };
            },
            .broadcast_envelope => |sb| {
                // Always record as our latest for on-connect catch-up, even
                // during restore; only touch the network once live.
                self.recordOwnLatest(sb.slot, sb.bytes);
                if (self.live) self.emitEnvelope("dispatch-broadcast", .all, sb.bytes);
            },
            .forward_envelope => |sb| {
                if (!self.live) return;
                if (self.cur_source) |src| {
                    self.emitEnvelope("dispatch-forward", .{ .except = src }, sb.bytes);
                } else {
                    self.emitEnvelope("dispatch-forward-all", .all, sb.bytes);
                }
            },
            .arm_timer => |a| {
                self.wheel.arm(a.slot, @backingInt(a.timer), a.delay_ms) catch |e|
                    log.err("timer arm failed: {s}", .{@errorName(e)});
            },
            .cancel_timer => |c| self.wheel.cancel(c.slot, @backingInt(c.timer)),
            .request_qset => |r| {
                if (!self.live) return;
                self.noteQsetRequested(r.hash);
                // Simplified relay (§9.2): flood the request; any holder
                // answers. Parked envelopes resolve on the first qset reply.
                self.ov.broadcast(.{ .get_qset = r.hash });
            },
            .externalized => |sb| self.onExternalized(sb.slot, sb.bytes),
            .input_status => {}, // observability only
            .phase_event => {}, // non-normative
        }
    }

    fn onExternalized(self: *Node, slot: u64, value: []const u8) void {
        // Write-ahead journal first; a failed append is FATAL (the app must
        // never consume a value the crash-bound computation cannot see, §10).
        self.store.appendExternalized(slot, value) catch |e| {
            log.err("externalized.log append failed: {s}", .{@errorName(e)});
            self.markFailed(e);
            return;
        };

        // Advance proposal state off the RAW slot (highest wins) — proposals
        // target the frontier of consensus, not of app delivery.
        self.prop_mu.lockUncancelable(self.io);
        if (slot + 1 > self.current_slot) {
            if (self.last_ext_value.len > 0) self.gpa.free(self.last_ext_value);
            self.last_ext_value = self.gpa.dupe(u8, value) catch &.{};
            self.current_slot = slot + 1;
        }
        self.nominating = false;
        self.prop_mu.unlock(self.io);
        self.maybeStartNomination();

        // App delivery is IN SLOT ORDER (§11.2's stream semantics): buffer
        // out-of-order externalizations (catch-up delivers slots in arbitrary
        // peer order) and drain the contiguous frontier. If the buffer
        // outgrows the answering window, the gap is unrecoverable (peers only
        // answer 16 slots back) — jump the frontier to the lowest buffered
        // slot with a loud log.
        const copy = self.gpa.dupe(u8, value) catch {
            // A journaled slot the app can never see = silent divergence;
            // going inert is the honest failure (review finding).
            log.err("OOM buffering externalized slot {d}", .{slot});
            self.markFailed(error.OutOfMemory);
            return;
        };
        if (slot < self.next_deliver) {
            self.gpa.free(copy); // stale duplicate below the frontier
            return;
        }
        const gop = self.pending_ext.getOrPut(self.gpa, slot) catch {
            self.gpa.free(copy);
            self.markFailed(error.OutOfMemory);
            return;
        };
        if (gop.found_existing) {
            self.gpa.free(copy); // the engine fires once per slot; be safe
            return;
        }
        gop.value_ptr.* = copy;

        // Gap-jump on UNANSWERABILITY: once any buffered slot sits a full
        // answering window past the frontier, the gap slot is older than
        // window-16 on every peer — no protocol can ever fill it. (A count
        // threshold is unreachable: peers can supply at most `purge_window`
        // old slots — review finding.)
        var highest: u64 = 0;
        var lowest: u64 = std.math.maxInt(u64);
        var it = self.pending_ext.keyIterator();
        while (it.next()) |k| {
            highest = @max(highest, k.*);
            lowest = @min(lowest, k.*);
        }
        if (self.pending_ext.count() > 0 and highest >= self.next_deliver + purge_window and lowest > self.next_deliver) {
            log.warn("externalized gap: slots {d}..{d} unrecoverable; resuming delivery at {d}", .{ self.next_deliver, lowest - 1, lowest });
            self.next_deliver = lowest;
        }
        self.drainDeliverable();
    }

    /// Deliver the contiguous frontier of buffered externalizations to the
    /// app, then GC behind it (engine thread only).
    fn drainDeliverable(self: *Node) void {
        var delivered_any = false;
        while (self.pending_ext.fetchRemove(self.next_deliver)) |kv| {
            const slot = kv.key;
            self.deliverSlot(slot, kv.value) catch |e| {
                // Either OOM on the queue path or the delivery hook refusing
                // a value the network agreed on: both mean the app can no
                // longer see what was journaled — going inert is the honest
                // failure (never silently diverge).
                log.err("delivery of externalized slot {d} failed: {s}", .{ slot, @errorName(e) });
                self.markFailed(e);
                return;
            };
            self.next_deliver = slot + 1;
            delivered_any = true;
        }
        if (!delivered_any) return;

        // GC (§10): keep a 16-slot answering window behind the DELIVERED
        // frontier (never purge a slot the app has not consumed).
        const frontier = self.next_deliver - 1;
        if (frontier >= purge_window) {
            const max_slot = frontier - (purge_window - 1);
            self.purge_floor.store(max_slot, .release);
            self.pruneOwnLatest(max_slot);
            self.q.push(.{ .input = .{ .purge_slots = .{ .max_slot = max_slot } }, .source_peer = null });
            // §10 "and compacts": rewrite the logs occasionally so they do
            // not grow without bound (every 64 delivered slots). A drain may
            // deliver several buffered slots at once and land past a
            // multiple of 64, so compare 64-slot buckets against the last
            // compaction instead of testing the frontier itself; a failed
            // compaction leaves the mark alone so the next drain retries.
            if (frontier / 64 > self.last_compact_frontier / 64) {
                if (self.store.compact(max_slot)) |_| {
                    self.last_compact_frontier = frontier;
                } else |e| {
                    log.warn("log compaction failed (will retry later): {s}", .{@errorName(e)});
                }
            }
        }
    }

    /// The single app hand-off for one externalized slot: the delivery hook
    /// when `Options.delivery` is set (engine thread, or the creating thread
    /// during the journal-tail replay), else the `waitExternalized` queue.
    /// Takes ownership of `val` on every path. Callers keep slots ascending
    /// (`next_deliver`); a hook error or a queue OOM is returned unchanged
    /// for the caller to turn into a create failure or an inert latch.
    fn deliverSlot(self: *Node, slot: u64, val: []u8) anyerror!void {
        if (self.delivery) |h| {
            defer self.gpa.free(val);
            try h.on_externalized(h.ctx, slot, val);
            return;
        }
        self.ext_mu.lockUncancelable(self.io);
        defer self.ext_mu.unlock(self.io);
        self.ext_queue.append(self.gpa, .{ .slot = slot, .value = val }) catch |e| {
            self.gpa.free(val);
            return e;
        };
        self.ext_cond.signal(self.io);
    }

    /// If idle and a proposal is queued, nominate the head for current_slot.
    fn maybeStartNomination(self: *Node) void {
        if (self.watcher) return;
        self.prop_mu.lockUncancelable(self.io);
        if (self.nominating or self.proposal_queue.items.len == 0) {
            self.prop_mu.unlock(self.io);
            return;
        }
        const value = self.proposal_queue.orderedRemove(0);
        const slot = self.current_slot;
        const prev = self.gpa.dupe(u8, self.last_ext_value) catch {
            // put it back on OOM
            self.proposal_queue.insert(self.gpa, 0, value) catch self.gpa.free(value);
            self.prop_mu.unlock(self.io);
            return;
        };
        self.nominating = true;
        self.prop_mu.unlock(self.io);

        // value + prev are owned; the input carries them, freed after push.
        self.q.push(.{ .input = .{ .nominate = .{ .slot = slot, .value = value, .prev_value = prev } }, .source_peer = null });
    }

    // -------------------------------------------------------------------
    // own_latest (catch-up source)
    // -------------------------------------------------------------------

    fn recordOwnLatest(self: *Node, slot: u64, framed_env: []const u8) void {
        // Zero-frame placeholders (engine lagger self-records) never reach
        // effects today, but the skip-zero-frames host contract applies here
        // too — never let an empty frame into the catch-up source.
        if (framed_env.len == 0) return;
        const bucket = envelopeBucket(self.gpa, framed_env) catch {
            log.warn("could not bucket own envelope for slot {d}", .{slot});
            return;
        };
        const copy = self.gpa.dupe(u8, framed_env) catch return;
        self.own_mu.lockUncancelable(self.io);
        defer self.own_mu.unlock(self.io);
        const gop = self.own_latest.getOrPut(self.gpa, slot) catch {
            self.gpa.free(copy);
            return;
        };
        if (!gop.found_existing) gop.value_ptr.* = .{};
        switch (bucket) {
            .nom => {
                if (gop.value_ptr.nom) |old| self.gpa.free(old);
                gop.value_ptr.nom = copy;
            },
            .ballot => {
                if (gop.value_ptr.ballot) |old| self.gpa.free(old);
                gop.value_ptr.ballot = copy;
            },
        }
    }

    fn pruneOwnLatest(self: *Node, max_slot: u64) void {
        self.own_mu.lockUncancelable(self.io);
        defer self.own_mu.unlock(self.io);
        var it = self.own_latest.iterator();
        var doomed: std.ArrayList(u64) = .empty;
        defer doomed.deinit(self.gpa);
        while (it.next()) |e| {
            if (e.key_ptr.* < max_slot) doomed.append(self.gpa, e.key_ptr.*) catch {};
        }
        for (doomed.items) |k| {
            if (self.own_latest.getPtr(k)) |v| v.free(self.gpa);
            _ = self.own_latest.remove(k);
        }
    }

    // -------------------------------------------------------------------
    // Overlay callbacks (reader threads)
    // -------------------------------------------------------------------

    fn onRecv(ctx: ?*anyopaque, peer_id: usize, frame: *const wire.OverlayFrame) void {
        const self: *Node = @ptrCast(@alignCast(ctx.?));
        switch (frame.*) {
            .hello => {}, // handled inside overlay; should not reach here
            .envelope => |bytes| self.enqueueEnvelope(bytes, peer_id),
            .qset => |bytes| self.onQsetFrame(bytes),
            .get_qset => |hash| self.answerGetQset(peer_id, hash),
            .dont_have => {}, // fetch-fallback hint; flood covers us (M5)
            .get_slot_state => |slot| self.answerGetSlotState(peer_id, slot),
            .slot_state => |ss| for (ss.envelopes) |env| self.enqueueEnvelope(env, peer_id),
            .ping => |n| self.ov.send(peer_id, .{ .pong = n }),
            .pong => {},
        }
    }

    fn onPeerUp(ctx: ?*anyopaque, peer_id: usize) void {
        const self: *Node = @ptrCast(@alignCast(ctx.?));
        // M6:example logs
        const live = self.peers_live.fetchAdd(1, .acq_rel) + 1;
        log.info("peer {d} up ({d} live connection(s); {d} peer(s) configured)", .{ peer_id, live, self.peer_specs.len });
        // Catch-up (§9.2): send our latest own envelopes, then ask for the
        // peer's externalized state.
        self.own_mu.lockUncancelable(self.io);
        var it = self.own_latest.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.nom) |b| self.emitEnvelope("peerup-nom", .{ .one = peer_id }, b);
            if (e.value_ptr.ballot) |b| self.emitEnvelope("peerup-ballot", .{ .one = peer_id }, b);
        }
        self.own_mu.unlock(self.io);
        self.ov.send(peer_id, .{ .get_slot_state = 0 });
    }

    /// M6:example logs — `Callbacks.on_peer_down`: fires on the peer's
    /// reader thread after its read loop ends (the connection is still
    /// counted by `ov.peerCount()` at this instant; `peers_live` is the
    /// Node's own up-minus-down tally). Log only; no protocol effect.
    fn onPeerDown(ctx: ?*anyopaque, peer_id: usize) void {
        const self: *Node = @ptrCast(@alignCast(ctx.?));
        const live = self.peers_live.fetchSub(1, .acq_rel) - 1;
        _ = self.peer_downs.fetchAdd(1, .acq_rel);
        log.info("peer {d} down ({d} live connection(s); {d} peer(s) configured)", .{ peer_id, live, self.peer_specs.len });
    }

    fn enqueueEnvelope(self: *Node, framed_env: []const u8, source: usize) void {
        const copy = self.gpa.dupe(u8, framed_env) catch return;
        self.q.push(.{ .input = .{ .envelope_received = .{ .bytes = copy } }, .source_peer = source });
    }

    /// Record a hash the engine asked the network for (engine thread).
    /// Bounded: a full set is cleared — crude, but the set only ever holds
    /// in-flight fetches and correctness never depends on membership.
    fn noteQsetRequested(self: *Node, hash: [32]u8) void {
        self.qset_mu.lockUncancelable(self.io);
        defer self.qset_mu.unlock(self.io);
        if (self.req_qsets.count() >= 256) self.req_qsets.clearRetainingCapacity();
        self.req_qsets.put(self.gpa, hash, {}) catch {};
    }

    /// True (once) iff we asked for this hash (reader threads).
    fn consumeQsetRequested(self: *Node, hash: [32]u8) bool {
        self.qset_mu.lockUncancelable(self.io);
        defer self.qset_mu.unlock(self.io);
        return self.req_qsets.remove(hash);
    }

    fn onQsetFrame(self: *Node, framed_qset: []const u8) void {
        // Persist for future getQset answers — but ONLY qsets we actually
        // requested (disk-fill DoS otherwise: any peer could push unlimited
        // unsolicited qsets into the cache). The engine is always fed; it
        // validates and bounds its own in-memory cache.
        const h = qsetHashOfFramed(self.gpa, framed_qset) catch null;
        if (h) |hash| {
            if (self.consumeQsetRequested(hash)) self.store.putQset(hash, framed_qset);
        }
        const copy = self.gpa.dupe(u8, framed_qset) catch return;
        self.q.push(.{ .input = .{ .qset_received = .{ .bytes = copy } }, .source_peer = null });
    }

    fn answerGetQset(self: *Node, peer_id: usize, hash: [32]u8) void {
        const framed = self.store.getQset(self.gpa, hash) catch null;
        if (framed) |bytes| {
            defer self.gpa.free(bytes);
            self.ov.send(peer_id, .{ .qset = bytes });
        } else {
            self.ov.send(peer_id, .{ .dont_have = .{ .kind = 0, .id = &hash } });
        }
    }

    fn answerGetSlotState(self: *Node, peer_id: usize, req_slot: u64) void {
        // Gather up to 64 of our own envelopes (ballot preferred) for the
        // requested window and send them back as one slotState.
        var list: std.ArrayList([]const u8) = .empty;
        defer list.deinit(self.gpa);
        var highest: u64 = 0;

        self.own_mu.lockUncancelable(self.io);
        var it = self.own_latest.iterator();
        while (it.next()) |e| {
            const slot = e.key_ptr.*;
            if (req_slot != 0 and slot != req_slot) continue;
            const env = e.value_ptr.ballot orelse e.value_ptr.nom orelse continue;
            if (list.items.len >= wire.max_slot_state_envelopes) break;
            list.append(self.gpa, env) catch break;
            if (slot > highest) highest = slot;
        }
        // Send while holding own_mu so the borrowed env slices stay valid
        // through encode (overlay copies them).
        self.ov.send(peer_id, .{ .slot_state = .{ .slot = highest, .envelopes = list.items } });
        self.own_mu.unlock(self.io);
    }

    // -------------------------------------------------------------------
    // Timer wheel callback (wheel thread)
    // -------------------------------------------------------------------

    fn onTimerFire(ctx: ?*anyopaque, slot: u64, timer_id: u16) void {
        const self: *Node = @ptrCast(@alignCast(ctx.?));
        // Drop stale fires for purged slots (a cancel can race an in-flight
        // fire; feeding a purged slot back would resurrect its state).
        if (slot < self.purge_floor.load(.acquire)) return;
        const timer: engine.TimerId = @fromBackingInt(@intCast(@as(u8, @intCast(timer_id))));
        self.q.push(.{ .input = .{ .timer_fired = .{ .slot = slot, .timer = timer } }, .source_peer = null });
    }
};

// -----------------------------------------------------------------------
// qset helpers (owned tree ⇄ framed message)
// -----------------------------------------------------------------------

const Bucket = enum { nom, ballot };

fn envelopeBucket(gpa: std.mem.Allocator, framed_env: []const u8) !Bucket {
    var emsg = try core.capnpc.message.Message.init(gpa, framed_env, .{});
    defer emsg.deinit();
    const er = try gen_slcp.Envelope.Reader.init(&emsg);
    const stmt_bytes = try er.getStatementBytes();
    var smsg = try canonical.decodeFlat(gpa, stmt_bytes, .{});
    defer smsg.deinit();
    const sr = try gen_slcp.Statement.Reader.init(&smsg);
    const which = try sr.getPledges().which();
    return if (which == .nominate) .nom else .ballot;
}

fn qsetHashOfFramed(gpa: std.mem.Allocator, framed_qset: []const u8) ![32]u8 {
    var msg = try core.capnpc.message.Message.init(gpa, framed_qset, .{});
    defer msg.deinit();
    const r = try gen_slcp.QuorumSet.Reader.init(&msg);
    var qs = try qset.fromReader(gpa, r);
    defer qs.deinit(gpa);
    const flat = try qset.canonicalBytes(gpa, &qs);
    defer gpa.free(flat);
    return crypto.qsetHash(flat);
}

fn ownedQsetToFramed(gpa: std.mem.Allocator, qs: *const qset.QuorumSetOwned) ![]u8 {
    var mb = MessageBuilder.init(gpa);
    defer mb.deinit();
    var qb = try gen_slcp.QuorumSet.Builder.init(&mb);
    try writeOwnedQset(&qb, qs);
    return @constCast(try mb.toBytes());
}

fn writeOwnedQset(qb: *gen_slcp.QuorumSet.Builder, qs: *const qset.QuorumSetOwned) !void {
    try qb.setThreshold(qs.threshold);
    if (qs.validators.len > 0) {
        var vb = try qb.initValidators(@intCast(qs.validators.len));
        for (qs.validators, 0..) |*v, i| try vb.set(@intCast(i), v);
    }
    if (qs.inner_sets.len > 0) {
        var ib = try qb.initInnerSets(@intCast(qs.inner_sets.len));
        for (qs.inner_sets, 0..) |*child, i| {
            var cb = try ib.get(@intCast(i));
            try writeOwnedQset(&cb, child);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "node: every method compiles (forces body analysis without instantiation)" {
    // Taking the address of each method forces the compiler to analyze its
    // body against the current leaf-module interfaces — a cheap full-compile
    // check for the Node spine, which the socket-driven e2e exercises at
    // runtime.
    const fns = .{
        Node.create,           Node.deinit,             Node.propose,
        Node.waitExternalized, Node.stats,              Node.boundPort,
        Node.engineLoop,       Node.applyInput,         Node.markFailed,
        Node.dispatch,         Node.onExternalized,     Node.maybeStartNomination,
        Node.recordOwnLatest,  Node.pruneOwnLatest,     Node.onRecv,
        Node.onPeerUp,         Node.enqueueEnvelope,    Node.onQsetFrame,
        Node.answerGetQset,    Node.answerGetSlotState, Node.onTimerFire,
        Node.drainDeliverable, Node.noteQsetRequested,  Node.consumeQsetRequested,
        Node.resyncLoop,       Node.deliverSlot,        Node.onPeerDown,
    };
    inline for (fns) |f| {
        const p = &f;
        _ = p;
    }
}

test "InputQueue: push, pop, and close over std.Io primitives" {
    const io = std.testing.io;
    var q = InputQueue{ .gpa = std.testing.allocator, .io = io };
    defer q.deinit();

    q.push(.{ .input = .{ .purge_slots = .{ .max_slot = 5 } }, .source_peer = null });
    q.push(.{ .input = .{ .purge_slots = .{ .max_slot = 6 } }, .source_peer = null });

    const a = q.pop().?;
    try std.testing.expectEqual(@as(u64, 5), a.input.purge_slots.max_slot);
    const b = q.pop().?;
    try std.testing.expectEqual(@as(u64, 6), b.input.purge_slots.max_slot);

    q.close();
    try std.testing.expect(q.pop() == null); // closed + drained
}

// -- delivery hook + create() reorder (M6 S3) ---------------------------------

const RecordingHook = struct {
    gpa: std.mem.Allocator,
    slots: std.ArrayList(u64) = .empty,
    values: std.ArrayList([]u8) = .empty,
    /// Refuse this slot with error.HookRefused.
    refuse: ?u64 = null,
    failed_with: ?anyerror = null,

    fn onExternalized(ctx: *anyopaque, slot: u64, value: []const u8) anyerror!void {
        const self: *RecordingHook = @ptrCast(@alignCast(ctx));
        if (self.refuse == slot) return error.HookRefused;
        try self.slots.append(self.gpa, slot);
        try self.values.append(self.gpa, try self.gpa.dupe(u8, value));
    }

    fn onFailed(ctx: *anyopaque, err: anyerror) void {
        const self: *RecordingHook = @ptrCast(@alignCast(ctx));
        self.failed_with = err;
    }

    fn hook(self: *RecordingHook) DeliveryHook {
        return .{ .ctx = @ptrCast(self), .on_externalized = onExternalized, .on_failed = onFailed };
    }

    fn deinit(self: *RecordingHook) void {
        for (self.values.items) |v| self.gpa.free(v);
        self.values.deinit(self.gpa);
        self.slots.deinit(self.gpa);
    }
};

/// A validly-signed, framed EXTERNALIZE envelope for `slot` by `seed` — what
/// own.log holds for a slot this node externalized before a crash.
fn buildSignedExternalize(gpa: std.mem.Allocator, seed: [32]u8, network_id: [32]u8, slot: u64, value: []const u8) ![]u8 {
    const node_id = try crypto.publicKeyFromSeed(seed);
    var mb = MessageBuilder.init(gpa);
    defer mb.deinit();
    var st = try gen_slcp.Statement.Builder.init(&mb);
    try st.setNodeId(&node_id);
    try st.setSlotIndex(slot);
    var pledges = st.getPledges();
    var ext = try pledges.initExternalize();
    var commit = try ext.initCommit();
    try commit.setCounter(1);
    try commit.setValue(value);
    try ext.setNH(1);
    const qh: [32]u8 = @splat(7);
    try ext.setCommitQuorumSetHash(&qh);
    const stmt_bytes = try canonical.canonicalFlatFromBuilder(gpa, &mb);
    defer gpa.free(stmt_bytes);
    const digest = crypto.statementDigest(network_id, stmt_bytes);
    const sig = try crypto.sign(seed, digest);

    var emb = MessageBuilder.init(gpa);
    defer emb.deinit();
    var env = try gen_slcp.Envelope.Builder.init(&emb);
    try env.setStatementBytes(stmt_bytes);
    try env.setSignature(&sig);
    return @constCast(try emb.toBytes());
}

// Non-vacuity: skipping the journal-tail replay, or replaying it through
// `ext_queue.append` instead of `deliverSlot`, leaves the hook with zero
// slots inside create (the `{3,5,7}` assertion goes red); moving the own.log
// restore loop back BEFORE the frontier set + tail replay (the M5 order)
// goes red on the refusing-hook arm — the restored slot-5 externalize is
// dispatched before the replay can fail, and create's unwind does not free
// what that dispatch buffered (the testing allocator reports the leak);
// dropping the `else` branch of `deliverSlot` makes the hookless reopen see
// nothing; ignoring the hook's error in the replay loop turns the
// `EngineFailed` expectation into a successful create.
test "delivery hook: journal tail 3,5,7 (+ own EXTERNALIZE 5) is delivered ascending inside create; the queue path sees each once; a refusing hook fails create" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(io, &dir_buf);
    const data_dir = dir_buf[0..dir_len];

    const passphrase = "delivery-hook-test v1";
    const seed: [32]u8 = @splat(0x42);
    const me = try crypto.publicKeyFromSeed(seed);
    const peer_a: [32]u8 = @splat(0x77);
    const peer_b: [32]u8 = @splat(0x78);
    const network_id = crypto.networkIdFromPassphrase(passphrase);

    // A crashed node's data_dir: the journal holds 3, 5, 7 and own.log the
    // EXTERNALIZE this node emitted for 5 (the half the M5 order mishandled).
    {
        var st = try store_mod.Store.open(gpa, io, data_dir);
        defer st.deinit();
        try st.appendExternalized(3, "three");
        try st.appendExternalized(5, "five");
        try st.appendExternalized(7, "seven");
        const env = try buildSignedExternalize(gpa, seed, network_id, 5, "five");
        defer gpa.free(env);
        try st.appendOwn(5, env);
    }

    var diag: Diagnostic = .{};
    const base = Options{
        .network = passphrase,
        .secret_seed = seed,
        .quorum = Quorum.twoThirdsOf(&.{ me, peer_a, peer_b }),
        .listen_port = 0,
        .data_dir = data_dir,
        .diagnostic = &diag,
    };
    const want_slots = [_]u64{ 3, 5, 7 };
    const want_values = [_][]const u8{ "three", "five", "seven" };

    // Hook path: all three arrive synchronously inside create, ascending,
    // and the waitExternalized queue stays empty.
    {
        var hook = RecordingHook{ .gpa = gpa };
        defer hook.deinit();
        var o = base;
        o.delivery = hook.hook();
        const n = try Node.create(gpa, io, o);
        defer n.deinit();
        try std.testing.expectEqualSlices(u64, &want_slots, hook.slots.items);
        for (want_values, hook.values.items) |w, got| try std.testing.expectEqualSlices(u8, w, got);
        try std.testing.expect(n.waitExternalized(.{ .timeout_ms = 50 }) == null);
        try std.testing.expect(hook.failed_with == null);
        try std.testing.expectEqual(@as(u64, 8), n.next_deliver);
    }

    // Queue path: the same dir yields 3, 5, 7 exactly once each.
    {
        const n = try Node.create(gpa, io, base);
        defer n.deinit();
        for (want_slots, want_values) |s, w| {
            const e = n.waitExternalized(.{ .timeout_ms = 1000 }) orelse return error.TailNotReplayed;
            defer gpa.free(e.value);
            try std.testing.expectEqual(s, e.slot);
            try std.testing.expectEqualSlices(u8, w, e.value);
        }
        try std.testing.expect(n.waitExternalized(.{ .timeout_ms = 50 }) == null);
    }

    // A hook that refuses a journaled value refuses the whole start.
    {
        var hook = RecordingHook{ .gpa = gpa, .refuse = 5 };
        defer hook.deinit();
        var o = base;
        o.delivery = hook.hook();
        try std.testing.expectError(error.EngineFailed, Node.create(gpa, io, o));
        try std.testing.expect(std.mem.indexOf(u8, diag.message(), "HookRefused") != null);
        try std.testing.expect(std.mem.indexOf(u8, diag.message(), "slot 5") != null);
        try std.testing.expectEqualSlices(u64, &[_]u64{3}, hook.slots.items); // stopped at the refusal
        try std.testing.expect(hook.failed_with == null); // create failed; no latch, no on_failed
    }
}

// -- M6:example logs: peer up/down wiring ------------------------------------

/// Poll `cond` every 50 ms for up to `max_ms`; error.Timeout when it never held.
fn pollUntil(io: std.Io, max_ms: u64, ctx: anytype, comptime cond: fn (@TypeOf(ctx)) bool) !void {
    var waited: u64 = 0;
    while (!cond(ctx)) {
        if (waited >= max_ms) return error.Timeout;
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(50), .awake);
        waited += 50;
    }
}

// Non-vacuity: dropping `.on_peer_down = onPeerDown` from create()'s overlay
// Callbacks leaves `peer_downs` at 0 and `peers_live` stuck at 1 — the
// second poll times out (red); dropping the fetchAdd in `onPeerUp` keeps
// `peers_live` at 0 — the first poll times out (red). `ov.peerCount() == 0`
// pins that the survivor really dropped the dead connection (the overlay's
// own teardown), not merely counted it.
test "peer up/down: two loopback Nodes, deinit one; the survivor's peerCount drops to 0 and on_peer_down fired" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buf[0..try tmp.dir.realPath(io, &root_buf)];
    var dir_a_buf: [std.fs.max_path_bytes]u8 = undefined;
    var dir_b_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_a = try std.fmt.bufPrint(&dir_a_buf, "{s}/a", .{root});
    const dir_b = try std.fmt.bufPrint(&dir_b_buf, "{s}/b", .{root});

    const seed_a: [32]u8 = @splat(0x61);
    const seed_b: [32]u8 = @splat(0x62);
    const ids = [2][32]u8{ try crypto.publicKeyFromSeed(seed_a), try crypto.publicKeyFromSeed(seed_b) };
    var diag: Diagnostic = .{};

    const a = try Node.create(gpa, io, .{
        .network = "peer-down v1",
        .secret_seed = seed_a,
        .quorum = core.quorum.Quorum.of(2, &ids),
        .listen_port = 0,
        .data_dir = dir_a,
        .diagnostic = &diag,
    });
    defer a.deinit();
    var spec_buf: [32]u8 = undefined;
    const spec = try std.fmt.bufPrint(&spec_buf, "127.0.0.1:{d}", .{a.boundPort()});
    const b = try Node.create(gpa, io, .{
        .network = "peer-down v1",
        .secret_seed = seed_b,
        .quorum = core.quorum.Quorum.of(2, &ids),
        .listen_port = 0,
        .peers = &.{spec},
        .data_dir = dir_b,
        .diagnostic = &diag,
    });
    var b_live = true;
    defer if (b_live) b.deinit();

    const Probe = struct {
        fn up(n: *Node) bool {
            return n.peers_live.load(.acquire) >= 1;
        }
        fn down(n: *Node) bool {
            return n.peer_downs.load(.acquire) >= 1 and n.peers_live.load(.acquire) == 0 and n.ov.peerCount() == 0;
        }
    };
    try pollUntil(io, 10_000, a, Probe.up);
    try std.testing.expectEqual(@as(u64, 0), a.peer_downs.load(.acquire));

    b.deinit();
    b_live = false;
    try pollUntil(io, 10_000, a, Probe.down);
    try std.testing.expectEqual(@as(usize, 0), a.peers_live.load(.acquire));
}

// -- S8 D2: compaction cadence vs. multi-slot drains ---------------------------

/// Journal slots 1..62 into a fresh data_dir, create a hooked Node (the tail
/// replay delivers 1..62 and sets next_deliver = 63), seed `pending_ext` with
/// `seed_slots` (an out-of-order catch-up batch), drain ONCE, and report what
/// externalized.log holds afterward.
fn probeDrainCompaction(gpa: std.mem.Allocator, io: std.Io, data_dir: []const u8, seed_slots: []const u64) !struct { records: usize, min_slot: u64, delivered: usize } {
    const passphrase = "s8 compaction cadence probe";
    const seed: [32]u8 = @splat(0x51);
    const me = try crypto.publicKeyFromSeed(seed);
    const peer_a: [32]u8 = @splat(0x52);
    const peer_b: [32]u8 = @splat(0x53);
    {
        var st = try store_mod.Store.open(gpa, io, data_dir);
        defer st.deinit();
        var s: u64 = 1;
        while (s <= 62) : (s += 1) {
            var vbuf: [8]u8 = undefined;
            try st.appendExternalized(s, try std.fmt.bufPrint(&vbuf, "v{d}", .{s}));
        }
    }
    var diag: Diagnostic = .{};
    var hook = RecordingHook{ .gpa = gpa };
    defer hook.deinit();
    const n = try Node.create(gpa, io, .{
        .network = passphrase,
        .secret_seed = seed,
        .quorum = Quorum.twoThirdsOf(&.{ me, peer_a, peer_b }),
        .listen_port = 0,
        .data_dir = data_dir,
        .diagnostic = &diag,
        .delivery = hook.hook(),
    });
    defer n.deinit();
    try std.testing.expectEqual(@as(u64, 63), n.next_deliver);
    try std.testing.expectEqual(@as(usize, 62), hook.slots.items.len);

    for (seed_slots) |s| {
        const v = try gpa.dupe(u8, "x");
        try n.pending_ext.put(gpa, s, v);
    }
    n.drainDeliverable();
    try std.testing.expectEqual(@as(usize, 0), n.pending_ext.count());

    var rec = try n.store.recover(gpa);
    defer store_mod.Store.deinitRecovery(gpa, &rec);
    var min_slot: u64 = std.math.maxInt(u64);
    for (rec.ext_tail) |r| min_slot = @min(min_slot, r.slot);
    return .{ .records = rec.ext_tail.len, .min_slot = min_slot, .delivered = hook.slots.items.len };
}

// Non-vacuity: reverting the compaction trigger to `frontier % 64 == 0`
// (tested once per drain, after the loop) leaves arm B — a single drain
// that steps 63 → 65 over the 64 boundary, the out-of-order catch-up case
// `pending_ext` exists for — with all 62 pre-existing journal records
// (min slot 1) instead of the 13 records >= 50 the §10 "every 64 delivered
// slots" cadence promises; arm A (a drain ending exactly on 64) passes
// either way and pins the steady-state cadence. Dropping the
// `last_compact_frontier` update after a successful compaction would
// compact on every later drain — not caught here, but harmless.
test "compaction cadence: a drain that ends on 64 compacts, and so does a drain that steps over 64 (63 -> 65) in one go" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buf[0..try tmp.dir.realPath(io, &root_buf)];
    var a_buf: [std.fs.max_path_bytes]u8 = undefined;
    var b_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_a = try std.fmt.bufPrint(&a_buf, "{s}/a", .{root});
    const dir_b = try std.fmt.bufPrint(&b_buf, "{s}/b", .{root});

    // Arm A: frontier 64 → compact(64 - 15 = 49): records 49..62 survive.
    const a = try probeDrainCompaction(gpa, io, dir_a, &.{ 63, 64 });
    try std.testing.expectEqual(@as(usize, 64), a.delivered);
    try std.testing.expectEqual(@as(usize, 14), a.records);
    try std.testing.expectEqual(@as(u64, 49), a.min_slot);
    // Arm B: frontier 65 crossed the 64 boundary inside one drain →
    // compact(65 - 15 = 50): records 50..62 survive.
    const b = try probeDrainCompaction(gpa, io, dir_b, &.{ 63, 64, 65 });
    try std.testing.expectEqual(@as(usize, 65), b.delivered);
    try std.testing.expectEqual(@as(usize, 13), b.records);
    try std.testing.expectEqual(@as(u64, 50), b.min_slot);
}

// -- S8 D2: stats().failed reflects the node-level inert latch ------------------

// Non-vacuity: `Node.stats()` returning `self.eng.stats()` verbatim (the
// engine's own DriverFault/EngineFailed latch only) leaves `.failed` false
// after the NODE latch is set — the second assertion goes red. The latch is
// set directly here (the same atomic `markFailed` swaps to true on a hook
// refusal, a failed own.log/externalized.log append, or a buffering OOM)
// because `markFailed` logs at err level, which this test runner counts as
// a failure; the live path is covered by the S8 d2-restart harness
// (waitApplied -> NodeHalted, then `raw().stats()`).
test "stats: .failed is true once the node latched inert, not only on an engine failure" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];

    const seed: [32]u8 = @splat(0x5a);
    const me = try crypto.publicKeyFromSeed(seed);
    const peer_a: [32]u8 = @splat(0x5b);
    const peer_b: [32]u8 = @splat(0x5c);
    var diag: Diagnostic = .{};
    const n = try Node.create(gpa, io, .{
        .network = "stats inert latch v1",
        .secret_seed = seed,
        .quorum = Quorum.twoThirdsOf(&.{ me, peer_a, peer_b }),
        .listen_port = 0,
        .data_dir = data_dir,
        .diagnostic = &diag,
    });
    defer n.deinit();

    try std.testing.expect(!n.stats().failed);
    try std.testing.expect(!n.eng.failed);
    n.failed.store(true, .seq_cst); // the inert latch, with the engine itself healthy
    try std.testing.expect(!n.eng.failed);
    try std.testing.expect(n.stats().failed);
}
