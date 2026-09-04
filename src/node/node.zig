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
const app_gossip = @import("app_gossip.zig");
const timers_mod = @import("timers.zig");
const store_mod = @import("store.zig");
const qset_disk_cache = @import("qset_disk_cache.zig");
const keys_mod = @import("keys.zig");
const lint_report = @import("lint_report.zig");

const engine = core.engine;
const crypto = core.crypto;
const qset = core.qset;
const gen_slcp = core.gen.slcp;
const canonical = core.canonical;
const MessageBuilder = core.capnpc.message.MessageBuilder;
const QsetDiskCache = qset_disk_cache.QsetDiskCache;

test {
    _ = qset_disk_cache;
    _ = app_gossip;
}

const log = std.log.scoped(.slcp_node);

/// GC window: keep 16 externalized slots answerable to laggards (§10).
const purge_window: u64 = 16;

/// First slot in the retained answering window for a delivered frontier.
/// Zero means no slot has aged out yet.
fn purgeFloorForFrontier(frontier: u64) u64 {
    return if (frontier >= purge_window) frontier - (purge_window - 1) else 0;
}

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
    KeyFileTooPermissive,
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
pub const PublishAppMessageError = app_gossip.PublishError;
pub const AppMessageStats = app_gossip.Stats;

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
        error.KeyFileTooPermissive => ".key_file is readable by group or other (mode 0644, say) but the seed must be owner-only like ssh keys; run `chmod 600 <file>` and start again.",
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

/// One queued engine input plus the overlay peer it came from (null for
/// timers, proposals, purges and the own.log restore). Public only because
/// `HoldBuffer.Entry` carries one (Experimental).
pub const InputItem = struct {
    input: engine.Input,
    source_peer: ?usize,
};

/// Native host ingress pressure. Experimental: queue budgets may be tuned in
/// later 0.x releases. `queued_items` includes the optional coalesced purge
/// barrier in addition to the bounded ordinary FIFO; `queued_bytes` covers
/// payload bytes in that FIFO. Queue size is one coherent lock snapshot; the
/// drop counter is an independent monotonic atomic total. A network drop is a
/// transport-accepted envelope or a valid, requested qset response lost to
/// queue-capacity or host allocation pressure (including metadata parsing at
/// the hold gate). Intentional shutdown and malformed or unsolicited qset
/// frames are not drops.
pub const IngressStats = struct {
    queued_items: usize,
    queued_bytes: usize,
    dropped_network_inputs: usize,
};

/// Best-effort host-storage health. Experimental: these fields describe the
/// bounded quorum-set answering cache, not the safety-critical consensus logs.
/// Entry and byte counts are logical managed payloads and include the pinned
/// local quorum set; filesystem allocation overhead and unrelated files under
/// `qsets/` are outside the accounting.
pub const StorageStats = struct {
    qset_cache_entries: usize,
    qset_cache_bytes: usize,
    qset_cache_evictions: u64,
    qset_cache_read_failures: u64,
    qset_cache_write_failures: u64,
    qset_cache_degraded: bool,
};

/// Host-side per-slot hold buffer (S8 D1, the stellar-core Herder shape —
/// `processSCPQueueUpToIndex(lcl + 1)` with `PendingEnvelopes` for later
/// slots). Inbound statements — NOMINATE / PREPARE / CONFIRM **and
/// EXTERNALIZE** — for slots beyond the delivery frontier + 1 are parked
/// here, on the engine thread, and fed to the engine only once the frontier
/// reaches their slot − 1, so for a typed app `apply(N)` has always run
/// before any `validate` for N + 1 and the engine's per-slot verdict cache
/// can never be filled with a `.maybe_valid`-because-behind verdict that
/// then mutes the node for that slot forever (the mute-node halt: n − t + 1
/// such nodes halt the network; the S8b skeptic showed a lone peer's
/// EXTERNALIZE(N + 1) does it just as well as a NOMINATE).
///
/// Catch-up (`admit` → `.ready`): a held slot is released ahead of the
/// frontier as soon as its held EXTERNALIZE statements come from a
/// **v-blocking set** of the local quorum set — SCP's own accept condition,
/// applied host-side. Under the FBAS assumption a v-blocking set contains an
/// honest node, so the network finished that slot and this node's vote on
/// it can never be needed: validating it against a stale state (and going
/// mute on it) is harmless, while feeding it lets the engine externalize
/// the slot from those statements alone and the delivery gap-jump (§10)
/// follow. A single signer — the case that halted — is never v-blocking.
/// Once released this way a slot is `open`: later statements for it pass
/// straight through (the engine already holds its EXTERNALIZEs; a third
/// signer's must not wait for the next re-flood).
///
/// Engine-thread-only state (like `pending_ext` / `next_deliver`); the
/// atomic counters exist for tests and logs. Bounded: `window` slots ahead,
/// `max_entries` / `max_bytes` in total, one entry per (slot, signer, kind)
/// — every entry was signature-verified before it was stored, so a spoofed
/// node id cannot displace a genuine statement, and an honest sender's
/// re-floods replace rather than accumulate; only signers inside the
/// transitive quorum graph are held at all (a stranger goes straight to the
/// engine's §5.4 step-8 relevance filter, which `ignored`s it before any
/// state — so no stranger can occupy the buffer). Drops are never fatal:
/// the 3 s anti-entropy re-flood re-delivers anything dropped.
pub const HoldBuffer = struct {
    /// Slots more than this far past the delivery frontier are dropped
    /// (counted `dropped_far`). Equals `Limits.max_live_slots`'s default:
    /// the engine would refuse to open more live slots anyway.
    pub const window: u64 = 64;
    /// Total caps, mirroring the engine's parking caps (§5.4).
    pub const max_entries: usize = 1024;
    pub const max_bytes: usize = 8 * 1024 * 1024;

    pub const Kind = enum(u8) { nominate, prepare, confirm, externalize };
    pub const Entry = struct { node_id: [32]u8, kind: Kind, item: InputItem };
    const List = std.ArrayList(Entry);
    pub const PutResult = enum { held, replaced, dropped_full };
    /// `admit`'s verdict. `.fed`: not consumed — the caller feeds the item
    /// now. `.ready`: held, and the slot's EXTERNALIZE signers are now
    /// v-blocking — the caller releases the whole slot (`takeSlot`). The
    /// rest consumed the item (held, or freed and counted).
    pub const Admit = enum { fed, held, ready, dropped_far, dropped_full, dropped_badsig };

    slots: std.AutoHashMapUnmanaged(u64, List) = .empty,
    /// Slots released ahead of the frontier on v-blocking EXTERNALIZE
    /// evidence: later statements for them pass straight through. Pruned
    /// below the frontier with the held slots (≤ `window` entries).
    open: std.AutoHashMapUnmanaged(u64, void) = .empty,
    count: usize = 0,
    bytes: usize = 0,
    /// Entries held right now (= `count`, readable from any thread).
    held_now: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    /// Entries handed to the engine at the frontier.
    released: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Entries handed to the engine AHEAD of the frontier (catch-up: the
    /// slot's EXTERNALIZE signers were v-blocking).
    released_early: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Statements for a slot above the frontier from a signer outside the
    /// quorum graph: fed, never held (the engine ignores them statelessly).
    fed_out_of_graph: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Drops: slot beyond `window`; caps hit; signature failed; slot fell
    /// below the frontier while held (delivered or gap-jumped past).
    dropped_far: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    dropped_full: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    dropped_badsig: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    dropped_behind: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    fn itemBytes(item: *const InputItem) usize {
        return switch (item.input) {
            .envelope_received => |a| a.bytes.len,
            else => 0,
        };
    }

    /// Free an entry's owned input (the frame bytes).
    pub fn freeEntry(gpa: std.mem.Allocator, e: *Entry) void {
        core.host_codec.freeInput(gpa, &e.item.input);
    }

    /// Hold `item` (ownership is taken on EVERY path, including the error
    /// one) for `slot`, keyed by (signer, kind): an existing entry for the
    /// same key is replaced — removed from its position, the newcomer
    /// appended, so a slot's list stays in arrival order of its survivors.
    /// A cap breach drops the INCOMING item (`.dropped_full`): no eviction,
    /// the nearest slots are the useful ones and the sender's next re-flood
    /// heals the drop.
    pub fn put(self: *HoldBuffer, gpa: std.mem.Allocator, slot: u64, node_id: [32]u8, kind: Kind, item: InputItem) std.mem.Allocator.Error!PutResult {
        var owned = item;
        const len = itemBytes(&owned);
        const gop = self.slots.getOrPut(gpa, slot) catch |e| {
            core.host_codec.freeInput(gpa, &owned.input);
            return e;
        };
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        const list = gop.value_ptr;
        var dup: ?usize = null;
        for (list.items, 0..) |*e, i| {
            if (e.kind == kind and std.mem.eql(u8, &e.node_id, &node_id)) {
                dup = i;
                break;
            }
        }
        // Caps are judged on the projected state (a replacement frees its
        // predecessor first), so a re-flood of an already-held statement
        // never trips them.
        const old_len: usize = if (dup) |i| itemBytes(&list.items[i].item) else 0;
        const projected_count = self.count + 1 - @as(usize, if (dup != null) 1 else 0);
        const projected_bytes = self.bytes + len - old_len;
        if (projected_count > max_entries or projected_bytes > max_bytes) {
            core.host_codec.freeInput(gpa, &owned.input);
            if (list.items.len == 0) self.removeEmpty(gpa, slot);
            _ = self.dropped_full.fetchAdd(1, .monotonic);
            return .dropped_full;
        }
        if (dup) |i| {
            var old = list.orderedRemove(i);
            self.count -= 1;
            self.bytes -= old_len;
            freeEntry(gpa, &old);
        }
        list.append(gpa, .{ .node_id = node_id, .kind = kind, .item = owned }) catch |e| {
            core.host_codec.freeInput(gpa, &owned.input);
            if (list.items.len == 0) self.removeEmpty(gpa, slot);
            self.held_now.store(self.count, .release);
            return e;
        };
        self.count += 1;
        self.bytes += len;
        self.held_now.store(self.count, .release);
        return if (dup != null) .replaced else .held;
    }

    fn removeEmpty(self: *HoldBuffer, gpa: std.mem.Allocator, slot: u64) void {
        if (self.slots.fetchRemove(slot)) |kv| {
            var l = kv.value;
            l.deinit(gpa);
        }
    }

    fn dropList(self: *HoldBuffer, gpa: std.mem.Allocator, list: *List) void {
        for (list.items) |*e| {
            self.count -= 1;
            self.bytes -= itemBytes(&e.item);
            freeEntry(gpa, e);
        }
        _ = self.dropped_behind.fetchAdd(list.items.len, .monotonic);
        list.deinit(gpa);
    }

    /// Frees every held slot BELOW `frontier` (statements for a slot this
    /// node already delivered or skipped are useless — `dropped_behind`)
    /// and forgets `open` slots below it.
    fn pruneBelow(self: *HoldBuffer, gpa: std.mem.Allocator, frontier: u64) void {
        while (true) {
            var doomed: ?u64 = null;
            var it = self.slots.keyIterator();
            while (it.next()) |k| {
                if (k.* < frontier) {
                    doomed = k.*;
                    break;
                }
            }
            const key = doomed orelse break;
            var kv = self.slots.fetchRemove(key).?;
            self.dropList(gpa, &kv.value);
        }
        while (true) {
            var doomed: ?u64 = null;
            var it = self.open.keyIterator();
            while (it.next()) |k| {
                if (k.* < frontier) {
                    doomed = k.*;
                    break;
                }
            }
            const key = doomed orelse break;
            _ = self.open.remove(key);
        }
        self.held_now.store(self.count, .release);
    }

    /// Remove and hand back the list held for `slot` (the caller owns the
    /// entries and the list), or null.
    pub fn takeSlot(self: *HoldBuffer, slot: u64) ?List {
        const kv = self.slots.fetchRemove(slot) orelse return null;
        for (kv.value.items) |*e| {
            self.count -= 1;
            self.bytes -= itemBytes(&e.item);
        }
        self.held_now.store(self.count, .release);
        return kv.value;
    }

    /// Frees every held slot BELOW `frontier` (see `pruneBelow`), then
    /// hands back the list for slot == `frontier` (exactly lcl + 1, Herder
    /// shape; the caller owns the entries and the list) or null. Nothing
    /// held is ever returned for a slot at or below the frontier.
    pub fn takeReleasable(self: *HoldBuffer, gpa: std.mem.Allocator, frontier: u64) ?List {
        self.pruneBelow(gpa, frontier);
        return self.takeSlot(frontier);
    }

    /// Do the EXTERNALIZE statements held for `slot` come from a v-blocking
    /// set of `qs` (the local quorum set)? OOM ⇒ false (the next EXTERNALIZE
    /// for the slot re-asks).
    pub fn extSignersVBlocking(self: *const HoldBuffer, gpa: std.mem.Allocator, slot: u64, qs: *const qset.QuorumSetOwned) bool {
        const list = self.slots.getPtr(slot) orelse return false;
        const ids = gpa.alloc([32]u8, list.items.len) catch return false;
        defer gpa.free(ids);
        var n: usize = 0;
        for (list.items) |*e| {
            if (e.kind != .externalize) continue;
            ids[n] = e.node_id;
            n += 1;
        }
        return n > 0 and core.local_node.isVBlocking(qs, ids[0..n]);
    }

    /// The gate for one inbound envelope whose `meta` decoded, given the
    /// delivery frontier (`next_deliver`), whether the signer is inside the
    /// transitive quorum graph, and the local quorum set. Ownership of
    /// `item` is taken on every path except `.fed`. Rules, in order:
    /// a statement for the frontier slot or anything behind it, from a
    /// signer outside the graph, or for an `open` slot is fed now; a slot
    /// more than `window` past the frontier is dropped; a bad signature is
    /// dropped (a forged signer must not occupy or displace a genuine
    /// entry); otherwise held — and if it is an EXTERNALIZE that completes
    /// a v-blocking set for its slot, the slot becomes `open` and `.ready`.
    pub fn admit(self: *HoldBuffer, gpa: std.mem.Allocator, meta: *const Meta, frontier: u64, in_graph: bool, qs: *const qset.QuorumSetOwned, item: InputItem) Admit {
        var owned = item;
        if (meta.slot <= frontier or self.open.contains(meta.slot)) return .fed;
        if (!in_graph) {
            _ = self.fed_out_of_graph.fetchAdd(1, .monotonic);
            return .fed;
        }
        if (meta.slot > frontier + window) {
            core.host_codec.freeInput(gpa, &owned.input);
            _ = self.dropped_far.fetchAdd(1, .monotonic);
            return .dropped_far;
        }
        if (!crypto.verify(meta.node_id, meta.digest, meta.signature)) {
            core.host_codec.freeInput(gpa, &owned.input);
            _ = self.dropped_badsig.fetchAdd(1, .monotonic);
            return .dropped_badsig;
        }
        const r = self.put(gpa, meta.slot, meta.node_id, meta.kind, owned) catch {
            // OOM: `put` freed the item; count it with the cap drops.
            _ = self.dropped_full.fetchAdd(1, .monotonic);
            return .dropped_full;
        };
        if (r == .dropped_full) return .dropped_full;
        if (meta.kind == .externalize and self.extSignersVBlocking(gpa, meta.slot, qs)) {
            // Best effort: without the mark a later statement for the slot
            // is held again and the next v-blocking EXTERNALIZE re-releases.
            self.open.put(gpa, meta.slot, {}) catch {};
            return .ready;
        }
        return .held;
    }

    pub fn deinit(self: *HoldBuffer, gpa: std.mem.Allocator) void {
        var it = self.slots.valueIterator();
        while (it.next()) |list| {
            for (list.items) |*e| freeEntry(gpa, e);
            list.deinit(gpa);
        }
        self.slots.deinit(gpa);
        self.open.deinit(gpa);
        self.count = 0;
        self.bytes = 0;
        self.held_now.store(0, .release);
    }
};

/// What the hold gate needs to know about a framed Envelope, decoded with
/// the pipeline's validating options (nesting 32, traversal scaled to the
/// frame / statement caps). `digest` is the signed preimage so the gate can
/// verify BEFORE holding (a spoofed signer must not displace a genuine
/// entry); the engine re-verifies whatever it is eventually fed.
pub const Meta = struct {
    slot: u64,
    node_id: [32]u8,
    kind: HoldBuffer.Kind,
    digest: [32]u8,
    signature: [64]u8,
};

pub fn envelopeMeta(gpa: std.mem.Allocator, network_id: [32]u8, framed_env: []const u8) !Meta {
    if (framed_env.len > core.limits.frozen_max_frame_bytes) return error.FrameTooLarge;
    var emsg = try core.capnpc.message.Message.init(gpa, framed_env, .{
        .nesting_limit = 32,
        .traversal_limit_words = core.limits.frozen_max_frame_bytes / 8,
    });
    defer emsg.deinit();
    const er = try gen_slcp.Envelope.Reader.init(&emsg);
    const stmt_bytes = try er.getStatementBytes();
    if (stmt_bytes.len == 0 or stmt_bytes.len > core.limits.frozen_max_statement_bytes) return error.BadStatementLength;
    const sig = try er.getSignature();
    if (sig.len != 64) return error.BadSignatureLength;
    var smsg = try canonical.decodeFlat(gpa, stmt_bytes, .{
        .nesting_limit = 32,
        .traversal_limit_words = core.limits.frozen_max_statement_bytes / 8,
    });
    defer smsg.deinit();
    const sr = try gen_slcp.Statement.Reader.init(&smsg);
    const nid = try sr.getNodeId();
    if (nid.len != 32) return error.BadNodeIdLength;
    const kind: HoldBuffer.Kind = switch (try sr.getPledges().which()) {
        .nominate => .nominate,
        .prepare => .prepare,
        .confirm => .confirm,
        .externalize => .externalize,
        .unset => return error.UnsetPledges,
    };
    return .{
        .slot = try sr.getSlotIndex(),
        .node_id = nid[0..32].*,
        .kind = kind,
        .digest = crypto.statementDigest(network_id, stmt_bytes),
        .signature = sig[0..64].*,
    };
}

/// Mutex+condvar FIFO of pending engine inputs. Payloads are owned; the engine
/// thread frees them after `pushInput` (which copies what it keeps).
/// This Zig's sync primitives live under std.Io and take `io` on every call
/// (cancellation is a no-op on our raw std.Thread workers, so the
/// *Uncancelable variants are used to avoid the error union).
const InputQueue = struct {
    const max_items: usize = 1024;
    /// The ordinary FIFO may retain at most one additional cap-sized consumed
    /// prefix. Compacting only at that threshold makes the copies amortized
    /// while bounding both physical list length and allocated element
    /// capacity to twice the live-item cap.
    const max_backing_items: usize = max_items * 2;
    const reserved_progress_items: usize = 64;
    const max_bytes: usize = 16 * 1024 * 1024;
    const reserved_progress_bytes: usize = 1024 * 1024;
    const PushError = std.mem.Allocator.Error || error{ InputQueueFull, QueueClosed };

    gpa: std.mem.Allocator,
    io: std.Io,
    mu: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    items: std.ArrayList(InputItem) = .empty,
    head: usize = 0,
    bytes: usize = 0,
    /// A non-allocating control lane outside the ordinary FIFO budget. Purges
    /// are monotonic, so one maximum watermark represents any number of
    /// pending purge inputs without losing work.
    pending_purge: ?u64 = null,
    dropped_network: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    closed: bool = false,

    /// Owning, fire-and-forget enqueue for timer fires and received frames.
    /// Failed admission always consumes the input; pressure is counted/logged
    /// while intentional shutdown is quiet.
    fn push(self: *InputQueue, item: InputItem) void {
        const network_input = inputItemIsNetwork(&item);
        self.tryPush(item) catch |err| {
            var in = item.input;
            core.host_codec.freeInput(self.gpa, &in);
            switch (err) {
                error.InputQueueFull => if (network_input) {
                    self.recordNetworkDrop();
                } else {
                    log.warn("input queue full; dropped one progress input", .{});
                },
                error.OutOfMemory => if (network_input) {
                    self.recordNetworkDrop();
                } else {
                    log.err("input queue OOM; dropped one progress input", .{});
                },
                error.QueueClosed => {},
            }
        };
    }

    /// Purge is a barrier for all already-queued network work: it updates the
    /// Engine's pending/live-slot state before a qset response can unpark a
    /// statement below the host's newly published purge floor. Its monotonic
    /// watermark is stored outside the ordinary item/byte budgets so pressure
    /// cannot drop the barrier; repeated purges coalesce to the highest floor.
    /// Engine-owner only: unlike external pushes, this remains admissible after
    /// `close` while the engine drains work that was already in the FIFO.
    fn pushPriority(self: *InputQueue, item: InputItem) void {
        const max_slot = switch (item.input) {
            .purge_slots => |p| p.max_slot,
            else => unreachable,
        };
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        self.pending_purge = if (self.pending_purge) |old| @max(old, max_slot) else max_slot;
        self.cond.signal(self.io);
    }

    fn recordNetworkDrop(self: *InputQueue) void {
        const dropped = self.dropped_network.fetchAdd(1, .monotonic) + 1;
        if (dropped == 1 or dropped & (dropped - 1) == 0) {
            log.warn("network ingress pressure; dropped {d} input(s)", .{dropped});
        }
    }

    /// Copy an already-classified network input into Node ownership. Callers
    /// decide admissibility first (notably qset correlation); this helper
    /// makes copy pressure accounting consistent across ingress paths. If the
    /// allocation fails after shutdown has closed the queue, the loss is
    /// intentional and stays out of the pressure counter.
    fn copyNetworkBytes(self: *InputQueue, bytes: []const u8) ?[]u8 {
        return self.gpa.dupe(u8, bytes) catch {
            self.mu.lockUncancelable(self.io);
            const closed = self.closed;
            self.mu.unlock(self.io);
            if (!closed) self.recordNetworkDrop();
            return null;
        };
    }

    /// Transactional enqueue: on every error the caller still owns `item`
    /// (nothing is freed or logged). This lets nomination roll back queue
    /// pressure and qset ingress release a request claim on shutdown instead
    /// of committing an input which never reached the Engine.
    fn tryPush(self: *InputQueue, item: InputItem) PushError!void {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        if (self.closed) return error.QueueClosed;
        const pending = self.items.items.len - self.head;
        const network_input = inputItemIsNetwork(&item);
        const item_bytes = inputItemBytes(&item);
        const next_bytes = std.math.add(usize, self.bytes, item_bytes) catch return error.InputQueueFull;
        if (pending >= max_items or
            next_bytes > max_bytes or
            (network_input and (pending >= max_items - reserved_progress_items or
                next_bytes > max_bytes - reserved_progress_bytes)))
        {
            return error.InputQueueFull;
        }
        if (self.head >= max_items) self.compactConsumed();
        try self.appendBounded(item);
        self.bytes = next_bytes;
        self.cond.signal(self.io);
    }

    /// ArrayList's default geometric growth may reserve ~1.5x beyond the
    /// requested length. Preserve amortized growth but clamp the allocation
    /// to the same explicit bound as the retained consumed prefix.
    fn appendBounded(self: *InputQueue, item: InputItem) std.mem.Allocator.Error!void {
        if (self.items.items.len == self.items.capacity) {
            const needed = self.items.items.len + 1;
            const grown = std.ArrayList(InputItem).growCapacity(needed);
            const bounded = @min(grown, max_backing_items);
            std.debug.assert(bounded >= needed);
            try self.items.ensureTotalCapacityPrecise(self.gpa, bounded);
        }
        self.items.appendAssumeCapacity(item);
    }

    /// Block for the next item; null once closed and drained.
    fn pop(self: *InputQueue) ?InputItem {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        while (self.head >= self.items.items.len and self.pending_purge == null and !self.closed) {
            self.cond.waitUncancelable(self.io, &self.mu);
        }
        if (self.pending_purge) |max_slot| {
            self.pending_purge = null;
            return .{ .input = .{ .purge_slots = .{ .max_slot = max_slot } }, .source_peer = null };
        }
        if (self.head >= self.items.items.len) return null;
        const it = self.items.items[self.head];
        self.bytes -= inputItemBytes(&it);
        self.head += 1;
        if (self.head == self.items.items.len) {
            self.items.clearRetainingCapacity();
            self.head = 0;
        }
        return it;
    }

    /// Discard the already-consumed prefix without touching ownership of the
    /// live suffix. Called under `mu` only after at least `max_items` pops, so
    /// copying at most `max_items - 1` live entries is amortized O(1).
    fn compactConsumed(self: *InputQueue) void {
        std.debug.assert(self.head > 0);
        const pending = self.items.items.len - self.head;
        std.mem.copyForwards(InputItem, self.items.items[0..pending], self.items.items[self.head..]);
        self.items.shrinkRetainingCapacity(pending);
        self.head = 0;
    }

    fn close(self: *InputQueue) void {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        self.closed = true;
        self.cond.broadcast(self.io);
    }

    fn snapshot(self: *InputQueue) IngressStats {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        return .{
            .queued_items = self.items.items.len - self.head + @intFromBool(self.pending_purge != null),
            .queued_bytes = self.bytes,
            .dropped_network_inputs = self.dropped_network.load(.acquire),
        };
    }

    fn deinit(self: *InputQueue) void {
        for (self.items.items[self.head..]) |*it| core.host_codec.freeInput(self.gpa, &it.input);
        self.items.deinit(self.gpa);
        self.* = undefined;
    }
};

fn inputItemBytes(item: *const InputItem) usize {
    return switch (item.input) {
        .envelope_received => |v| v.bytes.len,
        .qset_received => |v| v.bytes.len,
        .restore_own_envelope => |v| v.bytes.len,
        .nominate => |v| v.value.len +| v.prev_value.len,
        .timer_fired, .purge_slots => 0,
    };
}

fn inputItemIsNetwork(item: *const InputItem) bool {
    return switch (item.input) {
        .envelope_received, .qset_received => true,
        else => false,
    };
}

/// Bounded correlation between Engine `request_qset` effects and overlay
/// responses. The engine owner reconciles this index to the exact pending
/// hashes after every input, so evictions and purges cannot leave stale tokens
/// that crowd out a still-live request.
const QsetRequests = struct {
    const Phase = enum { available, claimed, queued };
    const State = struct {
        phase: Phase = .available,
        seen_generation: u64 = 0,
    };

    gpa: std.mem.Allocator,
    io: std.Io,
    mu: std.Io.Mutex = .init,
    states: std.AutoHashMapUnmanaged([32]u8, State) = .empty,
    order: std.ArrayList([32]u8) = .empty,
    generation: u64 = 0,
    /// One transient request may be dispatched after Pending has evicted back
    /// to its configured cap but before the end-of-input reconciliation.
    max_hashes: usize,

    fn init(gpa: std.mem.Allocator, io: std.Io, max_pending_envelopes: u32) !QsetRequests {
        const max_hashes = @as(usize, @intCast(max_pending_envelopes)) + 1;
        var self = QsetRequests{ .gpa = gpa, .io = io, .max_hashes = max_hashes };
        errdefer self.deinit();
        const map_capacity = std.math.cast(u32, max_hashes) orelse return error.OutOfMemory;
        try self.states.ensureTotalCapacity(gpa, map_capacity);
        try self.order.ensureTotalCapacity(gpa, max_hashes);
        return self;
    }

    fn note(self: *QsetRequests, hash: [32]u8) void {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);

        if (self.states.get(hash) != null) {
            const index = self.indexOf(hash) orelse unreachable;
            const existing = self.order.orderedRemove(index);
            self.order.appendAssumeCapacity(existing);
            return;
        }

        if (self.order.items.len >= self.max_hashes) {
            const oldest = self.order.orderedRemove(0);
            _ = self.states.remove(oldest);
        }
        self.states.putAssumeCapacity(hash, .{ .seen_generation = self.generation });
        self.order.appendAssumeCapacity(hash);
    }

    /// Atomically reserve one requested hash for a reader thread. A second
    /// peer racing the same response is rejected while the first owns it.
    fn claim(self: *QsetRequests, hash: [32]u8) bool {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        const state = self.states.getPtr(hash) orelse return false;
        if (state.phase != .available) return false;
        state.phase = .claimed;
        return true;
    }

    /// Mark the response queued. The token remains present (and rejects
    /// duplicates) until reconciliation observes that Engine Pending no
    /// longer contains the hash.
    fn commit(self: *QsetRequests, hash: [32]u8) void {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        const state = self.states.getPtr(hash) orelse return;
        if (state.phase == .claimed) state.phase = .queued;
    }

    /// Failed queue admission (pressure or shutdown) releases the same
    /// in-place token for retry; no allocation is needed on this path.
    fn release(self: *QsetRequests, hash: [32]u8) void {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        const state = self.states.getPtr(hash) orelse return;
        if (state.phase == .claimed) state.phase = .available;
    }

    /// Engine-owner only. `parked` is the post-input Pending FIFO. Mark its
    /// distinct hashes in O(pending), then compact the unique order in O(n),
    /// preserving any claim/queued phase for hashes that remain live.
    fn reconcile(self: *QsetRequests, parked: anytype) void {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);

        self.generation +%= 1;
        if (self.generation == 0) {
            // Avoid a stale generation match after the theoretical u64 wrap.
            self.generation = 1;
            var values = self.states.valueIterator();
            while (values.next()) |state| state.seen_generation = 0;
        }
        const generation = self.generation;
        for (parked) |entry| {
            if (self.states.getPtr(entry.needed_hash)) |state| {
                state.seen_generation = generation;
            } else {
                // Every pending hash first emitted request_qset in the same
                // feedInput, so preallocated capacity is sufficient even if
                // an earlier defensive bound evicted its transient token.
                if (self.order.items.len >= self.max_hashes) {
                    const oldest = self.order.orderedRemove(0);
                    _ = self.states.remove(oldest);
                }
                self.states.putAssumeCapacity(entry.needed_hash, .{ .seen_generation = generation });
                self.order.appendAssumeCapacity(entry.needed_hash);
            }
        }

        var write: usize = 0;
        for (self.order.items) |hash| {
            const state = self.states.get(hash) orelse continue;
            if (state.seen_generation == generation) {
                self.order.items[write] = hash;
                write += 1;
            } else {
                _ = self.states.remove(hash);
            }
        }
        self.order.shrinkRetainingCapacity(write);
    }

    fn indexOf(self: *const QsetRequests, hash: [32]u8) ?usize {
        for (self.order.items, 0..) |candidate, i| {
            if (std.mem.eql(u8, &candidate, &hash)) return i;
        }
        return null;
    }

    fn deinit(self: *QsetRequests) void {
        self.states.deinit(self.gpa);
        self.order.deinit(self.gpa);
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
    qset_cache: QsetDiskCache,
    wheel: timers_mod.Wheel,
    ov: overlay_mod.Overlay,
    app_gossip: app_gossip.State,

    engine_thread: ?std.Thread = null,
    failed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Last Engine stats observed at a completed input/drain boundary. The
    /// engine thread publishes it; callers read only this copy, never the
    /// live Engine containers owned by that thread.
    stats_mu: std.Io.Mutex = .init,
    stats_snapshot: engine.Stats = .{
        .live_slots = 0,
        .parked = 0,
        .cached_qsets = 0,
        .effects_queued = 0,
        .stored_statement_bytes = 0,
        .failed = false,
    },
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
    /// Threads currently inside `waitExternalized` (under `ext_mu`); `deinit`
    /// wakes them and waits on `ext_drained` for zero before freeing.
    ext_waiters: usize = 0,
    ext_drained: std.Io.Condition = .init,
    /// `Options.delivery`: when set, `deliverSlot` calls it instead of
    /// queueing for `waitExternalized`. Read on the engine thread (and on
    /// the creating thread during the journal-tail replay).
    delivery: ?DeliveryHook,

    /// Engine-thread-only: out-of-order externalizations awaiting their turn
    /// (values owned), and the next slot to hand the app (§11.2 ordering).
    pending_ext: std.AutoHashMapUnmanaged(u64, []u8) = .empty,
    next_deliver: u64,
    /// Engine-thread-only: inbound statements of every kind (EXTERNALIZE
    /// included) for slots above `next_deliver`, released at the frontier —
    /// or early, once a v-blocking set has externalized their slot (S8 D1 /
    /// S8b).
    hold: HoldBuffer = .{},
    /// Engine-thread-only: the delivered frontier at the last successful log
    /// compaction. Compaction runs whenever the frontier enters a new
    /// 64-slot bucket past this (§10 "every 64 delivered slots") — tracked
    /// rather than tested with `frontier % 64 == 0`, because one drain can
    /// step over a boundary when out-of-order catch-up slots are buffered.
    last_compact_frontier: u64 = 0,
    /// The externalized.log tail found at `create` (first and last slot;
    /// null when the journal was empty). Written once before go-live, then
    /// read-only: `AppNode` checks an app's `initialSlot()` against it
    /// (§8.5 delta-app recipe, S8 D2).
    journal_tail: ?JournalTail = null,
    /// Slots below this are purged; the timer wheel drops stale fires for
    /// them (read on the wheel thread).
    purge_floor: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Correlates requested qset responses before either queue admission or
    /// persistence, with an Engine-pending-sized bound.
    qset_requests: QsetRequests,

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
    /// as ONE `CreateError` member with a message in `options.diagnostic` —
    /// `OutOfMemory` included, and a reused buffer never keeps a previous
    /// failure's text (it is cleared first; a success leaves it empty).
    pub fn create(gpa: std.mem.Allocator, io: std.Io, options: Options) CreateError!*Node {
        if (options.diagnostic) |d| d.len = 0;
        return createChecked(gpa, io, options) catch |e| switch (e) {
            // The one member no check site writes (every `try` allocation
            // can raise it): give it the paragraph here (review finding).
            error.OutOfMemory => fail(options.diagnostic, error.OutOfMemory, "out of memory while creating the node; nothing was started — free memory or raise the process limit and try again.", .{}),
            else => e,
        };
    }

    fn createChecked(gpa: std.mem.Allocator, io: std.Io, options: Options) CreateError!*Node {
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
            // An empty level has no threshold in range by construction:
            // report the level, not a "[1, 0]" range (review finding).
            if (bad.members == 0) {
                return fail(diag, error.QuorumEmpty, ".quorum has a level with no members (threshold {d} of 0); every level needs at least one validator or inner set.", .{bad.threshold});
            }
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
            .qset_requests = try QsetRequests.init(gpa, io, limits.max_pending_envelopes),
            .store = undefined,
            .qset_cache = undefined,
            .wheel = undefined,
            .ov = undefined,
            .app_gossip = app_gossip.State.init(gpa, io),
            .current_slot = opts.start_slot,
            .next_deliver = opts.start_slot,
            .last_ext_value = &.{},
            .delivery = opts.delivery,
            .max_value_bytes = opts.max_value_bytes,
        };
        // Registered FIRST so it runs LAST on the unwind (after the thread
        // joins and the ov/wheel stops below): the journal-tail replay and
        // the own.log restore populate ext_queue / own_latest / pending_ext
        // BEFORE the listen and the thread spawns can still fail (review
        // finding: ListenPortInUse on a restart leaked the replayed tail).
        errdefer self.freeAppBuffers();

        // Engine.init does NOT free cfg.quorum_set on failure; we still own
        // it until this succeeds.
        self.eng = engine.Engine.init(gpa, cfg, drv) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return fail(diag, error.EngineFailed, "the consensus engine could not be initialized: {t}; this is a bug in slcp or an exotic limit — please report it with your options.", .{e}),
        };
        owned_live = false;
        // False only inside the corrupt-own.log watcher re-init below, while
        // the first engine is torn down and the second not yet up (review
        // finding: the unguarded errdefer ran deinit on an undefined Engine).
        var eng_live = true;
        errdefer if (eng_live) self.eng.deinit();

        // ---- store + recovery ----
        self.store = store_mod.Store.open(gpa, io, opts.data_dir) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Busy => return fail(diag, error.DataDirBusy, ".data_dir \"{s}\" is in use by another live slcp node (the lock file {s}/lock is held); one identity must never run twice — stop the other process, or point this node at its own data_dir.", .{ opts.data_dir, opts.data_dir }),
            error.AccessDenied, error.PermissionDenied => return fail(diag, error.DataDirAccessDenied, ".data_dir \"{s}\": a write-ahead log cannot be opened for writing (permission denied); fix the ownership/permissions of own.log and externalized.log — a restart as a different user than the one that created them is the usual cause — or point .data_dir at a directory this user owns.", .{opts.data_dir}),
            else => return fail(diag, error.DataDirUnusable, ".data_dir \"{s}\" cannot be used: the write-ahead logs could not be opened ({t}); check the path, the filesystem (read-only?) and free space.", .{ opts.data_dir, e }),
        };
        errdefer self.store.deinit();

        // The answering cache is deliberately separate from Store's fatal
        // write-ahead path. Reconcile it while Store's process lock is held and
        // before Overlay.init can expose the listener. Filesystem failures
        // degrade to memory-pinned local answers and Experimental counters.
        self.qset_cache = try QsetDiskCache.open(gpa, io, opts.data_dir, .{
            .hash = local_hash,
            .framed = framed_local,
        });
        errdefer self.qset_cache.deinit();

        self.wheel = timers_mod.Wheel.init(gpa, io, onTimerFire, self);
        errdefer self.wheel.deinit(); // stop() is idempotent; frees the timer list

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
        errdefer self.ov.deinit(); // after ov.stop() below on the unwind

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
            // warn, not err: the node starts (degraded) — and the test
            // runner fails any test that logs at err, which would leave
            // this fallback path untestable through a live create().
            log.warn("own.log integrity failure — falling back to WATCHER mode " ++
                "for the node's lifetime (safe: a watcher never emits, so it " ++
                "cannot emit stale-vs-self). Slots up to the externalized " ++
                "high-water mark + 1 were at risk.", .{});
            // Rebuild the engine as a watcher (secret_seed cleared). The old
            // engine owns a normalized qset clone; give the new one a fresh
            // clone. Engine.init does not free cfg.quorum_set on failure.
            const qs_clone = try qset.clone(gpa, &self.eng.cfg.quorum_set);
            self.eng.deinit();
            eng_live = false;
            var wcfg = cfg;
            wcfg.secret_seed = null;
            wcfg.quorum_set = qs_clone;
            self.eng = engine.Engine.init(gpa, wcfg, drv) catch |e| {
                wcfg.quorum_set.deinit(gpa);
                switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return fail(diag, error.EngineFailed, "the consensus engine could not be re-initialized in watcher mode: {t}; please report this.", .{e}),
                }
            };
            eng_live = true;
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
        // Rebuild the same host admission floor live delivery would have
        // published. Recovery can contain up to 79 slots just before the next
        // 64-slot compaction; restoring them all oldest-first would fill the
        // Engine's 64-slot budget before reaching current state. An explicit
        // start_slot also declares all earlier slots out of scope, including
        // when the journal is empty or ends below it.
        const recovery_floor = @max(opts.start_slot, purgeFloorForFrontier(self.next_deliver - 1));
        self.purge_floor.store(recovery_floor, .release);
        // §10: externalized.log is the app-visible journal. A crash can land
        // between journal append and app consumption, so REPLAY the (compaction
        // -bounded) journal tail into the app stream — the app dedups by slot
        // (the §10 contract). Without this, journaled-but-unconsumed values
        // would be silently lost across a restart (review finding).
        if (rec.ext_tail.len > 0) {
            self.journal_tail = .{ .first = rec.ext_tail[0].slot, .last = rec.ext_tail[rec.ext_tail.len - 1].slot };
        }
        for (rec.ext_tail) |r| {
            const v = try gpa.dupe(u8, r.value);
            self.deliverSlot(r.slot, v) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return fail(diag, error.EngineFailed, ".delivery hook refused journaled slot {d} of {s} during restart replay: {t}; the app cannot consume a value the network already agreed on, so the node will not start.", .{ r.slot, opts.data_dir, e }),
            };
        }
        if (!rec.own_log_corrupt) {
            for (rec.own_latest) |r| {
                if (r.slot < recovery_floor) continue;
                const clean = self.feedInput(.{
                    .input = .{ .restore_own_envelope = .{ .bytes = try gpa.dupe(u8, r.envelope) } },
                    .source_peer = null,
                }) catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return fail(diag, error.EngineFailed, "the own.log restore of {s} failed for slot {d}: {t}; the data_dir's own.log may be damaged — move it aside to start fresh, or report this.", .{ opts.data_dir, r.slot, e }),
                };
                // A restored statement that never made it into the catch-up
                // cache would be re-sent to nobody: OOM here is a create
                // failure, not a degraded start.
                if (!clean) return error.OutOfMemory;
            }
        }
        // An effect dispatched during the restore can latch the node inert
        // (a failed write-ahead append, OOM buffering an externalization).
        // Every create failure is a CreateError (§11.2): never hand back a
        // node that is already dead (review finding).
        if (self.failed.load(.acquire)) {
            return fail(diag, error.EngineFailed, "the node failed while restoring its state from {s} (see the preceding log line) and cannot start; check the filesystem and free space, or move the data_dir aside to start fresh.", .{opts.data_dir});
        }
        self.publishStats();

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
            // restored under umask 022 arrives 0644 (S8 finding: it was
            // accepted in silence, then only warned about). User decision
            // (S8b): REFUSE, ssh-style — a seed every account in the group
            // or on the machine can read is not this node's identity alone,
            // and the fix is one command the message spells out. A stat
            // failure is not a verdict (the seed did load): start.
            if (keys_mod.modeOf(io, path)) |mode| {
                if (keys_mod.modeTooOpen(mode)) {
                    return fail(diag, error.KeyFileTooPermissive, ".key_file \"{s}\" is mode 0{o}: readable by group/other, but the seed must be owner-only (slcp mints 0600 and, like ssh, refuses a key other accounts can read); run `chmod 600 {s}` and start again.", .{ path, mode, path });
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

        // App-message waiters are public callers, not overlay workers. Wake
        // and drain them before teardown, but retain the inbox until ov.stop
        // joins every reader that can still call receive().
        self.app_gossip.closeAndDrain();

        // Wake any app thread blocked in waitExternalized so it returns null,
        // and wait until every waiter has left (a woken waiter re-locks
        // ext_mu on its way out — that must happen before the free below).
        self.ext_mu.lockUncancelable(self.io);
        self.ext_closed = true;
        self.ext_cond.broadcast(self.io);
        while (self.ext_waiters > 0) self.ext_drained.waitUncancelable(self.io, &self.ext_mu);
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

        self.qset_cache.deinit();
        self.store.deinit();
        self.eng.deinit();
        self.freeAppBuffers();

        const gpa = self.gpa;
        self.* = undefined;
        gpa.destroy(self);
    }

    /// Free every buffer the replay/restore inside `create` and the engine
    /// thread populate: the input queue's leftovers, own_latest, the
    /// proposal queue, last_ext_value, ext_queue, pending_ext, qset requests.
    /// Shared by `deinit` and `create`'s unwind; safe on the zero state.
    /// Callers must have joined every thread that pushes or dispatches.
    fn freeAppBuffers(self: *Node) void {
        self.q.deinit();
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
        self.qset_requests.deinit();
        self.hold.deinit(self.gpa);
        self.app_gossip.deinit();
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
        self.maybeStartNomination() catch |e| {
            // Not accepted: take OUR value back out (an older head that
            // failed to nominate is already back at the head) so the
            // caller's OutOfMemory means exactly "propose it again".
            self.prop_mu.lockUncancelable(self.io);
            defer self.prop_mu.unlock(self.io);
            for (self.proposal_queue.items, 0..) |v, i| {
                if (v.ptr == copy.ptr) {
                    _ = self.proposal_queue.orderedRemove(i);
                    self.gpa.free(v);
                    break;
                }
            }
            return e;
        };
    }

    /// Bounds of the journal tail replayed at `create` (ascending slots).
    pub const JournalTail = struct { first: u64, last: u64 };

    pub const WaitOptions = struct {
        /// null = block until the next externalization or shutdown.
        timeout_ms: ?u64 = null,
    };

    /// Block for the next externalized slot in order. Returns null on timeout
    /// or shutdown. The returned `value` is owned by the caller.
    pub fn waitExternalized(self: *Node, wopts: WaitOptions) ?Externalized {
        self.ext_mu.lockUncancelable(self.io);
        defer self.ext_mu.unlock(self.io);
        self.ext_waiters += 1;
        defer { // runs before the unlock above (reverse order)
            self.ext_waiters -= 1;
            if (self.ext_waiters == 0) self.ext_drained.signal(self.io);
        }
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

    /// Best-effort, non-durable application broadcast to capable peers.
    /// The consensus Engine never sees these opaque bytes. Applications must
    /// authenticate, validate, deduplicate, and retry their own messages.
    pub fn publishAppMessage(self: *Node, payload: []const u8) PublishAppMessageError!void {
        try self.app_gossip.validatePublish(payload);
        self.ov.broadcast(.{ .app_message = payload });
    }

    /// Opt this node into bounded application-message retention and wait for
    /// one FIFO payload. Returns null on timeout or shutdown; returned bytes
    /// are owned by the caller and must be freed with `node.allocator()`.
    pub fn waitAppMessage(self: *Node, wopts: WaitOptions) ?[]u8 {
        return self.app_gossip.wait(wopts.timeout_ms);
    }

    /// Bounded application inbox accounting. Experimental.
    pub fn appMessageStats(self: *Node) AppMessageStats {
        return self.app_gossip.snapshot();
    }

    /// Coherent observability snapshot published by the engine thread after
    /// each complete input/effect drain. `.failed` is true when EITHER the
    /// engine latched (§7.2 DriverFault/EngineFailed) or the node itself went
    /// inert (`markFailed`: a hook refusal, a failed write-ahead append, a
    /// buffering OOM) — a halted node must not report itself healthy.
    pub fn stats(self: *Node) engine.Stats {
        self.stats_mu.lockUncancelable(self.io);
        var s = self.stats_snapshot;
        self.stats_mu.unlock(self.io);
        s.failed = s.failed or self.failed.load(.acquire);
        return s;
    }

    /// Native ingress pressure and drops. Experimental; the consensus
    /// Engine's Stable stats remain a separate snapshot.
    pub fn ingressStats(self: *Node) IngressStats {
        return self.q.snapshot();
    }

    /// Bounded quorum-set disk-cache accounting and failure counters.
    /// Experimental in v0.x; consensus Engine stats remain separate.
    pub fn storageStats(self: *Node) StorageStats {
        const s = self.qset_cache.snapshot();
        return .{
            .qset_cache_entries = s.entries,
            .qset_cache_bytes = s.bytes,
            .qset_cache_evictions = s.evictions,
            .qset_cache_read_failures = s.read_failures,
            .qset_cache_write_failures = s.write_failures,
            .qset_cache_degraded = s.degraded,
        };
    }

    /// Engine-owner only (or the creating thread before `engine_thread`
    /// starts): take the live Engine snapshot, then publish the POD copy.
    fn publishStats(self: *Node) void {
        const s = self.eng.stats();
        self.stats_mu.lockUncancelable(self.io);
        self.stats_snapshot = s;
        self.stats_mu.unlock(self.io);
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

            self.sendOwnLatest(.all, "resync");
            self.ov.broadcast(.{ .get_slot_state = 0 });
        }
    }

    /// Feed one input and drain all its effects (engine thread only) — the
    /// ONLY place inbound envelopes enter the engine, so the hold gate
    /// lives here: an envelope for a slot beyond the delivery frontier + 1
    /// is parked (`HoldBuffer`) instead of fed — or, when it completes a
    /// v-blocking set of EXTERNALIZEs for its slot, released with that
    /// whole slot ahead of the frontier (catch-up) — and whenever an input
    /// moved the frontier the parked statements for the new frontier slot
    /// are fed next, before the next queued input is popped.
    fn applyInput(self: *Node, item_in: InputItem) void {
        var item = item_in;
        defer self.publishStats();
        // A purge runs on the priority control lane and can therefore pass a
        // local nomination that was already waiting in the ordinary FIFO.
        // Re-check the monotonic host floor at apply-time: feeding that old
        // nomination would recreate a slot the Engine has just purged and
        // could make this node sign a fresh, incomparable statement for it.
        if (item.input == .nominate and
            item.input.nominate.slot < self.purge_floor.load(.acquire))
        {
            core.host_codec.freeInput(self.gpa, &item.input);
            return;
        }
        const before = self.next_deliver;
        if (item.input == .envelope_received and !self.failed.load(.acquire)) {
            switch (self.gateEnvelope(item)) {
                .feed => self.feedOne(item),
                .consumed => {},
                .ready => |slot| self.releaseSlot(slot),
            }
        } else {
            self.feedOne(item);
        }
        // Release ONLY here — after `feedOne` fully drained the input's
        // effects — never from dispatch / onExternalized / drainDeliverable:
        // a re-entrant pushInput would break the engine's one-input-then-
        // drain contract (§5.1) and its effect-queue ownership.
        if (self.next_deliver != before) self.releaseHeld();
    }

    /// `feedInput` with the runtime handling: a push failure latches the
    /// node inert; a best-effort effect that hit OOM (the catch-up cache, a
    /// timer arm) is logged — the node keeps running, the cache is refilled
    /// by the next emission for that slot and the timer re-armed on the next
    /// heard/round transition (review finding: it was silent).
    fn feedOne(self: *Node, item: InputItem) void {
        const clean = self.feedInput(item) catch |err| {
            self.markFailed(err);
            return;
        };
        if (!clean) log.warn("out of memory dispatching an effect; catch-up cache or a timer is degraded until the next emission", .{});
    }

    const Gate = union(enum) { feed, consumed, ready: u64 };

    /// The hold gate (S8 D1 / S8b): `HoldBuffer.admit` over the decoded
    /// envelope, with the logging. `.feed` — the caller feeds it now: a
    /// statement for the slot in progress or anything behind it that remains
    /// inside the answering window (purged statements are consumed here),
    /// a signer outside the quorum graph (the engine ignores it
    /// statelessly), a slot already released for catch-up, or a frame
    /// `envelopeMeta` cannot read (the engine says `insane`). `.ready` —
    /// held, and its slot's EXTERNALIZE signers are now v-blocking: release
    /// the slot. `.consumed` — held or dropped.
    fn gateEnvelope(self: *Node, item: InputItem) Gate {
        const bytes = item.input.envelope_received.bytes;
        const meta = envelopeMeta(self.gpa, self.network_id, bytes) catch |err| switch (err) {
            // The engine can authoritatively classify malformed metadata, but
            // allocation failure must not bypass the host's purge floor. It is
            // pressure at network admission: consume the owned input and make
            // the loss observable instead of giving a stale slot a second
            // allocation attempt inside Engine.
            error.OutOfMemory => {
                var input = item.input;
                core.host_codec.freeInput(self.gpa, &input);
                self.q.recordNetworkDrop();
                return .consumed;
            },
            else => return .feed,
        };
        if (meta.slot < self.purge_floor.load(.acquire)) {
            var input = item.input;
            core.host_codec.freeInput(self.gpa, &input);
            _ = self.hold.dropped_behind.fetchAdd(1, .monotonic);
            return .consumed;
        }
        if (meta.slot <= self.next_deliver) return .feed;
        const in_graph = self.eng.qsets.inGraph(meta.node_id);
        switch (self.hold.admit(self.gpa, &meta, self.next_deliver, in_graph, &self.eng.cfg.quorum_set, item)) {
            .fed => return .feed,
            .held => log.debug("hold: {t} for slot {d} held (frontier {d}, {d} held)", .{ meta.kind, meta.slot, self.next_deliver, self.hold.count }),
            .ready => {
                log.info("catch-up: releasing slot {d} ahead of the delivery frontier {d} — its EXTERNALIZE signers are v-blocking", .{ meta.slot, self.next_deliver });
                return .{ .ready = meta.slot };
            },
            .dropped_far => log.debug("hold: dropped {t} for slot {d}, more than {d} slots past the delivery frontier {d} (the sender's next resync re-sends it)", .{ meta.kind, meta.slot, HoldBuffer.window, self.next_deliver }),
            .dropped_badsig => log.debug("hold: dropped {t} for slot {d}: bad signature", .{ meta.kind, meta.slot }),
            .dropped_full => log.debug("hold: dropped {t} for slot {d}: buffer full ({d} entries, {d} bytes; the sender's next resync re-sends it)", .{ meta.kind, meta.slot, self.hold.count, self.hold.bytes }),
        }
        return .consumed;
    }

    /// Feed everything held for `slot` (catch-up release, ahead of the
    /// frontier). Entries whose slot fell below the frontier meanwhile (an
    /// earlier entry of the list externalized it and the gap-jump delivered
    /// it) are dropped, as is everything once the node latched inert.
    /// Engine thread only; from `applyInput`, never re-entrantly.
    fn releaseSlot(self: *Node, slot: u64) void {
        var list = self.hold.takeSlot(slot) orelse return;
        defer list.deinit(self.gpa);
        for (list.items) |*e| {
            if (self.failed.load(.acquire) or
                slot < self.next_deliver or
                slot < self.purge_floor.load(.acquire))
            {
                HoldBuffer.freeEntry(self.gpa, e);
                _ = self.hold.dropped_behind.fetchAdd(1, .monotonic);
                continue;
            }
            _ = self.hold.released_early.fetchAdd(1, .monotonic);
            self.feedOne(e.item);
        }
    }

    /// Feed the held statements for the frontier slot (`next_deliver`),
    /// looping while they keep advancing it (a released CONFIRM can complete
    /// F + 1, which delivers it and releases F + 2). Entries whose slot
    /// fell below the frontier meanwhile — an earlier item of the same list
    /// completed the slot, or a gap-jump skipped it — are dropped, as is
    /// everything once the node latched inert. Engine thread only; called
    /// from `applyInput` after a full drain (see the comment there).
    fn releaseHeld(self: *Node) void {
        while (self.hold.takeReleasable(self.gpa, self.next_deliver)) |taken| {
            var list = taken;
            defer list.deinit(self.gpa);
            const slot = self.next_deliver;
            for (list.items) |*e| {
                if (self.failed.load(.acquire) or
                    slot < self.next_deliver or
                    slot < self.purge_floor.load(.acquire))
                {
                    HoldBuffer.freeEntry(self.gpa, e);
                    _ = self.hold.dropped_behind.fetchAdd(1, .monotonic);
                    continue;
                }
                _ = self.hold.released.fetchAdd(1, .monotonic);
                self.feedOne(e.item);
            }
        }
    }

    /// `applyInput` without the latch: a `pushInput` failure is returned to
    /// the caller (the input is freed either way); the result says whether
    /// every effect was dispatched cleanly (false = a best-effort effect hit
    /// OOM — see `dispatch`). `create` uses this for the own.log restore so
    /// an allocation failure there is a create failure (`OutOfMemory`),
    /// never a successfully-created inert or degraded node (review
    /// findings); the engine thread wraps it in `markFailed` / a warning.
    fn feedInput(self: *Node, item_in: InputItem) engine.PushError!bool {
        var item = item_in;
        if (self.failed.load(.acquire)) {
            // Inert: consume and free inputs without touching the engine.
            core.host_codec.freeInput(self.gpa, &item.input);
            return true;
        }
        defer self.qset_requests.reconcile(self.eng.pending.items.items);
        self.cur_source = item.source_peer;
        defer self.cur_source = null;
        self.eng.pushInput(item.input) catch |err| {
            core.host_codec.freeInput(self.gpa, &item.input);
            return err;
        };
        core.host_codec.freeInput(self.gpa, &item.input);
        var clean = true;
        while (self.eng.popEffect()) |eff| {
            // A dispatch that trips markFailed (a failed write-ahead append)
            // must suppress every LATER effect of this input — most
            // importantly the broadcast paired with a failed persist (§10:
            // never send what is not durable). The remaining effects are
            // still committed so their payloads are freed.
            if (!self.failed.load(.acquire)) self.dispatch(eff) catch {
                clean = false;
            };
            self.eng.commitEffect();
        }
        return clean;
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

    /// Dispatch one effect. Returns `OutOfMemory` only for the two
    /// best-effort effects (the catch-up cache copy, a timer arm) — after
    /// doing everything else the effect asks for; the fatal ones (a failed
    /// write-ahead append, OOM buffering an externalization) latch inert
    /// inside, per §10.
    fn dispatch(self: *Node, eff: *const engine.Effect) std.mem.Allocator.Error!void {
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
                const recorded = self.recordOwnLatest(sb.slot, sb.bytes);
                if (self.live) self.emitEnvelope("dispatch-broadcast", .all, sb.bytes);
                try recorded;
            },
            .forward_envelope => |sb| {
                if (!self.live) return;
                if (self.cur_source) |src| {
                    self.emitEnvelope("dispatch-forward", .{ .except = src }, sb.bytes);
                } else {
                    self.emitEnvelope("dispatch-forward-all", .all, sb.bytes);
                }
            },
            .arm_timer => |a| try self.wheel.arm(a.slot, @backingInt(a.timer), a.delay_ms),
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
        self.maybeStartNomination() catch {
            // The proposal is back at the head and `nominating` is clear:
            // the next propose() or externalization retries it.
            log.warn("out of memory starting the next nomination; retried on the next proposal or externalization", .{});
        };

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
        const window_floor = purgeFloorForFrontier(frontier);
        if (window_floor != 0) {
            // `start_slot` may establish a later permanent floor than the
            // ordinary 16-slot calculation. GC can advance that declaration,
            // never lower it after the first delivery.
            const max_slot = @max(self.purge_floor.load(.acquire), window_floor);
            self.purge_floor.store(max_slot, .release);
            self.pruneOwnLatest(max_slot);
            self.q.pushPriority(.{ .input = .{ .purge_slots = .{ .max_slot = max_slot } }, .source_peer = null });
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
    /// Allocation/queue pressure is rolled back — the value goes back to the
    /// head and `nominating` stays clear — and returned, so no proposal is ever
    /// silently dropped or latched with nothing in flight. Queue closure is
    /// the one exception: shutdown consumes the owned proposal quietly.
    fn maybeStartNomination(self: *Node) std.mem.Allocator.Error!void {
        if (self.watcher) return;
        // Held across the enqueue (q.mu is a leaf lock, never taken before
        // prop_mu) so the rollback's re-insert is into the same list state
        // the pop left: the capacity is still there.
        self.prop_mu.lockUncancelable(self.io);
        defer self.prop_mu.unlock(self.io);
        if (self.nominating or self.proposal_queue.items.len == 0) return;
        const value = self.proposal_queue.orderedRemove(0);
        const slot = self.current_slot;
        const prev = self.gpa.dupe(u8, self.last_ext_value) catch |e| {
            self.proposal_queue.insertAssumeCapacity(0, value);
            return e;
        };
        // value + prev are owned; the input carries them, freed after push.
        self.q.tryPush(.{ .input = .{ .nominate = .{ .slot = slot, .value = value, .prev_value = prev } }, .source_peer = null }) catch |e| {
            self.gpa.free(prev);
            if (e == error.QueueClosed) {
                // Shutdown consumes fire-and-forget local work quietly. The
                // transactional queue left both allocations with us.
                self.gpa.free(value);
                return;
            }
            self.proposal_queue.insertAssumeCapacity(0, value);
            return switch (e) {
                error.InputQueueFull => error.OutOfMemory,
                error.OutOfMemory => error.OutOfMemory,
                error.QueueClosed => unreachable,
            };
        };
        self.nominating = true;
    }

    // -------------------------------------------------------------------
    // own_latest (catch-up source)
    // -------------------------------------------------------------------

    /// Record our own envelope as the catch-up source for `slot`. OOM is
    /// returned (the cache then lacks this slot until the next emission for
    /// it); an envelope that does not decode is logged and skipped.
    fn recordOwnLatest(self: *Node, slot: u64, framed_env: []const u8) std.mem.Allocator.Error!void {
        // Zero-frame placeholders (engine lagger self-records) never reach
        // effects today, but the skip-zero-frames host contract applies here
        // too — never let an empty frame into the catch-up source.
        if (framed_env.len == 0) return;
        const meta = envelopeMeta(self.gpa, self.network_id, framed_env) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                log.warn("could not bucket own envelope for slot {d}: {t}", .{ slot, e });
                return;
            },
        };
        const bucket: Bucket = if (meta.kind == .nominate) .nom else .ballot;
        const copy = try self.gpa.dupe(u8, framed_env);
        self.own_mu.lockUncancelable(self.io);
        defer self.own_mu.unlock(self.io);
        const gop = self.own_latest.getOrPut(self.gpa, slot) catch |e| {
            self.gpa.free(copy);
            return e;
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

    /// The catch-up cache's slots, ascending (own_mu held by the caller;
    /// caller frees). `own_latest` is a hash map, and bucket order put
    /// N+1 before N for consecutive slots often enough that a rejoining
    /// peer saw NOMINATE(N+1) before EXTERNALIZE(N) on the same stream
    /// (review finding); every sender goes through this instead.
    fn ownSlotsAscending(self: *Node) std.mem.Allocator.Error![]u64 {
        var slots = try self.gpa.alloc(u64, self.own_latest.count());
        var i: usize = 0;
        var it = self.own_latest.keyIterator();
        while (it.next()) |k| : (i += 1) slots[i] = k.*;
        std.mem.sort(u64, slots, {}, std.sort.asc(u64));
        return slots;
    }

    /// Re-flood our latest own envelopes to `target` in ascending slot
    /// order, nomination before ballot per slot (the on-connect catch-up
    /// and the anti-entropy backstop, §9.2). Borrowed under own_mu; the
    /// overlay copies on enqueue. OOM skips this round (the next resync
    /// retries).
    fn sendOwnLatest(self: *Node, target: EmitTarget, comptime site: []const u8) void {
        self.own_mu.lockUncancelable(self.io);
        defer self.own_mu.unlock(self.io);
        const slots = self.ownSlotsAscending() catch {
            log.warn("out of memory re-flooding own statements ({s}); the next resync retries", .{site});
            return;
        };
        defer self.gpa.free(slots);
        for (slots) |slot| {
            const e = self.own_latest.getPtr(slot).?;
            if (e.nom) |b| self.emitEnvelope(site ++ "-nom", target, b);
            if (e.ballot) |b| self.emitEnvelope(site ++ "-ballot", target, b);
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
            .app_message => |payload| self.app_gossip.receive(payload),
        }
    }

    fn onPeerUp(ctx: ?*anyopaque, peer_id: usize) void {
        const self: *Node = @ptrCast(@alignCast(ctx.?));
        // M6:example logs
        const live = self.peers_live.fetchAdd(1, .acq_rel) + 1;
        log.info("peer {d} up ({d} live connection(s); {d} peer(s) configured)", .{ peer_id, live, self.peer_specs.len });
        // Catch-up (§9.2): send our latest own envelopes, then ask for the
        // peer's externalized state.
        self.sendOwnLatest(.{ .one = peer_id }, "peerup");
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
        const copy = self.q.copyNetworkBytes(framed_env) orelse return;
        self.q.push(.{ .input = .{ .envelope_received = .{ .bytes = copy } }, .source_peer = source });
    }

    /// Record or refresh a hash the engine asked the network for.
    fn noteQsetRequested(self: *Node, hash: [32]u8) void {
        self.qset_requests.note(hash);
    }

    /// True (once) iff we asked for this hash (reader threads).
    fn consumeQsetRequested(self: *Node, hash: [32]u8) bool {
        if (!self.qset_requests.claim(hash)) return false;
        self.qset_requests.commit(hash);
        return true;
    }

    fn onQsetFrame(self: *Node, framed_qset: []const u8) void {
        // A qset frame is a response to request_qset, never an unsolicited
        // advertisement. Correlate before either persistence or Engine
        // admission so reader traffic cannot churn disk, memory or the input
        // queue with values no current statement asked us to resolve.
        const hash = qsetHashOfFramed(self.gpa, framed_qset) catch return;
        if (!self.qset_requests.claim(hash)) return;
        const copy = self.q.copyNetworkBytes(framed_qset) orelse {
            self.qset_requests.release(hash);
            return;
        };
        self.q.tryPush(.{ .input = .{ .qset_received = .{ .bytes = copy } }, .source_peer = null }) catch |err| {
            self.gpa.free(copy);
            if (err == error.InputQueueFull or err == error.OutOfMemory) self.q.recordNetworkDrop();
            self.qset_requests.release(hash);
            return;
        };
        self.qset_requests.commit(hash);
        self.qset_cache.rememberRequested(hash, framed_qset);
    }

    fn answerGetQset(self: *Node, peer_id: usize, hash: [32]u8) void {
        const framed = self.qset_cache.copy(self.gpa, hash);
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
        defer self.own_mu.unlock(self.io);
        // Ascending, so the receiver sees N before N+1 and the 64-envelope
        // cap drops the newest slots, deterministically (review finding).
        const slots = self.ownSlotsAscending() catch return; // the peer's next resync re-asks
        defer self.gpa.free(slots);
        for (slots) |slot| {
            if (req_slot != 0 and slot != req_slot) continue;
            const e = self.own_latest.getPtr(slot).?;
            const env = e.ballot orelse e.nom orelse continue;
            if (list.items.len >= wire.max_slot_state_envelopes) break;
            list.append(self.gpa, env) catch break;
            if (slot > highest) highest = slot;
        }
        // Send while holding own_mu so the borrowed env slices stay valid
        // through encode (overlay copies them).
        self.ov.send(peer_id, .{ .slot_state = .{ .slot = highest, .envelopes = list.items } });
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

/// The two own-latest slots per slot index: the latest nomination and the
/// latest ballot-family statement (prepare / confirm / externalize).
const Bucket = enum { nom, ballot };

fn qsetHashOfFramed(gpa: std.mem.Allocator, framed_qset: []const u8) ![32]u8 {
    if (framed_qset.len > core.limits.frozen_max_frame_bytes) return error.FrameTooLarge;
    var msg = try core.capnpc.message.Message.init(gpa, framed_qset, .{
        .nesting_limit = 32,
        .traversal_limit_words = core.limits.frozen_max_frame_bytes / 8,
    });
    defer msg.deinit();
    const r = try gen_slcp.QuorumSet.Reader.init(&msg);
    var qs = try qset.fromReader(gpa, r);
    defer qs.deinit(gpa);
    try qset.validateAndNormalize(gpa, &qs);
    return qset.hashNormalized(gpa, &qs);
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
        Node.waitExternalized, Node.waitAppMessage,     Node.publishAppMessage,
        Node.appMessageStats,  Node.stats,              Node.boundPort,
        Node.engineLoop,       Node.applyInput,         Node.markFailed,
        Node.dispatch,         Node.onExternalized,     Node.maybeStartNomination,
        Node.recordOwnLatest,  Node.pruneOwnLatest,     Node.onRecv,
        Node.onPeerUp,         Node.enqueueEnvelope,    Node.onQsetFrame,
        Node.answerGetQset,    Node.answerGetSlotState, Node.onTimerFire,
        Node.drainDeliverable, Node.noteQsetRequested,  Node.consumeQsetRequested,
        Node.resyncLoop,       Node.deliverSlot,        Node.onPeerDown,
        Node.gateEnvelope,     Node.releaseHeld,        Node.feedOne,
    };
    inline for (fns) |f| {
        const p = &f;
        _ = p;
    }
}

test "InputQueue: push, pop, and close over std.Io primitives" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var q = InputQueue{ .gpa = gpa, .io = io };
    defer q.deinit();

    q.push(.{ .input = .{ .purge_slots = .{ .max_slot = 5 } }, .source_peer = null });
    q.push(.{ .input = .{ .purge_slots = .{ .max_slot = 6 } }, .source_peer = null });

    const a = q.pop().?;
    try std.testing.expectEqual(@as(u64, 5), a.input.purge_slots.max_slot);
    const b = q.pop().?;
    try std.testing.expectEqual(@as(u64, 6), b.input.purge_slots.max_slot);

    q.close();
    // The transactional API must tell its caller that admission did not
    // happen and leave ownership untouched. This is what lets qset ingress
    // release its request claim instead of committing/persisting a response
    // which never reached the Engine.
    const closing_bytes = try gpa.dupe(u8, "closing");
    try std.testing.expectError(error.QueueClosed, q.tryPush(.{
        .input = .{ .qset_received = .{ .bytes = closing_bytes } },
        .source_peer = null,
    }));
    gpa.free(closing_bytes);

    // The fire-and-forget wrapper still consumes ownership quietly during
    // shutdown and does not misclassify intentional closure as pressure.
    const ignored_bytes = try gpa.dupe(u8, "ignored");
    q.push(.{ .input = .{ .envelope_received = .{ .bytes = ignored_bytes } }, .source_peer = 1 });
    try std.testing.expectEqual(@as(usize, 0), q.snapshot().dropped_network_inputs);

    // `close` stops external producers but the engine owner may still emit a
    // purge while draining the items that were already queued. That barrier
    // must run before `pop` finally reports the closed queue empty.
    q.pushPriority(.{ .input = .{ .purge_slots = .{ .max_slot = 7 } }, .source_peer = null });
    const closing_purge = q.pop() orelse return error.MissingClosingPurge;
    try std.testing.expectEqual(@as(u64, 7), closing_purge.input.purge_slots.max_slot);
    try std.testing.expect(q.pop() == null); // closed + drained
}

// Allocation failure while extending the queue is ingress pressure just like
// hitting its explicit item/byte caps. The payload has already been accepted
// from the network and must be consumed and counted exactly once.
test "InputQueue: network allocation pressure is counted and consumes ownership" {
    const io = std.testing.io;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 1 });
    const gpa = failing.allocator();
    var q = InputQueue{ .gpa = gpa, .io = io };
    defer q.deinit();

    const bytes = try gpa.dupe(u8, "x");
    q.push(.{ .input = .{ .envelope_received = .{ .bytes = bytes } }, .source_peer = 1 });

    const ingress = q.snapshot();
    try std.testing.expectEqual(@as(usize, 0), ingress.queued_items);
    try std.testing.expectEqual(@as(usize, 0), ingress.queued_bytes);
    try std.testing.expectEqual(@as(usize, 1), ingress.dropped_network_inputs);
    try std.testing.expect(failing.has_induced_failure);
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}

test "InputQueue: network copy allocation pressure is counted" {
    const io = std.testing.io;
    var storage: [0]u8 = .{};
    var fba = std.heap.FixedBufferAllocator.init(&storage);
    {
        var closed_q = InputQueue{ .gpa = fba.allocator(), .io = io };
        defer closed_q.deinit();
        closed_q.close();
        try std.testing.expect(closed_q.copyNetworkBytes("frame") == null);
        try std.testing.expectEqual(@as(usize, 0), closed_q.snapshot().dropped_network_inputs);
    }

    var open_q = InputQueue{ .gpa = fba.allocator(), .io = io };
    defer open_q.deinit();
    try std.testing.expect(open_q.copyNetworkBytes("frame") == null);
    try std.testing.expectEqual(@as(usize, 1), open_q.snapshot().dropped_network_inputs);
}

// Network work may occupy at most 960 of the queue's 1024 item budget. The
// remaining 64 entries are reserved for local proposals and timers so a full
// set of reader threads cannot starve progress work (purges use their own
// coalesced control lane). The 961st network input must be dropped.
test "InputQueue: network inputs leave reserved capacity for progress work" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var q = InputQueue{ .gpa = gpa, .io = io };
    defer q.deinit();

    for (0..961) |_| {
        const bytes = try gpa.dupe(u8, "x");
        q.push(.{ .input = .{ .envelope_received = .{ .bytes = bytes } }, .source_peer = 1 });
    }

    try std.testing.expectEqual(@as(usize, 960), q.items.items.len - q.head);
    try std.testing.expectEqual(@as(usize, 1), q.dropped_network.load(.acquire));
    const ingress = q.snapshot();
    try std.testing.expectEqual(@as(usize, 960), ingress.queued_items);
    try std.testing.expectEqual(@as(usize, 960), ingress.queued_bytes);
    try std.testing.expectEqual(@as(usize, 1), ingress.dropped_network_inputs);

    q.push(.{ .input = .{ .purge_slots = .{ .max_slot = 7 } }, .source_peer = null });
    try std.testing.expectEqual(@as(usize, 961), q.items.items.len - q.head);
}

// The byte budget has the same reservation rule: network frames may occupy
// 15 MiB of the 16 MiB aggregate queue, leaving 1 MiB for progress inputs.
test "InputQueue: network bytes are bounded independently of item count" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var q = InputQueue{ .gpa = gpa, .io = io };
    defer q.deinit();

    for (0..15) |_| {
        const bytes = try gpa.alloc(u8, 1024 * 1024);
        q.push(.{ .input = .{ .envelope_received = .{ .bytes = bytes } }, .source_peer = 1 });
    }
    const overflow = try gpa.dupe(u8, "x");
    q.push(.{ .input = .{ .envelope_received = .{ .bytes = overflow } }, .source_peer = 1 });

    try std.testing.expectEqual(@as(usize, 15), q.items.items.len - q.head);
    const local_value = try gpa.alloc(u8, 1024 * 1024);
    const local_prev = try gpa.dupe(u8, "");
    q.push(.{ .input = .{ .nominate = .{ .slot = 8, .value = local_value, .prev_value = local_prev } }, .source_peer = null });
    try std.testing.expectEqual(@as(usize, 16), q.items.items.len - q.head);
}

// A head-index FIFO is not bounded merely because its live suffix is bounded:
// if the queue never becomes empty, consumed prefix cells otherwise accumulate
// forever while every replacement appends at the physical end.
test "InputQueue: sustained non-empty churn bounds live and backing item storage" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var q = InputQueue{ .gpa = gpa, .io = io };
    defer q.deinit();

    const network_limit = InputQueue.max_items - InputQueue.reserved_progress_items;
    for (0..network_limit) |_| {
        const bytes = try gpa.dupe(u8, "x");
        q.push(.{ .input = .{ .envelope_received = .{ .bytes = bytes } }, .source_peer = 1 });
    }
    var observed_backing_items = q.items.items.len;
    for (0..InputQueue.max_items * 4) |_| {
        var consumed = q.pop().?;
        core.host_codec.freeInput(gpa, &consumed.input);
        const bytes = try gpa.dupe(u8, "x");
        q.push(.{ .input = .{ .envelope_received = .{ .bytes = bytes } }, .source_peer = 1 });
        observed_backing_items = @max(observed_backing_items, q.items.items.len);
    }

    const ingress = q.snapshot();
    try std.testing.expectEqual(network_limit, ingress.queued_items);
    try std.testing.expectEqual(network_limit, ingress.queued_bytes);
    try std.testing.expect(observed_backing_items <= InputQueue.max_backing_items);
    try std.testing.expect(q.items.capacity <= InputQueue.max_backing_items);
    try std.testing.expect(q.head < InputQueue.max_items);
}

// The host raises purge_floor while dispatching an externalization, then
// queues the matching Engine purge. It must be admitted even when ordinary
// ingress has filled every item slot, and must overtake already queued qset
// responses; otherwise one can unpark a now-expired statement in the gap.
test "InputQueue: purge work is coalesced outside a full ordinary backlog and overtakes it" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var q = InputQueue{ .gpa = gpa, .io = io };
    defer q.deinit();

    for (0..InputQueue.max_items - InputQueue.reserved_progress_items) |_| {
        const env = try gpa.dupe(u8, "e");
        q.push(.{ .input = .{ .envelope_received = .{ .bytes = env } }, .source_peer = 1 });
    }
    for (0..InputQueue.reserved_progress_items) |i| {
        q.push(.{ .input = .{ .timer_fired = .{ .slot = i, .timer = .nomination } }, .source_peer = null });
    }
    try std.testing.expectEqual(InputQueue.max_items, q.snapshot().queued_items);

    q.pushPriority(.{ .input = .{ .purge_slots = .{ .max_slot = 9 } }, .source_peer = null });
    q.pushPriority(.{ .input = .{ .purge_slots = .{ .max_slot = 7 } }, .source_peer = null });
    q.pushPriority(.{ .input = .{ .purge_slots = .{ .max_slot = 11 } }, .source_peer = null });
    try std.testing.expectEqual(InputQueue.max_items + 1, q.snapshot().queued_items);

    var first = q.pop().?;
    defer core.host_codec.freeInput(gpa, &first.input);
    try std.testing.expect(first.input == .purge_slots);
    try std.testing.expectEqual(@as(u64, 11), first.input.purge_slots.max_slot);
    try std.testing.expectEqual(InputQueue.max_items, q.snapshot().queued_items);
}

test "QsetRequests: bounded LRU preserves refreshed work and releases claims" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const max_pending = (core.limits.Limits{}).max_pending_envelopes;
    const max_hashes = @as(usize, @intCast(max_pending)) + 1;
    var requests = try QsetRequests.init(gpa, io, max_pending);
    defer requests.deinit();

    const active: [32]u8 = @splat(0xff);
    requests.note(active);
    for (0..max_hashes - 1) |i| {
        var hash: [32]u8 = @splat(0);
        std.mem.writeInt(u64, hash[0..8], @intCast(i + 1), .little);
        requests.note(hash);
    }
    try std.testing.expectEqual(max_hashes, requests.states.count());

    // A repeated Engine request represents newly parked work and refreshes
    // the hash before one more distinct request forces an eviction.
    requests.note(active);
    var newest: [32]u8 = @splat(0);
    std.mem.writeInt(u64, newest[0..8], max_hashes + 1, .little);
    requests.note(newest);
    try std.testing.expectEqual(max_hashes, requests.states.count());
    try std.testing.expect(requests.claim(active));
    try std.testing.expect(!requests.claim(active));
    requests.release(active);
    try std.testing.expect(requests.claim(active));
    requests.commit(active);
    try std.testing.expect(!requests.claim(active));
}

test "QsetRequests: pending reconciliation removes stale purge tokens" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const max_pending = (core.limits.Limits{}).max_pending_envelopes;
    const max_hashes = @as(usize, @intCast(max_pending)) + 1;
    var requests = try QsetRequests.init(gpa, io, max_pending);
    defer requests.deinit();

    const Parked = struct { needed_hash: [32]u8 };
    const active: [32]u8 = @splat(0xfe);
    requests.note(active);

    // Model repeated low-slot work being purged while one older high-slot
    // envelope remains parked. Without exact reconciliation, those stale
    // request tokens eventually evict the live hash from a bounded LRU.
    for (0..max_hashes * 2) |i| {
        var churn: [32]u8 = @splat(0);
        std.mem.writeInt(u64, churn[0..8], @intCast(i + 1), .little);
        requests.note(churn);
        const parked = [_]Parked{
            .{ .needed_hash = active },
            .{ .needed_hash = churn },
        };
        requests.reconcile(&parked);
    }

    try std.testing.expectEqual(@as(usize, 2), requests.states.count());
    try std.testing.expect(requests.claim(active));
}

// Native qset frames are responses, not advertisements. An unsolicited frame
// must not reach the semantic Engine cache; otherwise reader traffic can churn
// qset state without any preceding request_qset effect.
test "qset ingress: only a requested frame enters the engine" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];
    const seed: [32]u8 = @splat(0x62);
    const me = try crypto.publicKeyFromSeed(seed);
    var diag: Diagnostic = .{};
    const n = try Node.create(gpa, io, .{
        .network = "qset ingress correlation v1",
        .secret_seed = seed,
        .quorum = Quorum.of(1, &.{me}),
        .listen_port = 0,
        .data_dir = data_dir,
        .diagnostic = &diag,
    });
    defer n.deinit();
    try std.testing.expectEqual(@as(usize, 1), n.storageStats().qset_cache_entries);

    const remote = try crypto.publicKeyFromSeed(@splat(0x63));
    var remote_qset = try Quorum.of(1, &.{remote}).toOwned(gpa);
    defer remote_qset.deinit(gpa);
    try qset.validateAndNormalize(gpa, &remote_qset);
    const framed = try ownedQsetToFramed(gpa, &remote_qset);
    defer gpa.free(framed);

    n.onQsetFrame("malformed");
    n.onQsetFrame(framed);
    try std.testing.expectEqual(@as(usize, 0), n.ingressStats().dropped_network_inputs);

    const requested_node = try crypto.publicKeyFromSeed(@splat(0x64));
    var requested_qset = try Quorum.of(1, &.{requested_node}).toOwned(gpa);
    defer requested_qset.deinit(gpa);
    try qset.validateAndNormalize(gpa, &requested_qset);
    const requested_hash = try qset.hashNormalized(gpa, &requested_qset);
    const requested_framed = try ownedQsetToFramed(gpa, &requested_qset);
    defer gpa.free(requested_framed);
    n.noteQsetRequested(requested_hash);
    n.onQsetFrame(requested_framed);
    try std.testing.expectEqual(@as(usize, 2), n.storageStats().qset_cache_entries);

    n.q.close();
    if (n.engine_thread) |thread| thread.join();
    n.engine_thread = null;
    try std.testing.expectEqual(@as(usize, 2), n.stats().cached_qsets);
}

test "qset ingress: an oversized parseable response cannot consume its request" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];

    const seed: [32]u8 = @splat(0x6c);
    const me = try crypto.publicKeyFromSeed(seed);
    const n = try Node.create(gpa, io, .{
        .network = "qset ingress parser limits v1",
        .secret_seed = seed,
        .quorum = Quorum.of(1, &.{me}),
        .listen_port = 0,
        .data_dir = data_dir,
    });
    defer n.deinit();

    const remote = try crypto.publicKeyFromSeed(@splat(0x6d));
    var remote_qset = try Quorum.of(1, &.{remote}).toOwned(gpa);
    defer remote_qset.deinit(gpa);
    try qset.validateAndNormalize(gpa, &remote_qset);
    const hash = try qset.hashNormalized(gpa, &remote_qset);
    const framed = try ownedQsetToFramed(gpa, &remote_qset);
    defer gpa.free(framed);

    // Keep the valid root but enlarge its sole segment beyond the Engine's
    // frame cap. A loose Cap'n Proto pre-parse accepts and ignores the unused
    // trailing words, so this specifically pins parity with handleQset.
    const oversized_len = core.limits.frozen_max_frame_bytes + 8;
    const oversized = try gpa.alloc(u8, oversized_len);
    defer gpa.free(oversized);
    @memset(oversized, 0);
    @memcpy(oversized[0..framed.len], framed);
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, oversized[0..4], .little));
    std.mem.writeInt(u32, oversized[4..8], @intCast((oversized.len - 8) / 8), .little);

    n.noteQsetRequested(hash);
    n.onQsetFrame(oversized);
    try std.testing.expectEqual(@as(usize, 1), n.storageStats().qset_cache_entries);

    // The rejected response left the claim available; a normal response can
    // still enter the queue and the answering cache.
    n.onQsetFrame(framed);
    try std.testing.expectEqual(@as(usize, 2), n.storageStats().qset_cache_entries);
}

// Closing the queue is not successful admission. A requested qset which
// races shutdown remains unconsumed and is not persisted, while the frame
// copy remains owned by the caller of tryPush and is released exactly once.
test "qset ingress: closed queue releases the request and does not persist" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];

    const seed: [32]u8 = @splat(0x6a);
    const me = try crypto.publicKeyFromSeed(seed);
    var diag: Diagnostic = .{};
    const n = try Node.create(gpa, io, .{
        .network = "qset ingress shutdown v1",
        .secret_seed = seed,
        .quorum = Quorum.of(1, &.{me}),
        .listen_port = 0,
        .data_dir = data_dir,
        .diagnostic = &diag,
    });
    defer n.deinit();

    n.q.close();
    if (n.engine_thread) |thread| thread.join();
    n.engine_thread = null;

    const remote = try crypto.publicKeyFromSeed(@splat(0x6b));
    var remote_qset = try Quorum.of(1, &.{remote}).toOwned(gpa);
    defer remote_qset.deinit(gpa);
    try qset.validateAndNormalize(gpa, &remote_qset);
    const hash = try qset.hashNormalized(gpa, &remote_qset);
    const framed = try ownedQsetToFramed(gpa, &remote_qset);
    defer gpa.free(framed);

    n.noteQsetRequested(hash);
    n.onQsetFrame(framed);

    try std.testing.expect(n.consumeQsetRequested(hash));
    const persisted = n.qset_cache.copy(gpa, hash);
    defer if (persisted) |bytes| gpa.free(bytes);
    try std.testing.expectEqual(@as(?[]u8, null), persisted);
    try std.testing.expectEqual(@as(usize, 0), n.ingressStats().dropped_network_inputs);
}

// Request hashes name the normalized quorum set, while a valid peer may send
// an equivalent tree whose members have not yet been sorted. Correlation must
// use the same validate-and-normalize rule as the Engine or the response is
// mistaken for an unsolicited frame and the parked envelope never resumes.
test "qset ingress: correlation hashes the normalized quorum set" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];

    const seed: [32]u8 = @splat(0x67);
    const me = try crypto.publicKeyFromSeed(seed);
    var diag: Diagnostic = .{};
    const n = try Node.create(gpa, io, .{
        .network = "qset normalized correlation v1",
        .secret_seed = seed,
        .quorum = Quorum.of(1, &.{me}),
        .listen_port = 0,
        .data_dir = data_dir,
        .diagnostic = &diag,
    });
    defer n.deinit();

    const a = try crypto.publicKeyFromSeed(@splat(0x68));
    const b = try crypto.publicKeyFromSeed(@splat(0x69));
    var wire_qset = try Quorum.of(2, &.{ b, a }).toOwned(gpa);
    defer wire_qset.deinit(gpa);
    const framed = try ownedQsetToFramed(gpa, &wire_qset);
    defer gpa.free(framed);

    var normalized = try Quorum.of(2, &.{ b, a }).toOwned(gpa);
    defer normalized.deinit(gpa);
    try qset.validateAndNormalize(gpa, &normalized);
    const hash = try qset.hashNormalized(gpa, &normalized);
    n.noteQsetRequested(hash);
    n.onQsetFrame(framed);

    try std.testing.expect(!n.consumeQsetRequested(hash));
}

// Correlation is a claim, not consumption until the response has actually
// entered the engine queue. Under ingress pressure a valid requested response
// must remain retryable and must not be persisted as though it were accepted.
test "qset ingress: queue pressure preserves the request for retry" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];

    const seed: [32]u8 = @splat(0x65);
    const me = try crypto.publicKeyFromSeed(seed);
    var hook: PausingStatsHook = .{};
    var diag: Diagnostic = .{};
    const n = try Node.create(gpa, io, .{
        .network = "qset ingress retry v1",
        .secret_seed = seed,
        .quorum = Quorum.of(1, &.{me}),
        .listen_port = 0,
        .data_dir = data_dir,
        .delivery = hook.hook(),
        .diagnostic = &diag,
    });
    defer {
        hook.release.store(true, .release);
        n.deinit();
    }

    try n.propose("pause");
    try pollUntil(io, 10_000, &hook, PausingStatsHook.hasEntered);
    for (0..InputQueue.max_items - InputQueue.reserved_progress_items) |_| {
        n.enqueueEnvelope("x", 1);
    }
    try std.testing.expectEqual(
        InputQueue.max_items - InputQueue.reserved_progress_items,
        n.ingressStats().queued_items,
    );

    const remote = try crypto.publicKeyFromSeed(@splat(0x66));
    var remote_qset = try Quorum.of(1, &.{remote}).toOwned(gpa);
    defer remote_qset.deinit(gpa);
    try qset.validateAndNormalize(gpa, &remote_qset);
    const hash = try qset.hashNormalized(gpa, &remote_qset);
    const framed = try ownedQsetToFramed(gpa, &remote_qset);
    defer gpa.free(framed);

    n.noteQsetRequested(hash);
    n.onQsetFrame(framed);

    try std.testing.expectEqual(@as(usize, 1), n.ingressStats().dropped_network_inputs);
    try std.testing.expect(n.consumeQsetRequested(hash));
    try std.testing.expectEqual(@as(?[]u8, null), n.qset_cache.copy(gpa, hash));
}

test "qset cache failure degrades storage without making consensus inert" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];

    const seed: [32]u8 = @splat(0x72);
    const me = try crypto.publicKeyFromSeed(seed);
    var diag: Diagnostic = .{};
    const n = try Node.create(gpa, io, .{
        .network = "qset cache failure is nonfatal v1",
        .secret_seed = seed,
        .quorum = Quorum.of(1, &.{me}),
        .listen_port = 0,
        .data_dir = data_dir,
        .diagnostic = &diag,
    });
    defer n.deinit();

    const remote = try crypto.publicKeyFromSeed(@splat(0x73));
    var remote_qset = try Quorum.of(1, &.{remote}).toOwned(gpa);
    defer remote_qset.deinit(gpa);
    try qset.validateAndNormalize(gpa, &remote_qset);
    const hash = try qset.hashNormalized(gpa, &remote_qset);
    const framed = try ownedQsetToFramed(gpa, &remote_qset);
    defer gpa.free(framed);

    const hash_hex = std.fmt.bytesToHex(hash, .lower);
    var blocked_path_buf: ["qsets/".len + 64 + ".bin".len]u8 = undefined;
    const blocked_path = try std.fmt.bufPrint(&blocked_path_buf, "qsets/{s}.bin", .{&hash_hex});
    try tmp.dir.createDirPath(io, blocked_path);

    n.noteQsetRequested(hash);
    n.onQsetFrame(framed);
    const storage = n.storageStats();
    try std.testing.expectEqual(@as(usize, 1), storage.qset_cache_entries);
    try std.testing.expectEqual(@as(u64, 1), storage.qset_cache_write_failures);
    try std.testing.expect(storage.qset_cache_degraded);
    try std.testing.expect(!n.stats().failed);

    try n.propose("consensus survives cache failure");
    const decided = n.waitExternalized(.{ .timeout_ms = 5_000 }) orelse return error.Timeout;
    defer gpa.free(decided.value);
    try std.testing.expectEqualSlices(u8, "consensus survives cache failure", decided.value);
    try std.testing.expect(!n.stats().failed);
}

test "qset cache churn remains bounded across restart and consensus continues" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];

    const seed: [32]u8 = @splat(0x74);
    const me = try crypto.publicKeyFromSeed(seed);
    const opts: Options = .{
        .network = "qset cache production bounds v1",
        .secret_seed = seed,
        .quorum = Quorum.of(1, &.{me}),
        .listen_port = 0,
        .data_dir = data_dir,
    };

    const remote_count = 1027;
    var newest_hash: [32]u8 = undefined;
    {
        const n = try Node.create(gpa, io, opts);
        for (0..remote_count) |i| {
            var remote_seed: [32]u8 = @splat(0xd0);
            std.mem.writeInt(u64, remote_seed[0..8], @intCast(i + 1), .little);
            const validator = try crypto.publicKeyFromSeed(remote_seed);
            var remote_qset = try Quorum.of(1, &.{validator}).toOwned(gpa);
            defer remote_qset.deinit(gpa);
            try qset.validateAndNormalize(gpa, &remote_qset);
            const hash = try qset.hashNormalized(gpa, &remote_qset);
            newest_hash = hash;
            const framed = try ownedQsetToFramed(gpa, &remote_qset);
            defer gpa.free(framed);
            n.qset_cache.rememberRequested(hash, framed);
        }

        const storage = n.storageStats();
        try std.testing.expectEqual(@as(usize, 1024), storage.qset_cache_entries);
        try std.testing.expect(storage.qset_cache_bytes <= 64 * 1024 * 1024);
        try std.testing.expectEqual(@as(u64, remote_count - 1023), storage.qset_cache_evictions);
        try std.testing.expectEqual(@as(u64, 0), storage.qset_cache_write_failures);
        try std.testing.expect(!storage.qset_cache_degraded);
        try std.testing.expect(!n.stats().failed);
        n.deinit();
    }

    const restarted = try Node.create(gpa, io, opts);
    defer restarted.deinit();
    const restored = restarted.storageStats();
    try std.testing.expectEqual(@as(usize, 1024), restored.qset_cache_entries);
    try std.testing.expect(restored.qset_cache_bytes <= 64 * 1024 * 1024);
    try std.testing.expectEqual(@as(u64, 0), restored.qset_cache_write_failures);
    try std.testing.expect(!restored.qset_cache_degraded);

    const remote = restarted.qset_cache.copy(gpa, newest_hash) orelse return error.TestUnexpectedResult;
    gpa.free(remote);
    const local = restarted.qset_cache.copy(gpa, restarted.local_qset_hash) orelse return error.TestUnexpectedResult;
    gpa.free(local);
    try restarted.propose("consensus after cache restart");
    const decided = restarted.waitExternalized(.{ .timeout_ms = 5_000 }) orelse return error.Timeout;
    defer gpa.free(decided.value);
    try std.testing.expectEqualSlices(u8, "consensus after cache restart", decided.value);
    try std.testing.expect(!restarted.stats().failed);
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

// A normal compaction at frontier 64 leaves slots 49..64, after which a
// crash just before frontier 128 can leave slots 49..127 in both logs. The
// restart must derive the answering floor from the durable high-water mark
// before restoring own.log. Otherwise the oldest 64 slots fill the Engine,
// the newest statements are silently rejected as over-limit, and slot 128
// cannot be nominated.
test "restart recovery rebuilds the purge floor before restoring the retained own-log window" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];

    const passphrase = "restart purge-floor recovery v1";
    const seed: [32]u8 = @splat(0x43);
    const me = try crypto.publicKeyFromSeed(seed);
    const peer_a: [32]u8 = @splat(0x77);
    const peer_b: [32]u8 = @splat(0x78);
    const network_id = crypto.networkIdFromPassphrase(passphrase);

    // This is exactly the record range left by the 64-slot compaction cadence
    // immediately before its next boundary: 16 retained slots plus 63 newer
    // ones. Keep one latest own EXTERNALIZE per slot.
    {
        var st = try store_mod.Store.open(gpa, io, data_dir);
        defer st.deinit();
        var slot: u64 = 49;
        while (slot <= 127) : (slot += 1) {
            var value_buf: [16]u8 = undefined;
            const value = try std.fmt.bufPrint(&value_buf, "v{d}", .{slot});
            try st.appendExternalized(slot, value);
            const env = try buildSignedExternalize(gpa, seed, network_id, slot, value);
            try st.appendOwn(slot, env);
            gpa.free(env);
        }
    }

    var diag: Diagnostic = .{};
    const n = try Node.create(gpa, io, .{
        .network = passphrase,
        .secret_seed = seed,
        .quorum = Quorum.twoThirdsOf(&.{ me, peer_a, peer_b }),
        .listen_port = 0,
        .data_dir = data_dir,
        .diagnostic = &diag,
    });
    defer n.deinit();

    const expected_floor: u64 = 127 - (purge_window - 1);
    try std.testing.expectEqual(@as(u64, 128), n.next_deliver);
    try std.testing.expectEqual(expected_floor, n.purge_floor.load(.acquire));
    try std.testing.expectEqual(@as(usize, purge_window), n.stats().live_slots);

    // The current proposal must still fit: before the fix, stale restored
    // slots consumed all 64 live-slot entries and this never reached 65.
    try n.propose("fresh-after-restart");
    try pollUntil(io, 2_000, n, struct {
        fn admitted(node: *Node) bool {
            return node.stats().live_slots == @as(usize, purge_window + 1);
        }
    }.admitted);
}

// `start_slot` is another durable-frontier declaration: even without a
// journal, the host must not let old peer traffic populate the Engine below
// it. Leaving purge_floor at zero lets 64 historical slots exhaust the live
// slot budget before the first configured slot is proposed.
test "explicit start slot establishes the startup purge floor before peer ingress" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];

    const passphrase = "explicit startup purge floor v1";
    const seed: [32]u8 = @splat(0x44);
    const peer_seed: [32]u8 = @splat(0x45);
    const third_seed: [32]u8 = @splat(0x46);
    const me = try crypto.publicKeyFromSeed(seed);
    const peer = try crypto.publicKeyFromSeed(peer_seed);
    const third = try crypto.publicKeyFromSeed(third_seed);
    const n = try Node.create(gpa, io, .{
        .network = passphrase,
        .secret_seed = seed,
        .quorum = Quorum.twoThirdsOf(&.{ me, peer, third }),
        .listen_port = 0,
        .data_dir = data_dir,
        .start_slot = 100,
    });
    defer n.deinit();

    try std.testing.expectEqual(@as(u64, 100), n.purge_floor.load(.acquire));
    const stale = try buildSignedStatement(gpa, peer_seed, n.network_id, n.local_qset_hash, 99, .{ .nominate = "stale" });
    defer gpa.free(stale);
    n.q.push(try envelopeItem(gpa, stale));
    try pollUntil(io, 2_000, n, struct {
        fn rejected(node: *Node) bool {
            return node.hold.dropped_behind.load(.acquire) == 1;
        }
    }.rejected);
    try std.testing.expectEqual(@as(usize, 0), n.stats().live_slots);

    try n.propose("slot-100");
    try pollUntil(io, 2_000, n, struct {
        fn admitted(node: *Node) bool {
            return node.stats().live_slots == 1;
        }
    }.admitted);
}

// `start_slot` is a permanent out-of-scope declaration, not merely the
// startup value of the floor. The ordinary answering-window calculation for
// the first delivered high slot may be lower and must never move it backward.
test "explicit start slot remains the purge floor after the first delivery" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];

    const seed: [32]u8 = @splat(0x47);
    const me = try crypto.publicKeyFromSeed(seed);
    const n = try Node.create(gpa, io, .{
        .network = "explicit startup purge floor stays monotonic v1",
        .secret_seed = seed,
        .quorum = Quorum.of(1, &.{me}),
        .listen_port = 0,
        .data_dir = data_dir,
        .start_slot = 100,
    });
    defer n.deinit();

    try n.propose("slot-100");
    const decided = n.waitExternalized(.{ .timeout_ms = 5_000 }) orelse return error.Timeout;
    defer gpa.free(decided.value);
    try std.testing.expectEqual(@as(u64, 100), decided.slot);
    try std.testing.expectEqual(@as(u64, 100), n.purge_floor.load(.acquire));
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

test "app messages: a published payload crosses a real loopback connection as owned bytes" {
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

    const seed_a: [32]u8 = @splat(0x71);
    const seed_b: [32]u8 = @splat(0x72);
    const ids = [2][32]u8{ try crypto.publicKeyFromSeed(seed_a), try crypto.publicKeyFromSeed(seed_b) };
    var diag: Diagnostic = .{};

    const a = try Node.create(gpa, io, .{
        .network = "app-message-loopback v1",
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
        .network = "app-message-loopback v1",
        .secret_seed = seed_b,
        .quorum = core.quorum.Quorum.of(2, &ids),
        .listen_port = 0,
        .peers = &.{spec},
        .data_dir = dir_b,
        .diagnostic = &diag,
    });
    defer b.deinit();

    const Probe = struct {
        fn connected(n: *Node) bool {
            return n.peers_live.load(.acquire) >= 1;
        }
    };
    try pollUntil(io, 10_000, a, Probe.connected);
    try pollUntil(io, 10_000, b, Probe.connected);

    // The first wait opts this consumer into inbox retention. Nodes that
    // never consume app messages retain no untrusted application payloads.
    try std.testing.expect(b.waitAppMessage(.{ .timeout_ms = 1 }) == null);

    const want = "opaque signed registry transaction";
    try a.publishAppMessage(want);
    const got = b.waitAppMessage(.{ .timeout_ms = 5_000 }) orelse return error.Timeout;
    defer gpa.free(got);
    try std.testing.expectEqualSlices(u8, want, got);
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

const PausingStatsHook = struct {
    entered: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    release: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn onExternalized(ctx: *anyopaque, slot: u64, value: []const u8) anyerror!void {
        _ = slot;
        _ = value;
        const self: *PausingStatsHook = @ptrCast(@alignCast(ctx));
        self.entered.store(true, .release);
        while (!self.release.load(.acquire)) std.atomic.spinLoopHint();
    }

    fn onFailed(ctx: *anyopaque, _: anyerror) void {
        const self: *PausingStatsHook = @ptrCast(@alignCast(ctx));
        self.release.store(true, .release);
    }

    fn hook(self: *PausingStatsHook) DeliveryHook {
        return .{ .ctx = @ptrCast(self), .on_externalized = onExternalized, .on_failed = onFailed };
    }

    fn hasEntered(self: *PausingStatsHook) bool {
        return self.entered.load(.acquire);
    }
};

// A Node stats snapshot describes a completed input/drain boundary, not the
// Engine's mutable internals halfway through dispatch. The delivery hook
// deliberately parks the engine thread while its externalized effect is still
// queued; callers on another thread must continue to observe the previously
// published, fully-drained snapshot. Reading `self.eng.stats()` directly
// returns effects_queued >= 1 here (and races whenever dispatch is not parked).
test "stats: readers see the last fully-drained snapshot while the engine thread is dispatching" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];

    const seed: [32]u8 = @splat(0x59);
    const me = try crypto.publicKeyFromSeed(seed);
    var hook: PausingStatsHook = .{};
    var diag: Diagnostic = .{};
    const n = try Node.create(gpa, io, .{
        .network = "stats snapshot boundary v1",
        .secret_seed = seed,
        .quorum = Quorum.of(1, &.{me}),
        .listen_port = 0,
        .data_dir = data_dir,
        .delivery = hook.hook(),
        .diagnostic = &diag,
    });
    defer {
        hook.release.store(true, .release);
        n.deinit();
    }

    const ingress = n.ingressStats();
    try std.testing.expectEqual(@as(usize, 0), ingress.queued_items);
    try std.testing.expectEqual(@as(usize, 0), ingress.queued_bytes);
    try std.testing.expectEqual(@as(usize, 0), ingress.dropped_network_inputs);
    try std.testing.expectEqual(@as(usize, 0), n.stats().effects_queued);
    try n.propose("one");
    try pollUntil(io, 10_000, &hook, PausingStatsHook.hasEntered);

    try std.testing.expectEqual(@as(usize, 0), n.stats().effects_queued);
    hook.release.store(true, .release);
    const Published = struct {
        fn completed(node: *Node) bool {
            return node.stats().live_slots == 1;
        }
    };
    try pollUntil(io, 10_000, n, Published.completed);
    try std.testing.expectEqual(@as(usize, 0), n.stats().effects_queued);
}

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

// -- create() unwind after a restart replay ------------------------------------

/// Hold an ephemeral port with a plain listener (no SO_REUSEPORT) so a
/// `create` on that port fails at the listen step — AFTER the journal-tail
/// replay and the own.log restore have run.
fn holdEphemeralPort(io: std.Io) !std.Io.net.Server {
    const net = std.Io.net;
    const bind: net.IpAddress = .{ .ip4 = .unspecified(0) };
    return try net.IpAddress.listen(&bind, io, .{ .mode = .stream, .reuse_address = false });
}

fn portOfServer(server: *const std.Io.net.Server) u16 {
    return switch (server.socket.address) {
        .ip4 => |a| a.port,
        .ip6 => |a| a.port,
    };
}

// Non-vacuity: removing `errdefer self.freeAppBuffers()` from create() (or
// registering it after the thread-join errdefers so it runs before them)
// leaks the three replayed tail values + the ext_queue backing on the queue
// path, and the own_latest map + envelope copy on the own.log path — the
// testing allocator reports the leaks and the test goes red. On a host
// where a held port can still be bound (SO_REUSEPORT sandbox) the test
// skips rather than pass vacuously.
test "create() unwind: ListenPortInUse after a journal-tail replay (queue path) and after an own.log restore leaks nothing" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buf[0..try tmp.dir.realPath(io, &root_buf)];
    var dir_q_buf: [std.fs.max_path_bytes]u8 = undefined;
    var dir_o_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_q = try std.fmt.bufPrint(&dir_q_buf, "{s}/queue", .{root});
    const dir_o = try std.fmt.bufPrint(&dir_o_buf, "{s}/own", .{root});

    const passphrase = "create-unwind v1";
    const seed: [32]u8 = @splat(0x42);
    const me = try crypto.publicKeyFromSeed(seed);
    const peer_a: [32]u8 = @splat(0x77);
    const peer_b: [32]u8 = @splat(0x78);
    const network_id = crypto.networkIdFromPassphrase(passphrase);

    // Queue path: the journal holds 3, 5, 7 (replayed into ext_queue).
    {
        var st = try store_mod.Store.open(gpa, io, dir_q);
        defer st.deinit();
        try st.appendExternalized(3, "three");
        try st.appendExternalized(5, "five");
        try st.appendExternalized(7, "seven");
    }
    // Own.log path: journal 7 + this node's EXTERNALIZE for 8 (restored
    // into own_latest through the engine's re-emitted broadcast).
    {
        var st = try store_mod.Store.open(gpa, io, dir_o);
        defer st.deinit();
        try st.appendExternalized(7, "seven");
        const env = try buildSignedExternalize(gpa, seed, network_id, 8, "eight");
        defer gpa.free(env);
        try st.appendOwn(8, env);
    }

    var server = try holdEphemeralPort(io);
    defer server.deinit(io);
    const port = portOfServer(&server);
    try std.testing.expect(port != 0);

    var diag: Diagnostic = .{};
    for ([_][]const u8{ dir_q, dir_o }) |dir| {
        diag.len = 0;
        if (Node.create(gpa, io, .{
            .network = passphrase,
            .secret_seed = seed,
            .quorum = Quorum.twoThirdsOf(&.{ me, peer_a, peer_b }),
            .listen_port = port,
            .data_dir = dir,
            .diagnostic = &diag,
        })) |n| {
            n.deinit();
            std.debug.print("\nnode bound port {d} while a test listener held it (SO_REUSEPORT sandbox?); skipping\n", .{port});
            return error.SkipZigTest;
        } else |err| {
            try std.testing.expectEqual(error.ListenPortInUse, err);
        }
    }
}

// -- create() under allocation failure -----------------------------------------

/// A crashed node's data_dir: the journal holds 3, 5, 7 and own.log this
/// node's EXTERNALIZE for 8 (= hwm + 1, so the restore re-emits it).
fn seedCrashedDir(gpa: std.mem.Allocator, io: std.Io, dir: []const u8, seed: [32]u8, passphrase: []const u8) !void {
    const network_id = crypto.networkIdFromPassphrase(passphrase);
    var st = try store_mod.Store.open(gpa, io, dir);
    defer st.deinit();
    try st.appendExternalized(3, "three");
    try st.appendExternalized(5, "five");
    try st.appendExternalized(7, "seven");
    const env = try buildSignedExternalize(gpa, seed, network_id, 8, "eight");
    defer gpa.free(env);
    try st.appendOwn(8, env);
}

// Non-vacuity: with the restore loop feeding `applyInput` (which turns a
// pushInput OOM into the runtime inert latch) and no `failed` check before
// "Go live", an allocation failure inside the own.log restore hands back a
// successfully-created node with `failed == true` — this sweep counts those
// (red: "expected 0, found N"), and the latch's err-level log trips the
// runner's err rule as well.
test "create() never returns an already-inert node: FailingAllocator sweep over a crashed data_dir" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];
    const passphrase = "inert-at-create v1";
    const seed: [32]u8 = @splat(0x42);
    const me = try crypto.publicKeyFromSeed(seed);
    const peer_a: [32]u8 = @splat(0x77);
    const peer_b: [32]u8 = @splat(0x78);
    try seedCrashedDir(std.testing.allocator, io, data_dir, seed, passphrase);

    // Backed by the page allocator: leak accounting of the engine's own
    // OOM paths is the engine's business; this pins the create contract.
    var diag: Diagnostic = .{};
    var inert_creates: usize = 0;
    var oks: usize = 0;
    var errs: usize = 0;
    var idx: usize = 0;
    while (idx < 4096) : (idx += 1) {
        var fa = std.testing.FailingAllocator.init(std.heap.page_allocator, .{ .fail_index = idx });
        diag.len = 0;
        if (Node.create(fa.allocator(), io, .{
            .network = passphrase,
            .secret_seed = seed,
            .quorum = Quorum.twoThirdsOf(&.{ me, peer_a, peer_b }),
            .listen_port = 0,
            .data_dir = data_dir,
            .diagnostic = &diag,
        })) |n| {
            const inert = n.failed.load(.acquire);
            n.deinit();
            oks += 1;
            if (inert) {
                inert_creates += 1;
                std.debug.print("fail_index {d}: create() returned OK but the node is inert\n", .{idx});
            }
            if (!fa.has_induced_failure) break; // past every allocation in create
        } else |err| {
            errs += 1;
            if (err != error.OutOfMemory) std.debug.print("fail_index {d}: {t}: {s}\n", .{ idx, err, diag.message() });
        }
    }
    std.debug.print("create() sweep: {d} allocation points, {d} ok, {d} inert-at-create\n", .{ errs + oks, oks, inert_creates });
    try std.testing.expect(idx < 4096); // the sweep reached a clean create
    try std.testing.expectEqual(@as(usize, 0), inert_creates);
}

// Non-vacuity: `recordOwnLatest`'s bare `catch return` on the envelope copy /
// map insert (or a `catch` that only logs on the arm_timer effect) makes an
// induced allocation failure inside the own.log restore return a
// successfully-created node whose catch-up cache lacks the restored slot —
// this sweep counts creates that succeeded WITH an induced failure (red:
// "expected 0, found N"; the design's D5 bar is checkAllAllocationFailures
// over Node.create).
test "create() swallows no allocation failure: every induced OOM in the sweep is an OutOfMemory return" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];
    const passphrase = "swallowed-oom v1";
    const seed: [32]u8 = @splat(0x42);
    const me = try crypto.publicKeyFromSeed(seed);
    const peer_a: [32]u8 = @splat(0x77);
    const peer_b: [32]u8 = @splat(0x78);
    try seedCrashedDir(std.testing.allocator, io, data_dir, seed, passphrase);

    var diag: Diagnostic = .{};
    var swallowed: usize = 0;
    var idx: usize = 0;
    while (idx < 4096) : (idx += 1) {
        var fa = std.testing.FailingAllocator.init(std.heap.page_allocator, .{ .fail_index = idx });
        diag.len = 0;
        if (Node.create(fa.allocator(), io, .{
            .network = passphrase,
            .secret_seed = seed,
            .quorum = Quorum.twoThirdsOf(&.{ me, peer_a, peer_b }),
            .listen_port = 0,
            .data_dir = data_dir,
            .diagnostic = &diag,
        })) |n| {
            const induced = fa.has_induced_failure;
            const has_8 = blk: {
                n.own_mu.lockUncancelable(io);
                defer n.own_mu.unlock(io);
                break :blk n.own_latest.contains(8);
            };
            n.deinit();
            if (induced) {
                swallowed += 1;
                std.debug.print("fail_index {d}: create() returned OK although an allocation failed (own_latest has slot 8: {})\n", .{ idx, has_8 });
            } else {
                try std.testing.expect(has_8); // the clean create restored slot 8 into the catch-up cache
                break;
            }
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
        }
    }
    try std.testing.expect(idx < 4096);
    try std.testing.expectEqual(@as(usize, 0), swallowed);
}

// -- propose under allocation failure ------------------------------------------

/// Fails exactly ONE allocation — the `n`-th made by the arming thread after
/// `arm(n)` — and passes everything else through, so a live Node's other
/// threads (engine, wheel, overlay, resync) are never touched. The std
/// FailingAllocator fails every allocation after its index on every thread,
/// which would confound "one transient failure" with "the engine went OOM".
const ThreadFailOnce = struct {
    backing: std.mem.Allocator,
    tid: std.Thread.Id,
    armed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    remaining: usize = 0,
    fired: bool = false,

    fn arm(self: *ThreadFailOnce, n: usize) void {
        self.tid = std.Thread.getCurrentId();
        self.remaining = n;
        self.fired = false;
        self.armed.store(true, .release);
    }

    fn disarm(self: *ThreadFailOnce) void {
        self.armed.store(false, .release);
    }

    fn allocator(self: *ThreadFailOnce) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *ThreadFailOnce = @ptrCast(@alignCast(ctx));
        if (self.armed.load(.acquire) and std.Thread.getCurrentId() == self.tid) {
            if (self.remaining == 0) {
                self.fired = true;
                self.armed.store(false, .release);
                return null;
            }
            self.remaining -= 1;
        }
        return self.backing.rawAlloc(len, alignment, ra);
    }
    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *ThreadFailOnce = @ptrCast(@alignCast(ctx));
        return self.backing.rawResize(memory, alignment, new_len, ra);
    }
    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *ThreadFailOnce = @ptrCast(@alignCast(ctx));
        return self.backing.rawRemap(memory, alignment, new_len, ra);
    }
    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *ThreadFailOnce = @ptrCast(@alignCast(ctx));
        self.backing.rawFree(memory, alignment, ra);
    }
};

// Non-vacuity: with `InputQueue.push` swallowing the enqueue OOM (drop +
// log) and `maybeStartNomination` having already popped the value and set
// `nominating = true`, the index that lands on the queue append makes
// propose() return success while nothing is ever nominated — the first
// waitExternalized times out (red: NominationDropped) and `nominating`
// stays latched so the retry is never nominated either; the push's err-level
// log trips the runner too. The `prev` dupe index shows the same
// propose-succeeded-but-not-nominated shape.
test "propose: one allocation failure on the calling thread is either OutOfMemory or a nomination — never a silently dropped proposal" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buf[0..try tmp.dir.realPath(io, &root_buf)];
    const seed: [32]u8 = @splat(0x51);
    const me = try crypto.publicKeyFromSeed(seed);
    var diag: Diagnostic = .{};
    var tfo = ThreadFailOnce{ .backing = std.testing.allocator, .tid = std.Thread.getCurrentId() };
    const gpa = tfo.allocator();

    // The calling thread allocates at most a handful of times inside
    // propose (value copy, queue append, prev copy, input enqueue); sweep
    // past that so the last iterations are the no-failure control.
    var n: usize = 0;
    while (n < 6) : (n += 1) {
        var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
        const dir = try std.fmt.bufPrint(&dir_buf, "{s}/n{d}", .{ root, n });
        const node = try Node.create(gpa, io, .{
            .network = "propose-oom v1",
            .secret_seed = seed,
            .quorum = Quorum.of(1, &.{me}), // 1-of-1 self quorum: a nomination externalizes
            .listen_port = 0,
            .data_dir = dir,
            .diagnostic = &diag,
        });
        defer node.deinit();

        tfo.arm(n);
        const res = node.propose("first");
        tfo.disarm();
        if (res) |_| {
            const e = node.waitExternalized(.{ .timeout_ms = 10_000 }) orelse {
                std.debug.print("\nfail #{d}: propose() succeeded but nothing externalized (fired={})\n", .{ n, tfo.fired });
                return error.NominationDropped;
            };
            gpa.free(e.value);
        } else |err| {
            try std.testing.expectEqual(error.OutOfMemory, err);
            try std.testing.expect(tfo.fired);
            node.prop_mu.lockUncancelable(io);
            const nominating = node.nominating;
            const queued = node.proposal_queue.items.len;
            node.prop_mu.unlock(io);
            try std.testing.expect(!nominating); // no latch without a nomination in flight
            try std.testing.expectEqual(@as(usize, 0), queued); // the refused value is not held either
        }
        // The node is never stuck: the next proposal always goes through.
        try node.propose("second");
        const e2 = node.waitExternalized(.{ .timeout_ms = 10_000 }) orelse return error.NodeStuckAfterOom;
        gpa.free(e2.value);
    }
}

// -- catch-up re-flood order ---------------------------------------------------

/// The slot index of a framed Envelope (test helper for the order pins).
fn slotOfFramedEnvelope(gpa: std.mem.Allocator, framed_env: []const u8) !u64 {
    var emsg = try core.capnpc.message.Message.init(gpa, framed_env, .{});
    defer emsg.deinit();
    const er = try gen_slcp.Envelope.Reader.init(&emsg);
    const stmt_bytes = try er.getStatementBytes();
    var smsg = try canonical.decodeFlat(gpa, stmt_bytes, .{});
    defer smsg.deinit();
    const sr = try gen_slcp.Statement.Reader.init(&smsg);
    return sr.getSlotIndex();
}

/// A bare overlay peer (no Node behind it) that records the slot of every
/// envelope it receives, in arrival order, plus the envelope order of the
/// first slotState answer.
const OrderProbe = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    mu: std.Io.Mutex = .init,
    peer: ?usize = null,
    flood: std.ArrayList(u64) = .empty,
    answer: std.ArrayList(u64) = .empty,
    answered: bool = false,

    fn onRecv(ctx: ?*anyopaque, peer_id: usize, frame: *const wire.OverlayFrame) void {
        const self: *OrderProbe = @ptrCast(@alignCast(ctx.?));
        _ = peer_id;
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        switch (frame.*) {
            .envelope => |bytes| {
                const slot = slotOfFramedEnvelope(self.gpa, bytes) catch return;
                self.flood.append(self.gpa, slot) catch {};
            },
            .slot_state => |ss| {
                if (self.answered) return;
                self.answered = true;
                for (ss.envelopes) |env| {
                    const slot = slotOfFramedEnvelope(self.gpa, env) catch continue;
                    self.answer.append(self.gpa, slot) catch {};
                }
            },
            else => {},
        }
    }

    fn onPeerUp(ctx: ?*anyopaque, peer_id: usize) void {
        const self: *OrderProbe = @ptrCast(@alignCast(ctx.?));
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        self.peer = peer_id;
    }

    fn floodCount(self: *OrderProbe) usize {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        return self.flood.items.len;
    }

    fn hasAnswer(self: *OrderProbe) bool {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        return self.answered;
    }

    fn hasPeer(self: *OrderProbe) bool {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        return self.peer != null;
    }

    fn deinit(self: *OrderProbe) void {
        self.flood.deinit(self.gpa);
        self.answer.deinit(self.gpa);
    }
};

// Non-vacuity: iterating `own_latest` with `.iterator()` (bucket order) in
// onPeerUp / answerGetSlotState instead of by ascending slot sends the
// eight restored slots as {7, 1, 8, 4, 6, 5, 2, 3} on this std — both
// `expectEqualSlices` go red (a rejoining peer then sees NOMINATE(N+1)
// before EXTERNALIZE(N), the amplifier behind the 2-of-3 rejoin stall).
test "catch-up: onPeerUp's re-flood and the getSlotState answer send own statements in ascending slot order" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];

    const passphrase = "reflood-order v1";
    const seed: [32]u8 = @splat(0x42);
    const me = try crypto.publicKeyFromSeed(seed);
    const peer_a: [32]u8 = @splat(0x77);
    const peer_b: [32]u8 = @splat(0x78);
    const network_id = crypto.networkIdFromPassphrase(passphrase);
    var diag: Diagnostic = .{};

    const n = try Node.create(gpa, io, .{
        .network = passphrase,
        .secret_seed = seed,
        .quorum = Quorum.twoThirdsOf(&.{ me, peer_a, peer_b }),
        .listen_port = 0,
        .data_dir = data_dir,
        .diagnostic = &diag,
    });
    defer n.deinit();

    // Eight consecutive slots in the catch-up cache, inserted ascending —
    // exactly what a node holds after externalizing 1..8 (or restoring
    // them from own.log).
    const want = [_]u64{ 1, 2, 3, 4, 5, 6, 7, 8 };
    for (want) |slot| {
        const env = try buildSignedExternalize(gpa, seed, network_id, slot, "v");
        defer gpa.free(env);
        try n.recordOwnLatest(slot, env);
    }

    // A bare overlay peer dials the node: its Hello completes, the node's
    // onPeerUp re-floods, then we ask for the slot state ourselves.
    var probe = OrderProbe{ .gpa = gpa, .io = io };
    defer probe.deinit();
    var spec_buf: [32]u8 = undefined;
    const spec = try std.fmt.bufPrint(&spec_buf, "127.0.0.1:{d}", .{n.boundPort()});
    var ov = try overlay_mod.Overlay.init(gpa, io, .{
        .listen_port = 0,
        .peers = &.{spec},
        .network_id_prefix = network_id[0..8].*,
        .node_id = peer_a,
    }, .{ .ctx = &probe, .on_recv = OrderProbe.onRecv, .on_peer_up = OrderProbe.onPeerUp });
    defer ov.deinit();
    try ov.start();
    defer ov.stop();

    try pollUntil(io, 10_000, &probe, OrderProbe.hasPeer);
    const Wait = struct {
        fn flooded(p: *OrderProbe) bool {
            return p.floodCount() >= 8;
        }
    };
    try pollUntil(io, 10_000, &probe, Wait.flooded);
    ov.send(probe.peer.?, .{ .get_slot_state = 0 });
    try pollUntil(io, 10_000, &probe, OrderProbe.hasAnswer);

    probe.mu.lockUncancelable(io);
    defer probe.mu.unlock(io);
    std.debug.print("\nre-flood order: {any}\nslotState order: {any}\n", .{ probe.flood.items[0..8], probe.answer.items });
    try std.testing.expectEqualSlices(u64, &want, probe.flood.items[0..8]);
    try std.testing.expectEqualSlices(u64, &want, probe.answer.items);
}

/// A thread parked in `waitExternalized` until `deinit` wakes it.
const ExtDeinitWaiter = struct {
    n: *Node,
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    saw_null: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn run(self: *ExtDeinitWaiter) void {
        const r = self.n.waitExternalized(.{ .timeout_ms = null });
        if (r) |e| self.n.gpa.free(e.value);
        self.saw_null.store(r == null, .release);
        self.done.store(true, .release);
    }
};

// Non-vacuity (structural twin of AppNode's): `deinit` drains `ext_waiters`
// before freeing the Node. Without the drain the woken waiter re-locks
// `ext_mu` inside freed memory; the thread joins between wake and free mask
// it in practice (the S8 reviewers could not make it hang), so this test
// pins the contract rather than a reproduced crash.
test "deinit while another thread is parked in waitExternalized: the waiter returns null before the Node is freed" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];
    const seed: [32]u8 = @splat(0x63);
    const me = try crypto.publicKeyFromSeed(seed);
    var diag: Diagnostic = .{};

    const n = try Node.create(gpa, io, .{
        .network = "ext-deinit-waiter v1",
        .secret_seed = seed,
        .quorum = core.quorum.Quorum.of(1, &.{me}),
        .listen_port = 0,
        .data_dir = data_dir,
        .diagnostic = &diag,
    });
    var w: ExtDeinitWaiter = .{ .n = n };
    const t = try std.Thread.spawn(.{}, ExtDeinitWaiter.run, .{&w});
    try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(20), .awake);
    n.deinit();
    var waited_ms: u64 = 0;
    while (!w.done.load(.acquire) and waited_ms < 2000) : (waited_ms += 10) {
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .awake);
    }
    if (!w.done.load(.acquire)) return error.WaiterHungAfterDeinit;
    t.join();
    try std.testing.expect(w.saw_null.load(.acquire));
}

const AppMessageDeinitWaiter = struct {
    n: *Node,
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    saw_null: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn run(self: *AppMessageDeinitWaiter) void {
        const payload = self.n.waitAppMessage(.{ .timeout_ms = null });
        if (payload) |bytes| self.n.gpa.free(bytes);
        self.saw_null.store(payload == null, .release);
        self.done.store(true, .release);
    }
};

// The inbox is closed and all public waiter frames drain before Node storage
// is freed; overlay reader callbacks may still observe the closed state until
// ov.stop joins them later in teardown.
test "deinit while another thread is parked in waitAppMessage returns null before the Node is freed" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const data_dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];
    const seed: [32]u8 = @splat(0x73);
    const me = try crypto.publicKeyFromSeed(seed);

    const n = try Node.create(gpa, io, .{
        .network = "app-message-deinit-waiter v1",
        .secret_seed = seed,
        .quorum = core.quorum.Quorum.of(1, &.{me}),
        .listen_port = 0,
        .data_dir = data_dir,
    });
    var waiter: AppMessageDeinitWaiter = .{ .n = n };
    const thread = try std.Thread.spawn(.{}, AppMessageDeinitWaiter.run, .{&waiter});

    var waited_ms: u64 = 0;
    while (!n.appMessageStats().receiving and waited_ms < 1_000) : (waited_ms += 1) {
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake);
    }
    try std.testing.expect(n.appMessageStats().receiving);

    n.deinit();
    thread.join();
    try std.testing.expect(waiter.done.load(.acquire));
    try std.testing.expect(waiter.saw_null.load(.acquire));
}

// -- S8 D1: the hold buffer (host-side per-slot gate) --------------------------

/// A validly-signed, framed statement by `seed` for `slot`: the peer-side
/// twins of `buildSignedExternalize` the hold-gate tests need. `qset_hash`
/// is what the statement advertises (a node's own `local_qset_hash` keeps
/// the engine from parking it).
const SignedSpec = union(enum) {
    nominate: []const u8,
    prepare: struct { counter: u32, value: []const u8 },
    confirm: struct { counter: u32, value: []const u8 },
    externalize: []const u8,
};

fn buildSignedStatement(gpa: std.mem.Allocator, seed: [32]u8, network_id: [32]u8, qset_hash: [32]u8, slot: u64, spec: SignedSpec) ![]u8 {
    const node_id = try crypto.publicKeyFromSeed(seed);
    var mb = MessageBuilder.init(gpa);
    defer mb.deinit();
    var st = try gen_slcp.Statement.Builder.init(&mb);
    try st.setNodeId(&node_id);
    try st.setSlotIndex(slot);
    var pledges = st.getPledges();
    switch (spec) {
        .nominate => |value| {
            var nom = try pledges.initNominate();
            try nom.setQuorumSetHash(&qset_hash);
            const votes = try nom.initVotes(1);
            try votes.set(0, value);
        },
        .prepare => |p| {
            var prep = try pledges.initPrepare();
            try prep.setQuorumSetHash(&qset_hash);
            var ballot = try prep.initBallot();
            try ballot.setCounter(p.counter);
            try ballot.setValue(p.value);
            try prep.setNC(0);
            try prep.setNH(0);
        },
        .confirm => |c| {
            var conf = try pledges.initConfirm();
            try conf.setQuorumSetHash(&qset_hash);
            var ballot = try conf.initBallot();
            try ballot.setCounter(c.counter);
            try ballot.setValue(c.value);
            try conf.setNPrepared(c.counter);
            try conf.setNCommit(c.counter);
            try conf.setNH(c.counter);
        },
        .externalize => |value| {
            var ext = try pledges.initExternalize();
            var commit = try ext.initCommit();
            try commit.setCounter(1);
            try commit.setValue(value);
            try ext.setNH(1);
            try ext.setCommitQuorumSetHash(&qset_hash);
        },
    }
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

/// An owned `envelope_received` InputItem over a copy of `framed`.
fn envelopeItem(gpa: std.mem.Allocator, framed: []const u8) !InputItem {
    return .{ .input = .{ .envelope_received = .{ .bytes = try gpa.dupe(u8, framed) } }, .source_peer = null };
}

fn holdItem(gpa: std.mem.Allocator, payload: []const u8) !InputItem {
    return envelopeItem(gpa, payload);
}

fn heldBytes(e: *const HoldBuffer.Entry) []const u8 {
    return e.item.input.envelope_received.bytes;
}

// Non-vacuity: dropping the (node_id, kind) dedup scan in `put` makes the
// second A-nominate a `.held` (count 2, and the released order shows two
// A-nominates); appending in place instead of remove + append breaks the
// `{b, p, a3}` order; judging the caps on `count` before subtracting the
// replaced entry makes the 1024-entry replacement a `.dropped_full`;
// skipping the below-frontier sweep in `takeReleasable` leaves slots 2 and
// 3 held (count 3, dropped_behind 0); a missing `deinit` free is reported
// by the testing allocator.
test "HoldBuffer: dedup per (signer, kind) replaces and re-appends; caps drop the newcomer; takeReleasable frees below the frontier and hands back exactly the frontier slot" {
    const gpa = std.testing.allocator;
    var hb: HoldBuffer = .{};
    defer hb.deinit(gpa);
    const a: [32]u8 = @splat(0xa1);
    const b: [32]u8 = @splat(0xb2);

    try std.testing.expectEqual(HoldBuffer.PutResult.held, try hb.put(gpa, 5, a, .nominate, try holdItem(gpa, "a1")));
    try std.testing.expectEqual(HoldBuffer.PutResult.replaced, try hb.put(gpa, 5, a, .nominate, try holdItem(gpa, "a2")));
    try std.testing.expectEqual(HoldBuffer.PutResult.held, try hb.put(gpa, 5, b, .nominate, try holdItem(gpa, "b")));
    try std.testing.expectEqual(HoldBuffer.PutResult.held, try hb.put(gpa, 5, a, .prepare, try holdItem(gpa, "p")));
    try std.testing.expectEqual(@as(usize, 3), hb.count);
    try std.testing.expectEqual(@as(usize, 3), hb.held_now.load(.acquire));
    try std.testing.expectEqual(@as(usize, 4), hb.bytes); // "a2" + "b" + "p"
    // A re-flood of A's nomination moves it to the back of the line.
    try std.testing.expectEqual(HoldBuffer.PutResult.replaced, try hb.put(gpa, 5, a, .nominate, try holdItem(gpa, "a3")));
    try std.testing.expectEqual(@as(usize, 3), hb.count);
    {
        var list = hb.takeReleasable(gpa, 5).?;
        defer {
            for (list.items) |*e| HoldBuffer.freeEntry(gpa, e);
            list.deinit(gpa);
        }
        try std.testing.expectEqual(@as(usize, 3), list.items.len);
        try std.testing.expectEqualStrings("b", heldBytes(&list.items[0]));
        try std.testing.expectEqualStrings("p", heldBytes(&list.items[1]));
        try std.testing.expectEqualStrings("a3", heldBytes(&list.items[2]));
        try std.testing.expectEqual(@as(usize, 0), hb.count);
        try std.testing.expectEqual(@as(usize, 0), hb.bytes);
    }

    // Entry cap: 1024 distinct signers fit, the 1025th is dropped (and
    // freed); a replacement at the cap is not a drop.
    var i: usize = 0;
    while (i < HoldBuffer.max_entries) : (i += 1) {
        var id: [32]u8 = @splat(0);
        std.mem.writeInt(u32, id[0..4], @intCast(i), .little);
        try std.testing.expectEqual(HoldBuffer.PutResult.held, try hb.put(gpa, 7, id, .nominate, try holdItem(gpa, "x")));
    }
    try std.testing.expectEqual(HoldBuffer.max_entries, hb.count);
    try std.testing.expectEqual(HoldBuffer.PutResult.dropped_full, try hb.put(gpa, 8, a, .nominate, try holdItem(gpa, "overflow")));
    try std.testing.expectEqual(@as(u64, 1), hb.dropped_full.load(.acquire));
    try std.testing.expectEqual(HoldBuffer.max_entries, hb.count);
    {
        const id0: [32]u8 = @splat(0);
        try std.testing.expectEqual(HoldBuffer.PutResult.replaced, try hb.put(gpa, 7, id0, .nominate, try holdItem(gpa, "y")));
        try std.testing.expectEqual(HoldBuffer.max_entries, hb.count);
    }
    {
        var list = hb.takeReleasable(gpa, 7).?;
        for (list.items) |*e| HoldBuffer.freeEntry(gpa, e);
        list.deinit(gpa);
        try std.testing.expectEqual(@as(usize, 0), hb.count);
    }
    // Byte cap: one oversized item is dropped, nothing is held.
    {
        const big = try gpa.alloc(u8, HoldBuffer.max_bytes + 1);
        try std.testing.expectEqual(HoldBuffer.PutResult.dropped_full, try hb.put(gpa, 9, a, .prepare, .{ .input = .{ .envelope_received = .{ .bytes = big } }, .source_peer = null }));
        try std.testing.expectEqual(@as(usize, 0), hb.count);
        try std.testing.expect(hb.takeReleasable(gpa, 9) == null);
    }

    // Frontier sweep: {2, 3, 20, 21} at frontier 20 → 2 and 3 freed, 20
    // returned, 21 kept.
    for ([_]u64{ 2, 3, 20, 21 }) |slot| {
        try std.testing.expectEqual(HoldBuffer.PutResult.held, try hb.put(gpa, slot, a, .confirm, try holdItem(gpa, "c")));
    }
    try std.testing.expectEqual(@as(usize, 4), hb.count);
    {
        var list = hb.takeReleasable(gpa, 20).?;
        defer {
            for (list.items) |*e| HoldBuffer.freeEntry(gpa, e);
            list.deinit(gpa);
        }
        try std.testing.expectEqual(@as(usize, 1), list.items.len);
    }
    try std.testing.expectEqual(@as(u64, 2), hb.dropped_behind.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), hb.count);
    try std.testing.expect(hb.takeReleasable(gpa, 20) == null);
    try std.testing.expect(hb.slots.contains(21));
    // `deinit` (the defer) frees the remaining slot-21 entry.
}

/// Peer statements for the gate tests: `a` (seed 0x77) advertises the
/// node's own qset hash so nothing parks.
const GateFixture = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    tmp: std.testing.TmpDir,
    dir_buf: [std.fs.max_path_bytes]u8 = undefined,
    dir_len: usize = 0,
    seed_a: [32]u8 = @splat(0x77),
    seed_b: [32]u8 = @splat(0x78),
    network_id: [32]u8,
    diag: Diagnostic = .{},

    const passphrase = "hold-gate v1";

    fn init(gpa: std.mem.Allocator, io: std.Io) !GateFixture {
        var f: GateFixture = .{ .gpa = gpa, .io = io, .tmp = std.testing.tmpDir(.{}), .network_id = crypto.networkIdFromPassphrase(passphrase) };
        f.dir_len = try f.tmp.dir.realPath(io, &f.dir_buf);
        return f;
    }

    fn deinit(self: *GateFixture) void {
        self.tmp.cleanup();
    }

    fn dataDir(self: *GateFixture) []const u8 {
        return self.dir_buf[0..self.dir_len];
    }

    /// A signed statement by `seed` for `slot`, as an owned InputItem.
    fn item(self: *GateFixture, n: *Node, seed: [32]u8, slot: u64, spec: SignedSpec) !InputItem {
        const framed = try buildSignedStatement(self.gpa, seed, self.network_id, n.local_qset_hash, slot, spec);
        defer self.gpa.free(framed);
        return envelopeItem(self.gpa, framed);
    }

    /// Turn the node single-threaded: close the queue and join the engine
    /// thread, so the TEST thread can drive `applyInput` deterministically
    /// (timer fires and proposals now land on a closed queue and are freed;
    /// the tests below feed only envelopes). `deinit` skips the join.
    fn ownEngineThread(n: *Node) void {
        n.q.close();
        if (n.engine_thread) |t| t.join();
        n.engine_thread = null;
    }
};

const GateProbe = struct {
    fn heldOne(n: *Node) bool {
        return n.hold.held_now.load(.acquire) >= 1 or n.stats().live_slots >= 1;
    }
    fn heldTwo(n: *Node) bool {
        return n.hold.held_now.load(.acquire) >= 2 or n.stats().live_slots >= 1;
    }
    fn liveOne(n: *Node) bool {
        return n.stats().live_slots >= 1;
    }
    fn liveTwo(n: *Node) bool {
        return n.stats().live_slots >= 2;
    }
};

// The host purge floor is the admission floor, not merely a timer hint. Once
// slots below 5 have been purged, a late valid envelope for slot 4 must be
// consumed without recreating Engine state; slot 5 remains admissible.
test "hold gate: peer envelopes below the purge floor cannot recreate slots" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f = try GateFixture.init(gpa, io);
    defer f.deinit();
    const me = try crypto.publicKeyFromSeed(@splat(0x42));
    const n = try Node.create(gpa, io, .{
        .network = GateFixture.passphrase,
        .secret_seed = @splat(0x42),
        .quorum = Quorum.twoThirdsOf(&.{ me, try crypto.publicKeyFromSeed(f.seed_a), try crypto.publicKeyFromSeed(f.seed_b) }),
        .listen_port = 0,
        .data_dir = f.dataDir(),
        .diagnostic = &f.diag,
    });
    defer n.deinit();
    GateFixture.ownEngineThread(n);

    n.next_deliver = 20;
    n.purge_floor.store(5, .release);
    n.applyInput(try f.item(n, f.seed_a, 4, .{ .nominate = "old" }));
    try std.testing.expectEqual(@as(usize, 0), n.stats().live_slots);
    try std.testing.expectEqual(@as(u64, 1), n.hold.dropped_behind.load(.acquire));

    n.applyInput(try f.item(n, f.seed_a, 5, .{ .nominate = "edge" }));
    try std.testing.expectEqual(@as(usize, 1), n.stats().live_slots);
}

// Metadata parsing is only an optimization for malformed/current traffic,
// but it is the host's sole purge-floor gate. A transient allocation failure
// there must drop the network item; feeding it to the Engine lets the second
// parse succeed and recreate a retired slot because the Engine does not know
// the host floor.
test "hold gate: metadata OOM fails closed below the purge floor" {
    const io = std.testing.io;
    var fail_once = ThreadFailOnce{ .backing = std.testing.allocator, .tid = std.Thread.getCurrentId() };
    const gpa = fail_once.allocator();
    var f = try GateFixture.init(gpa, io);
    defer f.deinit();
    const me = try crypto.publicKeyFromSeed(@splat(0x42));
    const n = try Node.create(gpa, io, .{
        .network = GateFixture.passphrase,
        .secret_seed = @splat(0x42),
        .quorum = Quorum.twoThirdsOf(&.{ me, try crypto.publicKeyFromSeed(f.seed_a), try crypto.publicKeyFromSeed(f.seed_b) }),
        .listen_port = 0,
        .data_dir = f.dataDir(),
        .diagnostic = &f.diag,
    });
    defer n.deinit();
    GateFixture.ownEngineThread(n);

    n.next_deliver = 20;
    n.purge_floor.store(5, .release);
    const stale = try f.item(n, f.seed_a, 4, .{ .nominate = "old" });
    fail_once.arm(0);
    n.applyInput(stale);
    fail_once.disarm();

    try std.testing.expect(fail_once.fired);
    try std.testing.expectEqual(@as(usize, 0), n.stats().live_slots);
    try std.testing.expectEqual(@as(usize, 1), n.ingressStats().dropped_network_inputs);
}

// A priority purge may overtake local work that was already in the ordinary
// FIFO. The host floor therefore has to be re-checked when that work is
// applied: otherwise the stale nomination recreates the just-purged Engine
// slot and can sign a statement incomparable with the durable one.
test "purge floor: an overtaken local nomination cannot recreate a purged slot" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f = try GateFixture.init(gpa, io);
    defer f.deinit();
    const me = try crypto.publicKeyFromSeed(@splat(0x42));
    const n = try Node.create(gpa, io, .{
        .network = GateFixture.passphrase,
        .secret_seed = @splat(0x42),
        .quorum = Quorum.twoThirdsOf(&.{ me, try crypto.publicKeyFromSeed(f.seed_a), try crypto.publicKeyFromSeed(f.seed_b) }),
        .listen_port = 0,
        .data_dir = f.dataDir(),
        .diagnostic = &f.diag,
    });
    defer n.deinit();
    GateFixture.ownEngineThread(n);

    n.purge_floor.store(5, .release);
    n.applyInput(.{ .input = .{ .purge_slots = .{ .max_slot = 5 } }, .source_peer = null });
    const stale_value = try gpa.dupe(u8, "stale");
    const stale_prev = gpa.dupe(u8, "previous") catch |err| {
        gpa.free(stale_value);
        return err;
    };
    n.applyInput(.{ .input = .{ .nominate = .{
        .slot = 4,
        .value = stale_value,
        .prev_value = stale_prev,
    } }, .source_peer = null });

    try std.testing.expectEqual(@as(usize, 0), n.stats().live_slots);
    try std.testing.expect(n.eng.slots.get(4) == null);
    n.own_mu.lockUncancelable(io);
    const stale_latest_absent = n.own_latest.get(4) == null;
    n.own_mu.unlock(io);
    try std.testing.expect(stale_latest_absent);

    const edge_value = try gpa.dupe(u8, "edge");
    const edge_prev = gpa.dupe(u8, "previous") catch |err| {
        gpa.free(edge_value);
        return err;
    };
    n.applyInput(.{ .input = .{ .nominate = .{
        .slot = 5,
        .value = edge_value,
        .prev_value = edge_prev,
    } }, .source_peer = null });
    try std.testing.expectEqual(@as(usize, 1), n.stats().live_slots);
}

// A statement may have entered the hold buffer before the delivery frontier
// advanced. Re-check the purge floor when releasing, or that retained item can
// recreate state even though direct admission now rejects the same slot.
test "hold gate: held envelopes are checked against the purge floor again on release" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f = try GateFixture.init(gpa, io);
    defer f.deinit();
    const me = try crypto.publicKeyFromSeed(@splat(0x42));
    const n = try Node.create(gpa, io, .{
        .network = GateFixture.passphrase,
        .secret_seed = @splat(0x42),
        .quorum = Quorum.twoThirdsOf(&.{ me, try crypto.publicKeyFromSeed(f.seed_a), try crypto.publicKeyFromSeed(f.seed_b) }),
        .listen_port = 0,
        .data_dir = f.dataDir(),
        .diagnostic = &f.diag,
    });
    defer n.deinit();
    GateFixture.ownEngineThread(n);

    n.applyInput(try f.item(n, f.seed_a, 3, .{ .nominate = "held-old" }));
    try std.testing.expectEqual(@as(usize, 1), n.hold.held_now.load(.acquire));
    n.next_deliver = 3;
    n.purge_floor.store(4, .release);
    n.releaseHeld();
    n.publishStats();

    try std.testing.expectEqual(@as(usize, 0), n.stats().live_slots);
    try std.testing.expectEqual(@as(usize, 0), n.hold.held_now.load(.acquire));
    try std.testing.expectEqual(@as(u64, 1), n.hold.dropped_behind.load(.acquire));
}

// Pins the S8 D1 finding (state-dependent validate + engine verdict cache +
// sticky fully_validated: a node one slot behind that sees the next slot's
// nomination goes mute for that slot). Red before the fix — the ungated
// engine created slot 3 the moment NOMINATE(3) arrived:
//   after NOM(3): held_now=0 live_slots=1
// Ablations: exempting EXTERNALIZE from the gate opens slot 3 on a's lone
// EXT(3) (held_now stays 3, live_slots 1 one step early — the S8b skeptic's
// bypass); dropping the v-blocking release leaves live_slots at 0 after b's
// EXT(3) (the catch-up channel is cut); comparing `slot < next_deliver`
// instead of `<=` holds NOM(1) (live_slots stays 1 at the end).
test "hold gate: every statement kind for slot > next_deliver is held; a v-blocking set of EXTERNALIZEs releases its slot early; slot <= next_deliver passes" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f = try GateFixture.init(gpa, io);
    defer f.deinit();
    const me = try crypto.publicKeyFromSeed(@splat(0x42));
    const n = try Node.create(gpa, io, .{
        .network = GateFixture.passphrase,
        .secret_seed = @splat(0x42),
        .quorum = Quorum.twoThirdsOf(&.{ me, try crypto.publicKeyFromSeed(f.seed_a), try crypto.publicKeyFromSeed(f.seed_b) }),
        .listen_port = 0,
        .data_dir = f.dataDir(),
        .diagnostic = &f.diag,
    });
    defer n.deinit();
    try std.testing.expectEqual(@as(u64, 1), n.next_deliver);

    // NOM(3) from a: two slots past the frontier → held, no engine slot.
    n.q.push(try f.item(n, f.seed_a, 3, .{ .nominate = "x" }));
    try pollUntil(io, 10_000, n, GateProbe.heldOne);
    std.debug.print("\nafter NOM(3): held_now={d} live_slots={d}\n", .{ n.hold.held_now.load(.acquire), n.stats().live_slots });
    try std.testing.expectEqual(@as(usize, 1), n.hold.held_now.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), n.stats().live_slots);
    // PREPARE(4) and CONFIRM(4) from b: held too (two entries, one slot).
    n.q.push(try f.item(n, f.seed_b, 4, .{ .prepare = .{ .counter = 1, .value = "x" } }));
    n.q.push(try f.item(n, f.seed_b, 4, .{ .confirm = .{ .counter = 1, .value = "x" } }));
    const Three = struct {
        fn ok(nn: *Node) bool {
            return nn.hold.held_now.load(.acquire) >= 3 or nn.stats().live_slots >= 1;
        }
    };
    try pollUntil(io, 10_000, n, Three.ok);
    try std.testing.expectEqual(@as(usize, 3), n.hold.held_now.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), n.stats().live_slots);

    // EXT(3) from a: held like anything else — one signer is not
    // v-blocking for {me, a, b} at threshold 2.
    n.q.push(try f.item(n, f.seed_a, 3, .{ .externalize = "x" }));
    const Four = struct {
        fn ok(nn: *Node) bool {
            return nn.hold.held_now.load(.acquire) >= 4 or nn.stats().live_slots >= 1;
        }
    };
    try pollUntil(io, 10_000, n, Four.ok);
    try std.testing.expectEqual(@as(usize, 4), n.hold.held_now.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), n.stats().live_slots);
    // EXT(3) from b: {a, b} is v-blocking → slot 3 is released ahead of the
    // frontier (catch-up) → the engine opens slot 3 from a's NOM + both
    // EXTs (and externalizes it: accept via the v-blocking set, confirm
    // with the quorum {a, b}); PREPARE/CONFIRM(4) stay held.
    n.q.push(try f.item(n, f.seed_b, 3, .{ .externalize = "x" }));
    try pollUntil(io, 10_000, n, GateProbe.liveOne);
    try std.testing.expectEqual(@as(usize, 1), n.stats().live_slots);
    try std.testing.expectEqual(@as(usize, 2), n.hold.held_now.load(.acquire));
    try std.testing.expectEqual(@as(u64, 3), n.hold.released_early.load(.acquire)); // NOM(3), EXT(3) a, EXT(3) b
    try std.testing.expectEqual(@as(u64, 1), n.next_deliver); // no delivery: slot 3 is < 16 past the frontier

    // NOM(1) from a: the slot in progress → passes → slot 1 opens.
    n.q.push(try f.item(n, f.seed_a, 1, .{ .nominate = "x" }));
    try pollUntil(io, 10_000, n, GateProbe.liveTwo);
    try std.testing.expectEqual(@as(usize, 2), n.stats().live_slots);
    try std.testing.expectEqual(@as(usize, 2), n.hold.held_now.load(.acquire));
    try std.testing.expectEqual(@as(u64, 0), n.hold.released.load(.acquire));
}

// Non-vacuity: removing the `releaseHeld` call from `applyInput` (or
// releasing lazily on the next pop) leaves the counters at
//   after EXT(1) x2: released=0 held_now=3 live_slots=1
// (red on the `released == 2` line — the held statements never reach the
// engine, which is the mute-node shape). Removing the "slot fell below the
// frontier" drop in `takeReleasable` feeds NOM(2) after the gap-jump past it
// (dropped_behind 0, released 3). Releasing from inside `onExternalized`
// instead of after the drain would re-enter `pushInput` mid-drain (the
// engine's §5.1 contract); this test cannot see that, the comment in
// `applyInput` is the guard.
test "hold gate: released at the frontier inside the same applyInput, ascending; a gap-jump drops what it skipped and releases the new frontier" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f = try GateFixture.init(gpa, io);
    defer f.deinit();
    const me = try crypto.publicKeyFromSeed(@splat(0x42));
    const id_a = try crypto.publicKeyFromSeed(f.seed_a);
    const id_b = try crypto.publicKeyFromSeed(f.seed_b);
    var hook = RecordingHook{ .gpa = gpa };
    defer hook.deinit();
    const n = try Node.create(gpa, io, .{
        .network = GateFixture.passphrase,
        .secret_seed = @splat(0x42),
        .quorum = Quorum.twoThirdsOf(&.{ me, id_a, id_b }),
        .listen_port = 0,
        .data_dir = f.dataDir(),
        .diagnostic = &f.diag,
        .delivery = hook.hook(),
    });
    defer n.deinit();
    GateFixture.ownEngineThread(n);

    // Held: a's NOMINATE(2), b's PREPARE(2) (arrival order), a's CONFIRM(3).
    n.applyInput(try f.item(n, f.seed_a, 2, .{ .nominate = "two" }));
    n.applyInput(try f.item(n, f.seed_b, 2, .{ .prepare = .{ .counter = 1, .value = "two" } }));
    n.applyInput(try f.item(n, f.seed_a, 3, .{ .confirm = .{ .counter = 1, .value = "three" } }));
    try std.testing.expectEqual(@as(usize, 3), n.hold.held_now.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), n.stats().live_slots);

    // Slot 1 externalizes from a quorum of EXTERNALIZEs (a + b = 2 of 3):
    // the hook applies slot 1, next_deliver becomes 2, and — inside this
    // very applyInput, after the drain — slot 2's two statements are fed.
    n.applyInput(try f.item(n, f.seed_a, 1, .{ .externalize = "one" }));
    try std.testing.expectEqual(@as(usize, 3), n.hold.held_now.load(.acquire)); // 1 of 3 said so: nothing moved
    n.applyInput(try f.item(n, f.seed_b, 1, .{ .externalize = "one" }));
    std.debug.print("\nafter EXT(1) x2: released={d} held_now={d} live_slots={d}\n", .{ n.hold.released.load(.acquire), n.hold.held_now.load(.acquire), n.stats().live_slots });
    try std.testing.expectEqualSlices(u64, &[_]u64{1}, hook.slots.items);
    try std.testing.expectEqual(@as(u64, 2), n.next_deliver);
    try std.testing.expectEqual(@as(u64, 2), n.hold.released.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), n.hold.held_now.load(.acquire)); // CONFIRM(3) still waits
    try std.testing.expectEqual(@as(usize, 2), n.stats().live_slots);
    // The engine's slot 2 holds exactly what was released: a's nomination
    // and b's ballot statement.
    const s2 = n.eng.slots.get(2).?;
    try std.testing.expect(s2.latestFor(id_a, true) != null);
    try std.testing.expect(s2.latestFor(id_b, false) != null);
    try std.testing.expect(s2.latestFor(id_b, true) == null);

    // Gap-jump: EXTERNALIZE(19) from a is held (one signer); b's completes
    // a v-blocking set → slot 19 is released early → the engine
    // externalizes 19; it sits a full answering window past the frontier
    // (2 + 16 <= 19), so delivery jumps to 19 → next_deliver 20. The held
    // CONFIRM(3) is now behind the frontier: dropped, never fed. A
    // NOMINATE(20) held before the jump is the new frontier's statement:
    // released.
    n.applyInput(try f.item(n, f.seed_b, 20, .{ .nominate = "twenty" }));
    try std.testing.expectEqual(@as(usize, 2), n.hold.held_now.load(.acquire));
    n.applyInput(try f.item(n, f.seed_a, 19, .{ .externalize = "nineteen" }));
    try std.testing.expectEqual(@as(usize, 3), n.hold.held_now.load(.acquire)); // one signer: held
    try std.testing.expectEqual(@as(u64, 2), n.next_deliver);
    n.applyInput(try f.item(n, f.seed_b, 19, .{ .externalize = "nineteen" }));
    try std.testing.expectEqualSlices(u64, &[_]u64{ 1, 19 }, hook.slots.items);
    try std.testing.expectEqual(@as(u64, 20), n.next_deliver);
    try std.testing.expectEqual(@as(u64, 1), n.hold.dropped_behind.load(.acquire));
    try std.testing.expectEqual(@as(u64, 2), n.hold.released_early.load(.acquire)); // EXT(19) a + b
    try std.testing.expectEqual(@as(u64, 3), n.hold.released.load(.acquire)); // NOM(2), PREPARE(2), NOM(20)
    try std.testing.expectEqual(@as(usize, 0), n.hold.held_now.load(.acquire));
    try std.testing.expect(n.eng.slots.get(3) == null); // CONFIRM(3) never opened a slot
    try std.testing.expect(n.eng.slots.get(20).?.latestFor(id_b, true) != null);
}

// Non-vacuity: dropping the window check holds NOM(next_deliver + 65)
// (held_now 1, dropped_far 0); dropping the pre-hold `crypto.verify` holds
// the forged NOM(3) (held_now 1, dropped_badsig 0) — it would be rejected
// only at release, after occupying a genuine signer's entry.
test "hold gate: beyond the window and bad signatures are dropped, not held" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f = try GateFixture.init(gpa, io);
    defer f.deinit();
    const me = try crypto.publicKeyFromSeed(@splat(0x42));
    const n = try Node.create(gpa, io, .{
        .network = GateFixture.passphrase,
        .secret_seed = @splat(0x42),
        .quorum = Quorum.twoThirdsOf(&.{ me, try crypto.publicKeyFromSeed(f.seed_a), try crypto.publicKeyFromSeed(f.seed_b) }),
        .listen_port = 0,
        .data_dir = f.dataDir(),
        .diagnostic = &f.diag,
    });
    defer n.deinit();
    GateFixture.ownEngineThread(n);

    n.applyInput(try f.item(n, f.seed_a, n.next_deliver + HoldBuffer.window + 1, .{ .nominate = "far" }));
    try std.testing.expectEqual(@as(u64, 1), n.hold.dropped_far.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), n.hold.held_now.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), n.stats().live_slots);
    // Exactly at the window edge: held.
    n.applyInput(try f.item(n, f.seed_a, n.next_deliver + HoldBuffer.window, .{ .nominate = "edge" }));
    try std.testing.expectEqual(@as(usize, 1), n.hold.held_now.load(.acquire));

    // A NOMINATE(3) whose signature byte was flipped.
    {
        const framed = try buildSignedStatement(gpa, f.seed_a, f.network_id, n.local_qset_hash, 3, .{ .nominate = "forged" });
        defer gpa.free(framed);
        const meta = try envelopeMeta(gpa, f.network_id, framed);
        try std.testing.expect(crypto.verify(meta.node_id, meta.digest, meta.signature));
        // The signature is the last 64 bytes of the envelope's data section
        // in this framing; flip the byte that the decoded signature reads
        // back, found by re-decoding.
        var flipped = try gpa.dupe(u8, framed);
        defer gpa.free(flipped);
        const at = std.mem.lastIndexOf(u8, flipped, &meta.signature).?;
        flipped[at] ^= 0x01;
        const meta2 = try envelopeMeta(gpa, f.network_id, flipped);
        try std.testing.expect(!crypto.verify(meta2.node_id, meta2.digest, meta2.signature));
        n.applyInput(try envelopeItem(gpa, flipped));
    }
    try std.testing.expectEqual(@as(u64, 1), n.hold.dropped_badsig.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), n.hold.held_now.load(.acquire));
    // The genuine NOMINATE(3) is held.
    n.applyInput(try f.item(n, f.seed_a, 3, .{ .nominate = "genuine" }));
    try std.testing.expectEqual(@as(usize, 2), n.hold.held_now.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), n.stats().live_slots);
    // `deinit` → `freeAppBuffers` frees both held entries (leak-checked).
}

// -- S8b skeptic (liveness lens): the EXTERNALIZE bypass ----------------------

/// A Counter-shaped typed layer over the bytes driver: values are decimal
/// counts; validate reads the state the delivery hook applies (exactly the
/// AppNode(Counter) shape: `.maybe_valid` when the value is ahead of count+1).
const CounterProbe = struct {
    count: u64 = 0,
    delivered: std.ArrayList(u64) = .empty,
    gpa: std.mem.Allocator,
    maybe_verdicts: u32 = 0,

    fn parse(v: []const u8) ?u64 {
        return std.fmt.parseInt(u64, v, 10) catch null;
    }
    fn validate(ctx: *anyopaque, slot: u64, value: []const u8, is_nom: bool) core.driver.Validity {
        _ = slot;
        _ = is_nom;
        const self: *CounterProbe = @ptrCast(@alignCast(ctx));
        const next = parse(value) orelse return .invalid;
        if (next == self.count + 1) return .valid;
        if (next > self.count + 1) {
            self.maybe_verdicts += 1;
            return .maybe_valid;
        }
        return .invalid;
    }
    fn combine(ctx: *anyopaque, slot: u64, cands: []const []const u8, gpa: std.mem.Allocator, out: *std.ArrayList(u8)) core.driver.DriverError!void {
        _ = ctx;
        _ = slot;
        var best = cands[0];
        for (cands) |c| if ((parse(c) orelse 0) > (parse(best) orelse 0)) {
            best = c;
        };
        try out.appendSlice(gpa, best);
    }
    fn onExternalized(ctx: *anyopaque, slot: u64, value: []const u8) anyerror!void {
        const self: *CounterProbe = @ptrCast(@alignCast(ctx));
        self.count = parse(value) orelse return error.Undecodable;
        try self.delivered.append(self.gpa, slot);
    }
    fn onFailed(ctx: *anyopaque, err: anyerror) void {
        _ = ctx;
        std.debug.print("probe: node failed: {t}\n", .{err});
    }
    fn driver(self: *CounterProbe) core.driver.Driver {
        return .{ .ctx = @ptrCast(self), .validate_value = validate, .combine_candidates = combine };
    }
    fn hook(self: *CounterProbe) DeliveryHook {
        return .{ .ctx = @ptrCast(self), .on_externalized = onExternalized, .on_failed = onFailed };
    }
};

// Pins the S8b skeptic's refutation of the first hold buffer ("the gate
// exempts EXTERNALIZE for slots beyond next_deliver, so a single peer's
// EXTERNALIZE(next_deliver + 1) still fills the engine's per-slot verdict
// cache with .maybe_valid-because-behind and clears the sticky
// fully_validated for that slot"). 3-of-4 {me, a, b, c}; the node is one
// slot behind (it has a's EXTERNALIZE(1) only — 1 of 3). Red with the
// EXTERNALIZE bypass (ablation: `if (meta.kind == .externalize) return
// false` back in the gate):
//   [poisoned order] after a's EXTERNALIZE(2) at next_deliver=1: slot2 open=true fully_validated=false maybe_verdicts=1 held_now=1
// — the value was validated against count 0, the verdict cached, slot 2
// mute for good (own statement never on the wire even after catching up).
// Fixed: a's EXTERNALIZE(2) is held like any other statement (one signer is
// not v-blocking), released after slot 1 is applied, validated `.valid`,
// and the node's own EXTERNALIZE(2) reaches the wire. The control order
// (b's EXTERNALIZE(1) first) always converged and must keep doing so.
test "hold gate: an EXTERNALIZE(next_deliver + 1) from one peer is held while the node is behind; released after slot 1 is applied, the node votes for slot 2" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    for ([_]bool{ true, false }) |poisoned_order| {
        var f = try GateFixture.init(gpa, io);
        defer f.deinit();
        const seed_c: [32]u8 = @splat(0x79);
        const me = try crypto.publicKeyFromSeed(@splat(0x42));
        var probe = CounterProbe{ .gpa = gpa };
        defer probe.delivered.deinit(gpa);
        const n = try Node.create(gpa, io, .{
            .network = GateFixture.passphrase,
            .secret_seed = @splat(0x42),
            .quorum = Quorum.twoThirdsOf(&.{ me, try crypto.publicKeyFromSeed(f.seed_a), try crypto.publicKeyFromSeed(f.seed_b), try crypto.publicKeyFromSeed(seed_c) }),
            .listen_port = 0,
            .data_dir = f.dataDir(),
            .diagnostic = &f.diag,
            .driver = probe.driver(),
            .delivery = probe.hook(),
        });
        defer n.deinit();
        GateFixture.ownEngineThread(n);
        try std.testing.expectEqual(@as(u64, 1), n.next_deliver);

        // a's EXTERNALIZE(1): 1 of 3 — the node stays behind.
        n.applyInput(try f.item(n, f.seed_a, 1, .{ .externalize = "1" }));
        try std.testing.expectEqual(@as(u64, 1), n.next_deliver);
        if (poisoned_order) {
            // a's NOMINATE(2) and EXTERNALIZE(2) arrive while slot 1 is
            // still open here: BOTH are held.
            n.applyInput(try f.item(n, f.seed_a, 2, .{ .nominate = "2" }));
            try std.testing.expectEqual(@as(usize, 1), n.hold.held_now.load(.acquire));
            n.applyInput(try f.item(n, f.seed_a, 2, .{ .externalize = "2" }));
            try std.testing.expectEqual(@as(u64, 1), n.next_deliver);
            const s2_open = n.eng.slots.get(2) != null;
            std.debug.print("\n[poisoned order] after a's EXTERNALIZE(2) at next_deliver=1: slot2 open={} fully_validated={?} maybe_verdicts={d} held_now={d}\n", .{ s2_open, if (n.eng.slots.get(2)) |s| s.fully_validated else null, probe.maybe_verdicts, n.hold.held_now.load(.acquire) });
            try std.testing.expectEqual(@as(usize, 2), n.hold.held_now.load(.acquire));
            try std.testing.expect(!s2_open); // nothing for slot 2 reached the engine
            try std.testing.expectEqual(@as(u32, 0), probe.maybe_verdicts);
            // b's EXTERNALIZE(1): v-blocking {a,b} -> accept commit -> quorum -> slot 1 delivered.
            n.applyInput(try f.item(n, f.seed_b, 1, .{ .externalize = "1" }));
        } else {
            n.applyInput(try f.item(n, f.seed_b, 1, .{ .externalize = "1" }));
            n.applyInput(try f.item(n, f.seed_a, 2, .{ .nominate = "2" }));
            n.applyInput(try f.item(n, f.seed_a, 2, .{ .externalize = "2" }));
        }
        try std.testing.expectEqualSlices(u64, &[_]u64{1}, probe.delivered.items);
        try std.testing.expectEqual(@as(u64, 2), n.next_deliver);
        try std.testing.expectEqual(@as(u64, 1), probe.count);
        const s2 = n.eng.slots.get(2).?;
        // b's EXTERNALIZE(2): the network finishes slot 2; the node follows.
        n.applyInput(try f.item(n, f.seed_b, 2, .{ .externalize = "2" }));
        try std.testing.expectEqualSlices(u64, &[_]u64{ 1, 2 }, probe.delivered.items);
        const own2 = n.own_latest.get(2);
        std.debug.print("[{s} order] after catch-up: slot2.fully_validated={} released={d} maybe_verdicts={d} own statement for slot 2 on the wire={}\n", .{ if (poisoned_order) "poisoned" else "control", s2.fully_validated, n.hold.released.load(.acquire), probe.maybe_verdicts, own2 != null });
        if (poisoned_order) try std.testing.expectEqual(@as(u64, 2), n.hold.released.load(.acquire)); // NOMINATE(2) and EXTERNALIZE(2), at the frontier
        try std.testing.expectEqual(@as(u32, 0), probe.maybe_verdicts); // no .maybe_valid verdict was ever cached for slot 2
        try std.testing.expect(s2.fully_validated);
        try std.testing.expect(own2 != null); // our own EXTERNALIZE(2) is on the wire (re-flood / getSlotState carry it)
    }
}

// The catch-up channel after the EXTERNALIZE bypass was closed: a node far
// behind learns the live frontier from held EXTERNALIZEs the moment a
// v-blocking set of signers has sent them for a slot. 3-of-4 {me, a, b, c},
// frontier 1; a's EXT(20..22) alone stay held (one signer is not
// v-blocking — the S8b skeptic's halt needed exactly that lone EXTERNALIZE
// to be fed); b's EXT(20) completes the set → slot 20 is released early →
// the engine externalizes 20 from {a, b} + me → the delivery gap-jump
// (20 >= 1 + 16) lands on 20 → slot 21 is released at the frontier, and
// from there every slot is validated AFTER the one before it was applied:
// the Counter-shaped probe answers .maybe_valid exactly once (slot 20,
// judged against count 0 — harmless, a v-blocking set had externalized it)
// and .valid for 21 and 22, so the node's own EXTERNALIZE(21) and (22)
// reach the wire. Non-vacuity: dropping the v-blocking release (`.ready`)
// leaves next_deliver at 1 with 4 entries held after b's EXT(20); feeding
// EXTERNALIZE straight through makes maybe_verdicts 3 and own_latest(21)
// null (mute on every caught-up slot); dropping the `open` mark makes b's
// EXT(21) wait in the buffer instead of completing slot 21.
test "hold gate: catch-up far behind — a v-blocking set of EXTERNALIZEs releases its slot early, the gap-jump follows, later slots validate after apply and the node votes on them" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f = try GateFixture.init(gpa, io);
    defer f.deinit();
    const seed_c: [32]u8 = @splat(0x79);
    const me = try crypto.publicKeyFromSeed(@splat(0x42));
    var probe = CounterProbe{ .gpa = gpa };
    defer probe.delivered.deinit(gpa);
    const n = try Node.create(gpa, io, .{
        .network = GateFixture.passphrase,
        .secret_seed = @splat(0x42),
        .quorum = Quorum.twoThirdsOf(&.{ me, try crypto.publicKeyFromSeed(f.seed_a), try crypto.publicKeyFromSeed(f.seed_b), try crypto.publicKeyFromSeed(seed_c) }),
        .listen_port = 0,
        .data_dir = f.dataDir(),
        .diagnostic = &f.diag,
        .driver = probe.driver(),
        .delivery = probe.hook(),
    });
    defer n.deinit();
    GateFixture.ownEngineThread(n);

    // a's re-flood: NOM(20) EXT(20) EXT(21) EXT(22) — all held, nothing fed.
    n.applyInput(try f.item(n, f.seed_a, 20, .{ .nominate = "20" }));
    n.applyInput(try f.item(n, f.seed_a, 20, .{ .externalize = "20" }));
    n.applyInput(try f.item(n, f.seed_a, 21, .{ .externalize = "21" }));
    n.applyInput(try f.item(n, f.seed_a, 22, .{ .externalize = "22" }));
    try std.testing.expectEqual(@as(usize, 4), n.hold.held_now.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), n.stats().live_slots);
    try std.testing.expectEqual(@as(u64, 1), n.next_deliver);
    try std.testing.expectEqual(@as(u32, 0), probe.maybe_verdicts);

    // b's EXT(20): {a, b} is v-blocking for 3-of-4 → slot 20 released →
    // externalized → gap-jump → delivered; slot 21 (a's EXT) is fed at the
    // new frontier but stays 1 of 3.
    n.applyInput(try f.item(n, f.seed_b, 20, .{ .externalize = "20" }));
    std.debug.print("\nafter b's EXT(20): next_deliver={d} delivered={any} held_now={d} released_early={d} released={d} maybe_verdicts={d}\n", .{ n.next_deliver, probe.delivered.items, n.hold.held_now.load(.acquire), n.hold.released_early.load(.acquire), n.hold.released.load(.acquire), probe.maybe_verdicts });
    try std.testing.expectEqualSlices(u64, &[_]u64{20}, probe.delivered.items);
    try std.testing.expectEqual(@as(u64, 21), n.next_deliver);
    try std.testing.expectEqual(@as(u64, 3), n.hold.released_early.load(.acquire)); // NOM(20), EXT(20) a, EXT(20) b
    try std.testing.expectEqual(@as(u64, 1), n.hold.released.load(.acquire)); // a's EXT(21), at the frontier
    try std.testing.expectEqual(@as(usize, 1), n.hold.held_now.load(.acquire)); // a's EXT(22)
    try std.testing.expectEqual(@as(u32, 1), probe.maybe_verdicts); // slot 20 only, judged against count 0
    try std.testing.expect(n.own_latest.get(20) == null); // mute on 20: harmless, the network finished it

    // b's EXT(21) / EXT(22): frontier slots, fed straight in → each
    // externalizes and delivers in turn, validated against the count just
    // applied → .valid → our own EXTERNALIZE reaches the wire.
    n.applyInput(try f.item(n, f.seed_b, 21, .{ .externalize = "21" }));
    try std.testing.expectEqualSlices(u64, &[_]u64{ 20, 21 }, probe.delivered.items);
    try std.testing.expectEqual(@as(u64, 22), n.next_deliver);
    n.applyInput(try f.item(n, f.seed_b, 22, .{ .externalize = "22" }));
    try std.testing.expectEqualSlices(u64, &[_]u64{ 20, 21, 22 }, probe.delivered.items);
    try std.testing.expectEqual(@as(u64, 23), n.next_deliver);
    try std.testing.expectEqual(@as(u64, 22), probe.count);
    try std.testing.expectEqual(@as(u32, 1), probe.maybe_verdicts); // still only slot 20
    try std.testing.expect(n.eng.slots.get(21).?.fully_validated);
    try std.testing.expect(n.eng.slots.get(22).?.fully_validated);
    try std.testing.expect(n.own_latest.get(21) != null);
    try std.testing.expect(n.own_latest.get(22) != null);
    try std.testing.expectEqual(@as(usize, 0), n.hold.held_now.load(.acquire));
    try std.testing.expectEqual(@as(u64, 0), n.hold.dropped_far.load(.acquire));
}

// Strangers never occupy the buffer (the S8b catch-up skeptic filled all
// 1024 entries from one connection with random keys): a signer outside the
// transitive quorum graph is fed to the engine, which `ignored`s it before
// any per-slot state, so nothing is held and no slot opens. Non-vacuity:
// dropping the `in_graph` arm of `admit` holds the stranger's statement
// (held_now 1, fed_out_of_graph 0).
test "hold gate: a signer outside the quorum graph is fed straight to the engine's relevance filter, never held" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var f = try GateFixture.init(gpa, io);
    defer f.deinit();
    const me = try crypto.publicKeyFromSeed(@splat(0x42));
    const n = try Node.create(gpa, io, .{
        .network = GateFixture.passphrase,
        .secret_seed = @splat(0x42),
        .quorum = Quorum.twoThirdsOf(&.{ me, try crypto.publicKeyFromSeed(f.seed_a), try crypto.publicKeyFromSeed(f.seed_b) }),
        .listen_port = 0,
        .data_dir = f.dataDir(),
        .diagnostic = &f.diag,
    });
    defer n.deinit();
    GateFixture.ownEngineThread(n);
    const stranger: [32]u8 = @splat(0x99);
    const stats_before = n.stats();
    n.applyInput(try f.item(n, stranger, 5, .{ .nominate = "x" }));
    n.applyInput(try f.item(n, stranger, 5, .{ .externalize = "x" }));
    try std.testing.expectEqual(@as(u64, 2), n.hold.fed_out_of_graph.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), n.hold.held_now.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), n.stats().live_slots);
    try std.testing.expectEqual(stats_before.live_slots, n.stats().live_slots);
    // A member's statement for the same slot is held as usual.
    n.applyInput(try f.item(n, f.seed_a, 5, .{ .nominate = "x" }));
    try std.testing.expectEqual(@as(usize, 1), n.hold.held_now.load(.acquire));
}
