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

const engine = core.engine;
const crypto = core.crypto;
const qset = core.qset;
const gen_slcp = core.gen.slcp;
const canonical = core.canonical;
const MessageBuilder = core.capnpc.message.MessageBuilder;

const log = std.log.scoped(.slcp_node);

/// GC window: keep 16 externalized slots answerable to laggards (§10).
const purge_window: u64 = 16;

pub const Error = error{
    NoIdentity,
    EngineFailed,
} || std.mem.Allocator.Error;

/// One externalized slot, delivered to the app. `value` is owned by the
/// caller after `waitExternalized` returns — free it with `node.allocator()`.
pub const Externalized = struct {
    slot: u64,
    value: []u8,
};

pub const Options = struct {
    /// Passphrase → networkId (domain separation).
    network: []const u8,
    /// Explicit identity (bytes-level). Provide EITHER (node_id + secret_seed)
    /// OR key_path, unless watcher.
    node_id: ?[32]u8 = null,
    secret_seed: ?[32]u8 = null,
    key_path: ?[]const u8 = null,
    /// Pre-built quorum set; the Node validates/normalizes then takes
    /// ownership (freed by deinit via the engine).
    quorum_set: qset.QuorumSetOwned,
    listen_port: u16,
    /// "host:port" strings to dial.
    peers: []const []const u8 = &.{},
    data_dir: []const u8,
    /// No key, ephemeral nodeId, never signs, never proposes (§11).
    watcher: bool = false,
    strict_canonical: bool = true,
    max_value_bytes: u32 = 4096,
    /// First slot to nominate proposals for (default 1).
    start_slot: u64 = 1,
    /// Application driver; null → the omakase default (§8.4).
    driver: ?core.driver.Driver = null,
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
const InputQueue = struct {
    gpa: std.mem.Allocator,
    mu: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    items: std.ArrayList(InputItem) = .empty,
    head: usize = 0,
    closed: bool = false,

    fn push(self: *InputQueue, item: InputItem) void {
        self.mu.lock();
        defer self.mu.unlock();
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
        self.cond.signal();
    }

    /// Block for the next item; null once closed and drained.
    fn pop(self: *InputQueue) ?InputItem {
        self.mu.lock();
        defer self.mu.unlock();
        while (self.head >= self.items.items.len and !self.closed) self.cond.wait(&self.mu);
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
        self.mu.lock();
        defer self.mu.unlock();
        self.closed = true;
        self.cond.broadcast();
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

    own_mu: std.Thread.Mutex = .{},
    own_latest: std.AutoHashMapUnmanaged(u64, SlotOwn) = .empty,

    prop_mu: std.Thread.Mutex = .{},
    current_slot: u64,
    last_ext_value: []u8, // owned; empty slice initially
    proposal_queue: std.ArrayList([]u8) = .empty,
    nominating: bool = false,

    ext_mu: std.Thread.Mutex = .{},
    ext_cond: std.Thread.Condition = .{},
    ext_queue: std.ArrayList(Externalized) = .empty,
    ext_closed: bool = false,

    pub fn allocator(self: *Node) std.mem.Allocator {
        return self.gpa;
    }

    // -------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------

    pub fn create(gpa: std.mem.Allocator, io: std.Io, options: Options) !*Node {
        var opts = options;

        // Resolve identity.
        var node_id: [32]u8 = undefined;
        var secret_seed: ?[32]u8 = null;
        if (opts.watcher) {
            const kp = try keys_mod.ephemeral(io);
            node_id = if (opts.node_id) |n| n else kp.public_key;
            secret_seed = null;
        } else if (opts.secret_seed) |seed| {
            secret_seed = seed;
            node_id = if (opts.node_id) |n| n else try crypto.publicKeyFromSeed(seed);
        } else if (opts.key_path) |path| {
            const kp = try keys_mod.loadOrCreate(io, path);
            node_id = kp.public_key;
            secret_seed = kp.seed;
        } else {
            return error.NoIdentity;
        }

        // Validate + normalize the quorum set, then derive its hash + framed
        // form (for getQset answering) BEFORE the engine takes ownership.
        try qset.validateAndNormalize(gpa, &opts.quorum_set);
        const flat = try qset.canonicalBytes(gpa, &opts.quorum_set);
        const local_hash = crypto.qsetHash(flat);
        gpa.free(flat);
        const framed_local = try ownedQsetToFramed(gpa, &opts.quorum_set);
        defer gpa.free(framed_local);

        // Engine config (takes ownership of quorum_set on success).
        var limits = core.limits.Limits{};
        limits.max_value_bytes = opts.max_value_bytes;
        const cfg = engine.Config{
            .network_id = crypto.networkIdFromPassphrase(opts.network),
            .node_id = node_id,
            .secret_seed = secret_seed,
            .quorum_set = opts.quorum_set,
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
            .q = .{ .gpa = gpa },
            .store = undefined,
            .wheel = undefined,
            .ov = undefined,
            .current_slot = opts.start_slot,
            .last_ext_value = &.{},
        };

        self.eng = try engine.Engine.init(gpa, cfg, drv);
        errdefer self.eng.deinit();

        self.store = try store_mod.Store.open(gpa, io, opts.data_dir);
        errdefer self.store.deinit();

        // Cache our own qset on disk so getQset can answer it after restart.
        self.store.putQset(local_hash, framed_local);

        self.wheel = timers_mod.Wheel.init(gpa, io, onTimerFire, self);
        self.ov = try overlay_mod.Overlay.init(gpa, io, .{
            .listen_port = opts.listen_port,
            .peers = opts.peers,
            .network_id_prefix = self.network_id[0..8].*,
            .node_id = node_id,
        }, .{
            .ctx = self,
            .on_recv = onRecv,
            .on_peer_up = onPeerUp,
        });

        // ---- Restart recovery (§10), synchronous, pre-threads ----
        try self.wheel.start(); // arms during restore are honored
        errdefer self.wheel.stop();

        var rec = try self.store.recover(gpa);
        defer store_mod.Store.deinitRecovery(gpa, &rec);

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
            self.eng = try engine.Engine.init(gpa, wcfg, drv);
            self.watcher = true;
        }

        if (!rec.own_log_corrupt) {
            for (rec.own_latest) |r| {
                self.applyInput(.{
                    .input = .{ .restore_own_envelope = .{ .bytes = try gpa.dupe(u8, r.envelope) } },
                    .source_peer = null,
                });
            }
        }
        // Resume proposal slot past the highest externalized slot on disk.
        if (rec.externalized_hwm) |hwm| {
            if (hwm + 1 > self.current_slot) self.current_slot = hwm + 1;
        }

        // ---- Go live ----
        try self.ov.start();
        errdefer self.ov.stop();

        self.live = true; // dispatch may now emit to the network
        self.engine_thread = try std.Thread.spawn(.{}, engineLoop, .{self});
        return self;
    }

    pub fn deinit(self: *Node) void {
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

        const gpa = self.gpa;
        self.* = undefined;
        gpa.destroy(self);
    }

    // -------------------------------------------------------------------
    // App surface
    // -------------------------------------------------------------------

    /// Queue `value` to be nominated for the next available slot (§11). Error
    /// in watcher mode.
    pub fn propose(self: *Node, value: []const u8) !void {
        if (self.watcher) return error.EngineFailed; // watchers never propose
        const copy = try self.gpa.dupe(u8, value);
        self.prop_mu.lock();
        self.proposal_queue.append(self.gpa, copy) catch |e| {
            self.gpa.free(copy);
            self.prop_mu.unlock();
            return e;
        };
        self.prop_mu.unlock();
        self.maybeStartNomination();
    }

    pub const WaitOptions = struct {
        /// null = block until the next externalization or shutdown.
        timeout_ms: ?u64 = null,
    };

    /// Block for the next externalized slot in order. Returns null on timeout
    /// or shutdown. The returned `value` is owned by the caller.
    pub fn waitExternalized(self: *Node, wopts: WaitOptions) ?Externalized {
        self.ext_mu.lock();
        defer self.ext_mu.unlock();
        while (self.ext_queue.items.len == 0 and !self.ext_closed) {
            if (wopts.timeout_ms) |ms| {
                self.ext_cond.timedWait(&self.ext_mu, ms * std.time.ns_per_ms) catch return null;
            } else {
                self.ext_cond.wait(&self.ext_mu);
            }
        }
        if (self.ext_queue.items.len == 0) return null;
        return self.ext_queue.orderedRemove(0);
    }

    pub fn stats(self: *Node) engine.Stats {
        // Read-only snapshot; safe enough for observability (racy counters).
        return self.eng.stats();
    }

    pub fn boundPort(self: *Node) u16 {
        return self.ov.boundPort();
    }

    // -------------------------------------------------------------------
    // Engine thread
    // -------------------------------------------------------------------

    fn engineLoop(self: *Node) void {
        while (self.q.pop()) |item| {
            self.applyInput(item);
        }
    }

    /// Feed one input and drain all its effects (engine thread only).
    fn applyInput(self: *Node, item_in: InputItem) void {
        var item = item_in;
        self.cur_source = item.source_peer;
        self.eng.pushInput(item.input) catch |err| {
            core.host_codec.freeInput(self.gpa, &item.input);
            self.markFailed(err);
            return;
        };
        core.host_codec.freeInput(self.gpa, &item.input);
        while (self.eng.popEffect()) |eff| {
            self.dispatch(eff);
            self.eng.commitEffect();
        }
        self.cur_source = null;
    }

    fn markFailed(self: *Node, err: anyerror) void {
        if (!self.failed.swap(true, .seq_cst)) {
            log.err("engine failed: {s} — node going inert", .{@errorName(err)});
        }
    }

    fn dispatch(self: *Node, eff: *const engine.Effect) void {
        switch (eff.*) {
            .persist_own_envelope => |sb| {
                self.store.appendOwn(sb.slot, sb.bytes) catch |e|
                    log.err("own.log append failed: {s}", .{@errorName(e)});
            },
            .broadcast_envelope => |sb| {
                // Always record as our latest for on-connect catch-up, even
                // during restore; only touch the network once live.
                self.recordOwnLatest(sb.slot, sb.bytes);
                if (self.live) self.ov.broadcast(.{ .envelope = sb.bytes });
            },
            .forward_envelope => |sb| {
                if (!self.live) return;
                if (self.cur_source) |src| {
                    self.ov.broadcastExcept(src, .{ .envelope = sb.bytes });
                } else {
                    self.ov.broadcast(.{ .envelope = sb.bytes });
                }
            },
            .arm_timer => |a| {
                self.wheel.arm(a.slot, @intFromEnum(a.timer), a.delay_ms) catch |e|
                    log.err("timer arm failed: {s}", .{@errorName(e)});
            },
            .cancel_timer => |c| self.wheel.cancel(c.slot, @intFromEnum(c.timer)),
            .request_qset => |r| {
                if (!self.live) return;
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
        self.store.appendExternalized(slot, value) catch |e|
            log.err("externalized.log append failed: {s}", .{@errorName(e)});

        // Deliver to the app.
        const app_copy = self.gpa.dupe(u8, value) catch {
            log.err("OOM delivering externalized slot {d}", .{slot});
            return;
        };
        self.ext_mu.lock();
        self.ext_queue.append(self.gpa, .{ .slot = slot, .value = app_copy }) catch {
            self.gpa.free(app_copy);
            self.ext_mu.unlock();
            log.err("OOM queueing externalized slot {d}", .{slot});
            return;
        };
        self.ext_cond.signal();
        self.ext_mu.unlock();

        // Advance proposal state.
        self.prop_mu.lock();
        if (self.last_ext_value.len > 0) self.gpa.free(self.last_ext_value);
        self.last_ext_value = self.gpa.dupe(u8, value) catch &.{};
        if (slot + 1 > self.current_slot) self.current_slot = slot + 1;
        self.nominating = false;
        self.prop_mu.unlock();
        self.maybeStartNomination();

        // GC (§10): keep a 16-slot answering window.
        if (slot >= purge_window) {
            const max_slot = slot - (purge_window - 1);
            self.pruneOwnLatest(max_slot);
            self.q.push(.{ .input = .{ .purge_slots = .{ .max_slot = max_slot } }, .source_peer = null });
        }
    }

    /// If idle and a proposal is queued, nominate the head for current_slot.
    fn maybeStartNomination(self: *Node) void {
        if (self.watcher) return;
        self.prop_mu.lock();
        if (self.nominating or self.proposal_queue.items.len == 0) {
            self.prop_mu.unlock();
            return;
        }
        const value = self.proposal_queue.orderedRemove(0);
        const slot = self.current_slot;
        const prev = self.gpa.dupe(u8, self.last_ext_value) catch {
            // put it back on OOM
            self.proposal_queue.insert(self.gpa, 0, value) catch self.gpa.free(value);
            self.prop_mu.unlock();
            return;
        };
        self.nominating = true;
        self.prop_mu.unlock();

        // value + prev are owned; the input carries them, freed after push.
        self.q.push(.{ .input = .{ .nominate = .{ .slot = slot, .value = value, .prev_value = prev } }, .source_peer = null });
    }

    // -------------------------------------------------------------------
    // own_latest (catch-up source)
    // -------------------------------------------------------------------

    fn recordOwnLatest(self: *Node, slot: u64, framed_env: []const u8) void {
        const bucket = envelopeBucket(self.gpa, framed_env) catch {
            log.warn("could not bucket own envelope for slot {d}", .{slot});
            return;
        };
        const copy = self.gpa.dupe(u8, framed_env) catch return;
        self.own_mu.lock();
        defer self.own_mu.unlock();
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
        self.own_mu.lock();
        defer self.own_mu.unlock();
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
        // Catch-up (§9.2): send our latest own envelopes, then ask for the
        // peer's externalized state.
        self.own_mu.lock();
        var it = self.own_latest.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.nom) |b| self.ov.send(peer_id, .{ .envelope = b });
            if (e.value_ptr.ballot) |b| self.ov.send(peer_id, .{ .envelope = b });
        }
        self.own_mu.unlock();
        self.ov.send(peer_id, .{ .get_slot_state = 0 });
    }

    fn enqueueEnvelope(self: *Node, framed_env: []const u8, source: usize) void {
        const copy = self.gpa.dupe(u8, framed_env) catch return;
        self.q.push(.{ .input = .{ .envelope_received = .{ .bytes = copy } }, .source_peer = source });
    }

    fn onQsetFrame(self: *Node, framed_qset: []const u8) void {
        // Persist for future getQset answers, then feed the engine.
        const h = qsetHashOfFramed(self.gpa, framed_qset) catch null;
        if (h) |hash| self.store.putQset(hash, framed_qset);
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

        self.own_mu.lock();
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
        self.own_mu.unlock();
    }

    // -------------------------------------------------------------------
    // Timer wheel callback (wheel thread)
    // -------------------------------------------------------------------

    fn onTimerFire(ctx: ?*anyopaque, slot: u64, timer_id: u16) void {
        const self: *Node = @ptrCast(@alignCast(ctx.?));
        const timer: engine.TimerId = @enumFromInt(@as(u8, @intCast(timer_id)));
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
