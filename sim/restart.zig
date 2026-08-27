//! Restart-safety harness (design §13.1 "restart safety", §10 restore
//! semantics). A focused multi-engine world — smaller and more surgical than
//! sim.Sim — that can DESTROY one node's engine.Engine mid-run and rebuild a
//! FRESH one from an in-memory capture of that node's persist_own_envelope
//! log (the bytes the host would fsync), then prove the restarted node never
//! contradicts its pre-crash self.
//!
//! The property (§13.1). Let `prev` be the target's latest OWN emitted
//! statement (from a broadcast_envelope frame — the engine broadcasts only
//! its own emissions; peer relays are forward_envelope) for a given
//! (slot, protocol) BEFORE the crash. Every OWN statement `new` the RESTARTED
//! node emits for that (slot, protocol) must satisfy:
//!
//!     bytesEqual(new, prev)  OR  stored.isNewerOwned(prev, new)
//!
//! i.e. it is either the §10 byte-identical rebroadcast carve-out, or it
//! strictly supersedes the pre-crash statement in that protocol's partial
//! order. A `new` that is neither (stale-vs-self, or an equivocation with the
//! node's own past) is a restart-safety violation → error.RestartSafetyViolated.
//! When no pre-crash statement exists for a (slot, protocol) the restarted
//! node touched, the emission is trivially safe (nothing to contradict).
//!
//! Restore effect discipline (§10, verified against pipeline.zig
//! handleRestore): a restore_own_envelope input emits broadcast_envelope
//! (the rebroadcast) but NEVER persist_own_envelope — the log entry is
//! already durable. The harness ASSERTS zero persists across the whole
//! replay (error.RestoreEmittedPersist otherwise) and counts the
//! rebroadcasts.
//!
//! Restore order (§10): the captured append-only own.log is COMPACTED to the
//! latest record per (slot, protocol) before replay, and replayed in
//! deterministic order (slot ascending, nomination before ballot) as
//! restore_own_envelope inputs BEFORE any post-restart network input.
//!
//! Catch-up: the crash is instantaneous (no downtime), so in-flight queued
//! deliveries still arrive at the fresh engine; but statements delivered to
//! the target BEFORE the crash are gone from its memory. On restart the
//! overlay re-syncs — modeled here (as sim.Sim's heal does, §13.6) by
//! reliably re-delivering every peer's latest own envelopes to the restarted
//! node — which lets it re-establish peer state and converge.

const std = @import("std");
const slcp = @import("slcp-core");
const sim = @import("sim.zig");
const invariants = @import("invariants.zig");

const engine = slcp.engine;
const crypto = slcp.crypto;
const qset = slcp.qset;
const canonical = slcp.canonical;
const driver = slcp.driver;
const stored = slcp.stored;

// ---------------------------------------------------------------------------
// Virtual-clock event queue (a trimmed sim.zig: latency only, no drops/parts)
// ---------------------------------------------------------------------------

const TimerId = engine.TimerId;

const EventKind = union(enum) {
    deliver: struct { to: u8, bytes: []u8 },
    timer: struct { node: u8, slot: u64, timer: TimerId, gen: u32, epoch: u32 },
    propose: struct { node: u8, slot: u64, value: []const u8, prev: []const u8 },
};

const Event = struct { at: u64, seq: u64, kind: EventKind };

fn eventLess(a: *const Event, b: *const Event) bool {
    if (a.at != b.at) return a.at < b.at;
    return a.seq < b.seq;
}

fn freeEvent(gpa: std.mem.Allocator, ev: *Event) void {
    switch (ev.kind) {
        .deliver => |d| gpa.free(d.bytes),
        else => {},
    }
}

const EventQueue = struct {
    items: std.ArrayList(Event) = .empty,

    fn deinit(self: *EventQueue, gpa: std.mem.Allocator) void {
        for (self.items.items) |*e| freeEvent(gpa, e);
        self.items.deinit(gpa);
    }

    fn push(self: *EventQueue, gpa: std.mem.Allocator, ev: Event) !void {
        try self.items.append(gpa, ev);
        var i = self.items.items.len - 1;
        while (i > 0) {
            const parent = (i - 1) / 2;
            if (!eventLess(&self.items.items[i], &self.items.items[parent])) break;
            std.mem.swap(Event, &self.items.items[i], &self.items.items[parent]);
            i = parent;
        }
    }

    fn pop(self: *EventQueue) ?Event {
        const n = self.items.items.len;
        if (n == 0) return null;
        const top = self.items.items[0];
        self.items.items[0] = self.items.items[n - 1];
        self.items.shrinkRetainingCapacity(n - 1);
        var i: usize = 0;
        const len = self.items.items.len;
        while (true) {
            const l = 2 * i + 1;
            const r = 2 * i + 2;
            var smallest = i;
            if (l < len and eventLess(&self.items.items[l], &self.items.items[smallest])) smallest = l;
            if (r < len and eventLess(&self.items.items[r], &self.items.items[smallest])) smallest = r;
            if (smallest == i) break;
            std.mem.swap(Event, &self.items.items[i], &self.items.items[smallest]);
            i = smallest;
        }
        return top;
    }

    fn isEmpty(self: *const EventQueue) bool {
        return self.items.items.len == 0;
    }
};

// ---------------------------------------------------------------------------
// Per-node state
// ---------------------------------------------------------------------------

const TimerKey = struct { slot: u64, timer: TimerId };

/// Latest own envelope frame per protocol (for overlay catch-up on restart).
const OwnLatest = struct {
    nom: ?[]u8 = null,
    ballot: ?[]u8 = null,

    fn set(self: *OwnLatest, gpa: std.mem.Allocator, is_nom: bool, bytes: []const u8) !void {
        const slot_ptr = if (is_nom) &self.nom else &self.ballot;
        if (slot_ptr.*) |old| gpa.free(old);
        slot_ptr.* = try gpa.dupe(u8, bytes);
    }

    fn deinit(self: *OwnLatest, gpa: std.mem.Allocator) void {
        if (self.nom) |b| gpa.free(b);
        if (self.ballot) |b| gpa.free(b);
        self.* = undefined;
    }
};

const Node = struct {
    eng: engine.Engine,
    seed: [32]u8,
    node_id: [32]u8,
    epoch: u32 = 0,
    timer_gen: std.AutoHashMapUnmanaged(TimerKey, u32) = .empty,
    externalized: std.AutoArrayHashMapUnmanaged(u64, []u8) = .empty,
    /// The captured on-disk own.log: every persist_own_envelope payload, in
    /// emission order (append-only, survives the crash — the whole point).
    own_log: std.ArrayList([]u8) = .empty,
    own_latest: OwnLatest = .{},

    fn deinit(self: *Node, gpa: std.mem.Allocator) void {
        self.eng.deinit();
        self.timer_gen.deinit(gpa);
        for (self.externalized.values()) |v| gpa.free(v);
        self.externalized.deinit(gpa);
        for (self.own_log.items) |f| gpa.free(f);
        self.own_log.deinit(gpa);
        self.own_latest.deinit(gpa);
    }
};

// ---------------------------------------------------------------------------
// Crash schedule
// ---------------------------------------------------------------------------

pub const CrashTrigger = enum {
    /// Restart with an EMPTY own.log (crash before the node emits anything).
    empty_log,
    /// Crash after the first own nomination, before any ballot statement.
    mid_nomination,
    /// Crash after the first own PREPARE, before CONFIRM.
    mid_ballot_prepare,
    /// Crash after the node has externalized (restore must not un-externalize).
    after_externalize,
    /// Crash after a seed-chosen number of target inputs (matrix fuzzing).
    random,
};

pub const Options = struct {
    seed: u64,
    n: u8 = 4,
    target: u8 = 0,
    trigger: CrashTrigger,
};

pub const Report = struct {
    crashed: bool = false,
    records_replayed: usize = 0,
    restore_persist_count: usize = 0,
    restore_broadcast_count: usize = 0,
    target_externalized: bool = false,
    all_externalized: bool = false,
    agreed: bool = false,
};

pub const RestartError = error{
    RestartSafetyViolated,
    RestoreEmittedPersist,
    OwnEnvelopeDecodeFailed,
    EventBudgetExceeded,
} || engine.EngineError;

const ProtoKey = struct { slot: u64, is_nom: bool };

const prev_value = "genesis";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

pub const Harness = struct {
    gpa: std.mem.Allocator,
    n: u8,
    target: u8,
    trigger: CrashTrigger,
    prng: std.Random.DefaultPrng,
    queue: EventQueue = .{},
    seq: u64 = 0,
    now: u64 = 0,
    nodes: []Node,

    /// Shared flat ceil(2n/3)-of-n qset, kept owned so a fresh engine can be
    /// cloned from it on restart.
    shared: qset.QuorumSetOwned,
    shared_framed: []u8,
    shared_hash: [32]u8,
    network_id: [32]u8,

    // -- crash / property state ---------------------------------------------
    restarted: bool = false,
    crash_done: bool = false,
    target_input_count: u64 = 0,
    crash_after: u64 = 0, // for .random
    /// Target's pre-crash latest own emission per (slot, protocol), frozen at
    /// the crash. Post-restart emissions are checked against these.
    pre_crash: std.AutoArrayHashMapUnmanaged(ProtoKey, []u8) = .empty,

    report: Report = .{},

    const max_events: u64 = 2_000_000;
    const bound_ms: u64 = 240_000;

    pub fn init(gpa: std.mem.Allocator, opts: Options) !Harness {
        std.debug.assert(opts.n >= 3 and opts.n <= sim.max_nodes);
        std.debug.assert(opts.target < opts.n);

        var seeds: [sim.max_nodes][32]u8 = undefined;
        var pks: [sim.max_nodes][32]u8 = undefined;
        for (0..opts.n) |i| {
            seeds[i] = sim.nodeSeed(@intCast(i));
            pks[i] = try crypto.publicKeyFromSeed(seeds[i]);
        }

        var shared = blk: {
            const vals = try gpa.dupe([32]u8, pks[0..opts.n]);
            errdefer gpa.free(vals);
            break :blk qset.QuorumSetOwned{
                .threshold = sim.thresholdFor(opts.n),
                .validators = vals,
                .inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0),
            };
        };
        errdefer shared.deinit(gpa);
        try qset.validateAndNormalize(gpa, &shared);
        const shared_flat = try qset.canonicalBytes(gpa, &shared);
        defer gpa.free(shared_flat);
        const shared_hash = crypto.qsetHash(shared_flat);
        const shared_framed = try canonical.frameFlat(gpa, shared_flat);
        errdefer gpa.free(shared_framed);

        const network_id = crypto.networkIdFromPassphrase(sim.sim_passphrase);

        const nodes = try gpa.alloc(Node, opts.n);
        var made: usize = 0;
        errdefer {
            for (nodes[0..made]) |*node| node.deinit(gpa);
            gpa.free(nodes);
        }
        for (0..opts.n) |i| {
            nodes[i] = .{
                .eng = try engine.Engine.init(gpa, .{
                    .network_id = network_id,
                    .node_id = pks[i],
                    .secret_seed = seeds[i],
                    .quorum_set = try qset.clone(gpa, &shared),
                }, driver.Driver.default()),
                .seed = seeds[i],
                .node_id = pks[i],
            };
            made += 1;
        }

        var self = Harness{
            .gpa = gpa,
            .n = opts.n,
            .target = opts.target,
            .trigger = opts.trigger,
            .prng = std.Random.DefaultPrng.init(opts.seed),
            .nodes = nodes,
            .shared = shared,
            .shared_framed = shared_framed,
            .shared_hash = shared_hash,
            .network_id = network_id,
        };
        // For the fuzzing matrix, pick a crash point among the target's
        // inputs (0 == before anything ⇒ empty-ish log; large ⇒ may crash
        // post-externalize or never).
        if (opts.trigger == .random) self.crash_after = self.prng.random().uintAtMost(u64, 18);

        // Every node proposes its own value for slot 1 at t=0 (nomination race).
        for (0..opts.n) |i| {
            self.pushEvent(0, .{ .propose = .{
                .node = @intCast(i),
                .slot = 1,
                .value = proposal_values[i],
                .prev = prev_value,
            } }) catch |e| {
                self.deinit();
                return e;
            };
        }
        return self;
    }

    pub fn deinit(self: *Harness) void {
        const gpa = self.gpa;
        for (self.nodes) |*node| node.deinit(gpa);
        gpa.free(self.nodes);
        self.queue.deinit(gpa);
        for (self.pre_crash.values()) |v| gpa.free(v);
        self.pre_crash.deinit(gpa);
        self.shared.deinit(gpa);
        gpa.free(self.shared_framed);
        self.* = undefined;
    }

    // -- queue helpers ------------------------------------------------------

    fn pushEvent(self: *Harness, at: u64, kind: EventKind) !void {
        self.seq += 1;
        try self.queue.push(self.gpa, .{ .at = at, .seq = self.seq, .kind = kind });
    }

    fn rollLatency(self: *Harness) u64 {
        return 10 + self.prng.random().uintAtMost(u64, 90);
    }

    fn broadcast(self: *Harness, from: u8, bytes: []const u8) !void {
        for (0..self.n) |j| {
            if (j == from) continue;
            const copy = try self.gpa.dupe(u8, bytes);
            errdefer self.gpa.free(copy);
            try self.pushEvent(self.now + self.rollLatency(), .{ .deliver = .{ .to = @intCast(j), .bytes = copy } });
        }
    }

    fn deliverTo(self: *Harness, to: u8, bytes: []const u8) !void {
        const copy = try self.gpa.dupe(u8, bytes);
        errdefer self.gpa.free(copy);
        try self.pushEvent(self.now + self.rollLatency(), .{ .deliver = .{ .to = to, .bytes = copy } });
    }

    // -- decode helper ------------------------------------------------------

    fn decode(self: *Harness, frame: []const u8) RestartError!stored.OwnedStatement {
        return invariants.decodeOwnEnvelope(self.gpa, frame) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.OwnEnvelopeDecodeFailed,
        };
    }

    // -- input + effect drain ----------------------------------------------

    fn feed(self: *Harness, idx: u8, input: engine.Input, restore_mode: bool) RestartError!void {
        try self.nodes[idx].eng.pushInput(input);
        var want_qset = false;
        try self.drain(idx, restore_mode, &want_qset);
        if (want_qset) {
            // Answer request_qset after the drain (one-input-then-drain-all).
            try self.feed(idx, .{ .qset_received = .{ .bytes = self.shared_framed } }, false);
        }
    }

    fn drain(self: *Harness, idx: u8, restore_mode: bool, want_qset: *bool) RestartError!void {
        const gpa = self.gpa;
        const node = &self.nodes[idx];
        while (node.eng.popEffect()) |eff| {
            switch (eff.*) {
                .persist_own_envelope => |sb| {
                    // §10 restore effect discipline: a restore MUST NOT persist.
                    if (restore_mode) {
                        self.report.restore_persist_count += 1;
                        return error.RestoreEmittedPersist;
                    }
                    const frame = try gpa.dupe(u8, sb.bytes);
                    errdefer gpa.free(frame);
                    try node.own_log.append(gpa, frame);
                    var st = try self.decode(sb.bytes);
                    defer st.deinit(gpa);
                    try node.own_latest.set(gpa, st.isNomination(), sb.bytes);
                },
                .broadcast_envelope => |sb| {
                    if (restore_mode) self.report.restore_broadcast_count += 1;
                    // broadcast_envelope == this node's OWN statement (peer
                    // relays are forward_envelope). Property check for target.
                    if (idx == self.target) try self.onTargetEmission(sb.bytes);
                    try self.broadcast(idx, sb.bytes);
                },
                .forward_envelope => |sb| try self.broadcast(idx, sb.bytes),
                .arm_timer => |t| {
                    const gop = try node.timer_gen.getOrPut(gpa, .{ .slot = t.slot, .timer = t.timer });
                    if (!gop.found_existing) gop.value_ptr.* = 0;
                    gop.value_ptr.* +%= 1;
                    try self.pushEvent(self.now + t.delay_ms, .{ .timer = .{
                        .node = idx,
                        .slot = t.slot,
                        .timer = t.timer,
                        .gen = gop.value_ptr.*,
                        .epoch = node.epoch,
                    } });
                },
                .cancel_timer => |t| {
                    const gop = try node.timer_gen.getOrPut(gpa, .{ .slot = t.slot, .timer = t.timer });
                    if (!gop.found_existing) gop.value_ptr.* = 0;
                    gop.value_ptr.* +%= 1;
                },
                .request_qset => want_qset.* = true,
                .externalized => |sb| {
                    const gop = try node.externalized.getOrPut(gpa, sb.slot);
                    if (!gop.found_existing) gop.value_ptr.* = try gpa.dupe(u8, sb.bytes);
                },
                .input_status, .phase_event => {},
            }
            node.eng.commitEffect();
        }
    }

    /// Record (pre-crash) or check (post-restart) one target OWN emission.
    fn onTargetEmission(self: *Harness, frame: []const u8) RestartError!void {
        const gpa = self.gpa;
        var st = try self.decode(frame);
        defer st.deinit(gpa);
        const key = ProtoKey{ .slot = st.slot, .is_nom = st.isNomination() };

        if (!self.restarted) {
            // Pre-crash: remember the latest own emission for this (slot, proto).
            const gop = try self.pre_crash.getOrPut(gpa, key);
            if (gop.found_existing) gpa.free(gop.value_ptr.*);
            gop.value_ptr.* = try gpa.dupe(u8, frame);
            return;
        }

        // Post-restart: the §13.1 restart-safety predicate.
        const prev = self.pre_crash.get(key) orelse return; // nothing to contradict
        if (std.mem.eql(u8, prev, frame)) return; // §10 byte-identical rebroadcast carve-out
        var prev_st = try self.decode(prev);
        defer prev_st.deinit(gpa);
        if (!stored.isNewerOwned(&prev_st, &st)) return error.RestartSafetyViolated;
    }

    // -- crash / restart ----------------------------------------------------

    fn triggerFires(self: *Harness) RestartError!bool {
        const node = &self.nodes[self.target];
        return switch (self.trigger) {
            .empty_log => true, // fire at the first opportunity (log still empty)
            .mid_nomination => node.own_latest.nom != null and node.own_latest.ballot == null,
            .mid_ballot_prepare => blk: {
                const f = node.own_latest.ballot orelse break :blk false;
                if (node.externalized.count() != 0) break :blk false;
                var st = try self.decode(f);
                defer st.deinit(self.gpa);
                break :blk st.pledges == .prepare;
            },
            .after_externalize => node.externalized.count() != 0,
            .random => self.target_input_count >= self.crash_after,
        };
    }

    fn maybeCrash(self: *Harness) !void {
        if (self.crash_done) return;
        if (try self.triggerFires()) try self.crashRestart();
    }

    /// The scripted crash: capture + compact the own.log, DESTROY the engine,
    /// build a FRESH one with identical config, replay the compacted log as
    /// restore inputs, then re-sync peer state (overlay catch-up).
    fn crashRestart(self: *Harness) !void {
        const gpa = self.gpa;
        const node = &self.nodes[self.target];
        self.crash_done = true;
        self.report.crashed = true;

        // (1)+(3 order) Compact own.log → latest record per (slot, protocol),
        // deterministic order (slot asc, nomination before ballot). The slices
        // point into node.own_log, which survives the crash.
        var records: std.ArrayList([]const u8) = .empty;
        defer records.deinit(gpa);
        try self.compactLog(node, &records);

        // (2) DESTROY the engine; invalidate its queued timers via a new epoch.
        node.eng.deinit();
        node.epoch += 1;
        node.timer_gen.clearRetainingCapacity();

        // Build a FRESH engine with identical config.
        node.eng = try engine.Engine.init(gpa, .{
            .network_id = self.network_id,
            .node_id = node.node_id,
            .secret_seed = node.seed,
            .quorum_set = try qset.clone(gpa, &self.shared),
        }, driver.Driver.default());

        // From here, target emissions are CHECKED against the pre-crash latest.
        self.restarted = true;
        self.report.records_replayed = records.items.len;

        // (3) Replay the compacted own.log as restore_own_envelope inputs,
        // BEFORE any post-restart network input.
        for (records.items) |frame| {
            try self.feed(self.target, .{ .restore_own_envelope = .{ .bytes = frame } }, true);
        }

        // Overlay catch-up: re-deliver every peer's latest own envelopes to
        // the restarted node so it can re-establish peer state (§13.6).
        for (0..self.n) |j| {
            if (j == self.target) continue;
            const ol = &self.nodes[j].own_latest;
            if (ol.nom) |f| try self.deliverTo(self.target, f);
            if (ol.ballot) |f| try self.deliverTo(self.target, f);
        }
    }

    /// Keep the last own.log record for each (slot, protocol); append the kept
    /// slices to `out` sorted by (slot asc, nomination first).
    fn compactLog(self: *Harness, node: *Node, out: *std.ArrayList([]const u8)) RestartError!void {
        const gpa = self.gpa;
        var latest: std.AutoArrayHashMapUnmanaged(ProtoKey, []const u8) = .empty;
        defer latest.deinit(gpa);
        for (node.own_log.items) |frame| {
            var st = try self.decode(frame);
            defer st.deinit(gpa);
            try latest.put(gpa, .{ .slot = st.slot, .is_nom = st.isNomination() }, frame);
        }
        // Deterministic replay order: slot ascending, nomination before ballot.
        const Ctx = struct {
            keys: []ProtoKey,
            pub fn lessThan(c: @This(), a: usize, b: usize) bool {
                const ka = c.keys[a];
                const kb = c.keys[b];
                if (ka.slot != kb.slot) return ka.slot < kb.slot;
                return ka.is_nom and !kb.is_nom; // nomination first
            }
        };
        latest.sortUnstable(Ctx{ .keys = latest.keys() });
        for (latest.values()) |frame| try out.append(gpa, frame);
    }

    // -- run ----------------------------------------------------------------

    fn allExternalized(self: *const Harness) bool {
        for (self.nodes) |*node| {
            if (!node.externalized.contains(1)) return false;
        }
        return true;
    }

    pub fn run(self: *Harness) !void {
        var events: u64 = 0;
        try self.maybeCrash(); // handles .empty_log at t=0
        while (!self.queue.isEmpty()) {
            if (self.allExternalized()) break;
            if (events >= max_events) return error.EventBudgetExceeded;
            const ev = self.queue.pop().?;
            events += 1;
            std.debug.assert(ev.at >= self.now);
            self.now = ev.at;
            switch (ev.kind) {
                .deliver => |d| {
                    defer self.gpa.free(d.bytes);
                    try self.feed(d.to, .{ .envelope_received = .{ .bytes = d.bytes } }, false);
                    if (d.to == self.target) {
                        self.target_input_count += 1;
                        try self.maybeCrash();
                    }
                },
                .timer => |t| {
                    const node = &self.nodes[t.node];
                    if (t.epoch != node.epoch) continue; // pre-crash timer: dropped
                    const cur = node.timer_gen.get(.{ .slot = t.slot, .timer = t.timer }) orelse 0;
                    if (cur != t.gen) continue; // re-armed / canceled: stale
                    try self.feed(t.node, .{ .timer_fired = .{ .slot = t.slot, .timer = t.timer } }, false);
                    if (t.node == self.target) {
                        self.target_input_count += 1;
                        try self.maybeCrash();
                    }
                },
                .propose => |p| {
                    try self.feed(p.node, .{ .nominate = .{
                        .slot = p.slot,
                        .value = p.value,
                        .prev_value = p.prev,
                    } }, false);
                    if (p.node == self.target) {
                        self.target_input_count += 1;
                        try self.maybeCrash();
                    }
                },
            }
        }

        // Finalize the report.
        self.report.all_externalized = self.allExternalized();
        self.report.target_externalized = self.nodes[self.target].externalized.contains(1);
        self.report.agreed = self.checkAgreement();
    }

    /// No two nodes externalized different values for slot 1.
    fn checkAgreement(self: *const Harness) bool {
        var first: ?[]const u8 = null;
        for (self.nodes) |*node| {
            const v = node.externalized.get(1) orelse continue;
            if (first) |f| {
                if (!std.mem.eql(u8, f, v)) return false;
            } else first = v;
        }
        return true;
    }
};

/// Deterministic per-node proposal values (distinct ⇒ a real nomination race).
const proposal_values = [sim.max_nodes][]const u8{
    "restart-alpha",
    "restart-bravo",
    "restart-charlie",
    "restart-delta",
    "restart-echo",
    "restart-foxtrot",
    "restart-golf",
};

/// Run one restart-safety scenario end to end. The property + restore
/// discipline are asserted INLINE (errors); this returns the observed report.
pub fn runScenario(gpa: std.mem.Allocator, opts: Options) !Report {
    var h = try Harness.init(gpa, opts);
    defer h.deinit();
    try h.run();
    return h.report;
}

// ---------------------------------------------------------------------------
// Tests (design §13.1) — std.testing.allocator, leak-checked.
// ---------------------------------------------------------------------------

const testing = std.testing;

test "restart safety: crash-and-restart mid-nomination" {
    const gpa = testing.allocator;
    const r = try runScenario(gpa, .{ .seed = 7, .n = 4, .target = 0, .trigger = .mid_nomination });
    try testing.expect(r.crashed);
    try testing.expectEqual(@as(usize, 0), r.restore_persist_count); // §10: restore never persists
    try testing.expect(r.restore_broadcast_count > 0); // it DOES rebroadcast
    try testing.expect(r.all_externalized);
    try testing.expect(r.target_externalized);
    try testing.expect(r.agreed);
}

test "restart safety: crash mid-ballot (PREPARE emitted, before CONFIRM)" {
    const gpa = testing.allocator;
    const r = try runScenario(gpa, .{ .seed = 3, .n = 4, .target = 1, .trigger = .mid_ballot_prepare });
    try testing.expect(r.crashed);
    try testing.expectEqual(@as(usize, 0), r.restore_persist_count);
    try testing.expect(r.restore_broadcast_count > 0);
    try testing.expect(r.all_externalized);
    try testing.expect(r.target_externalized);
    try testing.expect(r.agreed);
}

test "restart safety: crash after externalize (restore must not un-externalize)" {
    const gpa = testing.allocator;
    const r = try runScenario(gpa, .{ .seed = 5, .n = 4, .target = 2, .trigger = .after_externalize });
    try testing.expect(r.crashed);
    try testing.expectEqual(@as(usize, 0), r.restore_persist_count);
    // The target had externalized before the crash; the restart must preserve
    // that (the durable record is kept) and it must still agree.
    try testing.expect(r.target_externalized);
    try testing.expect(r.all_externalized);
    try testing.expect(r.agreed);
    try testing.expect(r.records_replayed > 0); // externalize (+ nomination) replayed
}

test "restart safety: crash with EMPTY own.log (fresh node, trivially safe)" {
    const gpa = testing.allocator;
    const r = try runScenario(gpa, .{ .seed = 11, .n = 4, .target = 3, .trigger = .empty_log });
    try testing.expect(r.crashed);
    try testing.expectEqual(@as(usize, 0), r.records_replayed); // nothing to restore
    try testing.expectEqual(@as(usize, 0), r.restore_persist_count);
    try testing.expectEqual(@as(usize, 0), r.restore_broadcast_count);
    // A fresh node with nothing to contradict still converges and agrees.
    try testing.expect(r.all_externalized);
    try testing.expect(r.target_externalized);
    try testing.expect(r.agreed);
}

test "restart safety: seed matrix (seeds 1..30, random crash timing)" {
    const gpa = testing.allocator;
    var crashed_any = false;
    var replayed_any = false;
    var seed: u64 = 1;
    while (seed <= 30) : (seed += 1) {
        // Rotate the target across nodes for extra coverage.
        const target: u8 = @intCast(seed % 4);
        const r = try runScenario(gpa, .{ .seed = seed, .n = 4, .target = target, .trigger = .random });
        // The property + restore discipline held (else runScenario errored).
        try testing.expectEqual(@as(usize, 0), r.restore_persist_count);
        // Healthy n=4 (threshold 3): a single node's instantaneous restart
        // never blocks the quorum — everyone still externalizes and agrees.
        try testing.expect(r.all_externalized);
        try testing.expect(r.agreed);
        if (r.crashed) crashed_any = true;
        if (r.records_replayed > 0) replayed_any = true;
    }
    // The matrix must actually exercise crash + non-empty restore paths.
    try testing.expect(crashed_any);
    try testing.expect(replayed_any);
}
