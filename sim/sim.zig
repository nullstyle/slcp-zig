//! Deterministic multi-engine simulator (design §13.1) — the
//! generalization of tests/engine_e2e_test.zig: N engines in one process, a
//! VIRTUAL CLOCK (arm_timer effects → a deterministic priority queue), and a
//! SEEDED PRNG NETWORK (per-message latency, drops, duplication, reordering
//! via per-message deliver-at times, partitions with scripted heal times).
//!
//! Every run is (seed, config) → per-node traces, fully replayable: a
//! failing run prints a one-line repro (`zig build sim -- --seed=N
//! --nodes=N --scenario=name`). No real time, no global RNG — determinism
//! is the whole point.
//!
//! Structural invariants (sim/invariants.zig) are checked after EVERY input
//! on every engine; per-run properties (agreement / validity / liveness)
//! are exposed as check* methods for the scenario tests.
//!
//! Partition model: a single adjacency cut (side_a bitmask vs the rest)
//! active on [start_ms, heal_ms). Messages are dropped when the link is
//! down at SEND or DELIVERY time. At heal, the network re-delivers each
//! node's latest own envelopes across the healed cut — modeling the
//! overlay's reconnect state-sync (SCP itself never retransmits; the host
//! overlay does, §13.6) — which is what lets laggards catch up via the
//! EXTERNALIZE-∞ path.

const std = @import("std");
const slcp = @import("slcp-core");
pub const invariants = @import("invariants.zig");

const engine = slcp.engine;
const crypto = slcp.crypto;
const qset = slcp.qset;
const canonical = slcp.canonical;
const driver = slcp.driver;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

pub const LatencyRange = struct { min_ms: u32 = 10, max_ms: u32 = 100 };

pub const Partition = struct {
    /// Bitmask over node indices: side A; side B is the complement.
    side_a: u8,
    start_ms: u64 = 0,
    heal_ms: u64,
};

pub const Proposal = struct {
    node: u8,
    slot: u64 = 1,
    at_ms: u64 = 0,
    value: []const u8,
    prev_value: []const u8 = "genesis",
};

pub const SimConfig = struct {
    seed: u64,
    n: u8, // 3..7
    name: []const u8 = "custom", // scenario name for the repro line
    latency: LatencyRange = .{},
    drop_rate: f32 = 0,
    dup_rate: f32 = 0,
    partitions: []const Partition = &.{},
    proposals: []const Proposal,
};

pub const max_nodes: u8 = 7;

/// The sim's fixed network passphrase and per-node seed scheme, exposed so
/// the Byzantine harness (which builds mixed honest+adversary quorums) can
/// mint envelopes the honest engines accept. node i's seed is 0x10 + i.
pub const sim_passphrase = "slcp-sim v1";
pub fn nodeSeed(i: u8) [32]u8 {
    return @splat(@as(u8, 0x10) + i);
}

/// Shared flat qset threshold: ceil(2n/3) = (2n+2)/3.
pub fn thresholdFor(n: u8) u32 {
    return (2 * @as(u32, n) + 2) / 3;
}

// ---------------------------------------------------------------------------
// Event queue (virtual clock)
// ---------------------------------------------------------------------------

const EventKind = union(enum) {
    deliver: struct { from: u8, to: u8, bytes: []u8 },
    timer: struct { node: u8, slot: u64, timer: engine.TimerId, gen: u32 },
    propose: Proposal,
    heal: u8, // index into cfg.partitions
};

const Event = struct {
    at: u64,
    seq: u64, // insertion order — the deterministic tiebreak
    kind: EventKind,
};

fn eventLess(a: *const Event, b: *const Event) bool {
    if (a.at != b.at) return a.at < b.at;
    return a.seq < b.seq;
}

/// Minimal binary min-heap (std.PriorityQueue API churn avoidance).
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

    fn peek(self: *const EventQueue) ?*const Event {
        if (self.items.items.len == 0) return null;
        return &self.items.items[0];
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
};

fn freeEvent(gpa: std.mem.Allocator, ev: *Event) void {
    switch (ev.kind) {
        .deliver => |d| gpa.free(d.bytes),
        else => {},
    }
}

// ---------------------------------------------------------------------------
// Per-node state
// ---------------------------------------------------------------------------

const TimerKey = struct { slot: u64, timer: engine.TimerId };

/// Latest own envelope frames per slot (for heal-time state resync).
const OwnLatest = struct { nom: ?[]u8 = null, ballot: ?[]u8 = null };

const Node = struct {
    eng: engine.Engine,
    tracker: invariants.Tracker = .{},
    timer_gen: std.AutoHashMapUnmanaged(TimerKey, u32) = .empty,
    externalized: std.AutoArrayHashMapUnmanaged(u64, []u8) = .empty,
    own_latest: std.AutoArrayHashMapUnmanaged(u64, OwnLatest) = .empty,

    fn deinit(self: *Node, gpa: std.mem.Allocator) void {
        self.eng.deinit();
        self.tracker.deinit(gpa);
        self.timer_gen.deinit(gpa);
        for (self.externalized.values()) |v| gpa.free(v);
        self.externalized.deinit(gpa);
        for (self.own_latest.values()) |*ol| {
            if (ol.nom) |b| gpa.free(b);
            if (ol.ballot) |b| gpa.free(b);
        }
        self.own_latest.deinit(gpa);
    }
};

// ---------------------------------------------------------------------------
// Event log (determinism proof) + run result
// ---------------------------------------------------------------------------

pub const InputKind = enum(u8) { envelope = 0, timer = 1, nominate = 2, qset = 3 };

pub const LogEntry = struct { at: u64, node: u8, kind: InputKind };

pub const Counts = struct {
    inputs: u64 = 0,
    effects: u64 = 0,
    sent: u64 = 0,
    delivered: u64 = 0,
    dropped_partition: u64 = 0,
    dropped_random: u64 = 0,
    duplicated: u64 = 0,
    timer_fires: u64 = 0,
};

pub const RunResult = struct {
    /// True when not every node externalized every proposed slot by the
    /// bound. Halting can be CORRECT (majority-less partition side).
    stalled: bool,
    events_processed: u64,
    virtual_now_ms: u64,
    counts: Counts,
};

pub const SimError = error{ InvariantViolation, EventBudgetExceeded, OutOfMemory } || engine.EngineError;

// ---------------------------------------------------------------------------
// Sim
// ---------------------------------------------------------------------------

pub const Sim = struct {
    gpa: std.mem.Allocator,
    cfg: SimConfig,
    nodes: []Node,
    queue: EventQueue = .{},
    seq: u64 = 0,
    prng: std.Random.DefaultPrng,
    now: u64 = 0,
    events_processed: u64 = 0,
    counts: Counts = .{},
    log: std.ArrayList(LogEntry) = .empty,
    shared_framed: []u8,
    shared_hash: [32]u8,
    /// Set on invariant/property failure; the repro line has been printed.
    violation: ?invariants.Violation = null,
    violation_node: u8 = 0,
    /// One-shot flag per partition: resync already injected.
    healed: [8]bool = @splat(false),
    /// Hard budget so a runaway scenario cannot loop forever.
    max_events: u64 = 4_000_000,
    /// Debug tracing (repro tool only; never set by tests).
    trace: bool = false,

    pub fn init(gpa: std.mem.Allocator, cfg: SimConfig) !Sim {
        std.debug.assert(cfg.n >= 3 and cfg.n <= max_nodes);

        var seeds: [max_nodes][32]u8 = undefined;
        var pks: [max_nodes][32]u8 = undefined;
        for (0..cfg.n) |i| {
            seeds[i] = nodeSeed(@intCast(i));
            pks[i] = try crypto.publicKeyFromSeed(seeds[i]);
        }

        // Shared flat ceil(2n/3)-of-n qset.
        var shared = blk: {
            const vals = try gpa.dupe([32]u8, pks[0..cfg.n]);
            errdefer gpa.free(vals);
            break :blk qset.QuorumSetOwned{
                .threshold = thresholdFor(cfg.n),
                .validators = vals,
                .inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0),
            };
        };
        defer shared.deinit(gpa);
        try qset.validateAndNormalize(gpa, &shared);
        const shared_flat = try qset.canonicalBytes(gpa, &shared);
        defer gpa.free(shared_flat);
        const shared_hash = crypto.qsetHash(shared_flat);
        const shared_framed = try canonical.frameFlat(gpa, shared_flat);
        errdefer gpa.free(shared_framed);

        const network_id = crypto.networkIdFromPassphrase(sim_passphrase);

        const nodes = try gpa.alloc(Node, cfg.n);
        var made: usize = 0;
        errdefer {
            for (nodes[0..made]) |*node| node.deinit(gpa);
            gpa.free(nodes);
        }
        for (0..cfg.n) |i| {
            nodes[i] = .{ .eng = try engine.Engine.init(gpa, .{
                .network_id = network_id,
                .node_id = pks[i],
                .secret_seed = seeds[i],
                .quorum_set = try qset.clone(gpa, &shared),
            }, driver.Driver.default()) };
            made += 1;
        }

        var self = Sim{
            .gpa = gpa,
            .cfg = cfg,
            .nodes = nodes,
            .prng = std.Random.DefaultPrng.init(cfg.seed),
            .shared_framed = shared_framed,
            .shared_hash = shared_hash,
        };
        errdefer {
            self.queue.deinit(gpa);
            self.log.deinit(gpa);
        }

        // Scripted proposer schedule → propose events.
        for (cfg.proposals) |p| {
            std.debug.assert(p.node < cfg.n);
            try self.pushEvent(p.at_ms, .{ .propose = p });
        }
        // Partition heal events (state-resync injection points).
        std.debug.assert(cfg.partitions.len <= self.healed.len);
        for (cfg.partitions, 0..) |p, i| {
            try self.pushEvent(p.heal_ms, .{ .heal = @intCast(i) });
        }
        return self;
    }

    pub fn deinit(self: *Sim) void {
        const gpa = self.gpa;
        for (self.nodes) |*node| node.deinit(gpa);
        gpa.free(self.nodes);
        self.queue.deinit(gpa);
        self.log.deinit(gpa);
        gpa.free(self.shared_framed);
        self.* = undefined;
    }

    // -- repro / failure -----------------------------------------------------

    fn fail(self: *Sim, node: u8, v: invariants.Violation) SimError {
        self.violation = v;
        self.violation_node = node;
        std.debug.print(
            "\nSIM FAILURE: {s} (node {d}, slot {d}, t={d}ms)\nREPRO: zig build sim -- --seed={d} --nodes={d} --scenario={s}\n",
            .{ v.msg, node, v.slot, self.now, self.cfg.seed, self.cfg.n, self.cfg.name },
        );
        return error.InvariantViolation;
    }

    // -- event helpers -------------------------------------------------------

    fn pushEvent(self: *Sim, at: u64, kind: EventKind) !void {
        self.seq += 1;
        try self.queue.push(self.gpa, .{ .at = at, .seq = self.seq, .kind = kind });
    }

    fn sideOf(p: Partition, node: u8) u1 {
        return @intFromBool((p.side_a >> @intCast(node)) & 1 == 1);
    }

    fn linkUp(self: *const Sim, a: u8, b: u8, at: u64) bool {
        for (self.cfg.partitions) |p| {
            if (at >= p.start_ms and at < p.heal_ms and sideOf(p, a) != sideOf(p, b)) return false;
        }
        return true;
    }

    fn rollLatency(self: *Sim) u64 {
        const lat = self.cfg.latency;
        std.debug.assert(lat.max_ms >= lat.min_ms);
        const span: u32 = lat.max_ms - lat.min_ms;
        const jitter: u32 = if (span == 0) 0 else self.prng.random().uintAtMost(u32, span);
        return @as(u64, lat.min_ms + jitter);
    }

    /// Network send of one envelope frame from `from` to every peer, with
    /// partition/drop/latency/duplication applied in deterministic order.
    fn send(self: *Sim, from: u8, bytes: []const u8) !void {
        for (0..self.cfg.n) |j_usize| {
            const j: u8 = @intCast(j_usize);
            if (j == from) continue;
            self.counts.sent += 1;
            if (!self.linkUp(from, j, self.now)) {
                self.counts.dropped_partition += 1;
                continue;
            }
            if (self.cfg.drop_rate > 0 and self.prng.random().float(f32) < self.cfg.drop_rate) {
                self.counts.dropped_random += 1;
                continue;
            }
            const copy = try self.gpa.dupe(u8, bytes);
            errdefer self.gpa.free(copy);
            try self.pushEvent(self.now + self.rollLatency(), .{ .deliver = .{ .from = from, .to = j, .bytes = copy } });
            if (self.cfg.dup_rate > 0 and self.prng.random().float(f32) < self.cfg.dup_rate) {
                self.counts.duplicated += 1;
                const copy2 = try self.gpa.dupe(u8, bytes);
                errdefer self.gpa.free(copy2);
                try self.pushEvent(self.now + self.rollLatency(), .{ .deliver = .{ .from = from, .to = j, .bytes = copy2 } });
            }
        }
    }

    /// Reliable (no drop/dup) cross-cut re-delivery of each node's latest
    /// own envelopes after a heal — the overlay reconnect state-sync.
    fn healResync(self: *Sim, part_idx: u8) !void {
        if (self.healed[part_idx]) return;
        self.healed[part_idx] = true;
        const p = self.cfg.partitions[part_idx];
        for (0..self.cfg.n) |i_usize| {
            const i: u8 = @intCast(i_usize);
            for (0..self.cfg.n) |j_usize| {
                const j: u8 = @intCast(j_usize);
                if (i == j or sideOf(p, i) == sideOf(p, j)) continue;
                // Deterministic order: slots ascending, nomination first.
                const ol_map = &self.nodes[i].own_latest;
                const slots_sorted = try self.gpa.dupe(u64, ol_map.keys());
                defer self.gpa.free(slots_sorted);
                std.mem.sort(u64, slots_sorted, {}, std.sort.asc(u64));
                for (slots_sorted) |slot_index| {
                    const ol = ol_map.getPtr(slot_index).?;
                    inline for (.{ ol.nom, ol.ballot }) |maybe| {
                        if (maybe) |frame| {
                            const copy = try self.gpa.dupe(u8, frame);
                            errdefer self.gpa.free(copy);
                            try self.pushEvent(self.now + self.rollLatency(), .{ .deliver = .{ .from = i, .to = j, .bytes = copy } });
                        }
                    }
                }
            }
        }
    }

    // -- engine input + effect drain ----------------------------------------

    /// Feed one input, drain ALL effects, answer qset requests, then run the
    /// structural invariant check (§13.1: after EVERY input on every engine).
    fn pushInputChecked(self: *Sim, idx: u8, input: engine.Input, kind: InputKind) SimError!void {
        try self.log.append(self.gpa, .{ .at = self.now, .node = idx, .kind = kind });
        self.counts.inputs += 1;
        try self.nodes[idx].eng.pushInput(input);
        var want_qset = false;
        try self.drainEffects(idx, &want_qset);
        if (self.violation) |v| return self.fail(idx, v);
        if (invariants.checkEngine(&self.nodes[idx].eng, &self.nodes[idx].tracker, self.gpa) catch |e| return e) |v| {
            return self.fail(idx, v);
        }
        // Answer request_qset AFTER the drain (one-input-then-drain-all
        // contract) — recursion depth is 1: the answer never re-requests.
        if (want_qset) {
            try self.pushInputChecked(idx, .{ .qset_received = .{ .bytes = self.shared_framed } }, .qset);
        }
    }

    fn drainEffects(self: *Sim, idx: u8, want_qset: *bool) SimError!void {
        const gpa = self.gpa;
        const node = &self.nodes[idx];
        var status_count: usize = 0;
        var last_was_status = false;
        while (node.eng.popEffect()) |eff| {
            self.counts.effects += 1;
            last_was_status = false;
            if (self.trace) {
                switch (eff.*) {
                    .phase_event => |pe| std.debug.print("[{d}ms] n{d} phase_event slot={d} {t} detail={d}\n", .{ self.now, idx, pe.slot, pe.kind, pe.detail }),
                    .input_status => |st| std.debug.print("[{d}ms] n{d} status {t}\n", .{ self.now, idx, st.code }),
                    .arm_timer => |t| std.debug.print("[{d}ms] n{d} arm {t} +{d}ms\n", .{ self.now, idx, t.timer, t.delay_ms }),
                    .broadcast_envelope => |sb| std.debug.print("[{d}ms] n{d} broadcast {d}B\n", .{ self.now, idx, sb.bytes.len }),
                    else => std.debug.print("[{d}ms] n{d} effect {t}\n", .{ self.now, idx, std.meta.activeTag(eff.*) }),
                }
            }
            switch (eff.*) {
                .persist_own_envelope => |sb| {
                    // Decode for the own-statement freshness invariant and
                    // keep a copy as this node's latest own frame (resync).
                    const st = invariants.decodeOwnEnvelope(gpa, sb.bytes) catch {
                        self.violation = .{ .slot = sb.slot, .msg = "own persisted envelope failed to decode" };
                        break;
                    };
                    const is_nom = st.isNomination();
                    if (try invariants.recordOwnStatement(&node.tracker, gpa, st)) |v| {
                        self.violation = v;
                        break;
                    }
                    const gop = try node.own_latest.getOrPut(gpa, sb.slot);
                    if (!gop.found_existing) gop.value_ptr.* = .{};
                    const which = if (is_nom) &gop.value_ptr.nom else &gop.value_ptr.ballot;
                    if (which.*) |old| gpa.free(old);
                    which.* = try gpa.dupe(u8, sb.bytes);
                },
                .broadcast_envelope, .forward_envelope => |sb| try self.send(idx, sb.bytes),
                .arm_timer => |t| {
                    const gop = try node.timer_gen.getOrPut(gpa, .{ .slot = t.slot, .timer = t.timer });
                    if (!gop.found_existing) gop.value_ptr.* = 0;
                    gop.value_ptr.* +%= 1;
                    try self.pushEvent(self.now + t.delay_ms, .{ .timer = .{
                        .node = idx,
                        .slot = t.slot,
                        .timer = t.timer,
                        .gen = gop.value_ptr.*,
                    } });
                },
                .cancel_timer => |t| {
                    const gop = try node.timer_gen.getOrPut(gpa, .{ .slot = t.slot, .timer = t.timer });
                    if (!gop.found_existing) gop.value_ptr.* = 0;
                    gop.value_ptr.* +%= 1; // invalidates any queued fire
                },
                .request_qset => |r| {
                    std.debug.assert(std.mem.eql(u8, &r.hash, &self.shared_hash));
                    want_qset.* = true;
                },
                .externalized => |sb| {
                    if (try invariants.recordExternalizedEffect(&node.tracker, gpa, sb.slot)) |v| {
                        self.violation = v;
                        break;
                    }
                    const gop = try node.externalized.getOrPut(gpa, sb.slot);
                    if (gop.found_existing) {
                        self.violation = .{ .slot = sb.slot, .msg = "externalized twice for the same slot" };
                        break;
                    }
                    gop.value_ptr.* = try gpa.dupe(u8, sb.bytes);
                },
                .input_status => {
                    status_count += 1;
                    last_was_status = true;
                },
                .phase_event => {},
            }
            node.eng.commitEffect();
        }
        if (self.violation != null) {
            // Drain the remainder so the engine queue is clean before we bail.
            while (node.eng.popEffect() != null) node.eng.commitEffect();
            return;
        }
        // §5.1: exactly one input_status per input, always last.
        if (status_count != 1 or !last_was_status) {
            self.violation = .{ .slot = 0, .msg = "input_status contract violated (not exactly one, or not last)" };
        }
    }

    // -- main loop -----------------------------------------------------------

    pub fn allExternalized(self: *const Sim) bool {
        for (self.cfg.proposals) |p| {
            for (self.nodes) |*node| {
                if (!node.externalized.contains(p.slot)) return false;
            }
        }
        return true;
    }

    /// Process events with virtual time <= until_ms. May be called again
    /// with a later bound (staged partition scenarios). Stops early once
    /// every node externalized every proposed slot.
    pub fn run(self: *Sim, until_ms: u64) SimError!RunResult {
        while (self.queue.peek()) |head| {
            if (head.at > until_ms) break;
            if (self.allExternalized()) break;
            if (self.events_processed >= self.max_events) return error.EventBudgetExceeded;
            const ev = self.queue.pop().?;
            self.events_processed += 1;
            std.debug.assert(ev.at >= self.now);
            self.now = ev.at;
            switch (ev.kind) {
                .deliver => |d| {
                    defer self.gpa.free(d.bytes);
                    // Link must also be up at delivery time.
                    if (!self.linkUp(d.from, d.to, self.now)) {
                        self.counts.dropped_partition += 1;
                        continue;
                    }
                    self.counts.delivered += 1;
                    try self.pushInputChecked(d.to, .{ .envelope_received = .{ .bytes = d.bytes } }, .envelope);
                },
                .timer => |t| {
                    const cur = self.nodes[t.node].timer_gen.get(.{ .slot = t.slot, .timer = t.timer }) orelse 0;
                    if (cur != t.gen) continue; // re-armed or canceled: stale
                    self.counts.timer_fires += 1;
                    try self.pushInputChecked(t.node, .{ .timer_fired = .{ .slot = t.slot, .timer = t.timer } }, .timer);
                },
                .propose => |p| {
                    try self.pushInputChecked(p.node, .{ .nominate = .{
                        .slot = p.slot,
                        .value = p.value,
                        .prev_value = p.prev_value,
                    } }, .nominate);
                },
                .heal => |i| try self.healResync(i),
            }
        }
        return .{
            .stalled = !self.allExternalized(),
            .events_processed = self.events_processed,
            .virtual_now_ms = self.now,
            .counts = self.counts,
        };
    }

    // -- per-run properties (§13.1) -----------------------------------------

    pub fn externalizedValue(self: *const Sim, node: u8, slot: u64) ?[]const u8 {
        return self.nodes[node].externalized.get(slot);
    }

    /// AGREEMENT: no two nodes externalize different values for a slot.
    pub fn checkAgreement(self: *Sim) SimError!void {
        for (self.cfg.proposals) |p| {
            var first: ?[]const u8 = null;
            for (self.nodes, 0..) |*node, i| {
                const v = node.externalized.get(p.slot) orelse continue;
                if (first) |f| {
                    if (!std.mem.eql(u8, f, v)) {
                        return self.fail(@intCast(i), .{ .slot = p.slot, .msg = "AGREEMENT violated: two nodes externalized different values" });
                    }
                } else first = v;
            }
        }
    }

    /// VALIDITY: every externalized value traces to some scripted proposal
    /// for that slot (the default driver combines by picking one candidate).
    pub fn checkValidity(self: *Sim) SimError!void {
        for (self.nodes, 0..) |*node, i| {
            var it = node.externalized.iterator();
            while (it.next()) |entry| {
                const slot_index = entry.key_ptr.*;
                const v = entry.value_ptr.*;
                var found = false;
                for (self.cfg.proposals) |p| {
                    if (p.slot == slot_index and std.mem.eql(u8, p.value, v)) found = true;
                }
                if (!found) {
                    return self.fail(@intCast(i), .{ .slot = slot_index, .msg = "VALIDITY violated: externalized value traces to no proposal" });
                }
            }
        }
    }

    /// BOUNDED LIVENESS: `nodes_mask` (0 = all) must have externalized every
    /// proposed slot by now.
    pub fn checkLiveness(self: *Sim, nodes_mask: u8) SimError!void {
        const mask: u8 = if (nodes_mask == 0) @intCast((@as(u16, 1) << @intCast(self.cfg.n)) - 1) else nodes_mask;
        for (self.cfg.proposals) |p| {
            for (0..self.cfg.n) |i| {
                if ((mask >> @intCast(i)) & 1 == 0) continue;
                if (!self.nodes[i].externalized.contains(p.slot)) {
                    return self.fail(@intCast(i), .{ .slot = p.slot, .msg = "BOUNDED LIVENESS violated: node did not externalize within the scenario bound" });
                }
            }
        }
    }

    /// Assert that no node in `nodes_mask` (0 = all) has externalized
    /// anything yet (partition halt is CORRECT behavior).
    pub fn checkNoneExternalized(self: *Sim, nodes_mask: u8) SimError!void {
        const mask: u8 = if (nodes_mask == 0) @intCast((@as(u16, 1) << @intCast(self.cfg.n)) - 1) else nodes_mask;
        for (0..self.cfg.n) |i| {
            if ((mask >> @intCast(i)) & 1 == 0) continue;
            if (self.nodes[i].externalized.count() != 0) {
                return self.fail(@intCast(i), .{ .slot = self.nodes[i].externalized.keys()[0], .msg = "node externalized during a majority-less partition (halting was required)" });
            }
        }
    }
};
