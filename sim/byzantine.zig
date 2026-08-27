//! Byzantine fault-injection suite (design §13.2) — the adversarial companion
//! to the honest-network simulator (sim/sim.zig). Where sim.zig stresses the
//! engine against a lossy/partitioned but HONEST network, this harness puts
//! REAL key-holding validators inside the quorum and turns them malicious:
//! every attack is a scripted `adversary.Forger` (sim/adversary.zig) minting
//! crafted `envelope_received` frames that honest engines ingest through the
//! normal receive pipeline (pipeline.zig).
//!
//! The quorum is a shared flat ceil(2n/3)-of-n qset over `h` honest seeds
//! (nodeSeed 0..h) PLUS `b` adversary seeds, with n = h + b. The shape is
//! chosen so the honest set is a quorum ON ITS OWN (h >= threshold) and the
//! Byzantine set is within a DSet (n >= 3b + 1) — i.e. the intact nodes are
//! an intact quorum tolerating b faulty validators per FBA. Shapes used:
//! 3 honest + 1 Byzantine (3-of-4) and 5 honest + 2 Byzantine (5-of-7).
//!
//! The acceptance property (design §13.2, §14-M3): whenever the Byzantine set
//! is within a DSet the INTACT nodes AGREE (no two honest nodes externalize
//! different values), engines NEVER panic or leak on ANY adversarial input
//! (std.testing.allocator + the structural invariant tracker after EVERY
//! honest input), and every rejection is a typed InputStatus (§5.2).
//!
//! Actor → test map (each cites the stellar-core behavior it stresses):
//!   equivocator          — SCP receives contradictory PREPAREs/counter; the
//!                          per-(node,protocol) freshness order + federated
//!                          voting keep intact nodes in agreement.
//!   stale replayer       — freshness dedup (stored.isNewerOwned): replays are
//!                          `stale`, no state change, no relay storm.
//!   counter inflator     — no receive-side counter cap by design (§5.4); a
//!                          sub-v-blocking adversary CANNOT move honest
//!                          counters (measurement below).
//!   qset liar            — unresolvable/oversized/mismatched qset hashes park
//!                          then expire (pending.zig FIFO); honest progress via
//!                          the other validators.
//!   value spammer        — max-list nominations bounded by the engine's
//!                          stored-bytes budget (§5.1); no OOM.
//!   non-canonical encoder— §4.2 receive-side canonicality: strict engines
//!                          reject `insane`, lenient accept; both stay safe.
//!   sig forger           — Ed25519 verify over received bytes / wrong network
//!                          (§4.2) → `invalid_signature`, never processed.
//!   crash-at-phase       — a validator falling silent mid-protocol; the honest
//!                          quorum still externalizes.

const std = @import("std");
const slcp = @import("slcp-core");
pub const adversary = @import("adversary.zig");
pub const invariants = @import("invariants.zig");

const engine = slcp.engine;
const crypto = slcp.crypto;
const qset = slcp.qset;
const canonical = slcp.canonical;
const driver = slcp.driver;

// ---------------------------------------------------------------------------
// Shape + configuration
// ---------------------------------------------------------------------------

/// A DSet-respecting quorum shape: `honest` intact validators forming a quorum
/// (honest >= ceil(2n/3)) plus `byzantine` faulty ones within a DSet
/// (n >= 3*byzantine + 1), n = honest + byzantine.
pub const Shape = struct {
    honest: u8,
    byzantine: u8,

    pub fn n(self: Shape) u8 {
        return self.honest + self.byzantine;
    }

    pub fn threshold(self: Shape) u32 {
        return (2 * @as(u32, self.n()) + 2) / 3; // ceil(2n/3)
    }

    /// The intact set is a quorum on its own AND the faulty set is within a
    /// DSet (asymptotic BFT bound). Asserted at init.
    pub fn isDSet(self: Shape) bool {
        return self.honest >= self.threshold() and @as(u32, self.n()) >= 3 * @as(u32, self.byzantine) + 1;
    }
};

/// The two canonical shapes the suite exercises.
pub const shape_3_1 = Shape{ .honest = 3, .byzantine = 1 }; // 3-of-4
pub const shape_5_2 = Shape{ .honest = 5, .byzantine = 2 }; // 5-of-7

pub const byz_passphrase = "slcp-byz v1";

/// Honest seed i (0x10 + i) — disjoint from adversary seeds (0xB0 + j).
pub fn honestSeed(i: u8) [32]u8 {
    return @splat(@as(u8, 0x10) + i);
}
pub fn advSeed(j: u8) [32]u8 {
    return @splat(@as(u8, 0xB0) + j);
}

pub const Options = struct {
    strict_canonical: bool = true,
    limits: slcp.limits.Limits = .{},
    /// Fixed per-hop latency for the deterministic bus (no jitter needed —
    /// safety is order-insensitive; a constant keeps runs trivially replayable).
    latency_ms: u32 = 25,
};

// ---------------------------------------------------------------------------
// Virtual-clock event queue (honest bus)
// ---------------------------------------------------------------------------

const EventKind = union(enum) {
    /// An envelope frame (honest relay OR a scheduled adversary injection)
    /// arriving at honest node `to`. `bytes` are owned by the queue.
    deliver: struct { to: u8, bytes: []u8 },
    timer: struct { node: u8, slot: u64, timer: engine.TimerId, gen: u32 },
    propose: struct { node: u8, slot: u64, value: []const u8, prev_value: []const u8 },
};

const Event = struct { at: u64, seq: u64, kind: EventKind };

fn eventLess(a: Event, b: Event) bool {
    if (a.at != b.at) return a.at < b.at;
    return a.seq < b.seq;
}

fn freeEvent(gpa: std.mem.Allocator, ev: *Event) void {
    switch (ev.kind) {
        .deliver => |d| gpa.free(d.bytes),
        else => {},
    }
}

// ---------------------------------------------------------------------------
// Honest node
// ---------------------------------------------------------------------------

const TimerKey = struct { slot: u64, timer: engine.TimerId };

const HNode = struct {
    eng: engine.Engine,
    tracker: invariants.Tracker = .{},
    timer_gen: std.AutoHashMapUnmanaged(TimerKey, u32) = .empty,
    /// slot → externalized value bytes (owned). Presence == this honest node
    /// externalized that slot.
    externalized: std.AutoArrayHashMapUnmanaged(u64, []u8) = .empty,

    fn deinit(self: *HNode, gpa: std.mem.Allocator) void {
        self.eng.deinit();
        self.tracker.deinit(gpa);
        self.timer_gen.deinit(gpa);
        for (self.externalized.values()) |v| gpa.free(v);
        self.externalized.deinit(gpa);
    }
};

/// Per-input drain summary (assertions read the status + effect tallies).
pub const InjectResult = struct {
    status: engine.InputStatus = undefined,
    forwards: usize = 0,
    broadcasts: usize = 0,
    requests: usize = 0,
    evicted_events: usize = 0,
    externalized_now: usize = 0,
    last_request_hash: [32]u8 = @splat(0),
};

pub const Counts = struct {
    honest_inputs: u64 = 0,
    honest_effects: u64 = 0,
    delivered: u64 = 0,
    timer_fires: u64 = 0,
    ballot_timer_arms: u64 = 0,
    forwards: u64 = 0,
    parked_evictions: u64 = 0,
};

/// Measurement bucket for the counter-inflation study (§5.4/§16).
pub const Measure = struct {
    max_honest_ballot_counter: u32 = 0,
    max_seen_prepare_counter: u32 = 0,
    honest_externalizations: u64 = 0,
};

pub const ByzError = error{ InvariantViolation, EventBudgetExceeded, AgreementViolated, OutOfMemory } || engine.EngineError;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

pub const Harness = struct {
    gpa: std.mem.Allocator,
    shape: Shape,
    opts: Options,
    network_id: [32]u8,

    honest: []HNode,
    honest_pks: [][32]u8,

    adv_seeds: [][32]u8,
    adv_pks: [][32]u8,
    forgers: []adversary.Forger,

    /// The shared quorum-set (honest + adversary validators).
    shared_hash: [32]u8,
    shared_framed: []u8,

    queue: std.ArrayList(Event) = .empty,
    seq: u64 = 0,
    now: u64 = 0,
    events_processed: u64 = 0,
    max_events: u64 = 2_000_000,

    counts: Counts = .{},
    measure: Measure = .{},

    pub fn init(gpa: std.mem.Allocator, shape: Shape, opts: Options) !Harness {
        std.debug.assert(shape.isDSet());
        std.debug.assert(shape.n() <= 16);

        const network_id = crypto.networkIdFromPassphrase(byz_passphrase);
        const h = shape.honest;
        const b = shape.byzantine;

        // Keys.
        const honest_pks = try gpa.alloc([32]u8, h);
        errdefer gpa.free(honest_pks);
        for (0..h) |i| honest_pks[i] = try crypto.publicKeyFromSeed(honestSeed(@intCast(i)));

        const adv_seeds = try gpa.alloc([32]u8, b);
        errdefer gpa.free(adv_seeds);
        const adv_pks = try gpa.alloc([32]u8, b);
        errdefer gpa.free(adv_pks);
        for (0..b) |j| {
            adv_seeds[j] = advSeed(@intCast(j));
            adv_pks[j] = try crypto.publicKeyFromSeed(adv_seeds[j]);
        }

        // Shared flat ceil(2n/3)-of-n qset over honest ++ adversary pubkeys.
        var all_pks = try gpa.alloc([32]u8, shape.n());
        defer gpa.free(all_pks);
        @memcpy(all_pks[0..h], honest_pks);
        @memcpy(all_pks[h..], adv_pks);

        var shared = qset.QuorumSetOwned{
            .threshold = shape.threshold(),
            .validators = try gpa.dupe([32]u8, all_pks),
            .inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0),
        };
        defer shared.deinit(gpa);
        try qset.validateAndNormalize(gpa, &shared);
        const shared_flat = try qset.canonicalBytes(gpa, &shared);
        defer gpa.free(shared_flat);
        const shared_hash = crypto.qsetHash(shared_flat);
        const shared_framed = try canonical.frameFlat(gpa, shared_flat);
        errdefer gpa.free(shared_framed);

        // Forgers (one per adversary seed).
        const forgers = try gpa.alloc(adversary.Forger, b);
        errdefer gpa.free(forgers);
        for (0..b) |j| forgers[j] = try adversary.Forger.init(gpa, adv_seeds[j], network_id);

        // Honest engines.
        const honest = try gpa.alloc(HNode, h);
        var made: usize = 0;
        errdefer {
            for (honest[0..made]) |*node| node.deinit(gpa);
            gpa.free(honest);
        }
        for (0..h) |i| {
            honest[i] = .{ .eng = try engine.Engine.init(gpa, .{
                .network_id = network_id,
                .node_id = honest_pks[i],
                .secret_seed = honestSeed(@intCast(i)),
                .quorum_set = try qset.clone(gpa, &shared),
                .strict_canonical = opts.strict_canonical,
                .limits = opts.limits,
            }, driver.Driver.default()) };
            made += 1;
        }

        return .{
            .gpa = gpa,
            .shape = shape,
            .opts = opts,
            .network_id = network_id,
            .honest = honest,
            .honest_pks = honest_pks,
            .adv_seeds = adv_seeds,
            .adv_pks = adv_pks,
            .forgers = forgers,
            .shared_hash = shared_hash,
            .shared_framed = shared_framed,
        };
    }

    pub fn deinit(self: *Harness) void {
        const gpa = self.gpa;
        for (self.honest) |*node| node.deinit(gpa);
        gpa.free(self.honest);
        gpa.free(self.honest_pks);
        gpa.free(self.adv_seeds);
        gpa.free(self.adv_pks);
        gpa.free(self.forgers);
        gpa.free(self.shared_framed);
        for (self.queue.items) |*e| freeEvent(gpa, e);
        self.queue.deinit(gpa);
        self.* = undefined;
    }

    // -- accessors -----------------------------------------------------------

    pub fn sharedHash(self: *const Harness) [32]u8 {
        return self.shared_hash;
    }
    pub fn forger(self: *Harness, j: usize) *adversary.Forger {
        return &self.forgers[j];
    }

    // -- event queue ---------------------------------------------------------

    fn pushEvent(self: *Harness, at: u64, kind: EventKind) !void {
        self.seq += 1;
        // Keep sorted-on-insert via a simple insertion; queues here are small.
        const ev = Event{ .at = at, .seq = self.seq, .kind = kind };
        try self.queue.append(self.gpa, ev);
        var i = self.queue.items.len - 1;
        while (i > 0 and eventLess(self.queue.items[i], self.queue.items[i - 1])) : (i -= 1) {
            std.mem.swap(Event, &self.queue.items[i], &self.queue.items[i - 1]);
        }
    }

    fn popEvent(self: *Harness) ?Event {
        if (self.queue.items.len == 0) return null;
        return self.queue.orderedRemove(0);
    }

    // -- scheduling API ------------------------------------------------------

    /// Schedule honest node `node` to begin nomination of `value` at `at_ms`.
    pub fn proposeAt(self: *Harness, at_ms: u64, node: u8, slot: u64, value: []const u8, prev_value: []const u8) !void {
        std.debug.assert(node < self.shape.honest);
        try self.pushEvent(at_ms, .{ .propose = .{ .node = node, .slot = slot, .value = value, .prev_value = prev_value } });
    }

    /// Schedule a crafted adversary frame to arrive at honest node `to` at
    /// `at_ms`. `bytes` are copied (caller keeps ownership).
    pub fn injectAt(self: *Harness, at_ms: u64, to: u8, bytes: []const u8) !void {
        std.debug.assert(to < self.shape.honest);
        const copy = try self.gpa.dupe(u8, bytes);
        errdefer self.gpa.free(copy);
        try self.pushEvent(at_ms, .{ .deliver = .{ .to = to, .bytes = copy } });
    }

    /// Broadcast one crafted frame to a SUBSET of honest nodes given by a
    /// bitmask (the "partition" an equivocation is delivered to).
    pub fn injectMaskAt(self: *Harness, at_ms: u64, mask: u16, bytes: []const u8) !void {
        for (0..self.shape.honest) |i| {
            if ((mask >> @intCast(i)) & 1 == 0) continue;
            try self.injectAt(at_ms, @intCast(i), bytes);
        }
    }

    /// Deliver a crafted frame to one honest node IMMEDIATELY (at the current
    /// virtual time) and return the drain summary — for direct status
    /// assertions (sig forgery, non-canonical, stale, qset-liar).
    pub fn injectNow(self: *Harness, to: u8, bytes: []const u8) ByzError!InjectResult {
        return self.pushHonest(to, .{ .envelope_received = .{ .bytes = bytes } });
    }

    /// Push a nominate to one honest node immediately and drain.
    pub fn nominateNow(self: *Harness, node: u8, slot: u64, value: []const u8, prev_value: []const u8) ByzError!InjectResult {
        return self.pushHonest(node, .{ .nominate = .{ .slot = slot, .value = value, .prev_value = prev_value } });
    }

    // -- engine input + effect drain (honest only) ---------------------------

    fn pushHonest(self: *Harness, idx: u8, input: engine.Input) ByzError!InjectResult {
        const node = &self.honest[idx];
        self.counts.honest_inputs += 1;
        try node.eng.pushInput(input);

        var res = InjectResult{};
        var want_qset = false;
        try self.drain(idx, &res, &want_qset);

        // Structural invariants after EVERY honest input (§13.1 / §13.2).
        if (invariants.checkEngine(&node.eng, &node.tracker, self.gpa) catch |e| return e) |v| {
            std.debug.print(
                "\nBYZ INVARIANT: {s} (honest {d}, slot {d}, t={d}ms, shape {d}+{d})\n",
                .{ v.msg, idx, v.slot, self.now, self.shape.honest, self.shape.byzantine },
            );
            return error.InvariantViolation;
        }

        // Post-drain: record externalizations + measurement scan.
        try self.scanSlots(idx, &res);

        // Answer request_qset AFTER the drain (one-input-then-drain-all
        // contract, recursion depth 1). Only OUR shared hash is fetchable;
        // an adversary's unresolvable hash is left parked (the qset-liar test).
        if (want_qset and std.mem.eql(u8, &res.last_request_hash, &self.shared_hash)) {
            var ignore = InjectResult{};
            var ignore_want = false;
            self.counts.honest_inputs += 1;
            try node.eng.pushInput(.{ .qset_received = .{ .bytes = self.shared_framed } });
            try self.drain(idx, &ignore, &ignore_want);
            if (invariants.checkEngine(&node.eng, &node.tracker, self.gpa) catch |e| return e) |v| {
                _ = v;
                return error.InvariantViolation;
            }
            try self.scanSlots(idx, &ignore);
        }
        return res;
    }

    fn drain(self: *Harness, idx: u8, res: *InjectResult, want_qset: *bool) ByzError!void {
        const gpa = self.gpa;
        const node = &self.honest[idx];
        var status_count: usize = 0;
        var last_was_status = false;
        while (node.eng.popEffect()) |eff| {
            self.counts.honest_effects += 1;
            last_was_status = false;
            switch (eff.*) {
                .broadcast_envelope => |sb| {
                    res.broadcasts += 1;
                    try self.send(idx, sb.bytes);
                },
                .forward_envelope => |sb| {
                    res.forwards += 1;
                    self.counts.forwards += 1;
                    try self.send(idx, sb.bytes);
                },
                .arm_timer => |t| {
                    if (t.timer == .ballot) self.counts.ballot_timer_arms += 1;
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
                    gop.value_ptr.* +%= 1;
                },
                .request_qset => |r| {
                    res.requests += 1;
                    res.last_request_hash = r.hash;
                    want_qset.* = true;
                },
                .persist_own_envelope => |sb| {
                    // Own-emission freshness invariant (isNewerStatement order).
                    const st = invariants.decodeOwnEnvelope(gpa, sb.bytes) catch {
                        node.eng.commitEffect();
                        while (node.eng.popEffect() != null) node.eng.commitEffect();
                        return error.InvariantViolation;
                    };
                    if (try invariants.recordOwnStatement(&node.tracker, gpa, st)) |_| {
                        node.eng.commitEffect();
                        while (node.eng.popEffect() != null) node.eng.commitEffect();
                        return error.InvariantViolation;
                    }
                },
                .externalized => |sb| {
                    if (try invariants.recordExternalizedEffect(&node.tracker, gpa, sb.slot)) |_| {
                        node.eng.commitEffect();
                        while (node.eng.popEffect() != null) node.eng.commitEffect();
                        return error.InvariantViolation;
                    }
                },
                .phase_event => |p| {
                    if (p.kind == .parked_evicted) {
                        res.evicted_events += 1;
                        self.counts.parked_evictions += 1;
                    }
                },
                .input_status => |st| {
                    res.status = st.code;
                    status_count += 1;
                    last_was_status = true;
                },
            }
            node.eng.commitEffect();
        }
        // §5.1: exactly one input_status per input, always last.
        if (status_count != 1 or !last_was_status) return error.InvariantViolation;
    }

    /// Honest → honest fan-out (fully connected; drops/partitions are not the
    /// Byzantine question — see the equivocator note). `bytes` copied per peer.
    fn send(self: *Harness, from: u8, bytes: []const u8) !void {
        for (0..self.shape.honest) |j| {
            if (j == from) continue;
            const copy = try self.gpa.dupe(u8, bytes);
            errdefer self.gpa.free(copy);
            try self.pushEvent(self.now + self.opts.latency_ms, .{ .deliver = .{ .to = @intCast(j), .bytes = copy } });
        }
    }

    /// Record externalizations and update the counter-inflation measurement by
    /// scanning `idx`'s live slot state after a drained input.
    fn scanSlots(self: *Harness, idx: u8, res: *InjectResult) !void {
        const node = &self.honest[idx];
        var it = node.eng.slots.iterator();
        while (it.next()) |entry| {
            const slot_index = entry.key_ptr.*;
            const s = entry.value_ptr.*;
            if (s.ballot.current) |*bcur| {
                self.measure.max_honest_ballot_counter = @max(self.measure.max_honest_ballot_counter, bcur.counter);
            }
            if (s.externalized_value) |v| {
                if (!node.externalized.contains(slot_index)) {
                    const copy = try self.gpa.dupe(u8, v);
                    errdefer self.gpa.free(copy);
                    try node.externalized.put(self.gpa, slot_index, copy);
                    res.externalized_now += 1;
                    self.measure.honest_externalizations += 1;
                }
            }
        }
    }

    // -- main loop -----------------------------------------------------------

    pub fn allHonestExternalized(self: *const Harness, slot: u64) bool {
        for (self.honest) |*node| {
            if (!node.externalized.contains(slot)) return false;
        }
        return true;
    }

    pub fn honestExternalizedCount(self: *const Harness, slot: u64) usize {
        var count: usize = 0;
        for (self.honest) |*node| {
            if (node.externalized.contains(slot)) count += 1;
        }
        return count;
    }

    /// Process events with virtual time <= until_ms. Stops early once every
    /// honest node has externalized `stop_slot` (0 = run to the bound).
    pub fn run(self: *Harness, until_ms: u64, stop_slot: u64) ByzError!void {
        while (self.queue.items.len > 0) {
            if (self.queue.items[0].at > until_ms) break;
            if (stop_slot != 0 and self.allHonestExternalized(stop_slot)) break;
            if (self.events_processed >= self.max_events) return error.EventBudgetExceeded;
            const ev = self.popEvent().?;
            self.events_processed += 1;
            std.debug.assert(ev.at >= self.now);
            self.now = ev.at;
            switch (ev.kind) {
                .deliver => |d| {
                    defer self.gpa.free(d.bytes);
                    self.counts.delivered += 1;
                    var res = InjectResult{};
                    _ = try self.pushHonestDrain(d.to, .{ .envelope_received = .{ .bytes = d.bytes } }, &res);
                },
                .timer => |t| {
                    const cur = self.honest[t.node].timer_gen.get(.{ .slot = t.slot, .timer = t.timer }) orelse 0;
                    if (cur != t.gen) continue; // re-armed/canceled: stale
                    self.counts.timer_fires += 1;
                    var res = InjectResult{};
                    _ = try self.pushHonestDrain(t.node, .{ .timer_fired = .{ .slot = t.slot, .timer = t.timer } }, &res);
                },
                .propose => |p| {
                    var res = InjectResult{};
                    _ = try self.pushHonestDrain(p.node, .{ .nominate = .{
                        .slot = p.slot,
                        .value = p.value,
                        .prev_value = p.prev_value,
                    } }, &res);
                },
            }
        }
    }

    fn pushHonestDrain(self: *Harness, idx: u8, input: engine.Input, res: *InjectResult) ByzError!void {
        res.* = try self.pushHonest(idx, input);
    }

    // -- safety properties ---------------------------------------------------

    /// AGREEMENT (the core §13.2 safety property): no two honest nodes
    /// externalize different values for the same slot.
    pub fn checkAgreement(self: *Harness, slot: u64) ByzError!void {
        var first: ?[]const u8 = null;
        for (self.honest, 0..) |*node, i| {
            const v = node.externalized.get(slot) orelse continue;
            if (first) |f| {
                if (!std.mem.eql(u8, f, v)) {
                    std.debug.print(
                        "\nBYZ AGREEMENT: honest {d} externalized a different value for slot {d} (shape {d}+{d})\n",
                        .{ i, slot, self.shape.honest, self.shape.byzantine },
                    );
                    return error.AgreementViolated;
                }
            } else first = v;
        }
    }
};

// ===========================================================================
// Tests — the actor suite (design §13.2)
// ===========================================================================

const testing = std.testing;

/// Drive an honest quorum to externalize slot 1 under a scripted adversary.
/// Returns the harness (caller deinits) so the test can assert measurements.
fn honestBound() u64 {
    return 240_000;
}

/// Seed the honest proposers for slot 1 with distinct values at t=0.
fn seedProposals(h: *Harness, slot: u64) !void {
    const vals = [_][]const u8{
        "byz-alpha", "byz-bravo", "byz-charlie", "byz-delta", "byz-echo",
    };
    for (0..h.shape.honest) |i| {
        try h.proposeAt(0, @intCast(i), slot, vals[i % vals.len], "genesis");
    }
}

// --- 1. equivocator --------------------------------------------------------
// stellar-core: SCP tolerates a validator emitting contradictory statements;
// per-(node,protocol) freshness + federated voting keep intact nodes agreeing.
// THE core safety test: contradictory PREPAREs at the same counter delivered
// to disjoint honest partitions, then relayed across the whole honest set.

test "byz equivocator: contradictory PREPAREs to split partitions; intact nodes agree (3+1)" {
    const gpa = testing.allocator;
    var h = try Harness.init(gpa, shape_3_1, .{});
    defer h.deinit();

    try seedProposals(&h, 1);

    // Adversary equivocates at counter 1: value A to {honest 0}, value B to
    // {honest 1,2}. equivocatingPrepares mints both valid+canonical frames.
    const qh = h.sharedHash();
    const pair = try adversary.equivocatingPrepares(h.forger(0), 1, qh, 1, "zzzz-high-A", "zzzz-high-B");
    defer gpa.free(pair.a);
    defer gpa.free(pair.b);
    try h.injectMaskAt(5, 0b001, pair.a);
    try h.injectMaskAt(5, 0b110, pair.b);

    try h.run(honestBound(), 1);

    // Safety: every honest node that externalized agrees. Liveness: the honest
    // quorum (3-of-4) completes despite the equivocation.
    try h.checkAgreement(1);
    try testing.expect(h.allHonestExternalized(1));
}

test "byz equivocator: 5+2 shape, two independent equivocators, intact nodes agree" {
    const gpa = testing.allocator;
    var h = try Harness.init(gpa, shape_5_2, .{});
    defer h.deinit();

    try seedProposals(&h, 1);

    const qh = h.sharedHash();
    // Two forgers each equivocate across the honest set at counters 1 and 2.
    const p0 = try adversary.equivocatingPrepares(h.forger(0), 1, qh, 1, "eqv-A0", "eqv-B0");
    defer gpa.free(p0.a);
    defer gpa.free(p0.b);
    const p1 = try adversary.equivocatingPrepares(h.forger(1), 1, qh, 2, "eqv-A1", "eqv-B1");
    defer gpa.free(p1.a);
    defer gpa.free(p1.b);
    try h.injectMaskAt(5, 0b00011, p0.a);
    try h.injectMaskAt(5, 0b11100, p0.b);
    try h.injectMaskAt(6, 0b01010, p1.a);
    try h.injectMaskAt(6, 0b10101, p1.b);

    try h.run(honestBound(), 1);

    try h.checkAgreement(1);
    try testing.expect(h.allHonestExternalized(1));
}

// --- 2. stale replayer -----------------------------------------------------
// stellar-core: envelopes older than a peer's latest are dropped. SLCP:
// freshness dedup (stored.isNewerOwned) → `stale`, no state change, no relay.

test "byz stale replayer: superseded replays are stale, no relay storm, progress holds" {
    const gpa = testing.allocator;
    var h = try Harness.init(gpa, shape_3_1, .{});
    defer h.deinit();

    const qh = h.sharedHash();

    // Adversary's first nomination (accepted), then a strict superset (fresh),
    // then REPLAY the first (now superseded → stale) many times.
    const nom1 = try h.forger(0).sign(1, .{ .nominate = .{ .qset_hash = qh, .votes = &.{"aa"}, .accepted = &.{} } });
    defer gpa.free(nom1);
    const nom2 = try h.forger(0).sign(1, .{ .nominate = .{ .qset_hash = qh, .votes = &.{ "aa", "bb" }, .accepted = &.{} } });
    defer gpa.free(nom2);

    const r1 = try h.injectNow(0, nom1);
    try testing.expectEqual(engine.InputStatus.applied, r1.status);
    const r2 = try h.injectNow(0, nom2);
    try testing.expectEqual(engine.InputStatus.applied, r2.status);

    // Replays of the superseded envelope: stale, zero forwards each time.
    for (0..8) |_| {
        const rs = try h.injectNow(0, nom1);
        try testing.expectEqual(engine.InputStatus.stale, rs.status);
        try testing.expectEqual(@as(usize, 0), rs.forwards);
    }
    // An exact replay of the current latest is also stale (dedup).
    const rdup = try h.injectNow(0, nom2);
    try testing.expectEqual(engine.InputStatus.stale, rdup.status);
    try testing.expectEqual(@as(usize, 0), rdup.forwards);

    // Honest consensus still reaches externalization.
    try seedProposals(&h, 1);
    try h.run(honestBound(), 1);
    try h.checkAgreement(1);
    try testing.expect(h.allHonestExternalized(1));
}

// --- 3. counter inflator ---------------------------------------------------
// §5.4/§16: SLCP has NO receive-side counter cap by design. A single (or
// sub-v-blocking) adversary CANNOT move honest counters — the federated
// counter-bump rule needs a v-blocking set. This test MEASURES that: honest
// counters stay bounded by their OWN timeout schedule, not the adversary's
// escalation to u32 max. (v-blocking size = n - threshold + 1; 3-of-4 => 2,
// so 1 adversary is not v-blocking; 5-of-7 => 3, so 2 are not either.)

test "byz counter inflator: escalating counters to u32 max cannot inflate honest counters (3+1)" {
    const gpa = testing.allocator;
    var h = try Harness.init(gpa, shape_3_1, .{});
    defer h.deinit();

    const qh = h.sharedHash();
    try seedProposals(&h, 1);

    const counters = [_]u32{ 100, 1000, 1_000_000, std.math.maxInt(u32) };
    for (counters) |c| {
        const env = try h.forger(0).sign(1, .{ .prepare = .{ .qset_hash = qh, .ballot = .{ .counter = c, .value = "infl" } } });
        defer gpa.free(env);
        h.measure.max_seen_prepare_counter = @max(h.measure.max_seen_prepare_counter, c);
        // Deliver to every honest node; each stays safe and accepts/relays.
        try h.injectMaskAt(1, 0b111, env);
    }

    try h.run(honestBound(), 1);

    try h.checkAgreement(1);
    try testing.expect(h.allHonestExternalized(1));

    // MEASUREMENT (recorded for §16, 3-honest + 1-Byzantine, measured):
    //   injected PREPARE counter        = 4_294_967_295 (u32 max)
    //   max honest ballot counter       = 1
    //   ballot timers armed (all nodes) = 3 (one per honest node — the
    //                                     nomination→ballot handoff; NO
    //                                     adversary-driven re-arm/bump)
    //   honest externalizations         = 3 (full quorum)
    // The honest counter never leaves 1: a lone (sub-v-blocking) adversary
    // moves it by ZERO. The federated counter-bump rule needs a v-blocking set
    // (size n-threshold+1 = 2 here), which 1 adversary cannot reach — so the
    // absence of a receive-side cap (§5.4) is safe, and damage is bounded by
    // the honest timeout schedule, exactly the property §16 flags to verify.
    try testing.expect(h.measure.max_honest_ballot_counter <= 1);
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), h.measure.max_seen_prepare_counter);
}

test "byz counter inflator: 5+2, two inflators at u32 max, damage bounded" {
    const gpa = testing.allocator;
    var h = try Harness.init(gpa, shape_5_2, .{});
    defer h.deinit();

    const qh = h.sharedHash();
    try seedProposals(&h, 1);

    const counters = [_]u32{ 500, 50_000, std.math.maxInt(u32) };
    for (counters) |c| {
        for (0..2) |j| {
            const env = try h.forger(j).sign(1, .{ .prepare = .{ .qset_hash = qh, .ballot = .{ .counter = c, .value = "infl2" } } });
            defer gpa.free(env);
            try h.injectMaskAt(1, 0b11111, env);
        }
        h.measure.max_seen_prepare_counter = @max(h.measure.max_seen_prepare_counter, c);
    }

    try h.run(honestBound(), 1);
    try h.checkAgreement(1);
    try testing.expect(h.allHonestExternalized(1));
    // MEASUREMENT (5-honest + 2-Byzantine, measured): injected PREPARE counter
    // = u32 max; max honest ballot counter = 1; ballot timers armed = 5 (one
    // per honest node); 5 externalizations. Two adversaries are still below the
    // v-blocking size (n-threshold+1 = 3), so counter inflation is again 0.
    try testing.expect(h.measure.max_honest_ballot_counter <= 1);
}

// --- 4. qset liar ----------------------------------------------------------
// stellar-core: an unresolvable quorum-set hash parks the envelope pending a
// fetch; it never crashes and never counts. SLCP: park → FIFO expiry; honest
// progress flows through the other validators.

test "byz qset liar: unresolvable/mismatched qset hashes park then expire, progress holds" {
    const gpa = testing.allocator;
    // Small parking cap so the FIFO eviction (expiry) is observable.
    var h = try Harness.init(gpa, shape_3_1, .{ .limits = .{ .max_pending_envelopes = 3 } });
    defer h.deinit();

    // Nominations advertising a qset hash the host can never supply. Each
    // distinct slot is fresh so they all park (until the cap evicts the oldest).
    var parked: usize = 0;
    var evicted: usize = 0;
    for (0..6) |k| {
        var liar_hash: [32]u8 = @splat(0xC0);
        liar_hash[0] = @intCast(k); // distinct unresolvable hash each time
        const env = try h.forger(0).sign(@intCast(k + 1), .{ .nominate = .{
            .qset_hash = liar_hash,
            .votes = &.{"liar"},
            .accepted = &.{},
        } });
        defer gpa.free(env);
        const r = try h.injectNow(0, env);
        // Parks (never a crash); an over-cap arrival evicts the FIFO victim.
        try testing.expect(r.status == .parked_awaiting_qset or r.status == .over_limit);
        if (r.status == .parked_awaiting_qset) parked += 1;
        evicted += r.evicted_events;
    }
    // The cap held: at most `max_pending_envelopes` remain parked, and the
    // excess produced eviction phase-events (expiry) rather than growth.
    try testing.expect(h.honest[0].eng.stats().parked <= 3);
    try testing.expect(evicted > 0 or parked <= 3);

    // A structurally-parked liar never blocks the honest quorum.
    try seedProposals(&h, 1);
    try h.run(honestBound(), 1);
    try h.checkAgreement(1);
    try testing.expect(h.allHonestExternalized(1));
}

// --- 5. value spammer ------------------------------------------------------
// §5.1: the engine-wide stored-bytes budget bounds memory; a flood of
// max-list nominations cannot OOM the honest node.

test "byz value spammer: max-list nominations stay within the stored-bytes budget" {
    const gpa = testing.allocator;
    var h = try Harness.init(gpa, shape_3_1, .{});
    defer h.deinit();

    const qh = h.sharedHash();

    // 64 strictly-ascending values (the frozen max list length), each ~256 B.
    const max_list = slcp.limits.frozen_max_nomination_values;
    var buf: [max_list][]u8 = undefined;
    var made: usize = 0;
    defer for (buf[0..made]) |b| gpa.free(b);
    for (0..max_list) |i| {
        const v = try gpa.alloc(u8, 256);
        buf[i] = v;
        made += 1;
        @memset(v, 'a');
        // Distinct, strictly-ascending prefix so checkStatementSane accepts.
        std.mem.writeInt(u32, v[0..4], @intCast(i), .big);
    }
    const votes: [][]u8 = buf[0..max_list];

    const budget = h.honest[0].eng.cfg.limits.max_stored_statement_bytes;

    // Flood: each adversary nomination at slot 1 is a strict superset growth
    // is impossible (list is already maximal), so after the first it is stale.
    // Instead spam DISTINCT slots to force distinct stored entries, and assert
    // the engine-wide byte budget is never exceeded and no OOM occurs.
    for (0..40) |k| {
        const env = try h.forger(0).sign(@intCast(k + 1), .{ .nominate = .{
            .qset_hash = qh,
            .votes = @ptrCast(votes),
            .accepted = &.{},
        } });
        defer gpa.free(env);
        const r = try h.injectNow(0, env);
        try testing.expect(r.status == .applied or r.status == .over_limit);
        // Invariant: stored bytes NEVER exceed the configured budget.
        try testing.expect(h.honest[0].eng.stats().stored_statement_bytes <= budget);
    }

    // The honest node is still healthy and makes progress.
    try seedProposals(&h, 1);
    try h.run(honestBound(), 1);
    try h.checkAgreement(1);
}

// --- 6. non-canonical encoder ----------------------------------------------
// §4.2: receive-side canonicality. strict_canonical=true engines reject a
// valid signature over non-canonical bytes as `insane`; lenient engines
// accept. Both stay safe.

test "byz non-canonical encoder: strict rejects insane, lenient accepts, both safe" {
    const gpa = testing.allocator;

    // Strict engine.
    {
        var h = try Harness.init(gpa, shape_3_1, .{ .strict_canonical = true });
        defer h.deinit();
        const qh = h.sharedHash();
        const nc = try h.forger(0).signNonCanonical(1, .{ .nominate = .{ .qset_hash = qh, .votes = &.{"nc"}, .accepted = &.{} } });
        defer gpa.free(nc);
        const r = try h.injectNow(0, nc);
        try testing.expectEqual(engine.InputStatus.insane, r.status);
        try testing.expectEqual(@as(usize, 0), r.forwards);

        // Still safe + live afterward.
        try seedProposals(&h, 1);
        try h.run(honestBound(), 1);
        try h.checkAgreement(1);
        try testing.expect(h.allHonestExternalized(1));
    }

    // Lenient engine: the interop opt-out (§4.2) accepts it.
    {
        var h = try Harness.init(gpa, shape_3_1, .{ .strict_canonical = false });
        defer h.deinit();
        const qh = h.sharedHash();
        const nc = try h.forger(0).signNonCanonical(1, .{ .nominate = .{ .qset_hash = qh, .votes = &.{"nc"}, .accepted = &.{} } });
        defer gpa.free(nc);
        const r = try h.injectNow(0, nc);
        try testing.expectEqual(engine.InputStatus.applied, r.status);

        try seedProposals(&h, 1);
        try h.run(honestBound(), 1);
        try h.checkAgreement(1);
    }
}

// --- 7. sig forger ---------------------------------------------------------
// §4.2 domain separation + signature verification: a corrupted signature and a
// correctly-signed-but-wrong-network envelope both fail verify → never
// processed.

test "byz sig forger: forged signature and wrong-network are invalid_signature, never processed" {
    const gpa = testing.allocator;
    var h = try Harness.init(gpa, shape_3_1, .{});
    defer h.deinit();

    const qh = h.sharedHash();
    const st = adversary.RawStatement{ .nominate = .{ .qset_hash = qh, .votes = &.{"forge"}, .accepted = &.{} } };

    const forged = try h.forger(0).signForged(1, st);
    defer gpa.free(forged);
    const r1 = try h.injectNow(0, forged);
    try testing.expectEqual(engine.InputStatus.invalid_signature, r1.status);
    try testing.expectEqual(@as(usize, 0), r1.forwards);

    // Wrong network: correctly signed under a foreign networkId → digest
    // differs on our network → invalid_signature.
    const other_net = crypto.networkIdFromPassphrase("some-other-network");
    const xnet = try h.forger(0).signWrongNetwork(other_net, 1, st);
    defer gpa.free(xnet);
    const r2 = try h.injectNow(0, xnet);
    try testing.expectEqual(engine.InputStatus.invalid_signature, r2.status);
    try testing.expectEqual(@as(usize, 0), r2.forwards);

    // Nothing was stored: the honest node has no live slot from these.
    try testing.expectEqual(@as(usize, 0), h.honest[0].eng.stats().live_slots);

    // Honest quorum still externalizes.
    try seedProposals(&h, 1);
    try h.run(honestBound(), 1);
    try h.checkAgreement(1);
    try testing.expect(h.allHonestExternalized(1));
}

// --- 8. crash-at-phase -----------------------------------------------------
// A Byzantine validator falling silent mid-protocol (at nomination, and never
// participating). The honest quorum (h >= threshold) still externalizes.

test "byz crash-at-phase: adversary silent from start; honest quorum externalizes" {
    const gpa = testing.allocator;
    var h = try Harness.init(gpa, shape_3_1, .{});
    defer h.deinit();

    // Adversary never emits anything.
    try seedProposals(&h, 1);
    try h.run(honestBound(), 1);
    try h.checkAgreement(1);
    try testing.expect(h.allHonestExternalized(1));
}

test "byz crash-at-phase: adversary nominates then goes silent; honest quorum externalizes" {
    const gpa = testing.allocator;
    var h = try Harness.init(gpa, shape_5_2, .{});
    defer h.deinit();

    const qh = h.sharedHash();
    try seedProposals(&h, 1);

    // Both adversaries participate honestly in nomination for slot 1, then
    // fall silent (never send ballot statements).
    for (0..2) |j| {
        const nom = try h.forger(j).sign(1, .{ .nominate = .{ .qset_hash = qh, .votes = &.{"crash-nom"}, .accepted = &.{} } });
        defer gpa.free(nom);
        try h.injectMaskAt(2, 0b11111, nom);
    }

    try h.run(honestBound(), 1);
    try h.checkAgreement(1);
    try testing.expect(h.allHonestExternalized(1));
}

// --- Byzantine seed matrix (§14-M3 accept criterion) -----------------------
// seeds 1..50 × {equivocator, counter-inflator}. The "seed" perturbs the
// per-hop bus latency and the adversary's value/counter choices; every cell
// must preserve agreement and never trip an invariant or leak.

pub const MatrixActor = enum { equivocator, inflator };

/// Run every seed in [1, seeds] × {equivocator, inflator}. The §14-M3 accept
/// gate; `zig build test` runs 50 seeds, `zig build byz-matrix` runs 1000.
pub fn runMatrix(gpa: std.mem.Allocator, seeds: u64) !void {
    var seed: u64 = 1;
    while (seed <= seeds) : (seed += 1) {
        try matrixCell(gpa, seed, .equivocator);
        try matrixCell(gpa, seed, .inflator);
    }
}

fn matrixCell(gpa: std.mem.Allocator, seed: u64, actor: MatrixActor) !void {
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    const latency: u32 = 5 + rnd.uintAtMost(u32, 200);
    var h = try Harness.init(gpa, shape_3_1, .{ .latency_ms = latency });
    defer h.deinit();

    try seedProposals(&h, 1);
    const qh = h.sharedHash();

    // Randomized adversary values keep the attack from being a fixed string.
    var va: [8]u8 = undefined;
    var vb: [8]u8 = undefined;
    rnd.bytes(&va);
    rnd.bytes(&vb);

    switch (actor) {
        .equivocator => {
            const counter: u32 = 1 + rnd.uintAtMost(u32, 3);
            const pair = try adversary.equivocatingPrepares(h.forger(0), 1, qh, counter, &va, &vb);
            defer gpa.free(pair.a);
            defer gpa.free(pair.b);
            try h.injectMaskAt(latency / 2 + 1, 0b001, pair.a);
            try h.injectMaskAt(latency / 2 + 1, 0b110, pair.b);
        },
        .inflator => {
            const counters = [_]u32{ rnd.int(u32) | 1, std.math.maxInt(u32) };
            for (counters) |c| {
                const env = try h.forger(0).sign(1, .{ .prepare = .{ .qset_hash = qh, .ballot = .{ .counter = c, .value = &va } } });
                defer gpa.free(env);
                try h.injectMaskAt(1, 0b111, env);
            }
        },
    }

    try h.run(honestBound(), 1);
    try h.checkAgreement(1); // the seed-matrix safety assertion
    // Agreement is the hard invariant; liveness under adversarial timing is
    // expected here too (honest quorum is intact), so require it.
    try testing.expect(h.allHonestExternalized(1));
}

test "byz seed matrix: seeds 1..50 x {equivocator, counter-inflator} preserve agreement" {
    try runMatrix(testing.allocator, 50);
}

// --- baseline sanity: the harness itself converges with no adversary --------

test "byz baseline: honest-only quorum externalizes (both shapes)" {
    const gpa = testing.allocator;
    inline for (.{ shape_3_1, shape_5_2 }) |shape| {
        var h = try Harness.init(gpa, shape, .{});
        defer h.deinit();
        try seedProposals(&h, 1);
        try h.run(honestBound(), 1);
        try h.checkAgreement(1);
        try testing.expect(h.allHonestExternalized(1));
    }
}
