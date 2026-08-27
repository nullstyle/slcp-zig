//! stellar-core oracle scenarios (design §13.3): a curated port of the SCP
//! unit-test torture cases from stellar-core/src/scp/test/SCPTests.cpp into
//! SLCP scenarios with expected-behavior assertions.
//!
//! Scenarios 1, 2 and 4 drive a single Engine directly through pushInput
//! with fabricated peer envelopes (the pipeline.zig test pattern: emit.emit
//! with a peer Ctx), mirroring the oracle's TestSCP::receiveEnvelope calls;
//! ballot state fields are asserted directly (they are pub). Scenario 3
//! drives a fresh engine with only EXTERNALIZE statements. Scenario 5 runs
//! the full 3-node simulator and cross-checks the outcome against an
//! INDEPENDENT leader computation via the slcp.nomination Gi machinery over
//! the self-excised qsets.
//!
//! Oracle qset shapes, scaled per §13.3:
//!  - the core5 shape (SCPTests.cpp:834-859): 5 nodes {self, v1..v4},
//!    threshold 4 — v-blocking size 2, quorum 4, so a v-blocking set is
//!    NEVER quorum-completing (scenarios 1, 2, 4);
//!  - a 2-of-3 {self, v1, v2} for the EXTERNALIZE catch-up (scenario 3),
//!    where exactly two externalizing peers + self complete a quorum through
//!    the singleton-qset arm.

const std = @import("std");
const testing = std.testing;

const slcp = @import("slcp-core");
const sim = @import("sim.zig");
const scenario = @import("scenario.zig");
const invariants = @import("invariants.zig");

const engine = slcp.engine;
const crypto = slcp.crypto;
const qset = slcp.qset;
const qset_store = slcp.qset_store;
const stored = slcp.stored;
const emit_mod = slcp.emit;
const ballot = slcp.ballot;
const nomination = slcp.nomination;
const driver = slcp.driver;

// ---------------------------------------------------------------------------
// Fixture: engine + fabricated peer envelopes (pipeline.zig test pattern)
// ---------------------------------------------------------------------------

const self_seed: [32]u8 = @splat(0x11);
const peer_seeds = [4][32]u8{ @splat(0x22), @splat(0x33), @splat(0x44), @splat(0x55) };

fn testNet() [32]u8 {
    return crypto.networkIdFromPassphrase("oracle-scenarios-net");
}

/// Engine over a shared flat qset {self, peer_seeds[0..n_peers]} with the
/// given threshold. Peers advertise the SAME qset hash the engine
/// self-inserts at init, so no statement ever parks.
fn makeEngine(gpa: std.mem.Allocator, comptime n_peers: usize, threshold: u32) !engine.Engine {
    const self_pk = try crypto.publicKeyFromSeed(self_seed);
    var members: [n_peers + 1][32]u8 = undefined;
    members[0] = self_pk;
    inline for (0..n_peers) |i| members[i + 1] = try crypto.publicKeyFromSeed(peer_seeds[i]);

    const vals = try gpa.dupe([32]u8, &members);
    errdefer gpa.free(vals);
    var qs = qset.QuorumSetOwned{
        .threshold = threshold,
        .validators = vals,
        .inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0),
    };
    try qset.validateAndNormalize(gpa, &qs);
    return engine.Engine.init(gpa, .{
        .network_id = testNet(),
        .node_id = self_pk,
        .secret_seed = self_seed,
        .quorum_set = qs,
    }, driver.Driver.default());
}

/// Signed Envelope frame from `seed`'s keypair via emit (a stand-in peer
/// Ctx) — the peer-envelope fabrication pattern from src/engine/pipeline.zig.
/// Caller frees.
fn peerEnvelope(gpa: std.mem.Allocator, seed: [32]u8, slot: u64, own: emit_mod.OwnStatement) ![]u8 {
    var effects = engine.EffectQueue.init(gpa);
    defer effects.deinit();
    var store = qset_store.Store.init(gpa, 4);
    defer store.deinit();
    const cfg = engine.Config{
        .network_id = testNet(),
        .node_id = try crypto.publicKeyFromSeed(seed),
        .secret_seed = seed,
        .quorum_set = undefined, // emit never touches it
        .limits = .{},
    };
    const drv = driver.Driver.default();
    var stored_bytes: usize = 0;
    var ctx = engine.Ctx{
        .gpa = gpa,
        .cfg = &cfg,
        .drv = &drv,
        .effects = &effects,
        .qsets = &store,
        .excised = null,
        .local_qset_hash = @splat(0),
        .stored_bytes = &stored_bytes,
    };
    var env = try emit_mod.emit(&ctx, slot, own);
    defer env.deinit(gpa);
    return gpa.dupe(u8, env.envelope_framed);
}

/// Drain ALL effects of the last input; asserts exactly one input_status,
/// pushed last (the §5.3 1:1 rule). Keeps a copy of the LAST
/// persist_own_envelope frame and the last externalized value.
const Drained = struct {
    status: engine.InputStatus = undefined,
    persists: usize = 0,
    externalized: usize = 0,
    last_persist: ?[]u8 = null,
    last_externalized: ?[]u8 = null,

    fn deinit(self: *Drained, gpa: std.mem.Allocator) void {
        if (self.last_persist) |b| gpa.free(b);
        if (self.last_externalized) |b| gpa.free(b);
        self.* = undefined;
    }
};

fn drain(gpa: std.mem.Allocator, eng: *engine.Engine) !Drained {
    var out = Drained{};
    errdefer out.deinit(gpa);
    var got_status = false;
    while (eng.popEffect()) |e| {
        try testing.expect(!got_status); // input_status is ALWAYS last
        switch (e.*) {
            .input_status => |st| {
                out.status = st.code;
                got_status = true;
            },
            .persist_own_envelope => |sb| {
                out.persists += 1;
                if (out.last_persist) |b| gpa.free(b);
                out.last_persist = try gpa.dupe(u8, sb.bytes);
            },
            .externalized => |sb| {
                out.externalized += 1;
                if (out.last_externalized) |b| gpa.free(b);
                out.last_externalized = try gpa.dupe(u8, sb.bytes);
            },
            else => {},
        }
        eng.commitEffect();
    }
    try testing.expect(got_status); // exactly one per input
    return out;
}

/// Push one input, drain, and assert the input_status.
fn pushExpect(gpa: std.mem.Allocator, eng: *engine.Engine, input: engine.Input, expected: engine.InputStatus) !Drained {
    try eng.pushInput(input);
    var d = try drain(gpa, eng);
    errdefer d.deinit(gpa);
    try testing.expectEqual(expected, d.status);
    return d;
}

fn pushEnvelope(gpa: std.mem.Allocator, eng: *engine.Engine, seed: [32]u8, slot: u64, own: emit_mod.OwnStatement) !Drained {
    const env = try peerEnvelope(gpa, seed, slot, own);
    defer gpa.free(env);
    return pushExpect(gpa, eng, .{ .envelope_received = .{ .bytes = env } }, .applied);
}

fn ballotState(eng: *engine.Engine, slot: u64) *ballot.State {
    return &eng.slots.get(slot).?.ballot; // boxed slot: pointer stable
}

fn expectBallot(b: ?stored.OwnedBallot, counter: u32, value: []const u8) !void {
    try testing.expect(b != null);
    try testing.expectEqual(counter, b.?.counter);
    try testing.expectEqualSlices(u8, value, b.?.value);
}

const BV = emit_mod.BV;

fn prepareSt(qh: [32]u8, b: BV, p: ?BV, pp: ?BV, n_c: u32, n_h: u32) emit_mod.OwnStatement {
    return .{ .prepare = .{
        .qset_hash = qh,
        .ballot = b,
        .prepared = p,
        .prepared_prime = pp,
        .n_c = n_c,
        .n_h = n_h,
    } };
}

// Ordered like the oracle's xValue < zValue (aValue = x, bValue = z in the
// "start <1,x>" section, SCPTests.cpp:1005-1008).
const val_a = "aaa-value";
const val_z = "zzz-value";

/// Shared preamble for scenarios 1 and 2 — the peer half of the oracle's
/// nodesAllPledgeToCommit (SCPTests.cpp:933-988), without the local
/// bumpState: three peers send PREPARE(b=(1,a), p=(1,a)); on the second the
/// engine accepts prepared (1,a) (v-blocking, BallotProtocol.cpp:938-969),
/// on the third a 4-of-5 quorum ratifies it, so setConfirmPrepared
/// (BallotProtocol.cpp:1136-1221) sets h=c=(1,a) — the local node VOTES
/// commit (nC=1) while staying in phase PREPARE — and step (8) adopts
/// b=(1,a).
fn pledgePreamble(gpa: std.mem.Allocator, eng: *engine.Engine) !void {
    const qh = eng.ctx.local_qset_hash;
    const a1: BV = .{ .counter = 1, .value = val_a };
    for (peer_seeds[0..3]) |sd| {
        var d = try pushEnvelope(gpa, eng, sd, 1, prepareSt(qh, a1, a1, null, 0, 0));
        d.deinit(gpa);
    }
    const bs = ballotState(eng, 1);
    try testing.expectEqual(ballot.Phase.prepare, bs.phase);
    try expectBallot(bs.current, 1, val_a);
    try expectBallot(bs.prepared, 1, val_a);
    try expectBallot(bs.high, 1, val_a);
    try expectBallot(bs.commit, 1, val_a); // c is SET (voting to commit)
}

// ---------------------------------------------------------------------------
// 1. c-reset on higher incompatible prepared
//
// Port of SCPTests.cpp:1343-1360 — SECTION "get conflicting prepared B" /
// "same counter" (inside "ballot protocol core5" → "start <1,x>" →
// "Confirm prepared A2"): with h=c set on the a-value ballot, a v-blocking
// set announcing prepared (1,z) (z incompatible, same counter, higher value)
// makes the node accept prepared (1,z); since h ⋦ p the commit vote is
// CLEARED — the oracle's expected envelope is PREPARE(b=A_, p=B_, nC=0,
// nH=1, p'=A_) (SCPTests.cpp:1349-1352). Mechanism: setAcceptPrepared's
// c-reset, BallotProtocol.cpp:989-1003.
// ---------------------------------------------------------------------------

test "oracle: c-reset on higher incompatible prepared" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, 4, 4); // core5 shape: 4-of-5
    defer eng.deinit();
    try pledgePreamble(gpa, &eng);
    const qh = eng.ctx.local_qset_hash;
    const z1: BV = .{ .counter = 1, .value = val_z };

    // v-blocking (2 of 5) announces prepared (1,z) — the oracle's
    // recvVBlocking(makePrepareGen(qSetHash, B2, &B2)), SCPTests.cpp:1347.
    {
        var d = try pushEnvelope(gpa, &eng, peer_seeds[0], 1, prepareSt(qh, z1, z1, null, 0, 0));
        d.deinit(gpa);
    }
    // One peer is not v-blocking: nothing may change yet.
    {
        const bs = ballotState(&eng, 1);
        try expectBallot(bs.prepared, 1, val_a);
        try expectBallot(bs.commit, 1, val_a);
    }
    var d = try pushEnvelope(gpa, &eng, peer_seeds[1], 1, prepareSt(qh, z1, z1, null, 0, 0));
    defer d.deinit(gpa);

    const bs = ballotState(&eng, 1);
    try testing.expectEqual(ballot.Phase.prepare, bs.phase);
    try testing.expect(bs.commit == null); // c CLEARED (the c-reset)
    try expectBallot(bs.prepared, 1, val_z); // p  = (1,z)
    try expectBallot(bs.prepared_prime, 1, val_a); // p' = (1,a)
    try expectBallot(bs.high, 1, val_a); // h survives
    try expectBallot(bs.current, 1, val_a); // b unchanged

    // The emitted own statement mirrors the oracle's verifyPrepare
    // (SCPTests.cpp:1349-1352): PREPARE(b=a, p=z, p'=a, nC=0, nH=1).
    var st = try invariants.decodeOwnEnvelope(gpa, d.last_persist.?);
    defer st.deinit(gpa);
    try testing.expect(st.pledges == .prepare);
    const p = &st.pledges.prepare;
    try testing.expectEqualSlices(u8, val_a, p.ballot.value);
    try testing.expectEqualSlices(u8, val_z, p.prepared.?.value);
    try testing.expectEqualSlices(u8, val_a, p.prepared_prime.?.value);
    try testing.expectEqual(@as(u32, 0), p.n_c);
    try testing.expectEqual(@as(u32, 1), p.n_h);
}

// ---------------------------------------------------------------------------
// 2. v-blocking counter jump (no timer)
//
// Port of SCPTests.cpp:1524-1539 — SECTION "prepare higher counter
// (v-blocking)": a v-blocking set with ballot counters strictly ahead makes
// the node jump its counter immediately, WITHOUT any timer, to the SMALLEST
// counter at which the set is no longer strictly ahead. The oracle jumps
// 1→2→3 off B2/B3; here the two peers sit at counters 5 and 7, so the node
// must jump 1→5 (not 7) in one step. Mechanism: BallotProtocol::attemptBump,
// BallotProtocol.cpp:1559-1602 (step 9 of the paper).
// ---------------------------------------------------------------------------

test "oracle: v-blocking counter jump without timer" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, 4, 4); // core5 shape: 4-of-5
    defer eng.deinit();
    try pledgePreamble(gpa, &eng);
    const qh = eng.ctx.local_qset_hash;
    const a1: BV = .{ .counter = 1, .value = val_a };

    // One peer at counter 5: not v-blocking alone — counter must not move
    // (the oracle's "nothing should happen with first message",
    // SCPTests.cpp:875-880).
    {
        var d = try pushEnvelope(gpa, &eng, peer_seeds[0], 1, prepareSt(qh, .{ .counter = 5, .value = val_a }, a1, null, 0, 0));
        d.deinit(gpa);
        try testing.expectEqual(@as(u32, 1), ballotState(&eng, 1).current.?.counter);
    }

    // Second peer at counter 7 completes the v-blocking set {5, 7}. NO
    // timer_fired input is ever pushed in this test: the jump is immediate,
    // and lands on 5 — the smallest counter with no v-blocking set strictly
    // ahead — never 7.
    var d = try pushEnvelope(gpa, &eng, peer_seeds[1], 1, prepareSt(qh, .{ .counter = 7, .value = val_a }, a1, null, 0, 0));
    defer d.deinit(gpa);

    const bs = ballotState(&eng, 1);
    try testing.expectEqual(ballot.Phase.prepare, bs.phase);
    try expectBallot(bs.current, 5, val_a); // jumped 1 → 5, not 7
    try expectBallot(bs.high, 1, val_a); // h/c untouched (compatible bump)
    try expectBallot(bs.commit, 1, val_a);

    // The own statement emitted by the jump carries the new counter.
    var st = try invariants.decodeOwnEnvelope(gpa, d.last_persist.?);
    defer st.deinit(gpa);
    try testing.expect(st.pledges == .prepare);
    try testing.expectEqual(@as(u32, 5), st.pledges.prepare.ballot.counter);
}

// ---------------------------------------------------------------------------
// 3. EXTERNALIZE-∞ catch-up
//
// Port of SCPTests.cpp:2643-2672 — SECTION "non validator watching the
// network": a node that never took part in a slot reaches EXTERNALIZE
// purely from peers' EXTERNALIZE statements, because each EXTERNALIZE
// sender counts as the singleton qset {threshold 1, [sender]} with ballot
// counter ∞ (Slot::getQuorumSetFromStatement, Slot.cpp:316-348;
// LocalNode::getSingletonQSet, LocalNode.cpp:66). The oracle needs 4
// externalizers for its 4-of-5 qset; scaled to a 2-of-3 here, exactly TWO
// peers' EXTERNALIZE statements complete the {v1, v2, self} quorum through
// the singleton arm. Expected intermediate/final counters mirror the
// oracle's verifyConfirm(∞, (∞,x), c, ∞) / verifyExternalize(c, ∞)
// (SCPTests.cpp:2661-2671).
// ---------------------------------------------------------------------------

test "oracle: EXTERNALIZE-infinity catch-up on a fresh engine" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, 2, 2); // 2-of-3 {self, v1, v2}
    defer eng.deinit();
    const inf = std.math.maxInt(u32);
    const val_c = "catchup-value";
    const ext: emit_mod.OwnStatement = .{ .externalize = .{
        .commit = .{ .counter = 2, .value = val_c },
        .n_h = 2,
        .commit_qset_hash = eng.ctx.local_qset_hash,
    } };

    // First EXTERNALIZE: a singleton is not v-blocking and {v1, self} lacks
    // v1's vote weight... nothing externalizes yet.
    {
        var d = try pushEnvelope(gpa, &eng, peer_seeds[0], 1, ext);
        defer d.deinit(gpa);
        try testing.expectEqual(@as(usize, 0), d.externalized);
        try testing.expect(eng.slots.get(1).?.externalized_value == null);
    }

    // Second EXTERNALIZE completes the singleton-arm quorum: the fresh
    // engine accepts prepared (∞,c), confirms, accepts commit, and
    // externalizes — in ONE input.
    var d = try pushEnvelope(gpa, &eng, peer_seeds[1], 1, ext);
    defer d.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), d.externalized);
    try testing.expectEqualSlices(u8, val_c, d.last_externalized.?);

    const s = eng.slots.get(1).?;
    const bs = &s.ballot;
    try testing.expectEqual(ballot.Phase.externalize, bs.phase);
    try testing.expectEqualSlices(u8, val_c, s.externalized_value.?);
    try expectBallot(bs.commit, 2, val_c); // c = (2,c) — the ratified low bound
    try expectBallot(bs.high, inf, val_c); // h = (∞,c)
    try expectBallot(bs.current, inf, val_c); // b = (∞,c)

    // The engine's own final statement is an EXTERNALIZE(commit=(2,c), nH=∞)
    // — the oracle's verifyExternalize(..., b, UINT32_MAX) shape.
    var st = try invariants.decodeOwnEnvelope(gpa, d.last_persist.?);
    defer st.deinit(gpa);
    try testing.expect(st.pledges == .externalize);
    try testing.expectEqual(@as(u32, 2), st.pledges.externalize.commit.counter);
    try testing.expectEqual(inf, st.pledges.externalize.n_h);
}

// ---------------------------------------------------------------------------
// 4. Value-override stickiness across timeouts
//
// Port of SCPTests.cpp:2523-2549 — SECTION "timeout when h exists but can't
// be set -> vote for h" (plus a second timeout): the node's ballot is on
// value y (its nomination composite), but a quorum confirms the x-value
// ballot prepared. setConfirmPrepared cannot set h (b is on the
// incompatible y) but it DOES latch mValueOverride = x
// (BallotProtocol.cpp:1145-1146; the same override that setAcceptCommit
// latches at :1478-1479). On every subsequent ballot timeout the override
// beats both the composite and the current value (bumpState value pick,
// BallotProtocol.cpp:456-465): each emitted PREPARE keeps value x while the
// nomination composite stays y — the oracle's verifyPrepare(newbx=(2,x),
// &bx, 0, 1) at SCPTests.cpp:2545-2548.
// ---------------------------------------------------------------------------

test "oracle: value-override stickiness across ballot timeouts" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, 4, 4); // core5 shape: 4-of-5
    defer eng.deinit();
    const qh = eng.ctx.local_qset_hash;
    const val_x = "aaa-locked"; // x < y, incompatible values
    const val_y = "yyy-composite";
    const x1: BV = .{ .counter = 1, .value = val_x };

    // Nomination: the app proposes y and a quorum of peers nominates y, so
    // the confirmed composite is y and the ballot starts at b=(1,y).
    {
        var d = try pushExpect(gpa, &eng, .{ .nominate = .{ .slot = 1, .value = val_y, .prev_value = "prev" } }, .applied);
        d.deinit(gpa);
    }
    for (peer_seeds[0..3]) |sd| {
        var d = try pushEnvelope(gpa, &eng, sd, 1, .{ .nominate = .{
            .qset_hash = qh,
            .votes = &.{val_y},
            .accepted = &.{val_y},
        } });
        d.deinit(gpa);
    }
    {
        const s = eng.slots.get(1).?;
        try testing.expectEqualSlices(u8, val_y, s.nom.latest_composite.?);
        try expectBallot(s.ballot.current, 1, val_y);
        try testing.expect(s.ballot.value_override == null);
    }

    // But the quorum goes with x: v-blocking → accept prepared (1,x); quorum
    // → confirm prepared (1,x). h CANNOT be set (b=(1,y) is incompatible,
    // BallotProtocol.cpp:1148-1150) — yet the value override latches to x.
    for (peer_seeds[0..3]) |sd| {
        var d = try pushEnvelope(gpa, &eng, sd, 1, prepareSt(qh, x1, x1, null, 0, 0));
        d.deinit(gpa);
    }
    {
        const bs = ballotState(&eng, 1);
        try expectBallot(bs.current, 1, val_y); // still on y
        try expectBallot(bs.prepared, 1, val_x);
        try testing.expect(bs.high == null); // h could not be set
        try testing.expectEqualSlices(u8, val_x, bs.value_override.?); // latched
    }

    // First ballot timeout: the override WINS over the y composite — the
    // emitted PREPARE is (2,x) with p=(1,x), nC=0, nH=1 (the h gets set by
    // the self-recursion once b is compatible) — SCPTests.cpp:2540-2548.
    {
        var d = try pushExpect(gpa, &eng, .{ .timer_fired = .{ .slot = 1, .timer = .ballot } }, .applied);
        defer d.deinit(gpa);
        var st = try invariants.decodeOwnEnvelope(gpa, d.last_persist.?);
        defer st.deinit(gpa);
        try testing.expect(st.pledges == .prepare);
        const p = &st.pledges.prepare;
        try testing.expectEqual(@as(u32, 2), p.ballot.counter);
        try testing.expectEqualSlices(u8, val_x, p.ballot.value);
        try testing.expectEqualSlices(u8, val_x, p.prepared.?.value);
        try testing.expectEqual(@as(u32, 0), p.n_c);
        try testing.expectEqual(@as(u32, 1), p.n_h);
    }

    // Second timeout: STILL x (stickiness across timeouts), counter 3,
    // even though the nomination composite remains y.
    {
        var d = try pushExpect(gpa, &eng, .{ .timer_fired = .{ .slot = 1, .timer = .ballot } }, .applied);
        defer d.deinit(gpa);
        var st = try invariants.decodeOwnEnvelope(gpa, d.last_persist.?);
        defer st.deinit(gpa);
        try testing.expect(st.pledges == .prepare);
        try testing.expectEqual(@as(u32, 3), st.pledges.prepare.ballot.counter);
        try testing.expectEqualSlices(u8, val_x, st.pledges.prepare.ballot.value);
    }
    const s = eng.slots.get(1).?;
    try expectBallot(s.ballot.current, 3, val_x);
    try testing.expectEqualSlices(u8, val_y, s.nom.latest_composite.?); // composite never switched
}

// ---------------------------------------------------------------------------
// 5. Nomination race: leader determinism
//
// Port of SCPTests.cpp:2924-3003 ("nomination tests core5" → "nomination -
// v0 is top" → "others nominate what v0 says (x) -> prepare x") and
// :3275-3339 ("v1 is top node"): whichever node the per-round Gi priority
// machinery elects as the round-0 leader is whose value the network adopts
// and externalizes. Here the full 3-node simulator runs a nomination race
// (every node proposes its own value at t=0 on a fixed seed) and the
// expected winner is computed INDEPENDENTLY through the slcp.nomination
// leader functions (weight/priority over the SELF-EXCISED qsets — the
// oracle's normalizeQSet(myQSet, &localID), NominationProtocol.cpp:226).
// ---------------------------------------------------------------------------

test "oracle: nomination race externalizes the round-0 leader's value" {
    const gpa = testing.allocator;

    // Fixed cell: healthy 3-node network, one proposal per node at t=0.
    // Node identities are pinned by sim.Sim.init (seeds 0x10+i).
    const cfg = scenario.config(.healthy, 7, 3);
    var s = try sim.Sim.init(gpa, cfg);
    defer s.deinit();
    const res = try s.run(scenario.bound_ms);
    try testing.expect(!res.stalled);
    try s.checkAgreement();
    try s.checkValidity();
    try s.checkLiveness(0);

    // Independent expectation: recompute every node's round-0 leader from
    // scratch via the nomination Gi machinery over its self-excised qset.
    var pks: [3][32]u8 = undefined;
    for (0..3) |i| {
        const seed: [32]u8 = @splat(@as(u8, 0x10) + @as(u8, @intCast(i)));
        pks[i] = try crypto.publicKeyFromSeed(seed);
    }
    var shared = blk: {
        const vals = try gpa.dupe([32]u8, &pks);
        errdefer gpa.free(vals);
        break :blk qset.QuorumSetOwned{
            .threshold = sim.thresholdFor(3),
            .validators = vals,
            .inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0),
        };
    };
    defer shared.deinit(gpa);
    try qset.validateAndNormalize(gpa, &shared);

    var leaders: [3][32]u8 = undefined;
    for (0..3) |i| {
        var excised = (try qset.exciseNode(gpa, &shared, pks[i])).?;
        defer excised.deinit(gpa);
        const r = nomination.LeaderRound{
            .slot = 1,
            .prev_value = "genesis", // sim.Proposal default prev_value
            .round = 0,
            .local_node = pks[i],
            .qs = &excised,
        };
        leaders[i] = (try nomination.roundLeader(gpa, r)).?;
    }
    // On this fixed identity set every node elects the SAME round-0 leader
    // (self weighs maxInt but the top-priority node's neighbor draw passes
    // for all viewers) — the deterministic analog of "v0 is top".
    try testing.expectEqualSlices(u8, &leaders[0], &leaders[1]);
    try testing.expectEqualSlices(u8, &leaders[0], &leaders[2]);

    var leader_idx: usize = 3;
    for (0..3) |i| {
        if (std.mem.eql(u8, &leaders[0], &pks[i])) leader_idx = i;
    }
    try testing.expect(leader_idx < 3);

    // The externalized value is exactly the round-0 leader's proposal, on
    // every node ("others nominate what the leader says").
    const expected = scenario.proposal_values[leader_idx];
    for (0..3) |node| {
        const got = s.externalizedValue(@intCast(node), 1).?;
        try testing.expectEqualSlices(u8, expected, got);
    }
}
