//! Nomination protocol (design §5.4 `nomination.zig` bullet): the Gi leader
//! election machinery (M1) plus the X/Y/Z-set nomination protocol itself
//! (M2) — a line-level transcription of stellar-core
//! `NominationProtocol` (NominationProtocol.cpp), with the design-normative
//! divergences called out inline (§5.4 own-set admission cap, the 3-level
//! validity collapse, SLCP round numbering).
//!
//! Oracle: stellar-core `NominationProtocol::updateRoundLeaders` /
//! `getNodePriority` / `hashNode` / `hashValue` /
//! `getNewValueFromNomination` (NominationProtocol.cpp) and
//! `SCPDriver::computeHashNode` / `computeValueHash` / `getNodeWeight`
//! (SCPDriver.cpp). The hash itself is SLCP's Gi (§5.4, crypto.zig):
//! `Gi(tag, m) = first 8 bytes BE of SHA-256("SLCP-GI-V1\x00\x00" ‖ slot:u64be
//! ‖ prevValue ‖ tag:u32be ‖ round:u32be ‖ m)`, tags 1 = neighbor,
//! 2 = priority, 3 = valueHash — the byte layout is normative and vectored
//! (`vectors/leader.json`).
//!
//! Self-excision (design §5.4/§12, normative): leader weights for OTHER
//! nodes are computed over the SELF-EXCISED local qset — `qset.exciseNode` of
//! the configured set, matching stellar-core's `normalizeQSet(myQSet,
//! &localID)` before any weighting (NominationProtocol.cpp:226; removal +
//! threshold decrement in QuorumSetUtils.cpp:137-174). The local node itself
//! never consults the tree: its weight is pinned to maxInt(u64).
//!
//! Documented divergences from the oracle (design text normative):
//! - stellar-core keeps EVERY node tied at top priority as a leader
//!   (`std::set` insert, NominationProtocol.cpp:261-264). SLCP's
//!   `roundLeader` returns exactly one node: the LOWEST NodeId among the
//!   tied maximum — i.e. the first element of the oracle's ascending-ordered
//!   set. With 64-bit Gi outputs a tie is a ~2^-64 event.

const std = @import("std");
const crypto = @import("../crypto.zig");
const local_node = @import("local_node.zig");
const qset = @import("qset.zig");

pub const NodeId = qset.NodeId;

/// Inputs fixed for one (slot, round) of leader election. `prev_value` is the
/// composite value externalized for the previous slot (oracle:
/// `mPreviousValue`); `qs` is the SELF-EXCISED local qset —
/// `qset.exciseNode` of the configured set with `local_node` removed
/// (oracle: `normalizeQSet(myQSet, &localID)`, NominationProtocol.cpp:226);
/// null when excision emptied it (e.g. a singleton-self configuration), in
/// which case every node but the local one weighs 0.
pub const LeaderRound = struct {
    slot: u64,
    prev_value: []const u8,
    round: u32,
    local_node: NodeId,
    qs: ?*const qset.QuorumSetOwned,
};

/// Weight of `node` for leader election: `local_node.nodeWeight` over the
/// EXCISED qset tree (0 when excision left nothing), except the local node
/// itself gets maxInt(u64) — "local node is in all quorum sets" (oracle:
/// SCPDriver::getNodeWeight's `isLocalNode` early-out, SCPDriver.cpp:152-156;
/// the flag is fed by `nodeID == localID` in getNodePriority,
/// NominationProtocol.cpp:335-336).
pub fn weight(r: LeaderRound, node: NodeId) u64 {
    if (std.mem.eql(u8, &node, &r.local_node)) return std.math.maxInt(u64);
    const qs = r.qs orelse return 0;
    return local_node.nodeWeight(qs, node);
}

/// Is `node` a neighbor of the local node this round?
/// `Gi(tag=1 neighbor, node) <= weight(node)` — the design's INCLUSIVE `<=`
/// (§5.4), which the oracle also uses: "w is inclusive here as
/// 0 <= hashNode <= UINT64_MAX" (`hashNode(false, nodeID) <= w`,
/// NominationProtocol.cpp:338-341). Zero-weight nodes are never neighbors
/// (the oracle's `w > 0 &&` guard on the same line).
pub fn isNeighbor(r: LeaderRound, node: NodeId) bool {
    const w = weight(r, node);
    if (w == 0) return false;
    return crypto.gi(.neighbor, r.slot, r.prev_value, r.round, &node) <= w;
}

/// Priority of `node` this round: `Gi(tag=2 priority, node)` if neighbor,
/// else 0 (oracle: getNodePriority, NominationProtocol.cpp:330-349 —
/// `res = hashNode(true, nodeID)` behind the neighbor test, else 0).
pub fn priority(r: LeaderRound, node: NodeId) u64 {
    if (!isNeighbor(r, node)) return 0;
    return crypto.gi(.priority, r.slot, r.prev_value, r.round, &node);
}

fn containsNode(nodes: []const NodeId, node: NodeId) bool {
    for (nodes) |*n| {
        if (std.mem.eql(u8, n, &node)) return true;
    }
    return false;
}

fn collectTree(gpa: std.mem.Allocator, qs: *const qset.QuorumSetOwned, out: *std.ArrayList(NodeId)) !void {
    for (qs.validators) |v| {
        if (!containsNode(out.items, v)) try out.append(gpa, v);
    }
    for (qs.inner_sets) |*inner| try collectTree(gpa, inner, out);
}

/// The leader-election candidate set: the local node FIRST, then every node
/// appearing in the EXCISED tree in declaration order, deduplicated. The
/// local node is always a candidate — the oracle excises it from `myQSet`
/// and then unconditionally seeds `newRoundLeaders` with `localID` and its
/// priority (NominationProtocol.cpp:250-252) before scanning the excised
/// qset's nodes via `forAllNodes` (NominationProtocol.cpp:253-265).
/// Caller frees the returned slice.
pub fn memberNodes(gpa: std.mem.Allocator, r: LeaderRound) ![]NodeId {
    var out: std.ArrayList(NodeId) = .empty;
    errdefer out.deinit(gpa);
    try out.append(gpa, r.local_node);
    if (r.qs) |qs| try collectTree(gpa, qs, &out);
    return out.toOwnedSlice(gpa);
}

/// The single leader for `r.round`: the maximum-priority candidate from
/// `memberNodes`, or null when every candidate has priority 0 — the oracle's
/// "No one had priority ... fast timeout" branch (`topPriority == 0` →
/// `newRoundLeaders.clear()`, NominationProtocol.cpp:268-274). Ties at the
/// maximum resolve to the LOWEST NodeId (see the module doc's divergence
/// note; oracle keeps the whole tied set, NominationProtocol.cpp:261-264).
pub fn roundLeader(gpa: std.mem.Allocator, r: LeaderRound) !?NodeId {
    const members = try memberNodes(gpa, r);
    defer gpa.free(members);

    var best: ?NodeId = null;
    var best_priority: u64 = 0;
    for (members) |node| {
        const p = priority(r, node);
        if (p == 0) continue; // never a leader (oracle's `w > 0` insert guard)
        const better = best == null or p > best_priority or
            (p == best_priority and std.mem.order(u8, &node, &best.?) == .lt);
        if (better) {
            best = node;
            best_priority = p;
        }
    }
    return best;
}

/// Accumulating round-leader set (design §5.4: "accumulating round leaders;
/// rounds adding no new leader fast-forward"; oracle: `mRoundLeaders`
/// grow-only insert, NominationProtocol.cpp:276-296). Engine-agnostic — no
/// timers, no round counter: the caller owns the round schedule and calls
/// `advance` once per round, fast-forwarding when it returns false (the
/// oracle's `mRoundNumber++` no-op branch).
///
/// Internal representation: a sorted (ascending NodeId) dedup'd list —
/// the same iteration order as the oracle's `std::set<NodeID>`.
pub const RoundLeaders = struct {
    leaders: std.ArrayList(NodeId) = .empty,

    pub fn deinit(self: *RoundLeaders, gpa: std.mem.Allocator) void {
        self.leaders.deinit(gpa);
    }

    pub fn contains(self: *const RoundLeaders, node: NodeId) bool {
        return self.find(node) != null;
    }

    /// Sorted ascending by NodeId; borrowed until the next `advance`.
    pub fn items(self: *const RoundLeaders) []const NodeId {
        return self.leaders.items;
    }

    /// Compute the leader for `r.round` and add it if new. Returns whether
    /// the set grew — false means "fast-forward this round" (no leader, or
    /// a leader we already follow).
    pub fn advance(self: *RoundLeaders, gpa: std.mem.Allocator, r: LeaderRound) !bool {
        const leader = (try roundLeader(gpa, r)) orelse return false;
        if (self.contains(leader)) return false;
        // insertion sort into the ascending list
        var i: usize = self.leaders.items.len;
        for (self.leaders.items, 0..) |*existing, idx| {
            if (std.mem.order(u8, &leader, existing) == .lt) {
                i = idx;
                break;
            }
        }
        try self.leaders.insert(gpa, i, leader);
        return true;
    }

    fn find(self: *const RoundLeaders, node: NodeId) ?usize {
        for (self.leaders.items, 0..) |*n, i| {
            if (std.mem.eql(u8, n, &node)) return i;
        }
        return null;
    }
};

/// Index of the value with the maximum `Gi(tag=3 valueHash)` over `values`,
/// or null for an empty list.
///
/// CALLER CONTRACT (oracle: getNewValueFromNomination,
/// NominationProtocol.cpp:352-399): pass the LEADER's `accepted` list; fall
/// back to the leader's `votes` ONLY when NO VALID accepted value existed
/// (the oracle's `foundValidValue` flag). An accepted value that is valid but
/// skipped as already in our own `votes` still counts as found —
/// `foundValidValue = true` is set BEFORE the `mVotes` membership check
/// (NominationProtocol.cpp:359-383) — so such a round yields no new vote
/// rather than falling back. Validity filtering and the "skip values we
/// already vote for" rule are the M2 caller's job — this function is the
/// pure hash-maximum.
///
/// Ties keep the LATER index — transcribing the oracle's `curHash >= newHash`
/// update (NominationProtocol.cpp:377-381).
pub fn pickLeaderValue(r: LeaderRound, values: []const []const u8) ?usize {
    var best: ?usize = null;
    var best_hash: u64 = 0;
    for (values, 0..) |v, i| {
        const h = crypto.gi(.value_hash, r.slot, r.prev_value, r.round, v);
        if (best == null or h >= best_hash) {
            best = i;
            best_hash = h;
        }
    }
    return best;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn nid(byte: u8) NodeId {
    return @splat(byte);
}

/// Test-only qset over borrowed slices (no allocator, no deinit) — same
/// helper shape as local_node.zig's tests.
fn flatQs(threshold: u32, validators: []NodeId) qset.QuorumSetOwned {
    return .{ .threshold = threshold, .validators = validators, .inner_sets = &.{} };
}

const test_prev: [32]u8 = @splat(0xaa);

test "weight: self is maxInt (excised or null qset); others are nodeWeight over the excised tree" {
    const gpa = testing.allocator;
    var vals = [_]NodeId{ nid(1), nid(2), nid(3) };
    const configured = flatQs(2, &vals);

    // local INSIDE the configured qset: excised = 1-of-{2,3}; self-rule wins
    var ex_inside = (try qset.exciseNode(gpa, &configured, nid(1))).?;
    defer ex_inside.deinit(gpa);
    const inside: LeaderRound = .{ .slot = 7, .prev_value = &test_prev, .round = 0, .local_node = nid(1), .qs = &ex_inside };
    try testing.expectEqual(std.math.maxInt(u64), weight(inside, nid(1)));

    // local OUTSIDE the configured qset: excision is an unchanged copy
    var ex_outside = (try qset.exciseNode(gpa, &configured, nid(9))).?;
    defer ex_outside.deinit(gpa);
    const outside: LeaderRound = .{ .slot = 7, .prev_value = &test_prev, .round = 0, .local_node = nid(9), .qs = &ex_outside };
    try testing.expectEqual(std.math.maxInt(u64), weight(outside, nid(9)));

    // non-self member: floor(maxInt * 2 / 3); non-member: 0
    const expect23: u64 = @intCast(@as(u128, std.math.maxInt(u64)) * 2 / 3);
    try testing.expectEqual(expect23, weight(outside, nid(2)));
    try testing.expectEqual(@as(u64, 0), weight(outside, nid(8)));

    // null qset (excision emptied it, e.g. singleton-self config): self is
    // still maxInt, everyone else weighs 0
    const emptied: LeaderRound = .{ .slot = 7, .prev_value = &test_prev, .round = 0, .local_node = nid(1), .qs = null };
    try testing.expectEqual(std.math.maxInt(u64), weight(emptied, nid(1)));
    try testing.expectEqual(@as(u64, 0), weight(emptied, nid(2)));
}

test "weight: excision changes OTHER nodes' weights — 2-of-{1,2,3} with local=02" {
    const gpa = testing.allocator;
    var vals = [_]NodeId{ nid(1), nid(2), nid(3) };
    const configured = flatQs(2, &vals);

    // Excised round: qset becomes 1-of-{1,3} → others weigh floor(maxInt/2),
    // NOT the unexcised tree's floor(maxInt*2/3). This is the consensus-
    // critical F1 fix: same Gi hashes, different weight → different
    // neighbor sets → different leaders.
    var ex = (try qset.exciseNode(gpa, &configured, nid(2))).?;
    defer ex.deinit(gpa);
    const r: LeaderRound = .{ .slot = 7, .prev_value = &test_prev, .round = 0, .local_node = nid(2), .qs = &ex };

    const expect_excised: u64 = @intCast(@as(u128, std.math.maxInt(u64)) * 1 / 2);
    const expect_unexcised: u64 = @intCast(@as(u128, std.math.maxInt(u64)) * 2 / 3);
    try testing.expectEqual(expect_excised, weight(r, nid(1)));
    try testing.expectEqual(expect_excised, weight(r, nid(3)));
    try testing.expect(expect_excised != expect_unexcised);
    // the unexcised tree really would have said 2/3 — proves the flip
    try testing.expectEqual(expect_unexcised, local_node.nodeWeight(&configured, nid(1)));
}

test "neighbor and priority: deterministic, and exactly the Gi formulas" {
    const gpa = testing.allocator;
    var vals = [_]NodeId{ nid(1), nid(2), nid(3) };
    const configured = flatQs(2, &vals);
    var ex = (try qset.exciseNode(gpa, &configured, nid(1))).?; // 1-of-{2,3}
    defer ex.deinit(gpa);
    const r: LeaderRound = .{ .slot = 42, .prev_value = &test_prev, .round = 3, .local_node = nid(1), .qs = &ex };

    // self weight = maxInt, so the local node is ALWAYS a neighbor
    try testing.expect(isNeighbor(r, nid(1)));
    try testing.expectEqual(
        crypto.gi(.priority, r.slot, r.prev_value, r.round, &nid(1)),
        priority(r, nid(1)),
    );

    for ([_]NodeId{ nid(2), nid(3), nid(8) }) |node| {
        const w = weight(r, node);
        const expect_neighbor = w > 0 and
            crypto.gi(.neighbor, r.slot, r.prev_value, r.round, &node) <= w;
        try testing.expectEqual(expect_neighbor, isNeighbor(r, node));
        const expect_priority: u64 = if (expect_neighbor)
            crypto.gi(.priority, r.slot, r.prev_value, r.round, &node)
        else
            0;
        try testing.expectEqual(expect_priority, priority(r, node));
        // determinism: same inputs, same answers
        try testing.expectEqual(expect_neighbor, isNeighbor(r, node));
        try testing.expectEqual(expect_priority, priority(r, node));
    }

    // zero-weight node is never a neighbor and never has priority
    try testing.expect(!isNeighbor(r, nid(8)));
    try testing.expectEqual(@as(u64, 0), priority(r, nid(8)));
}

test "roundLeader: picks the max-priority node on a 3-node qset (expected derived via crypto.gi)" {
    const gpa = testing.allocator;
    var vals = [_]NodeId{ nid(1), nid(2), nid(3) };
    const configured = flatQs(2, &vals);
    // Local outside the qset: excision is an unchanged copy.
    var ex = (try qset.exciseNode(gpa, &configured, nid(9))).?;
    defer ex.deinit(gpa);

    // Candidates = {9, 1, 2, 3}. Scan several (slot, round) points so the
    // expected leader varies with the hash.
    var slot: u64 = 1;
    while (slot <= 4) : (slot += 1) {
        var round: u32 = 0;
        while (round < 4) : (round += 1) {
            const r: LeaderRound = .{ .slot = slot, .prev_value = &test_prev, .round = round, .local_node = nid(9), .qs = &ex };

            // independent expectation: direct crypto.gi over the candidates
            const member_w: u64 = @intCast(@as(u128, std.math.maxInt(u64)) * 2 / 3);
            var expected: ?NodeId = null;
            var expected_p: u64 = 0;
            for ([_]struct { node: NodeId, w: u64 }{
                .{ .node = nid(9), .w = std.math.maxInt(u64) },
                .{ .node = nid(1), .w = member_w },
                .{ .node = nid(2), .w = member_w },
                .{ .node = nid(3), .w = member_w },
            }) |c| {
                if (crypto.gi(.neighbor, slot, &test_prev, round, &c.node) > c.w) continue;
                const p = crypto.gi(.priority, slot, &test_prev, round, &c.node);
                if (p > expected_p) {
                    expected = c.node;
                    expected_p = p;
                }
            }

            const actual = try roundLeader(gpa, r);
            try testing.expect(actual != null);
            try testing.expectEqualSlices(u8, &expected.?, &actual.?);
        }
    }
}

test "roundLeader: local node inside the qset is excised from the tree, listed once" {
    const gpa = testing.allocator;
    var vals = [_]NodeId{ nid(1), nid(2), nid(3) };
    const configured = flatQs(2, &vals);
    var ex = (try qset.exciseNode(gpa, &configured, nid(2))).?; // 1-of-{1,3}
    defer ex.deinit(gpa);
    const r: LeaderRound = .{ .slot = 5, .prev_value = &test_prev, .round = 0, .local_node = nid(2), .qs = &ex };

    const members = try memberNodes(gpa, r);
    defer gpa.free(members);
    try testing.expectEqual(@as(usize, 3), members.len);
    // local first, then the excised tree's nodes
    try testing.expectEqualSlices(u8, &nid(2), &members[0]);
    try testing.expectEqualSlices(u8, &nid(1), &members[1]);
    try testing.expectEqualSlices(u8, &nid(3), &members[2]);

    const leader = try roundLeader(gpa, r);
    try testing.expect(leader != null);
}

test "RoundLeaders: grow-only accumulation over rounds 0..5" {
    const gpa = testing.allocator;
    var vals = [_]NodeId{ nid(1), nid(2), nid(3) };
    const configured = flatQs(2, &vals);
    var ex = (try qset.exciseNode(gpa, &configured, nid(9))).?; // local outside: no-op copy
    defer ex.deinit(gpa);

    var rl: RoundLeaders = .{};
    defer rl.deinit(gpa);

    var prev_len: usize = 0;
    var round: u32 = 0;
    while (round <= 5) : (round += 1) {
        const r: LeaderRound = .{ .slot = 11, .prev_value = &test_prev, .round = round, .local_node = nid(9), .qs = &ex };
        const grew = try rl.advance(gpa, r);

        // monotone non-shrinking; grew == exactly-one-added
        try testing.expect(rl.items().len >= prev_len);
        try testing.expectEqual(prev_len + @intFromBool(grew), rl.items().len);
        prev_len = rl.items().len;

        // this round's leader (if any) is now contained
        if (try roundLeader(gpa, r)) |leader| {
            try testing.expect(rl.contains(leader));
        }

        // sorted + dedup invariant
        for (rl.items(), 0..) |*n, i| {
            if (i > 0) {
                try testing.expect(std.mem.order(u8, &rl.items()[i - 1], n) == .lt);
            }
        }
    }
    // the set actually accumulated something
    try testing.expect(rl.items().len >= 1);

    // replaying an already-seen round never grows the set
    const r0: LeaderRound = .{ .slot = 11, .prev_value = &test_prev, .round = 0, .local_node = nid(9), .qs = &ex };
    try testing.expect(!try rl.advance(gpa, r0));
}

test "pickLeaderValue: max-Gi selection, single value, empty list" {
    // qs plays no part in value hashing — a null (fully excised) round works.
    const r: LeaderRound = .{ .slot = 3, .prev_value = &test_prev, .round = 1, .local_node = nid(1), .qs = null };

    // empty → null
    try testing.expectEqual(@as(?usize, null), pickLeaderValue(r, &.{}));

    // single → index 0 (even when its hash is small)
    try testing.expectEqual(@as(?usize, 0), pickLeaderValue(r, &.{"only"}));

    // multi: expected = argmax of direct crypto.gi calls (later index on tie)
    const values = [_][]const u8{ "alpha", "bravo", "charlie", "delta" };
    var expected: usize = 0;
    var expected_h: u64 = 0;
    for (values, 0..) |v, i| {
        const h = crypto.gi(.value_hash, r.slot, r.prev_value, r.round, v);
        if (i == 0 or h >= expected_h) {
            expected = i;
            expected_h = h;
        }
    }
    try testing.expectEqual(@as(?usize, expected), pickLeaderValue(r, &values));

    // duplicate maximum value: the LATER index wins (oracle's `>=`)
    const dup = [_][]const u8{ values[expected], values[expected] };
    try testing.expectEqual(@as(?usize, 1), pickLeaderValue(r, &dup));
}


// ---------------------------------------------------------------------------
// M2: per-slot nomination protocol state (design §5.4 nomination.zig bullet).
// The X/Y/Z sets, round tracking, and leader accumulation for one slot.
// Owned by slot.Slot; protocol logic (M2) operates on (*slot.Slot, *engine.Ctx).
// ---------------------------------------------------------------------------

const values_mod = @import("values.zig");

pub const State = struct {
    /// true once `nominate` was called (oracle: mNominationStarted).
    started: bool = false,
    /// Permanently stopped at externalize (§5.4: "nomination stops
    /// permanently only at externalize"). SLCP keeps a dedicated sticky flag
    /// where the oracle's stopNomination clears mNominationStarted
    /// (NominationProtocol.cpp:716-720) — see `stopNomination`.
    stopped: bool = false,
    /// SLCP round numbering starts at 0 on the first `nominate` call and is
    /// bumped by the nomination timer (task-normative divergence: the
    /// oracle's mRoundNumber++ lives at the top of nominate itself,
    /// NominationProtocol.cpp:591). Fast-forward rounds inside
    /// `updateRoundLeaders` bump it too (oracle 295).
    round: u32 = 0,
    /// X / Y / Z (§5.4): own votes, own accepted, confirmed candidates.
    votes: values_mod.ValueSet = .{},
    accepted: values_mod.ValueSet = .{},
    candidates: values_mod.ValueSet = .{},
    leaders: RoundLeaders = .{},
    previous_value: ?[]u8 = null,
    /// The application's proposed value from the latest `nominate` call —
    /// SLCP's stand-in for the oracle's timer closure capture of `value`
    /// (NominationProtocol.cpp:672-677); timerFired re-nominates it.
    last_value: ?[]u8 = null,
    latest_composite: ?[]u8 = null,

    pub fn deinit(self: *State, gpa: std.mem.Allocator) void {
        self.votes.deinit(gpa);
        self.accepted.deinit(gpa);
        self.candidates.deinit(gpa);
        self.leaders.deinit(gpa);
        if (self.previous_value) |v| gpa.free(v);
        if (self.last_value) |v| gpa.free(v);
        if (self.latest_composite) |v| gpa.free(v);
        self.* = undefined;
    }
};

// --- M2 protocol entry points (contract pinned for pipeline.zig / ---
// --- ballot.zig) — transcribed from stellar-core NominationProtocol.cpp ---

const engine_mod = @import("engine.zig");
const slot_mod2 = @import("slot.zig");
const stored_mod = @import("stored.zig");
const driver_mod = @import("../driver.zig");
const ballot_mod = @import("ballot.zig");
const emit_mod = @import("emit.zig");

/// The LeaderRound for the slot's CURRENT round — the (slot, prevValue,
/// round) tuple every Gi call in this module hashes over (oracle: hashNode /
/// hashValue read mPreviousValue + mRoundNumber, NominationProtocol.cpp:
/// 311-327). previous_value is set by the first `nominate`; the "" fallback
/// is defensively unreachable (leaders stay empty until nominate runs).
fn leaderRound(ctx: *const engine_mod.Ctx, s: *const slot_mod2.Slot) LeaderRound {
    return .{
        .slot = s.index,
        .prev_value = s.nom.previous_value orelse "",
        .round = s.nom.round,
        .local_node = ctx.cfg.node_id,
        .qs = ctx.excised,
    };
}

/// Per-slot cached driver validation for nomination values (§5.4: each
/// distinct value crosses the driver boundary at most once per slot; oracle:
/// NominationProtocol::validateValue → SCPDriver::validateValue,
/// NominationProtocol.cpp:73-78).
fn validateCached(ctx: *engine_mod.Ctx, s: *slot_mod2.Slot, value: []const u8) anyerror!driver_mod.Validity {
    if (s.validation_cache.get(value)) |vl| return vl;
    const vl = ctx.driverValidate(s.index, value, true);
    try s.validation_cache.put(ctx.gpa, value, vl);
    return vl;
}

/// §5.4 own-set admission cap (design-normative, no oracle counterpart):
/// once an own set holds limits.max_nomination_values entries, no further
/// values are promoted into it — superset freshness forbids shrinking, so
/// admission control is the only way to respect the frozen wire cap.
fn ownSetFull(ctx: *const engine_mod.Ctx, set: *const values_mod.ValueSet) bool {
    return set.len() >= ctx.cfg.limits.max_nomination_values;
}

/// Driver extract_valid_value fallback (oracle: extractValidValue →
/// SCPDriver::extractValidValue, NominationProtocol.cpp:80-85; stellar-core's
/// default returns nullptr, mirrored by the null vtable slot). The extracted
/// value is length-gated like any other before entering own sets. Returns an
/// owned copy or null.
fn extractValid(ctx: *engine_mod.Ctx, slot_index: u64, value: []const u8) anyerror!?[]u8 {
    const f = ctx.drv.extract_valid_value orelse return null;
    const gpa = ctx.gpa;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    if (!try f(ctx.drv.ctx, slot_index, value, gpa, &out)) return null;
    if (out.items.len == 0 or out.items.len > ctx.cfg.limits.max_value_bytes) return null;
    return try gpa.dupe(u8, out.items);
}

fn listHasValue(list: []const []u8, v: []const u8) bool {
    for (list) |x| {
        if (std.mem.eql(u8, x, v)) return true;
    }
    return false;
}

const Membership = enum { votes, accepted };

/// The node set whose LATEST nomination statement carries `v` in the given
/// array — the node-set image of the oracle's statement predicates over
/// mLatestNominations (votedPredicate NominationProtocol.cpp:438-444;
/// acceptPredicate NominationProtocol.cpp:191-199). Caller frees.
fn nodesWith(gpa: std.mem.Allocator, s: *slot_mod2.Slot, v: []const u8, which: Membership) ![]NodeId {
    var out: std.ArrayList(NodeId) = .empty;
    errdefer out.deinit(gpa);
    var it = s.latest_nom.iterator();
    while (it.next()) |e| {
        const st = &e.value_ptr.statement;
        if (st.pledges != .nominate) continue;
        const nom = &st.pledges.nominate;
        const list = switch (which) {
            .votes => nom.votes,
            .accepted => nom.accepted,
        };
        if (listHasValue(list, v)) try out.append(gpa, e.key_ptr.*);
    }
    return out.toOwnedSlice(gpa);
}

/// Federated-accept promotion into own accepted AND votes (oracle:
/// `mAccepted.emplace(vw); mVotes.emplace(vw);`, NominationProtocol.cpp:
/// 451-452 — accepting adds to both sets, §4.1), gated by the §5.4 own-set
/// admission cap: blocked when accepted is full, or when the value would
/// also need a votes slot and votes is full (keeping accepted ⊆ votes).
fn promoteToAccepted(ctx: *engine_mod.Ctx, s: *slot_mod2.Slot, v: []const u8) !bool {
    const needs_vote = !s.nom.votes.contains(v);
    if (ownSetFull(ctx, &s.nom.accepted)) return false;
    if (needs_vote and ownSetFull(ctx, &s.nom.votes)) return false;
    const gpa = ctx.gpa;
    const inserted_accepted = try s.nom.accepted.insert(gpa, v);
    var inserted_vote = false;
    if (needs_vote) inserted_vote = try s.nom.votes.insert(gpa, v);
    return inserted_accepted or inserted_vote;
}

/// Transcribed from NominationProtocol::getNewValueFromNomination
/// (NominationProtocol.cpp:352-402): pick the highest-hashValue value from
/// the leader's statement that we don't already vote for. accepted first;
/// fall back to votes only when NO valid accepted value existed (the
/// oracle's foundValidValue flag — a valid value already in own votes still
/// counts as found, cpp:374 before the mVotes check on cpp:375). Per value
/// (pickValue, cpp:361-385): validity != invalid → use the value itself
/// (SLCP's 3-level collapse of `vl >= kStructurallyValidValue`, cpp:363-367;
/// maybe_valid additionally clears fully_validated, §5.4), else the
/// extract_valid_value fallback. Ties keep the later value (`curHash >=
/// newHash`, cpp:378). Returns an owned copy of the new vote, or null.
fn getNewValueFromNomination(
    ctx: *engine_mod.Ctx,
    s: *slot_mod2.Slot,
    nom_votes: []const []u8,
    nom_accepted: []const []u8,
) anyerror!?[]u8 {
    const gpa = ctx.gpa;
    const r = leaderRound(ctx, s);
    var new_vote: ?[]u8 = null;
    errdefer if (new_vote) |nv| gpa.free(nv);
    var new_hash: u64 = 0;
    var found_valid = false;

    var pass: usize = 0;
    while (pass < 2) : (pass += 1) {
        // accepted first (cpp:387-390); votes only if nothing valid (391-399)
        if (pass == 1 and found_valid) break;
        const list = if (pass == 0) nom_accepted else nom_votes;
        for (list) |val| {
            const vl = try validateCached(ctx, s, val);
            var candidate: ?[]u8 = null; // owned (the oracle's valueToNominate)
            if (vl != .invalid) {
                if (vl == .maybe_valid) s.fully_validated = false;
                candidate = try gpa.dupe(u8, val);
            } else {
                candidate = try extractValid(ctx, s.index, val);
            }
            if (candidate) |c| {
                found_valid = true; // cpp:374
                var keep = false;
                if (!s.nom.votes.contains(c)) { // cpp:375
                    const h = crypto.gi(.value_hash, r.slot, r.prev_value, r.round, c); // hashValue, cpp:377
                    if (h >= new_hash) { // cpp:378
                        if (new_vote) |old| gpa.free(old);
                        new_vote = c;
                        new_hash = h;
                        keep = true;
                    }
                }
                if (!keep) gpa.free(c);
            }
        }
    }
    return new_vote;
}

/// Duplicate a value list into an independently-owned copy (recursion
/// safety: emitNomination's self-processing must never iterate arrays that a
/// nested storeLatest / own_nom replacement can free).
fn dupeValueList(gpa: std.mem.Allocator, vals: []const []u8) ![][]u8 {
    var out = try gpa.alloc([]u8, vals.len);
    var built: usize = 0;
    errdefer {
        for (out[0..built]) |v| gpa.free(v);
        gpa.free(out);
    }
    for (vals, 0..) |v, i| {
        out[i] = try gpa.dupe(u8, v);
        built += 1;
    }
    return out;
}

fn freeValueList(gpa: std.mem.Allocator, vals: [][]u8) void {
    for (vals) |v| gpa.free(v);
    gpa.free(vals);
}

/// Deep-copy a stored own-nomination envelope (used to mirror the own
/// statement into latest_nom while own_nom keeps its own copy).
fn cloneNomStored(gpa: std.mem.Allocator, env: *const stored_mod.StoredEnvelope) !stored_mod.StoredEnvelope {
    std.debug.assert(env.statement.pledges == .nominate);
    const framed = try gpa.dupe(u8, env.envelope_framed);
    errdefer gpa.free(framed);
    const n = &env.statement.pledges.nominate;
    const votes = try dupeValueList(gpa, n.votes);
    errdefer freeValueList(gpa, votes);
    const accepted = try dupeValueList(gpa, n.accepted);
    return .{
        .envelope_framed = framed,
        .statement = .{
            .node_id = env.statement.node_id,
            .slot = env.statement.slot,
            .pledges = .{ .nominate = .{
                .qset_hash = n.qset_hash,
                .votes = votes,
                .accepted = accepted,
            } },
        },
    };
}

/// Transcribed from NominationProtocol::emitNomination
/// (NominationProtocol.cpp:146-189). Emission is gated on started, watcher
/// mode (§5.1: watcher = zero emissions) and slot fully_validated (the
/// oracle gates only the broadcast on isFullyValidated, cpp:177-180, but
/// still self-processes; SLCP task-normatively gates the whole emission —
/// a non-fully-validated node advances state without emitting).
///
/// Self-recording: stellar-core records its own envelope into
/// mLatestNominations via `mSlot.processEnvelope(envW, true)` (cpp:170) →
/// NominationProtocol::processEnvelope → recordEnvelope (cpp:420, 130-144),
/// so its own votes count toward federated math. SLCP mirrors that by
/// storing a duplicate StoredEnvelope into s.latest_nom via storeLatest,
/// then re-running the promotion logic over the own statement (the
/// recursion the oracle gets from processEnvelope(self)).
///
/// Effect-order divergence (receiver-freshness-safe): SLCP pushes the
/// persist/broadcast effects BEFORE self-processing, so nested emissions
/// appear oldest-first; the oracle broadcasts after self-processing (and
/// therefore newest-first under recursion).
fn emitNomination(ctx: *engine_mod.Ctx, s: *slot_mod2.Slot) anyerror!void {
    if (!s.nom.started or s.nom.stopped) return;
    if (ctx.isWatcher() or !s.fully_validated) return;
    if (s.nom.votes.len() == 0) return; // wire-sane: votes nonempty (§4.1)
    const gpa = ctx.gpa;

    var env = try emit_mod.emit(ctx, s.index, .{ .nominate = .{
        .qset_hash = ctx.local_qset_hash,
        .votes = @ptrCast(s.nom.votes.slice()),
        .accepted = @ptrCast(s.nom.accepted.slice()),
    } });
    {
        errdefer env.deinit(gpa);
        var dup = try cloneNomStored(gpa, &env);
        _ = s.storeLatest(gpa, dup) catch |err| {
            dup.deinit(gpa);
            return err;
        };
    }
    // mLastEnvelope replacement (cpp:172-176; own sets only grow, so the
    // freshly emitted statement is always the newer one).
    if (s.own_nom) |*old| old.deinit(gpa);
    s.own_nom = env;

    // Self-process over recursion-safe copies of the emitted sets.
    const lv = try dupeValueList(gpa, s.nom.votes.slice());
    defer freeValueList(gpa, lv);
    const la = try dupeValueList(gpa, s.nom.accepted.slice());
    defer freeValueList(gpa, la);
    try processNomination(ctx, s, ctx.cfg.node_id, lv, la);
}

/// The started-body of NominationProtocol::processEnvelope
/// (NominationProtocol.cpp:422-524), shared by the fresh-peer path and the
/// emitNomination self-processing path. `sender` is the statement's nodeID;
/// `nom_votes` / `nom_accepted` are the statement's value arrays (stable for
/// the duration of the call — see emitNomination's recursion note).
fn processNomination(
    ctx: *engine_mod.Ctx,
    s: *slot_mod2.Slot,
    sender: NodeId,
    nom_votes: []const []u8,
    nom_accepted: []const []u8,
) anyerror!void {
    if (!s.nom.started or s.nom.stopped) return; // cpp:423 mNominationStarted gate
    const gpa = ctx.gpa;
    var modified = false; // tracks whether to emit (cpp:426)
    var new_candidates = false; // cpp:427

    // Attempt to promote some of the statement's votes to accepted
    // (cpp:429-470).
    for (nom_votes) |v| {
        if (s.nom.accepted.contains(v)) continue; // cpp:433-435 already accepted
        const voted_nodes = try nodesWith(gpa, s, v, .votes);
        defer gpa.free(voted_nodes);
        const accepted_nodes = try nodesWith(gpa, s, v, .accepted);
        defer gpa.free(accepted_nodes);
        if (try slot_mod2.federatedAccept(
            gpa,
            &ctx.cfg.quorum_set,
            voted_nodes,
            accepted_nodes,
            ctx.qsets.lookup(),
        )) { // cpp:437-446
            const vl = try validateCached(ctx, s, v); // cpp:448
            if (vl != .invalid) {
                // cpp:449-454 `vl >= kStructurallyValidValue` — SLCP's
                // 3-level collapse (§5.4): maybe_valid is processed but
                // marks the slot not fully validated.
                if (vl == .maybe_valid) s.fully_validated = false;
                if (try promoteToAccepted(ctx, s, v)) modified = true;
            } else if (try extractValid(ctx, s.index, v)) |ev| {
                // cpp:456-467: the value made it pretty far — vote for a
                // valid variation instead.
                defer gpa.free(ev);
                if (!ownSetFull(ctx, &s.nom.votes)) {
                    if (try s.nom.votes.insert(gpa, ev)) modified = true;
                }
            }
        }
    }

    // Attempt to promote accepted values to candidates (cpp:472-492).
    const had_candidates = s.nom.candidates.len() != 0;
    for (s.nom.accepted.slice()) |a| {
        if (s.nom.candidates.contains(a)) continue; // cpp:474-477
        const accepted_nodes = try nodesWith(gpa, s, a, .accepted);
        defer gpa.free(accepted_nodes);
        if (try slot_mod2.federatedRatify(
            gpa,
            &ctx.cfg.quorum_set,
            accepted_nodes,
            ctx.qsets.lookup(),
        )) { // cpp:478-481
            _ = try s.nom.candidates.insert(gpa, a); // cpp:483
            new_candidates = true;
        }
    }
    if (new_candidates and !had_candidates) {
        // First-ever candidate: stop nominating per the whitepaper — the
        // oracle stops the timer on each candidate insertion (cpp:485-491,
        // idempotent); SLCP emits one cancel_timer at the empty→nonempty
        // transition plus the candidate_updated phase event.
        try ctx.cancelTimer(s.index, .nomination);
        try ctx.phaseEvent(s.index, .candidate_updated, @intCast(s.nom.candidates.len()));
    }

    // Only take round-leader votes while still looking for candidates
    // (cpp:494-507), cap-gated per §5.4 (leader picks stop when votes full).
    if (s.nom.candidates.len() == 0 and
        s.nom.leaders.contains(sender) and
        !ownSetFull(ctx, &s.nom.votes))
    {
        if (try getNewValueFromNomination(ctx, s, nom_votes, nom_accepted)) |nv| {
            defer gpa.free(nv);
            if (try s.nom.votes.insert(gpa, nv)) modified = true; // cpp:502
        }
    }

    if (modified) try emitNomination(ctx, s); // cpp:509-512

    if (new_candidates) { // cpp:514-523
        // combineCandidates over Z → latest composite; oversized/empty
        // result is a fatal driver error (§4.4 — crash, never the wire).
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try ctx.drv.combine_candidates(ctx.drv.ctx, s.index, @ptrCast(s.nom.candidates.slice()), gpa, &out);
        if (out.items.len == 0 or out.items.len > ctx.cfg.limits.max_value_bytes) return error.DriverFault;
        const comp = try gpa.dupe(u8, out.items);
        if (s.nom.latest_composite) |old| gpa.free(old);
        s.nom.latest_composite = comp; // cpp:516-517
        // Hand off to the ballot protocol (cpp:522 mSlot.bumpState).
        _ = try ballot_mod.bumpState(ctx, s, comp, false);
    }
}

/// Process a fresh (sanity-, signature-, freshness-checked and stored) peer
/// nomination statement. Transcribed from
/// NominationProtocol::processEnvelope (NominationProtocol.cpp:404-526); the
/// isNewerStatement / isSane / recordEnvelope prefix (cpp:411-420) is the
/// pipeline's job in SLCP, so this begins at the mNominationStarted body.
///
/// Up-front (task-normative, §5.4 validation-levels bullet): every
/// vote/accepted value is validated through the per-slot cache; a
/// maybe_valid verdict marks the slot not fully validated (suppressing own
/// emissions) while the statement is still processed — never treated as
/// invalid, or lagging nodes could not catch up. invalid values are simply
/// never promoted into own sets (the promotion points re-check the cached
/// verdict, with the extract_valid_value fallback where the oracle has it).
pub fn processEnvelope(ctx: *engine_mod.Ctx, s: *slot_mod2.Slot, st: *const stored_mod.OwnedStatement) !void {
    std.debug.assert(st.pledges == .nominate);
    const nom = &st.pledges.nominate;
    for ([_][]const []u8{ nom.votes, nom.accepted }) |list| {
        for (list) |v| {
            const vl = try validateCached(ctx, s, v);
            if (vl == .maybe_valid) s.fully_validated = false;
        }
    }
    // Ensure node doesn't vote on future slots (cpp:422-424): promotion
    // logic only runs once nomination started (and not stopped, §5.4).
    if (s.nom.started and !s.nom.stopped) {
        try processNomination(ctx, s, st.node_id, nom.votes, nom.accepted);
    }
}

/// Transcribed from NominationProtocol::updateRoundLeaders
/// (NominationProtocol.cpp:219-309): count potential leaders (nodes with
/// non-zero weight, cpp:229-241 — self always counts, its weight is
/// maxInt), then advance the accumulating leader set; rounds adding no new
/// leader fast-forward (mRoundNumber++, cpp:293-299) until the set grows or
/// holds every potential leader, with the oracle's 1000-iteration guard
/// (cpp:244-306).
fn updateRoundLeaders(ctx: *engine_mod.Ctx, s: *slot_mod2.Slot) anyerror!void {
    const gpa = ctx.gpa;
    var r = leaderRound(ctx, s);
    const members = try memberNodes(gpa, r);
    defer gpa.free(members);
    var max_leader_count: usize = 0;
    for (members) |m| {
        if (weight(r, m) > 0) max_leader_count += 1;
    }
    var iterations_remaining: u32 = 1000; // cpp:245
    while (s.nom.leaders.items().len < max_leader_count) {
        r.round = s.nom.round;
        if (try s.nom.leaders.advance(gpa, r)) return; // grew (cpp:276-292)
        s.nom.round += 1; // fast timeout (cpp:293-299)
        iterations_remaining -= 1;
        if (iterations_remaining == 0) return error.RoundLeaderStuck; // cpp:301-306
    }
}

/// Shared body of `nominate` / `timerFired` — transcribed from
/// NominationProtocol::nominate (NominationProtocol.cpp:555-714) minus the
/// stellar-only upgrade-stripping machinery (cpp:619-658, no SLCP
/// counterpart: values are opaque). Divergences (task-normative): the round
/// is NOT bumped here (timerFired owns the bump; fast-forwards still happen
/// inside updateRoundLeaders), and the return value is "did nomination
/// proceed" rather than the oracle's `updated`.
fn nominateInternal(
    ctx: *engine_mod.Ctx,
    s: *slot_mod2.Slot,
    value: []const u8,
    prev_value: []const u8,
    timedout: bool,
) anyerror!bool {
    // Stopped / already-externalized slots never nominate (task: pipeline
    // reports ignored).
    if (s.nom.stopped or s.externalized_value != null) return false;
    // No need to continue nominating once a candidate exists (cpp:561-569).
    if (s.nom.candidates.len() != 0) return false;
    // A timeout before the first nominate call is a stale no-op (cpp:581-585).
    if (timedout and !s.nom.started) return false;

    const gpa = ctx.gpa;
    const first_start = !s.nom.started;
    s.nom.started = true; // cpp:587

    // mPreviousValue = previousValue (cpp:589) + the timer-capture value;
    // dupe BEFORE freeing the old copies — timerFired passes the stored
    // slices themselves back in.
    const pv = try gpa.dupe(u8, prev_value);
    if (s.nom.previous_value) |old| gpa.free(old);
    s.nom.previous_value = pv;
    const lv = try gpa.dupe(u8, value);
    if (s.nom.last_value) |old| gpa.free(old);
    s.nom.last_value = lv;

    var updated = false; // cpp:574
    try updateRoundLeaders(ctx, s); // cpp:592

    // Add a few more values from other leaders' latest statements
    // (cpp:597-613), cap-gated per §5.4.
    for (s.nom.leaders.items()) |leader| {
        if (s.latest_nom.getPtr(leader)) |env| {
            if (env.statement.pledges != .nominate) continue;
            const nom = &env.statement.pledges.nominate;
            if (ownSetFull(ctx, &s.nom.votes)) break;
            if (try getNewValueFromNomination(ctx, s, nom.votes, nom.accepted)) |nv| {
                defer gpa.free(nv);
                if (try s.nom.votes.insert(gpa, nv)) updated = true; // cpp:607-608
            }
        }
    }

    // If we are a leader for this round, vote for our own value — but only
    // when we have not added any votes yet (cpp:615-669, upgrade branches
    // elided; shouldVoteForValue = mVotes.empty(), cpp:624-629).
    if (s.nom.leaders.contains(ctx.cfg.node_id)) {
        if (s.nom.votes.len() == 0 and !ownSetFull(ctx, &s.nom.votes)) {
            if (try s.nom.votes.insert(gpa, s.nom.last_value.?)) updated = true; // cpp:660-669
        }
    }

    // Arm the nomination timer with the deterministic schedule (cpp:594-595
    // computeTimeout + cpp:672-677 setupTimer; SLCP §5.4 timeoutMs).
    try ctx.armTimer(s.index, .nomination, engine_mod.timeoutMs(ctx.cfg.limits, s.nom.round));
    if (first_start) try ctx.phaseEvent(s.index, .nominating, s.nom.round);
    if (updated) try emitNomination(ctx, s); // cpp:704-711

    return true;
}

/// Application nominate input (oracle: NominationProtocol::nominate with
/// timedout=false, NominationProtocol.cpp:555-714). Returns false when
/// nomination is not legal for this slot (stopped / externalized / already
/// holding a candidate) → pipeline reports ignored.
pub fn nominate(ctx: *engine_mod.Ctx, s: *slot_mod2.Slot, value: []const u8, prev_value: []const u8) !bool {
    return nominateInternal(ctx, s, value, prev_value, false);
}

/// Nomination timer fired: next round, re-nominate the stored value (the
/// oracle's timer closure `slot->nominate(value, previousValue, true)`,
/// NominationProtocol.cpp:672-677). Stale timers (nomination never started,
/// or permanently stopped) are no-ops.
pub fn timerFired(ctx: *engine_mod.Ctx, s: *slot_mod2.Slot) !void {
    if (!s.nom.started or s.nom.stopped) return;
    const value = s.nom.last_value orelse return;
    const prev = s.nom.previous_value orelse return;
    s.nom.round += 1; // the oracle's mRoundNumber++ (cpp:591), moved here per task
    _ = try nominateInternal(ctx, s, value, prev, true);
}

/// restore_own_envelope replay — transcribed from
/// NominationProtocol::setStateFromEnvelope (NominationProtocol.cpp:
/// 820-840): own votes/accepted restored from the own statement, error if
/// nomination already started (cpp:823-827). The oracle's recordEnvelope +
/// mLastEnvelope bookkeeping (cpp:828, 839) is the pipeline's job in SLCP
/// (it owns the StoredEnvelope). No emission, no timers. Divergence
/// (task-normative): SLCP sets started=true (the oracle leaves
/// mNominationStarted false until the next nominate call).
pub fn setStateFromEnvelope(ctx: *engine_mod.Ctx, s: *slot_mod2.Slot, st: *const stored_mod.OwnedStatement) !void {
    if (s.nom.started) return error.NominationAlreadyStarted;
    std.debug.assert(st.pledges == .nominate);
    const gpa = ctx.gpa;
    const nom = &st.pledges.nominate;
    for (nom.accepted) |a| _ = try s.nom.accepted.insert(gpa, a); // cpp:830-833
    for (nom.votes) |v| _ = try s.nom.votes.insert(gpa, v); // cpp:834-837
    s.nom.started = true;
}

/// Ballot protocol calls this at externalize: nomination stops permanently
/// (§5.4). The oracle's stopNomination clears mNominationStarted
/// (NominationProtocol.cpp:716-720) — a resumable stop; SLCP's flag is
/// sticky because §5.4 pins "stops permanently only at externalize".
pub fn stopNomination(s: *slot_mod2.Slot) void {
    s.nom.stopped = true;
}

// ---------------------------------------------------------------------------
// M2 tests: own-module nomination protocol flows over a real Ctx (built like
// emit.zig's test). Peer statements are fabricated StoredEnvelopes — the
// pipeline's sanity/signature/freshness stages are out of scope here.
// ---------------------------------------------------------------------------

const qset_store_mod = @import("qset_store.zig");
const limits_mod = @import("limits.zig");
const driver_test = driver_mod;

const TestHarness = struct {
    gpa: std.mem.Allocator,
    effects: engine_mod.EffectQueue,
    store: qset_store_mod.Store,
    drv: driver_mod.Driver,
    cfg: engine_mod.Config,
    excised: ?qset.QuorumSetOwned,
    ctx: engine_mod.Ctx,
    s: slot_mod2.Slot,
    local_hash: [32]u8,
    ids: [3][32]u8, // A (local), B, C

    const Opts = struct {
        watcher: bool = false,
        advertise: bool = true,
        max_nom_values: u32 = 64,
        drv: ?driver_mod.Driver = null,
    };

    /// In-place init (ctx holds pointers into self — self must not move).
    fn setup(self: *TestHarness, gpa: std.mem.Allocator, opts: Opts) !void {
        self.gpa = gpa;
        self.effects = engine_mod.EffectQueue.init(gpa);
        self.store = qset_store_mod.Store.init(gpa, 16);
        self.drv = opts.drv orelse driver_mod.Driver.default();
        const seed_a: [32]u8 = @splat(1);
        self.ids = .{
            try crypto.publicKeyFromSeed(seed_a),
            try crypto.publicKeyFromSeed(@splat(2)),
            try crypto.publicKeyFromSeed(@splat(3)),
        };
        const qs = try makeQs(gpa, 2, &self.ids);
        self.local_hash = try qset.hashNormalized(gpa, &qs);
        self.cfg = .{
            .network_id = crypto.networkIdFromPassphrase("nomination-test"),
            .node_id = self.ids[0],
            .secret_seed = if (opts.watcher) null else seed_a,
            .quorum_set = qs,
            .limits = limits_mod.Limits{ .max_nomination_values = opts.max_nom_values },
        };
        self.excised = try qset.exciseNode(gpa, &self.cfg.quorum_set, self.cfg.node_id);
        if (opts.advertise) {
            for (self.ids) |id| {
                const copy = try makeQs(gpa, 2, &self.ids);
                try self.store.insert(self.local_hash, copy);
                try self.store.setAdvertised(id, self.local_hash);
            }
        }
        self.s = slot_mod2.Slot.init(1);
        self.ctx = .{
            .gpa = gpa,
            .cfg = &self.cfg,
            .drv = &self.drv,
            .effects = &self.effects,
            .qsets = &self.store,
            .excised = if (self.excised) |*e| e else null,
            .local_qset_hash = self.local_hash,
        };
    }

    fn deinit(self: *TestHarness) void {
        self.s.deinit(self.gpa);
        if (self.excised) |*e| e.deinit(self.gpa);
        self.cfg.quorum_set.deinit(self.gpa);
        self.store.deinit();
        self.effects.deinit();
        self.* = undefined;
    }

    fn resetSlot(self: *TestHarness, index: u64) void {
        self.s.deinit(self.gpa);
        self.s = slot_mod2.Slot.init(index);
    }

    /// First slot index whose round-0 leader is `node` (from the local
    /// node's perspective, prev_value "prev").
    fn findSlotLedBy(self: *TestHarness, node: [32]u8) !u64 {
        var idx: u64 = 1;
        while (idx < 10_000) : (idx += 1) {
            const r: LeaderRound = .{
                .slot = idx,
                .prev_value = "prev",
                .round = 0,
                .local_node = self.cfg.node_id,
                .qs = self.ctx.excised,
            };
            const l = (try roundLeader(self.gpa, r)) orelse continue;
            if (std.mem.eql(u8, &l, &node)) return idx;
        }
        return error.NoLeaderSlot;
    }

    /// Store a fabricated peer nomination as that node's latest and return
    /// the stored statement pointer.
    fn storePeerNom(
        self: *TestHarness,
        peer: [32]u8,
        votes: []const []const u8,
        accepted: []const []const u8,
    ) !*const stored_mod.OwnedStatement {
        const gpa = self.gpa;
        const env = stored_mod.StoredEnvelope{
            .envelope_framed = try gpa.dupe(u8, "peer-frame"),
            .statement = .{
                .node_id = peer,
                .slot = self.s.index,
                .pledges = .{ .nominate = .{
                    .qset_hash = self.local_hash,
                    .votes = try dupeConstList(gpa, votes),
                    .accepted = try dupeConstList(gpa, accepted),
                } },
            },
        };
        _ = try self.s.storeLatest(gpa, env);
        return &self.s.latestFor(peer, true).?.statement;
    }

    fn peerNom(
        self: *TestHarness,
        peer: [32]u8,
        votes: []const []const u8,
        accepted: []const []const u8,
    ) !void {
        const stp = try self.storePeerNom(peer, votes, accepted);
        try processEnvelope(&self.ctx, &self.s, stp);
    }

    const Drained = struct {
        persist: usize = 0,
        broadcast: usize = 0,
        arm: usize = 0,
        cancel: usize = 0,
        nominating: usize = 0,
        candidate_updated: usize = 0,
        arm_delays: [16]u32 = @splat(0),
    };

    fn drain(self: *TestHarness) Drained {
        var d: Drained = .{};
        while (self.effects.peek()) |e| {
            switch (e.*) {
                .persist_own_envelope => d.persist += 1,
                .broadcast_envelope => d.broadcast += 1,
                .arm_timer => |a| {
                    if (d.arm < d.arm_delays.len) d.arm_delays[d.arm] = a.delay_ms;
                    d.arm += 1;
                },
                .cancel_timer => d.cancel += 1,
                .phase_event => |p| switch (p.kind) {
                    .nominating => d.nominating += 1,
                    .candidate_updated => d.candidate_updated += 1,
                    else => {},
                },
                else => {},
            }
            self.effects.commit();
        }
        return d;
    }
};

fn makeQs(gpa: std.mem.Allocator, threshold: u32, ids: []const [32]u8) !qset.QuorumSetOwned {
    const vals = try gpa.alloc(qset.NodeId, ids.len);
    for (ids, 0..) |id, i| vals[i] = id;
    var qs: qset.QuorumSetOwned = .{
        .threshold = threshold,
        .validators = vals,
        .inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0),
    };
    try qset.validateAndNormalize(gpa, &qs);
    return qs;
}

fn dupeConstList(gpa: std.mem.Allocator, vals: []const []const u8) ![][]u8 {
    var out = try gpa.alloc([]u8, vals.len);
    var built: usize = 0;
    errdefer {
        for (out[0..built]) |v| gpa.free(v);
        gpa.free(out);
    }
    for (vals, 0..) |v, i| {
        out[i] = try gpa.dupe(u8, v);
        built += 1;
    }
    return out;
}

fn makeOwnedNomStatement(
    gpa: std.mem.Allocator,
    node: [32]u8,
    slot_index: u64,
    votes: []const []const u8,
    accepted: []const []const u8,
    qhash: [32]u8,
) !stored_mod.OwnedStatement {
    return .{
        .node_id = node,
        .slot = slot_index,
        .pledges = .{ .nominate = .{
            .qset_hash = qhash,
            .votes = try dupeConstList(gpa, votes),
            .accepted = try dupeConstList(gpa, accepted),
        } },
    };
}

test "nominate as leader: own vote emitted; quorum-voted value promoted to accepted" {
    const gpa = testing.allocator;
    var h: TestHarness = undefined;
    try h.setup(gpa, .{});
    defer h.deinit();
    h.resetSlot(try h.findSlotLedBy(h.ids[0])); // A leads round 0

    try testing.expect(try nominate(&h.ctx, &h.s, "v1", "prev"));
    try testing.expect(h.s.nom.started);
    try testing.expect(h.s.nom.votes.contains("v1"));
    // own statement emitted and self-recorded for quorum math
    try testing.expect(h.s.own_nom != null);
    try testing.expect(h.s.latestFor(h.ids[0], true) != null);
    var d = h.drain();
    try testing.expectEqual(@as(usize, 1), d.persist);
    try testing.expectEqual(@as(usize, 1), d.broadcast);
    try testing.expectEqual(@as(usize, 1), d.arm);
    try testing.expectEqual(@as(u32, 1000), d.arm_delays[0]); // round 0
    try testing.expectEqual(@as(usize, 1), d.nominating);

    // Peer B votes the same value: {A, B} voted is a quorum for 2-of-3 →
    // federatedAccept promotes v1 into own accepted (and it stays in votes).
    try h.peerNom(h.ids[1], &.{"v1"}, &.{});
    try testing.expect(h.s.nom.accepted.contains("v1"));
    try testing.expect(h.s.nom.votes.contains("v1"));
    // re-emitted with accepted ⊆ votes; own_nom reflects the new statement
    const own = &h.s.own_nom.?.statement.pledges.nominate;
    try testing.expect(listHasValue(own.votes, "v1"));
    try testing.expect(listHasValue(own.accepted, "v1"));
    d = h.drain();
    try testing.expect(d.persist >= 1 and d.broadcast >= 1);

    // Peer C merely voting does not confirm a candidate (accepted-set is
    // only {A}) — the flow stops short of the ballot handoff.
    try h.peerNom(h.ids[2], &.{"v1"}, &.{});
    try testing.expectEqual(@as(usize, 0), h.s.nom.candidates.len());
}

test "accept from a v-blocking set alone (no advertised qsets, no quorum arm)" {
    const gpa = testing.allocator;
    var h: TestHarness = undefined;
    try h.setup(gpa, .{ .advertise = false });
    defer h.deinit();
    h.resetSlot(try h.findSlotLedBy(h.ids[0]));

    try testing.expect(try nominate(&h.ctx, &h.s, "aa", "prev"));
    _ = h.drain();

    // One accepter is not v-blocking for 2-of-3; with no advertised qsets
    // the quorum arm is dead.
    try h.peerNom(h.ids[1], &.{"vv"}, &.{"vv"});
    try testing.expect(!h.s.nom.accepted.contains("vv"));

    // Two accepters ARE v-blocking → own accept without any quorum.
    try h.peerNom(h.ids[2], &.{"vv"}, &.{"vv"});
    try testing.expect(h.s.nom.accepted.contains("vv"));
    try testing.expect(h.s.nom.votes.contains("vv")); // accepting adds to both
    try testing.expect(h.s.nom.votes.contains("aa"));
    // ratify has no v-blocking arm → still no candidate
    try testing.expectEqual(@as(usize, 0), h.s.nom.candidates.len());
    const d = h.drain();
    try testing.expect(d.broadcast >= 1); // the accept re-emission
}

test "own-set admission cap: full votes block promotion; peer statements still tracked" {
    const gpa = testing.allocator;
    var h: TestHarness = undefined;
    try h.setup(gpa, .{ .advertise = false, .max_nom_values = 2 });
    defer h.deinit();

    // Restore own state with votes at the cap (2 values).
    var own_st = try makeOwnedNomStatement(gpa, h.ids[0], h.s.index, &.{ "x1", "x2" }, &.{}, h.local_hash);
    defer own_st.deinit(gpa);
    try setStateFromEnvelope(&h.ctx, &h.s, &own_st);
    try testing.expect(h.s.nom.started);
    try testing.expectEqual(@as(usize, 2), h.s.nom.votes.len());
    try testing.expectError(error.NominationAlreadyStarted, setStateFromEnvelope(&h.ctx, &h.s, &own_st));

    // v-blocking accept of a NEW value v3: promotion into own sets is
    // blocked (votes full and v3 ∉ votes) — deterministic admission cutoff.
    try h.peerNom(h.ids[1], &.{"v3"}, &.{"v3"});
    try h.peerNom(h.ids[2], &.{"v3"}, &.{"v3"});
    try testing.expectEqual(@as(usize, 0), h.s.nom.accepted.len());
    try testing.expectEqual(@as(usize, 2), h.s.nom.votes.len());
    try testing.expect(!h.s.nom.votes.contains("v3"));
    // peers' statements are still tracked for candidate confirmation
    try testing.expect(h.s.latestFor(h.ids[1], true) != null);
    try testing.expect(h.s.latestFor(h.ids[2], true) != null);
    const d = h.drain();
    try testing.expectEqual(@as(usize, 0), d.persist); // nothing to emit

    // A value already IN votes can still be accepted (only the accepted
    // set needs room).
    try h.peerNom(h.ids[1], &.{ "v3", "x1" }, &.{ "v3", "x1" });
    try h.peerNom(h.ids[2], &.{ "v3", "x1" }, &.{ "v3", "x1" });
    try testing.expect(h.s.nom.accepted.contains("x1"));
    try testing.expectEqual(@as(usize, 2), h.s.nom.votes.len());
}

test "leader adoption: non-leader local adopts the round leader's vote" {
    const gpa = testing.allocator;
    var h: TestHarness = undefined;
    try h.setup(gpa, .{});
    defer h.deinit();
    h.resetSlot(try h.findSlotLedBy(h.ids[1])); // B leads round 0 → A is not leader

    try testing.expect(try nominate(&h.ctx, &h.s, "mine", "prev"));
    // not a leader: own value NOT voted, nothing emitted
    try testing.expectEqual(@as(usize, 0), h.s.nom.votes.len());
    var d = h.drain();
    try testing.expectEqual(@as(usize, 0), d.broadcast);
    try testing.expectEqual(@as(usize, 1), d.arm);

    // Leader B's statement arrives → its vote is adopted into own votes.
    try h.peerNom(h.ids[1], &.{"bval"}, &.{});
    try testing.expect(h.s.nom.votes.contains("bval"));
    try testing.expect(!h.s.nom.votes.contains("mine"));
    d = h.drain();
    try testing.expect(d.broadcast >= 1); // adoption emitted

    // Non-leader C's vote is NOT adopted.
    try h.peerNom(h.ids[2], &.{"cval"}, &.{});
    try testing.expect(!h.s.nom.votes.contains("cval"));
}

fn greyValidate(dctx: *anyopaque, slot_index: u64, value: []const u8, is_nomination: bool) driver_mod.Validity {
    _ = dctx;
    _ = slot_index;
    _ = is_nomination;
    if (value.len == 0) return .invalid;
    return if (value[0] == 'g') .maybe_valid else .valid;
}

test "maybe_valid value: processed, fully_validated cleared, emission suppressed" {
    const gpa = testing.allocator;
    var h: TestHarness = undefined;
    var d0 = driver_test.Driver.default();
    d0.validate_value = greyValidate;
    try h.setup(gpa, .{ .advertise = false, .drv = d0 });
    defer h.deinit();
    h.resetSlot(try h.findSlotLedBy(h.ids[0]));

    try testing.expect(try nominate(&h.ctx, &h.s, "aa", "prev"));
    try testing.expect(h.s.fully_validated);
    _ = h.drain();

    // A maybe_valid value in a peer statement clears fully_validated even
    // before any promotion (up-front cache validation).
    try h.peerNom(h.ids[1], &.{"gg"}, &.{"gg"});
    try testing.expect(!h.s.fully_validated);

    // v-blocking accept still PROCESSES the value (state advances)…
    try h.peerNom(h.ids[2], &.{"gg"}, &.{"gg"});
    try testing.expect(h.s.nom.accepted.contains("gg"));
    // …but own emission is suppressed: own_nom still the pre-"gg" statement.
    const own = &h.s.own_nom.?.statement.pledges.nominate;
    try testing.expect(!listHasValue(own.accepted, "gg"));
    const d = h.drain();
    try testing.expectEqual(@as(usize, 0), d.persist);
    try testing.expectEqual(@as(usize, 0), d.broadcast);
}

test "watcher: state advances, zero emissions" {
    const gpa = testing.allocator;
    var h: TestHarness = undefined;
    try h.setup(gpa, .{ .watcher = true, .advertise = false });
    defer h.deinit();
    h.resetSlot(try h.findSlotLedBy(h.ids[0]));

    try testing.expect(try nominate(&h.ctx, &h.s, "v1", "prev"));
    try testing.expect(h.s.nom.votes.contains("v1"));
    try testing.expect(h.s.own_nom == null);
    var d = h.drain();
    try testing.expectEqual(@as(usize, 0), d.persist);
    try testing.expectEqual(@as(usize, 0), d.broadcast);
    try testing.expectEqual(@as(usize, 1), d.arm); // timers still run

    // peer-driven accept advances state, still without emission
    try h.peerNom(h.ids[1], &.{"vv"}, &.{"vv"});
    try h.peerNom(h.ids[2], &.{"vv"}, &.{"vv"});
    try testing.expect(h.s.nom.accepted.contains("vv"));
    d = h.drain();
    try testing.expectEqual(@as(usize, 0), d.persist);
    try testing.expectEqual(@as(usize, 0), d.broadcast);
}

test "timer: round bump re-arms with a growing timeout; stale timer is a no-op" {
    const gpa = testing.allocator;
    var h: TestHarness = undefined;
    try h.setup(gpa, .{});
    defer h.deinit();
    h.resetSlot(try h.findSlotLedBy(h.ids[0]));

    // stale: never started → no effects
    try timerFired(&h.ctx, &h.s);
    var d = h.drain();
    try testing.expectEqual(@as(usize, 0), d.arm);

    try testing.expect(try nominate(&h.ctx, &h.s, "v1", "prev"));
    d = h.drain();
    try testing.expectEqual(@as(u32, 1000), d.arm_delays[0]); // round 0
    try testing.expectEqual(@as(u32, 0), h.s.nom.round);

    try timerFired(&h.ctx, &h.s);
    try testing.expect(h.s.nom.round >= 1);
    d = h.drain();
    try testing.expectEqual(@as(usize, 1), d.arm);
    try testing.expect(d.arm_delays[0] >= 2000); // timeoutMs grows with round

    const round_after_first = h.s.nom.round;
    try timerFired(&h.ctx, &h.s);
    try testing.expect(h.s.nom.round > round_after_first);
    const d2 = h.drain();
    try testing.expect(d2.arm_delays[0] > d.arm_delays[0]);
}

test "candidate confirmation hands the composite to ballot.bumpState (integrated)" {
    const gpa = testing.allocator;
    var h: TestHarness = undefined;
    try h.setup(gpa, .{});
    defer h.deinit();
    h.resetSlot(try h.findSlotLedBy(h.ids[0]));

    try testing.expect(try nominate(&h.ctx, &h.s, "v1", "prev"));
    _ = h.drain();

    // B votes+accepts v1: quorum-voted {A,B} → own accept → re-emit →
    // self-process sees accepted-set {A,B} = quorum → candidate → composite
    // → ballot.bumpState starts the ballot protocol on the composite.
    try h.peerNom(h.ids[1], &.{"v1"}, &.{"v1"});
    try testing.expect(h.s.nom.candidates.contains("v1"));
    try testing.expectEqualSlices(u8, "v1", h.s.nom.latest_composite.?);
    // the real ballot protocol took the handoff: b started on the composite
    try testing.expect(h.s.ballot.current != null);
    try testing.expectEqualSlices(u8, "v1", h.s.ballot.current.?.value);
    const d = h.drain();
    // nomination timer canceled (the live ballot protocol adds its own
    // timer traffic on top, so >= not ==)
    try testing.expect(d.cancel >= 1);
    try testing.expectEqual(@as(usize, 1), d.candidate_updated);

    // nominate after a candidate exists is refused (oracle cpp:561-569)
    try testing.expect(!try nominate(&h.ctx, &h.s, "v2", "prev"));
}

test "stopNomination: sticky — nominate refused, timer and peer promotion inert" {
    const gpa = testing.allocator;
    var h: TestHarness = undefined;
    try h.setup(gpa, .{ .advertise = false });
    defer h.deinit();
    h.resetSlot(try h.findSlotLedBy(h.ids[0]));

    try testing.expect(try nominate(&h.ctx, &h.s, "v1", "prev"));
    _ = h.drain();
    stopNomination(&h.s);

    try testing.expect(!try nominate(&h.ctx, &h.s, "v2", "prev"));
    try timerFired(&h.ctx, &h.s); // no-op
    // v-blocking accept no longer promotes
    try h.peerNom(h.ids[1], &.{"vv"}, &.{"vv"});
    try h.peerNom(h.ids[2], &.{"vv"}, &.{"vv"});
    try testing.expect(!h.s.nom.accepted.contains("vv"));
    const d = h.drain();
    try testing.expectEqual(@as(usize, 0), d.arm);
    try testing.expectEqual(@as(usize, 0), d.persist);
}
