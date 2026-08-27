//! Nomination leader election — the Gi machinery (design §5.4 `nomination.zig`
//! bullet). M1 scope ONLY: per-round weights, neighbor test, priority, round
//! leader, the accumulating grow-only leader set, and the leader value pick.
//! The X/Y/Z-set nomination protocol itself lands at M2.
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
    started: bool = false,
    round: u32 = 0,
    /// X / Y / Z (§5.4): own votes, own accepted, confirmed candidates.
    votes: values_mod.ValueSet = .{},
    accepted: values_mod.ValueSet = .{},
    candidates: values_mod.ValueSet = .{},
    leaders: RoundLeaders = .{},
    previous_value: ?[]u8 = null,
    latest_composite: ?[]u8 = null,

    pub fn deinit(self: *State, gpa: std.mem.Allocator) void {
        self.votes.deinit(gpa);
        self.accepted.deinit(gpa);
        self.candidates.deinit(gpa);
        self.leaders.deinit(gpa);
        if (self.previous_value) |v| gpa.free(v);
        if (self.latest_composite) |v| gpa.free(v);
        self.* = undefined;
    }
};

// --- M2 protocol entry points (implemented by the nomination agent; ---
// --- signatures are the pinned contract for pipeline.zig / ballot.zig) ---

const engine_mod = @import("engine.zig");
const slot_mod2 = @import("slot.zig");
const stored_mod = @import("stored.zig");

/// Process a fresh (freshness-checked, stored) peer nomination statement.
pub fn processEnvelope(ctx: *engine_mod.Ctx, s: *slot_mod2.Slot, st: *const stored_mod.OwnedStatement) !void {
    _ = ctx;
    _ = s;
    _ = st;
    return error.NotImplemented;
}

/// Application nominate input. Returns false when nomination is not legal
/// for this slot (already externalized / stopped) → pipeline reports ignored.
pub fn nominate(ctx: *engine_mod.Ctx, s: *slot_mod2.Slot, value: []const u8, prev_value: []const u8) !bool {
    _ = ctx;
    _ = s;
    _ = value;
    _ = prev_value;
    return error.NotImplemented;
}

/// Nomination timer fired: next round.
pub fn timerFired(ctx: *engine_mod.Ctx, s: *slot_mod2.Slot) !void {
    _ = ctx;
    _ = s;
    return error.NotImplemented;
}

/// restore_own_envelope replay (stellar-core setStateFromEnvelope semantics).
pub fn setStateFromEnvelope(ctx: *engine_mod.Ctx, s: *slot_mod2.Slot, st: *const stored_mod.OwnedStatement) !void {
    _ = ctx;
    _ = s;
    _ = st;
    return error.NotImplemented;
}
