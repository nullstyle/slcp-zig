//! Federated-voting quorum math (design §5.4 `local_node.zig`).
//!
//! Line-level transcription of stellar-core's LocalNode quorum predicates
//! (stellar-core/src/scp/LocalNode.cpp) plus the node-weight fixed point
//! (stellar-core/src/scp/SCPDriver.cpp getNodeWeight/computeWeight — the
//! function lived in LocalNode.cpp before stellar-core v20 moved it into the
//! driver; the math is unchanged apart from rounding, see `nodeWeight`).
//!
//! Contract for all `nodes: []const NodeId` arguments: an unsorted small SET —
//! no duplicate entries. Membership is a linear scan, mirroring the oracle's
//! `std::find` over a `std::vector<NodeID>`.
//!
//! The self = maxInt(u64) weight rule ("local node is in all quorum sets")
//! lives in the NOMINATION layer (§5.4), not here — `nodeWeight` is pure
//! oracle math over the qset tree.

const std = @import("std");
const qset = @import("qset.zig");

pub const NodeId = qset.NodeId;

/// Resolver from node id to that node's STATEMENT-ADVERTISED quorum set
/// (§5.4: `isQuorum` fixpoint runs over advertised qsets, then the local
/// qset). The engine backs this with its qset cache; `null` means the qset
/// is unknown (unfetched), and `isQuorum` drops such nodes — the oracle's
/// `qfun` returning an empty `SCPQuorumSetPtr` (LocalNode.cpp:222-229).
/// Borrow contract: pointers returned by `get` must stay valid (unmoved,
/// unevicted) for the full duration of the `isQuorum` call, and `get` must
/// not mutate the backing store (an LRU touch-on-read violates this) —
/// M2's qset cache must respect both.
pub const QSetLookup = struct {
    ctx: *const anyopaque,
    get: *const fn (ctx: *const anyopaque, node: NodeId) ?*const qset.QuorumSetOwned,
};

fn contains(nodes: []const NodeId, node: NodeId) bool {
    for (nodes) |*n| {
        if (std.mem.eql(u8, n, &node)) return true;
    }
    return false;
}

/// Does `nodes` satisfy one of `qs`'s slices? Transcribed from
/// LocalNode::isQuorumSliceInternal (LocalNode.cpp:92-122): count matching
/// top-level validators, then recursively satisfied inner sets, until
/// `threshold` members are satisfied.
///
/// The oracle's `thresholdLeft` is a `uint32` and its `<= 0` check is `== 0`,
/// so a threshold-0 set is (vacuously) NEVER satisfied there — the first
/// decrement wraps. Transcribed faithfully with a wrapping decrement; validated
/// SLCP qsets always have threshold >= 1 (qset.zig `ThresholdOutOfRange`), so
/// the wrap is unreachable in engine use.
pub fn isQuorumSlice(qs: *const qset.QuorumSetOwned, nodes: []const NodeId) bool {
    var threshold_left: u32 = qs.threshold;
    for (qs.validators) |v| {
        if (contains(nodes, v)) {
            threshold_left -%= 1;
            if (threshold_left == 0) return true;
        }
    }
    for (qs.inner_sets) |*inner| {
        if (isQuorumSlice(inner, nodes)) {
            threshold_left -%= 1;
            if (threshold_left == 0) return true;
        }
    }
    return false;
}

/// Does `nodes` intersect every slice of `qs` (i.e. block it)? Transcribed
/// from LocalNode::isVBlockingInternal (LocalNode.cpp:132-171):
/// `left_till_block = (1 + members) - threshold` — the number of members that
/// must be hit before no `threshold`-subset avoiding `nodes` remains — with
/// the oracle's guard that a threshold-0 set has slices for every subset and
/// therefore can never be blocked.
pub fn isVBlocking(qs: *const qset.QuorumSetOwned, nodes: []const NodeId) bool {
    // There is no v-blocking set for {\empty} (LocalNode.cpp:136-140).
    if (qs.threshold == 0) return false;

    var left_till_block: i64 = @as(i64, @intCast(1 + qs.validators.len + qs.inner_sets.len)) -
        @as(i64, qs.threshold);

    for (qs.validators) |v| {
        if (contains(nodes, v)) {
            left_till_block -= 1;
            if (left_till_block <= 0) return true;
        }
    }
    for (qs.inner_sets) |*inner| {
        if (isVBlocking(inner, nodes)) {
            left_till_block -= 1;
            if (left_till_block <= 0) return true;
        }
    }
    return false;
}

/// Is `candidates` a quorum for the local node? Transcribed from
/// LocalNode::isQuorum (LocalNode.cpp:198-238): fixpoint-filter `candidates`
/// down to the nodes whose ADVERTISED qset (via `lookup`; unknown qset →
/// node dropped) has a satisfied slice inside the remaining set, iterate
/// until stable, then require the remaining set to contain a slice of the
/// LOCAL qset.
///
/// Each filter pass tests every node against the set as it stood at the top
/// of the pass (the oracle copies `pNodes` into `fNodes` per pass), so two
/// buffers are used — never an in-place compaction.
pub fn isQuorum(
    gpa: std.mem.Allocator,
    local_qset: *const qset.QuorumSetOwned,
    candidates: []const NodeId,
    lookup: QSetLookup,
) !bool {
    var cur = try gpa.alloc(NodeId, candidates.len);
    defer gpa.free(cur);
    var next = try gpa.alloc(NodeId, candidates.len);
    defer gpa.free(next);

    @memcpy(cur, candidates);
    var cur_len: usize = candidates.len;

    while (true) {
        const count = cur_len;
        var next_len: usize = 0;
        for (cur[0..count]) |node| {
            if (lookup.get(lookup.ctx, node)) |advertised| {
                if (isQuorumSlice(advertised, cur[0..count])) {
                    next[next_len] = node;
                    next_len += 1;
                }
            }
            // unknown qset → drop (oracle: qfun returned null, LocalNode.cpp:226-229)
        }
        std.mem.swap([]NodeId, &cur, &next);
        cur_len = next_len;
        if (cur_len == count) break;
    }

    return isQuorumSlice(local_qset, cur[0..cur_len]);
}

/// floor(m * threshold / total) with a u128 intermediate. The oracle's
/// computeWeight (SCPDriver.cpp:21-33) is `bigDivideUnsigned(res, m,
/// threshold, total, ...)`; `threshold <= total` (release-asserted there,
/// guaranteed here by qset validation) keeps the result <= m, so it always
/// fits u64.
///
/// ROUNDING: design §5.4 pins **floor per level** (the classic
/// LocalNode::getNodeWeight ROUND_DOWN rule), frozen by leader.json. The
/// checked-out stellar-core tree rounds UP here (SCPDriver.cpp:29, part of
/// the v20 nomination-weight rework) — a documented, deliberate divergence.
fn computeWeight(m: u64, total: u64, threshold: u64) u64 {
    // Defensive (release-safe): an unvalidated tree weighs nothing rather
    // than overflowing or dividing by zero.
    if (total == 0 or threshold > total) return 0;
    return @intCast(@as(u128, m) * threshold / total);
}

/// Fixed-point weight of `node` within `qs`: the product of `threshold /
/// members` along the nesting path from the root to the node, scaled so that
/// weight 1.0 == maxInt(u64). Transcribed from SCPDriver::getNodeWeight
/// (SCPDriver.cpp:148-182), minus its `isLocalNode` early-out (nomination
/// layer's job, §5.4).
///
/// PATH-COMBINATION RULE (oracle, transcribed faithfully): FIRST MATCH wins —
/// "if a validator is repeated multiple times its weight is only the weight
/// of the first occurrence" (SCPDriver.cpp:146-147). At each level the
/// top-level `validators` are scanned in declaration order BEFORE any inner
/// set; inner sets are then scanned in order and the first whose recursive
/// weight is nonzero terminates the search. Weights along other paths are
/// never combined (no max, no sum). Validated SLCP qsets forbid duplicate
/// nodes anywhere in the tree (§4.1), so at most one path exists here anyway.
///
/// Returns 0 when `node` is not in the tree.
pub fn nodeWeight(qs: *const qset.QuorumSetOwned, node: NodeId) u64 {
    const n: u64 = qs.threshold;
    const d: u64 = @intCast(qs.validators.len + qs.inner_sets.len);

    for (qs.validators) |v| {
        if (std.mem.eql(u8, &v, &node)) {
            return computeWeight(std.math.maxInt(u64), d, n);
        }
    }
    for (qs.inner_sets) |*inner| {
        const leaf_w = nodeWeight(inner, node);
        if (leaf_w != 0) {
            return computeWeight(leaf_w, d, n);
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn nid(byte: u8) NodeId {
    return @splat(byte);
}

/// Test-only qset built over borrowed slices (no allocator, no deinit).
fn flatQs(threshold: u32, validators: []NodeId) qset.QuorumSetOwned {
    return .{ .threshold = threshold, .validators = validators, .inner_sets = &.{} };
}

fn nestedQs(threshold: u32, validators: []NodeId, inner: []qset.QuorumSetOwned) qset.QuorumSetOwned {
    return .{ .threshold = threshold, .validators = validators, .inner_sets = inner };
}

/// Reference slice evaluator for the property tests: the mathematical
/// definition, written independently of the implementation — count satisfied
/// members, compare against threshold. (Deliberately diverges from the
/// oracle's unsigned-wrap only at threshold 0, which validated qsets forbid.)
fn refSliceSat(qs: *const qset.QuorumSetOwned, nodes: []const NodeId) bool {
    var sat: usize = 0;
    for (qs.validators) |v| {
        if (contains(nodes, v)) sat += 1;
    }
    for (qs.inner_sets) |*inner| {
        if (refSliceSat(inner, nodes)) sat += 1;
    }
    return sat >= qs.threshold;
}

fn collectMembers(qs: *const qset.QuorumSetOwned, out: *std.ArrayList(NodeId), gpa: std.mem.Allocator) !void {
    for (qs.validators) |v| {
        if (!contains(out.items, v)) try out.append(gpa, v);
    }
    for (qs.inner_sets) |*inner| try collectMembers(inner, out, gpa);
}

/// Reference v-blocking: S blocks qs iff qs has NO satisfied slice that
/// avoids S entirely — by monotonicity of refSliceSat, iff the complement of
/// S over the qset's member universe fails to satisfy any slice.
fn refVBlocking(gpa: std.mem.Allocator, qs: *const qset.QuorumSetOwned, s: []const NodeId) !bool {
    var members: std.ArrayList(NodeId) = .empty;
    defer members.deinit(gpa);
    try collectMembers(qs, &members, gpa);
    var complement: std.ArrayList(NodeId) = .empty;
    defer complement.deinit(gpa);
    for (members.items) |m| {
        if (!contains(s, m)) try complement.append(gpa, m);
    }
    return !refSliceSat(qs, complement.items);
}

const TestLookup = struct {
    const Entry = struct { id: NodeId, qs: *const qset.QuorumSetOwned };
    entries: []const Entry,

    fn get(ctx: *const anyopaque, node: NodeId) ?*const qset.QuorumSetOwned {
        const self: *const TestLookup = @ptrCast(@alignCast(ctx));
        for (self.entries) |e| {
            if (std.mem.eql(u8, &e.id, &node)) return e.qs;
        }
        return null;
    }

    fn lookup(self: *const TestLookup) QSetLookup {
        return .{ .ctx = self, .get = get };
    }
};

test "isQuorumSlice / isVBlocking: flat 3-of-4 (oracle 'vblocking and quorum', SCPTests.cpp:634)" {
    var vals = [_]NodeId{ nid(0), nid(1), nid(2), nid(3) };
    const qs = flatQs(3, &vals);

    // {v0}
    try testing.expect(!isQuorumSlice(&qs, &.{nid(0)}));
    try testing.expect(!isVBlocking(&qs, &.{nid(0)}));
    // {v0, v2}
    try testing.expect(!isQuorumSlice(&qs, &.{ nid(0), nid(2) }));
    try testing.expect(isVBlocking(&qs, &.{ nid(0), nid(2) }));
    // {v0, v2, v3}
    try testing.expect(isQuorumSlice(&qs, &.{ nid(0), nid(2), nid(3) }));
    try testing.expect(isVBlocking(&qs, &.{ nid(0), nid(2), nid(3) }));
    // {v0, v1, v2, v3}
    try testing.expect(isQuorumSlice(&qs, &.{ nid(0), nid(1), nid(2), nid(3) }));
    try testing.expect(isVBlocking(&qs, &.{ nid(0), nid(1), nid(2), nid(3) }));
}

test "flat 2-of-3 slices; non-members never count" {
    var vals = [_]NodeId{ nid(1), nid(2), nid(3) };
    const qs = flatQs(2, &vals);

    try testing.expect(isQuorumSlice(&qs, &.{ nid(1), nid(3) }));
    try testing.expect(!isQuorumSlice(&qs, &.{nid(2)}));
    // outsiders contribute nothing
    try testing.expect(!isQuorumSlice(&qs, &.{ nid(2), nid(9), nid(8) }));
    try testing.expect(isQuorumSlice(&qs, &.{ nid(9), nid(2), nid(1) }));
    // v-blocking needs n - t + 1 = 2 members
    try testing.expect(!isVBlocking(&qs, &.{nid(1)}));
    try testing.expect(isVBlocking(&qs, &.{ nid(1), nid(2) }));
    try testing.expect(!isVBlocking(&qs, &.{ nid(9), nid(8) }));
}

test "nested org sets: 2-of-{A, {2-of-3 org1}, {2-of-3 org2}}" {
    var org1_vals = [_]NodeId{ nid(10), nid(11), nid(12) };
    var org2_vals = [_]NodeId{ nid(20), nid(21), nid(22) };
    var inner = [_]qset.QuorumSetOwned{ flatQs(2, &org1_vals), flatQs(2, &org2_vals) };
    var top_vals = [_]NodeId{nid(1)};
    const qs = nestedQs(2, &top_vals, &inner);

    // A + a satisfied org
    try testing.expect(isQuorumSlice(&qs, &.{ nid(1), nid(10), nid(11) }));
    // two satisfied orgs, no A
    try testing.expect(isQuorumSlice(&qs, &.{ nid(10), nid(12), nid(20), nid(22) }));
    // A + half an org is not enough
    try testing.expect(!isQuorumSlice(&qs, &.{ nid(1), nid(10) }));
    // v-blocking: left_till_block = 3 - 2 + 1 = 2 at top; blocking both orgs
    // (each needs 2 of its 3) blocks the whole set without touching A.
    try testing.expect(isVBlocking(&qs, &.{ nid(10), nid(11), nid(20), nid(21) }));
    // blocking one org + A also blocks
    try testing.expect(isVBlocking(&qs, &.{ nid(1), nid(20), nid(21) }));
    // one org blocked alone is not enough
    try testing.expect(!isVBlocking(&qs, &.{ nid(20), nid(21) }));
    // one member per org never blocks an org, so never blocks the top
    try testing.expect(!isVBlocking(&qs, &.{ nid(1), nid(10), nid(20) }));
}

test "v-blocking thresholds at boundaries" {
    // 1-of-3: any single member blocks nothing... left_till_block = 3, needs all 3.
    var vals3 = [_]NodeId{ nid(1), nid(2), nid(3) };
    const one_of_three = flatQs(1, &vals3);
    try testing.expect(!isVBlocking(&one_of_three, &.{ nid(1), nid(2) }));
    try testing.expect(isVBlocking(&one_of_three, &.{ nid(1), nid(2), nid(3) }));

    // n-of-n: any single member blocks (left_till_block = 1).
    const three_of_three = flatQs(3, &vals3);
    try testing.expect(isVBlocking(&three_of_three, &.{nid(2)}));
    try testing.expect(!isVBlocking(&three_of_three, &.{nid(9)}));

    // 1-of-1
    var vals1 = [_]NodeId{nid(7)};
    const singleton = flatQs(1, &vals1);
    try testing.expect(isVBlocking(&singleton, &.{nid(7)}));
    try testing.expect(!isVBlocking(&singleton, &.{nid(8)}));
}

test "threshold-0 set can never be blocked (and threshold-0 inner can't block parent)" {
    var vals = [_]NodeId{ nid(1), nid(2) };
    const zero = flatQs(0, &vals);
    try testing.expect(!isVBlocking(&zero, &.{ nid(1), nid(2) }));

    // parent 2-of-{A, B, zero-set}: left_till_block = 3 - 2 + 1 = 2, and the
    // zero-threshold inner can never contribute a hit — even engulfing all of
    // its members plus A leaves the parent unblocked, while {A, B} blocks.
    var inner = [_]qset.QuorumSetOwned{flatQs(0, &vals)};
    var top_vals = [_]NodeId{ nid(8), nid(9) };
    const parent = nestedQs(2, &top_vals, &inner);
    try testing.expect(!isVBlocking(&parent, &.{ nid(9), nid(1), nid(2) }));
    try testing.expect(isVBlocking(&parent, &.{ nid(8), nid(9) }));
}

test "isQuorum: fixpoint drops a node with a missing qset" {
    const gpa = testing.allocator;
    var vals = [_]NodeId{ nid(1), nid(2), nid(3) };
    const two_of_three = flatQs(2, &vals);
    const three_of_three = flatQs(3, &vals);

    // A(1) and B(2) advertise 2-of-{1,2,3}; C(3)'s qset is unknown.
    const tl = TestLookup{ .entries = &.{
        .{ .id = nid(1), .qs = &two_of_three },
        .{ .id = nid(2), .qs = &two_of_three },
    } };
    const candidates = [_]NodeId{ nid(1), nid(2), nid(3) };
    // C dropped; {A,B} still satisfies everyone's 2-of-3 → quorum.
    try testing.expect(try isQuorum(gpa, &two_of_three, &candidates, tl.lookup()));

    // With 3-of-3 advertised sets the drop of C cascades to the empty set.
    const tl3 = TestLookup{ .entries = &.{
        .{ .id = nid(1), .qs = &three_of_three },
        .{ .id = nid(2), .qs = &three_of_three },
    } };
    try testing.expect(!try isQuorum(gpa, &three_of_three, &candidates, tl3.lookup()));

    // Same 3-of-3 shape with C's qset known → quorum.
    const tl_full = TestLookup{ .entries = &.{
        .{ .id = nid(1), .qs = &three_of_three },
        .{ .id = nid(2), .qs = &three_of_three },
        .{ .id = nid(3), .qs = &three_of_three },
    } };
    try testing.expect(try isQuorum(gpa, &three_of_three, &candidates, tl_full.lookup()));
}

test "isQuorum: mutually-referencing qsets and cascading removal" {
    const gpa = testing.allocator;
    var ab = [_]NodeId{ nid(1), nid(2) };
    var ac = [_]NodeId{ nid(1), nid(3) };
    const q_ab = flatQs(2, &ab); // requires both A and B
    const q_ac = flatQs(2, &ac); // requires both A and C

    // A and B reference each other → {A, B} is a quorum for local 2-of-{A,B}.
    const tl = TestLookup{ .entries = &.{
        .{ .id = nid(1), .qs = &q_ab },
        .{ .id = nid(2), .qs = &q_ab },
    } };
    const cand_ab = [_]NodeId{ nid(1), nid(2) };
    try testing.expect(try isQuorum(gpa, &q_ab, &cand_ab, tl.lookup()));

    // A requires {A, C} but C is not a candidate: A drops on pass 1, then B
    // (requiring A) drops on pass 2, fixpoint = {} → not a quorum.
    const tl2 = TestLookup{ .entries = &.{
        .{ .id = nid(1), .qs = &q_ac },
        .{ .id = nid(2), .qs = &q_ab },
    } };
    try testing.expect(!try isQuorum(gpa, &q_ab, &cand_ab, tl2.lookup()));

    // Empty candidate set is never a quorum (threshold >= 1).
    try testing.expect(!try isQuorum(gpa, &q_ab, &.{}, tl.lookup()));
}

test "nodeWeight: oracle 'nomination weight' cases (SCPUnitTests.cpp:201)" {
    // 3-of-4 flat: weight(v2) ~ 0.75 — exactly floor(maxInt * 3 / 4).
    var vals = [_]NodeId{ nid(0), nid(1), nid(2), nid(3) };
    const qs34 = flatQs(3, &vals);
    const expect34: u64 = @intCast(@as(u128, std.math.maxInt(u64)) * 3 / 4);
    try testing.expectEqual(expect34, nodeWeight(&qs34, nid(2)));

    // non-member → 0
    try testing.expectEqual(@as(u64, 0), nodeWeight(&qs34, nid(4)));

    // add inner 1-of-{v4, v5}: top becomes 3-of-5; weight(v4) ~ 0.6 * 0.5.
    var inner_vals = [_]NodeId{ nid(4), nid(5) };
    var inner = [_]qset.QuorumSetOwned{flatQs(1, &inner_vals)};
    const qs_nested = nestedQs(3, &vals, &inner);
    const leaf: u64 = @intCast(@as(u128, std.math.maxInt(u64)) * 1 / 2);
    const expect_nested: u64 = @intCast(@as(u128, leaf) * 3 / 5);
    try testing.expectEqual(expect_nested, nodeWeight(&qs_nested, nid(4)));

    // top-level member weight in the widened set: floor(maxInt * 3 / 5)
    const expect35: u64 = @intCast(@as(u128, std.math.maxInt(u64)) * 3 / 5);
    try testing.expectEqual(expect35, nodeWeight(&qs_nested, nid(1)));
}

// ---------------------------------------------------------------------------
// Property tests vs brute force (M1 accept criterion).
// Universe: 5 nodes. For every generated qset shape, enumerate ALL 2^5
// subsets and check the implementation against independent reference
// definitions.
// ---------------------------------------------------------------------------

fn subsetNodes(mask: u5, buf: *[5]NodeId) []NodeId {
    var len: usize = 0;
    var i: u8 = 0;
    while (i < 5) : (i += 1) {
        if ((@as(u8, mask) >> @intCast(i)) & 1 == 1) {
            buf[len] = nid(i);
            len += 1;
        }
    }
    return buf[0..len];
}

fn checkAllSubsets(gpa: std.mem.Allocator, qs: *const qset.QuorumSetOwned, checked: *usize) !void {
    var mask: u8 = 0;
    while (mask < 32) : (mask += 1) {
        var buf: [5]NodeId = undefined;
        const s = subsetNodes(@intCast(mask), &buf);

        // slice predicate vs direct counting definition
        try testing.expectEqual(refSliceSat(qs, s), isQuorumSlice(qs, s));
        // v-blocking iff no slice avoids S
        try testing.expectEqual(try refVBlocking(gpa, qs, s), isVBlocking(qs, s));
        checked.* += 1;
    }
}

test "property: flat qsets, thresholds 1..n, all 2^5 subsets" {
    const gpa = testing.allocator;
    var checked: usize = 0;
    var shapes: usize = 0;

    var n: u8 = 1;
    while (n <= 5) : (n += 1) {
        var vals: [5]NodeId = undefined;
        for (0..n) |i| vals[i] = nid(@intCast(i));
        var t: u32 = 1;
        while (t <= n) : (t += 1) {
            const qs = flatQs(t, vals[0..n]);
            try checkAllSubsets(gpa, &qs, &checked);
            shapes += 1;

            // weight: every member == floor(maxInt * t / n); non-member == 0
            const expect: u64 = @intCast(@as(u128, std.math.maxInt(u64)) * t / n);
            for (0..5) |i| {
                const w = nodeWeight(&qs, nid(@intCast(i)));
                try testing.expectEqual(if (i < n) expect else 0, w);
            }
        }
    }
    // 15 flat shapes x 32 subsets
    try testing.expectEqual(@as(usize, 15), shapes);
    try testing.expectEqual(@as(usize, 480), checked);
}

test "property: nested shape t-of-{v0, {t1-of-{v1,v2}}, {t2-of-{v3,v4}}}, all 2^5 subsets" {
    const gpa = testing.allocator;
    var checked: usize = 0;
    var shapes: usize = 0;

    var top_vals = [_]NodeId{nid(0)};
    var in1_vals = [_]NodeId{ nid(1), nid(2) };
    var in2_vals = [_]NodeId{ nid(3), nid(4) };

    var t: u32 = 1;
    while (t <= 3) : (t += 1) {
        var t1: u32 = 1;
        while (t1 <= 2) : (t1 += 1) {
            var t2: u32 = 1;
            while (t2 <= 2) : (t2 += 1) {
                var inner = [_]qset.QuorumSetOwned{ flatQs(t1, &in1_vals), flatQs(t2, &in2_vals) };
                const qs = nestedQs(t, &top_vals, &inner);
                try checkAllSubsets(gpa, &qs, &checked);
                shapes += 1;

                // weight monotonicity: nesting scales by t1/2 (resp. t2/2) <= 1,
                // so an inner member never outweighs the top-level validator.
                const w_top = nodeWeight(&qs, nid(0));
                const w_in1 = nodeWeight(&qs, nid(1));
                const w_in2 = nodeWeight(&qs, nid(3));
                try testing.expect(w_in1 <= w_top);
                try testing.expect(w_in2 <= w_top);
                // exact: top factor applied to the inner leaf weight
                const leaf1: u64 = @intCast(@as(u128, std.math.maxInt(u64)) * t1 / 2);
                const expect_in1: u64 = @intCast(@as(u128, leaf1) * t / 3);
                try testing.expectEqual(expect_in1, w_in1);
            }
        }
    }
    // 12 nested shapes x 32 subsets
    try testing.expectEqual(@as(usize, 12), shapes);
    try testing.expectEqual(@as(usize, 384), checked);
}

test "property: depth-3 chain never increases weight" {
    // {1-of-{ {1-of-{ {t-of-{v0,v1}} }} }} — pure 1-of-1 wrappers multiply by
    // 1/1 and must leave the leaf weight unchanged; wider levels only shrink it.
    var leaf_vals = [_]NodeId{ nid(0), nid(1) };
    var t: u32 = 1;
    while (t <= 2) : (t += 1) {
        const leaf = flatQs(t, &leaf_vals);
        var mid_inner = [_]qset.QuorumSetOwned{leaf};
        const mid = nestedQs(1, &.{}, &mid_inner);
        var top_inner = [_]qset.QuorumSetOwned{mid};
        const top = nestedQs(1, &.{}, &top_inner);

        const w_leaf = nodeWeight(&leaf, nid(0));
        const w_top = nodeWeight(&top, nid(0));
        try testing.expectEqual(w_leaf, w_top); // 1-of-1 chain: factor 1
        try testing.expect(w_top <= w_leaf); // never increases

        // widening the top to 1-of-2 strictly shrinks
        var wide_vals = [_]NodeId{nid(9)};
        var wide_inner = [_]qset.QuorumSetOwned{leaf};
        const wide = nestedQs(1, &wide_vals, &wide_inner);
        try testing.expect(nodeWeight(&wide, nid(0)) <= w_leaf);
        try testing.expectEqual(w_leaf / 2, nodeWeight(&wide, nid(0)));
    }
}
