//! Quorum-set validation, normalization, hashing, and lint (design §4.3, §12).
//!
//! Normalization (reject, not repair): validators sorted bytewise ascending
//! and unique; `{threshold: 1, [single validator]}` innerSets flattened into
//! the parent; innerSets sorted by their own qsetHash; duplicates / empties /
//! threshold violations are errors. Hashing rebuilds the NORMALIZED set with
//! no present-but-default pointers (the §4.3 normative build rule) and takes
//! SHA-256("SLCP-QSET-V1" ‖ canonicalFlat(bytes)).
//!
//! Lint (§12) judges a LOCAL configuration: sub-majority thresholds are a
//! fork machine (error); fragile-but-legal shapes get warnings. Wire-received
//! qsets are only normalized+hashed — other nodes' unsafe configs are their
//! problem and must still be processed.

const std = @import("std");
const capnpc = @import("capnpc-zig");
const canonical = @import("../canonical.zig");
const crypto = @import("../crypto.zig");
const gen_slcp = @import("../gen/slcp.zig");

pub const NodeId = [32]u8;

pub const max_depth = 4; // frozen wire limit (§4.5)
pub const max_total_validators = 255; // frozen wire limit (§4.5)

pub const Error = error{
    EmptyQuorumSet,
    ThresholdOutOfRange,
    DepthExceeded,
    TooManyValidators,
    DuplicateNode,
    BadValidatorLength,
};

pub const QuorumSetOwned = struct {
    threshold: u32,
    validators: []NodeId,
    inner_sets: []QuorumSetOwned,

    pub fn deinit(self: *QuorumSetOwned, gpa: std.mem.Allocator) void {
        for (self.inner_sets) |*inner| inner.deinit(gpa);
        gpa.free(self.inner_sets);
        gpa.free(self.validators);
        self.* = undefined;
    }
};

/// Parse a wire QuorumSet into an owned tree. Validates lengths and depth
/// only; call `validateAndNormalize` afterwards. Caller owns the result.
pub fn fromReader(gpa: std.mem.Allocator, reader: gen_slcp.QuorumSet.Reader) !QuorumSetOwned {
    return fromReaderRec(gpa, reader, 1);
}

fn fromReaderRec(gpa: std.mem.Allocator, reader: gen_slcp.QuorumSet.Reader, depth: u32) !QuorumSetOwned {
    if (depth > max_depth) return Error.DepthExceeded;

    const vals = try reader.getValidators();
    var validators = try gpa.alloc(NodeId, vals.len());
    errdefer gpa.free(validators);
    for (0..vals.len()) |i| {
        const v = try vals.get(@intCast(i));
        if (v.len != 32) return Error.BadValidatorLength;
        @memcpy(&validators[i], v);
    }

    const inners = try reader.getInnerSets();
    var inner_sets = try gpa.alloc(QuorumSetOwned, inners.len());
    var built: usize = 0;
    errdefer {
        for (inner_sets[0..built]) |*inner| inner.deinit(gpa);
        gpa.free(inner_sets);
    }
    for (0..inners.len()) |i| {
        inner_sets[i] = try fromReaderRec(gpa, try inners.get(@intCast(i)), depth + 1);
        built += 1;
    }

    return .{
        .threshold = try reader.getThreshold(),
        .validators = validators,
        .inner_sets = inner_sets,
    };
}

/// Normalize in place, then validate the whole tree (§4.3). Reject, not repair.
pub fn validateAndNormalize(gpa: std.mem.Allocator, qs: *QuorumSetOwned) !void {
    try normalizeRec(gpa, qs);
    try checkTree(gpa, qs);
}

fn normalizeRec(gpa: std.mem.Allocator, qs: *QuorumSetOwned) !void {
    // Children first, so flattening sees already-normalized inner sets.
    for (qs.inner_sets) |*inner| try normalizeRec(gpa, inner);

    // Flatten {threshold: 1, [single validator], no innerSets} into the parent.
    var lifted: usize = 0;
    for (qs.inner_sets) |*inner| {
        if (inner.threshold == 1 and inner.validators.len == 1 and inner.inner_sets.len == 0) lifted += 1;
    }
    if (lifted > 0) {
        const new_vals = try gpa.alloc(NodeId, qs.validators.len + lifted);
        errdefer gpa.free(new_vals);
        @memcpy(new_vals[0..qs.validators.len], qs.validators);
        var vi = qs.validators.len;
        const kept = try gpa.alloc(QuorumSetOwned, qs.inner_sets.len - lifted);
        var ki: usize = 0;
        for (qs.inner_sets) |*inner| {
            if (inner.threshold == 1 and inner.validators.len == 1 and inner.inner_sets.len == 0) {
                new_vals[vi] = inner.validators[0];
                vi += 1;
                inner.deinit(gpa);
            } else {
                kept[ki] = inner.*;
                ki += 1;
            }
        }
        gpa.free(qs.validators);
        gpa.free(qs.inner_sets);
        qs.validators = new_vals;
        qs.inner_sets = kept;
    }

    // Validators bytewise ascending.
    std.mem.sort(NodeId, qs.validators, {}, nodeIdLessThan);

    // Inner sets ascending by their own qsetHash.
    if (qs.inner_sets.len > 1) {
        const Keyed = struct { h: [32]u8, set: QuorumSetOwned };
        const keyed = try gpa.alloc(Keyed, qs.inner_sets.len);
        defer gpa.free(keyed);
        for (qs.inner_sets, 0..) |inner, i| {
            keyed[i] = .{ .h = try hashNormalized(gpa, &inner), .set = inner };
        }
        std.mem.sort(Keyed, keyed, {}, struct {
            fn lessThan(_: void, a: Keyed, b: Keyed) bool {
                return std.mem.order(u8, &a.h, &b.h) == .lt;
            }
        }.lessThan);
        for (keyed, 0..) |k, i| qs.inner_sets[i] = k.set;
    }

    // Local shape: nonempty; threshold in [1, members].
    const members: u32 = @intCast(qs.validators.len + qs.inner_sets.len);
    if (members == 0) return Error.EmptyQuorumSet;
    if (qs.threshold < 1 or qs.threshold > members) return Error.ThresholdOutOfRange;
}

fn nodeIdLessThan(_: void, a: NodeId, b: NodeId) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

/// Whole-tree rules: total validator entries <= 255; no duplicate node
/// anywhere in the tree (§4.1).
fn checkTree(gpa: std.mem.Allocator, qs: *const QuorumSetOwned) !void {
    var all: std.ArrayList(NodeId) = .empty;
    defer all.deinit(gpa);
    try collectValidators(gpa, qs, &all);
    if (all.items.len > max_total_validators) return Error.TooManyValidators;
    std.mem.sort(NodeId, all.items, {}, nodeIdLessThan);
    var i: usize = 1;
    while (i < all.items.len) : (i += 1) {
        if (std.mem.eql(u8, &all.items[i - 1], &all.items[i])) return Error.DuplicateNode;
    }
}

fn collectValidators(gpa: std.mem.Allocator, qs: *const QuorumSetOwned, out: *std.ArrayList(NodeId)) !void {
    try out.appendSlice(gpa, qs.validators);
    for (qs.inner_sets) |*inner| try collectValidators(gpa, inner, out);
}

/// Canonical flat bytes of a NORMALIZED set. Normative build rule (§4.3):
/// empty lists stay ABSENT pointers, so every implementation rebuilding the
/// same normalized qset produces identical canonical bytes.
pub fn canonicalBytes(gpa: std.mem.Allocator, qs: *const QuorumSetOwned) ![]u8 {
    var mb = capnpc.message.MessageBuilder.init(gpa);
    defer mb.deinit();
    var root = try gen_slcp.QuorumSet.Builder.init(&mb);
    try writeInto(&root, qs);
    const framed = try mb.toBytes();
    defer gpa.free(framed);
    return canonical.canonicalFlatFromFramed(gpa, framed);
}

fn writeInto(b: *gen_slcp.QuorumSet.Builder, qs: *const QuorumSetOwned) !void {
    try b.setThreshold(qs.threshold);
    if (qs.validators.len > 0) {
        const vl = try b.initValidators(@intCast(qs.validators.len));
        for (qs.validators, 0..) |*v, i| try vl.set(@intCast(i), v);
    }
    if (qs.inner_sets.len > 0) {
        const il = try b.initInnerSets(@intCast(qs.inner_sets.len));
        for (qs.inner_sets, 0..) |*inner, i| {
            var ib = try il.get(@intCast(i));
            try writeInto(&ib, inner);
        }
    }
}

/// Deep copy of `qs` with `node` excised (design §5.4/§12: leader weights run
/// over the SELF-excised local qset). Transcribed from stellar-core
/// `normalizeQSetSimplify`'s removal step (QuorumSetUtils.cpp:141-148): at
/// every level where `node` appears in `validators` it is removed and THAT
/// level's threshold is decremented by the number of entries removed
/// (`qSet.threshold -= uint32(v.end() - it_v)`). The copy is then re-run
/// through `validateAndNormalize`, which supplies the rest of `normalizeQSet`'s
/// simplification — singleton-inner flattening (QuorumSetUtils.cpp:154-166) —
/// plus SLCP's canonical ordering.
///
/// Returns null when the excised tree is unusable — exactly the shapes a
/// re-run of `validateAndNormalize` rejects: the whole set emptied (a
/// singleton-`node` qset), or some level's threshold fell to 0 or its member
/// list emptied. `node` absent from the tree yields an unchanged (still
/// deep-copied) set. Caller deinits the returned set.
pub fn exciseNode(gpa: std.mem.Allocator, qs: *const QuorumSetOwned, node: NodeId) !?QuorumSetOwned {
    var copy = try exciseCopy(gpa, qs, node);
    validateAndNormalize(gpa, &copy) catch |err| switch (err) {
        error.OutOfMemory => {
            copy.deinit(gpa);
            return error.OutOfMemory;
        },
        else => {
            copy.deinit(gpa);
            return null;
        },
    };
    return copy;
}

fn exciseCopy(gpa: std.mem.Allocator, qs: *const QuorumSetOwned, node: NodeId) !QuorumSetOwned {
    var removed: u32 = 0;
    for (qs.validators) |*v| {
        if (std.mem.eql(u8, v, &node)) removed += 1;
    }
    const vals = try gpa.alloc(NodeId, qs.validators.len - removed);
    errdefer gpa.free(vals);
    var vi: usize = 0;
    for (qs.validators) |*v| {
        if (std.mem.eql(u8, v, &node)) continue;
        vals[vi] = v.*;
        vi += 1;
    }

    var inners = try gpa.alloc(QuorumSetOwned, qs.inner_sets.len);
    var built: usize = 0;
    errdefer {
        for (inners[0..built]) |*inner| inner.deinit(gpa);
        gpa.free(inners);
    }
    for (qs.inner_sets, 0..) |*inner, i| {
        inners[i] = try exciseCopy(gpa, inner, node);
        built += 1;
    }

    return .{
        // Saturating only for defense: a validated tree has unique nodes and
        // threshold >= 1, so removed <= 1 <= threshold and this never clips.
        .threshold = qs.threshold -| removed,
        .validators = vals,
        .inner_sets = inners,
    };
}

/// qsetHash of an already-normalized set (§4.3).
pub fn hashNormalized(gpa: std.mem.Allocator, qs: *const QuorumSetOwned) ![32]u8 {
    const flat = try canonicalBytes(gpa, qs);
    defer gpa.free(flat);
    return crypto.qsetHash(flat);
}

// ---------------------------------------------------------------------------
// Lint (§12) — v2 (M6). The top-level threshold checks judge the LOCAL
// configuration; `critical_node` is tree-wide (a validator present in every
// slice). Lint never reasons about OTHER nodes' qsets (no cross-node
// intersection analysis — see threat-model §4). Findings are emitted in a
// fixed order so lint output is byte-stable for the lint.json vectors.
// ---------------------------------------------------------------------------

pub const LintLevel = enum { err, warning };

/// Ordinals are the wire `LintFinding.code` (host.capnp) — append-only.
pub const LintCode = enum {
    sub_majority_threshold, // error: two disjoint "quorums" can exist in your own slice
    below_two_thirds, // warning: threshold < ceil(2n/3) — weak Byzantine margin
    all_members_critical, // warning: threshold == n — any single member offline halts you
    critical_node, // warning: THIS validator is in every slice — it alone offline halts you
};

pub const LintFinding = struct {
    level: LintLevel,
    code: LintCode,
    members: u32, // top-level member count n
    threshold: u32,
    /// Set only for `critical_node` (the validator in question); null otherwise.
    /// On the wire this is `LintFinding.node @4` — an ABSENT pointer when null.
    node: ?NodeId = null,
};

/// Lint a NORMALIZED local quorum set. Caller frees the returned slice.
/// Order: the three top-level findings (each at most once, in enum order),
/// then one `critical_node` per critical validator, ascending by bytes.
pub fn lint(gpa: std.mem.Allocator, qs: *const QuorumSetOwned) ![]LintFinding {
    var findings: std.ArrayList(LintFinding) = .empty;
    defer findings.deinit(gpa);

    const n: u32 = @intCast(qs.validators.len + qs.inner_sets.len);
    const t = qs.threshold;

    // threshold < n - threshold + 1  <=>  2t < n + 1
    if (2 * t < n + 1) {
        try findings.append(gpa, .{ .level = .err, .code = .sub_majority_threshold, .members = n, .threshold = t });
    }
    const two_thirds = std.math.divCeil(u32, 2 * n, 3) catch unreachable;
    if (t < two_thirds) {
        try findings.append(gpa, .{ .level = .warning, .code = .below_two_thirds, .members = n, .threshold = t });
    }
    if (t == n and n > 1) {
        try findings.append(gpa, .{ .level = .warning, .code = .all_members_critical, .members = n, .threshold = t });
    }

    const critical = try criticalNodes(gpa, qs);
    defer gpa.free(critical);
    for (critical) |id| {
        try findings.append(gpa, .{ .level = .warning, .code = .critical_node, .members = n, .threshold = t, .node = id });
    }

    return findings.toOwnedSlice(gpa);
}

/// Size of the smallest set of validators whose simultaneous outage makes
/// `qs` unsatisfiable (the §12 "halts if any K of these are offline" K).
/// Validator → 1; set → sum of the (n − t + 1) smallest member values. Exact
/// for validated trees (members are disjoint, so the cheapest way to knock
/// out n − t + 1 members is the n − t + 1 cheapest ones).
pub fn minBlockingSize(qs: *const QuorumSetOwned) u32 {
    var costs: [max_total_validators + 1]u32 = undefined;
    var len: usize = 0;
    for (qs.validators) |_| {
        if (len < costs.len) {
            costs[len] = 1;
            len += 1;
        }
    }
    for (qs.inner_sets) |*inner| {
        if (len < costs.len) {
            costs[len] = minBlockingSize(inner);
            len += 1;
        }
    }
    const members = costs[0..len];
    std.mem.sort(u32, members, {}, std.sort.asc(u32));
    const n: u32 = @intCast(members.len);
    if (qs.threshold == 0 or qs.threshold > n) return 0; // unvalidated shapes: nothing to block / already blocked
    const need: usize = n - qs.threshold + 1;
    var sum: u32 = 0;
    for (members[0..need]) |c| sum += c;
    return sum;
}

/// Does `qs` still have a satisfiable slice when `node` is offline? Direct
/// counting definition over the tree: a validator counts unless it IS `node`;
/// an inner set counts if it is itself satisfiable without `node`. Equals
/// `!local_node.isVBlocking(qs, &.{node})` (property-tested there).
pub fn isSatisfiableWithout(qs: *const QuorumSetOwned, node: NodeId) bool {
    var sat: u32 = 0;
    for (qs.validators) |*v| {
        if (!std.mem.eql(u8, v, &node)) sat += 1;
    }
    for (qs.inner_sets) |*inner| {
        if (isSatisfiableWithout(inner, node)) sat += 1;
    }
    return sat >= qs.threshold;
}

/// Every validator in the tree whose outage alone makes `qs` unsatisfiable,
/// ascending by bytes. Caller frees.
pub fn criticalNodes(gpa: std.mem.Allocator, qs: *const QuorumSetOwned) ![]NodeId {
    var all: std.ArrayList(NodeId) = .empty;
    defer all.deinit(gpa);
    try collectValidators(gpa, qs, &all);
    std.mem.sort(NodeId, all.items, {}, nodeIdLessThan);

    var out: std.ArrayList(NodeId) = .empty;
    defer out.deinit(gpa);
    for (all.items, 0..) |id, i| {
        if (i > 0 and std.mem.eql(u8, &all.items[i - 1], &id)) continue; // unvalidated duplicate
        if (!isSatisfiableWithout(qs, id)) try out.append(gpa, id);
    }
    return out.toOwnedSlice(gpa);
}

/// Is `node` a validator anywhere in the tree?
pub fn containsNode(qs: *const QuorumSetOwned, node: NodeId) bool {
    for (qs.validators) |*v| {
        if (std.mem.eql(u8, v, &node)) return true;
    }
    for (qs.inner_sets) |*inner| {
        if (containsNode(inner, node)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn nodeId(byte: u8) NodeId {
    return @splat(byte);
}

fn ownedFlat(gpa: std.mem.Allocator, threshold: u32, validator_bytes: []const u8) !QuorumSetOwned {
    const vals = try gpa.alloc(NodeId, validator_bytes.len);
    for (validator_bytes, 0..) |b, i| vals[i] = nodeId(b);
    return .{ .threshold = threshold, .validators = vals, .inner_sets = try gpa.alloc(QuorumSetOwned, 0) };
}

test "normalize sorts validators; hash is input-order independent" {
    const gpa = std.testing.allocator;
    var a = try ownedFlat(gpa, 2, &.{ 3, 1, 2 });
    defer a.deinit(gpa);
    var b = try ownedFlat(gpa, 2, &.{ 1, 2, 3 });
    defer b.deinit(gpa);
    try validateAndNormalize(gpa, &a);
    try validateAndNormalize(gpa, &b);
    try std.testing.expect(std.mem.order(u8, &a.validators[0], &a.validators[1]) == .lt);
    const ha = try hashNormalized(gpa, &a);
    const hb = try hashNormalized(gpa, &b);
    try std.testing.expectEqualSlices(u8, &ha, &hb);
}

test "singleton inner sets are flattened into the parent" {
    const gpa = std.testing.allocator;
    var qs: QuorumSetOwned = blk: {
        const vals = try gpa.alloc(NodeId, 1);
        vals[0] = nodeId(1);
        const inners = try gpa.alloc(QuorumSetOwned, 1);
        inners[0] = try ownedFlat(gpa, 1, &.{2});
        break :blk .{ .threshold = 2, .validators = vals, .inner_sets = inners };
    };
    defer qs.deinit(gpa);
    try validateAndNormalize(gpa, &qs);
    try std.testing.expectEqual(@as(usize, 2), qs.validators.len);
    try std.testing.expectEqual(@as(usize, 0), qs.inner_sets.len);

    var flat = try ownedFlat(gpa, 2, &.{ 1, 2 });
    defer flat.deinit(gpa);
    try validateAndNormalize(gpa, &flat);
    const h1 = try hashNormalized(gpa, &qs);
    const h2 = try hashNormalized(gpa, &flat);
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "rejections: empty, threshold range, duplicates, depth, 255 cap" {
    const gpa = std.testing.allocator;

    var empty: QuorumSetOwned = .{ .threshold = 1, .validators = try gpa.alloc(NodeId, 0), .inner_sets = try gpa.alloc(QuorumSetOwned, 0) };
    defer empty.deinit(gpa);
    try std.testing.expectError(Error.EmptyQuorumSet, validateAndNormalize(gpa, &empty));

    var zero = try ownedFlat(gpa, 0, &.{1});
    defer zero.deinit(gpa);
    try std.testing.expectError(Error.ThresholdOutOfRange, validateAndNormalize(gpa, &zero));

    var high = try ownedFlat(gpa, 3, &.{ 1, 2 });
    defer high.deinit(gpa);
    try std.testing.expectError(Error.ThresholdOutOfRange, validateAndNormalize(gpa, &high));

    var dup = try ownedFlat(gpa, 1, &.{ 1, 1 });
    defer dup.deinit(gpa);
    try std.testing.expectError(Error.DuplicateNode, validateAndNormalize(gpa, &dup));

    // 256 distinct validators via two-byte variation.
    var big: QuorumSetOwned = blk: {
        const vals = try gpa.alloc(NodeId, 256);
        for (vals, 0..) |*v, i| {
            v.* = @splat(0);
            v.*[0] = @intCast(i / 16);
            v.*[1] = @intCast(i % 16);
        }
        break :blk .{ .threshold = 200, .validators = vals, .inner_sets = try gpa.alloc(QuorumSetOwned, 0) };
    };
    defer big.deinit(gpa);
    try std.testing.expectError(Error.TooManyValidators, validateAndNormalize(gpa, &big));
}

// Non-vacuity: checkTree sorts the collected validators before its neighbour
// compare. Every other DuplicateNode check (the flat [1,1] above, the qset.json
// `duplicate node across tree` vector: top [01] + inner [01,02]) collects its
// duplicate ADJACENTLY in pre-order, so deleting the `std.mem.sort` in
// checkTree leaves them green. The four shapes below are never adjacent in
// collection order; delete that sort and this goes red
// (`expected error.DuplicateNode, found void`).
test "rejections: duplicate validators that are not adjacent in collection order" {
    const gpa = std.testing.allocator;

    // t1: top [1, 2] + inner {2, [1, 3]} — collected 1,2,1,3.
    var t1 = try ownedNested(gpa, 2, &.{ 1, 2 }, &.{
        try ownedFlat(gpa, 2, &.{ 1, 3 }),
    });
    defer t1.deinit(gpa);
    try std.testing.expectError(Error.DuplicateNode, validateAndNormalize(gpa, &t1));

    // t2: node 1 in two sibling inner sets — collected 1,5,1,6 (or 1,6,1,5
    // after the inner-set hash sort); never adjacent either way.
    var t2 = try ownedNested(gpa, 2, &.{}, &.{
        try ownedFlat(gpa, 1, &.{ 1, 5 }),
        try ownedFlat(gpa, 1, &.{ 6, 1 }),
    });
    defer t2.deinit(gpa);
    try std.testing.expectError(Error.DuplicateNode, validateAndNormalize(gpa, &t2));

    // t3: node 1 at the root and again at depth 4, with 9, 8, 7, 2 between.
    var t3 = try ownedNested(gpa, 2, &.{ 1, 9 }, &.{
        try ownedNested(gpa, 1, &.{8}, &.{
            try ownedNested(gpa, 1, &.{7}, &.{
                try ownedFlat(gpa, 2, &.{ 2, 1 }),
            }),
        }),
    });
    defer t3.deinit(gpa);
    try std.testing.expectError(Error.DuplicateNode, validateAndNormalize(gpa, &t3));

    // t4: duplicate visible only after singleton flattening:
    // {2, [2], [{1,[1]}, {2,[1,3]}]} — flattening lifts 1 beside 2 at the
    // root, then the inner [1,3] repeats it: collected 1,2,1,3.
    var t4 = try ownedNested(gpa, 2, &.{2}, &.{
        try ownedFlat(gpa, 1, &.{1}),
        try ownedFlat(gpa, 2, &.{ 1, 3 }),
    });
    defer t4.deinit(gpa);
    try std.testing.expectError(Error.DuplicateNode, validateAndNormalize(gpa, &t4));
}

test "wire roundtrip: build → read → normalize → hash matches direct hash" {
    const gpa = std.testing.allocator;

    var mb = capnpc.message.MessageBuilder.init(gpa);
    defer mb.deinit();
    var root = try gen_slcp.QuorumSet.Builder.init(&mb);
    try root.setThreshold(2);
    const vl = try root.initValidators(3);
    // deliberately unsorted on the wire side of this test
    const v3 = nodeId(3);
    const v1 = nodeId(1);
    const v2 = nodeId(2);
    try vl.set(0, &v3);
    try vl.set(1, &v1);
    try vl.set(2, &v2);
    const framed = try mb.toBytes();
    defer gpa.free(framed);

    var msg = try capnpc.message.Message.init(gpa, framed, .{});
    defer msg.deinit();
    const reader = try gen_slcp.QuorumSet.Reader.init(&msg);
    var owned = try fromReader(gpa, reader);
    defer owned.deinit(gpa);
    try validateAndNormalize(gpa, &owned);

    var direct = try ownedFlat(gpa, 2, &.{ 1, 2, 3 });
    defer direct.deinit(gpa);
    try validateAndNormalize(gpa, &direct);

    const h1 = try hashNormalized(gpa, &owned);
    const h2 = try hashNormalized(gpa, &direct);
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "exciseNode: flat 2-of-3 excising a member yields 1-of-2" {
    const gpa = std.testing.allocator;
    var qs = try ownedFlat(gpa, 2, &.{ 1, 2, 3 });
    defer qs.deinit(gpa);
    try validateAndNormalize(gpa, &qs);

    var out = (try exciseNode(gpa, &qs, nodeId(2))).?;
    defer out.deinit(gpa);
    try std.testing.expectEqual(@as(u32, 1), out.threshold);
    try std.testing.expectEqual(@as(usize, 2), out.validators.len);
    try std.testing.expectEqualSlices(u8, &nodeId(1), &out.validators[0]);
    try std.testing.expectEqualSlices(u8, &nodeId(3), &out.validators[1]);
    try std.testing.expectEqual(@as(usize, 0), out.inner_sets.len);
    // the input is untouched
    try std.testing.expectEqual(@as(u32, 2), qs.threshold);
    try std.testing.expectEqual(@as(usize, 3), qs.validators.len);
}

test "exciseNode: non-member excision is an unchanged deep copy" {
    const gpa = std.testing.allocator;
    var qs = try ownedFlat(gpa, 2, &.{ 1, 2, 3 });
    defer qs.deinit(gpa);
    try validateAndNormalize(gpa, &qs);

    var out = (try exciseNode(gpa, &qs, nodeId(9))).?;
    defer out.deinit(gpa);
    const h_in = try hashNormalized(gpa, &qs);
    const h_out = try hashNormalized(gpa, &out);
    try std.testing.expectEqualSlices(u8, &h_in, &h_out);
    // deep copy, not a borrow
    try std.testing.expect(out.validators.ptr != qs.validators.ptr);
}

test "exciseNode: nested — excision hits the inner org level only" {
    const gpa = std.testing.allocator;
    // 2-of-{A, {2-of-{10,11,12}}, {2-of-{20,21,22}}}; excise 11.
    var qs: QuorumSetOwned = blk: {
        const vals = try gpa.alloc(NodeId, 1);
        vals[0] = nodeId(1);
        const inners = try gpa.alloc(QuorumSetOwned, 2);
        inners[0] = try ownedFlat(gpa, 2, &.{ 0x10, 0x11, 0x12 });
        inners[1] = try ownedFlat(gpa, 2, &.{ 0x20, 0x21, 0x22 });
        break :blk .{ .threshold = 2, .validators = vals, .inner_sets = inners };
    };
    defer qs.deinit(gpa);
    try validateAndNormalize(gpa, &qs);

    var out = (try exciseNode(gpa, &qs, nodeId(0x11))).?;
    defer out.deinit(gpa);
    // top level untouched: threshold 2, validator A, two inner sets
    try std.testing.expectEqual(@as(u32, 2), out.threshold);
    try std.testing.expectEqual(@as(usize, 1), out.validators.len);
    try std.testing.expectEqual(@as(usize, 2), out.inner_sets.len);
    // org1 became 1-of-{10,12}; org2 stayed 2-of-3
    var saw_excised = false;
    var saw_intact = false;
    for (out.inner_sets) |*inner| {
        if (inner.validators.len == 2) {
            try std.testing.expectEqual(@as(u32, 1), inner.threshold);
            try std.testing.expectEqualSlices(u8, &nodeId(0x10), &inner.validators[0]);
            try std.testing.expectEqualSlices(u8, &nodeId(0x12), &inner.validators[1]);
            saw_excised = true;
        } else {
            try std.testing.expectEqual(@as(u32, 2), inner.threshold);
            try std.testing.expectEqual(@as(usize, 3), inner.validators.len);
            saw_intact = true;
        }
    }
    try std.testing.expect(saw_excised and saw_intact);
}

test "exciseNode: singleton-self and other unusable shapes yield null" {
    const gpa = std.testing.allocator;

    // 1-of-{self} → empty set → null
    var single = try ownedFlat(gpa, 1, &.{7});
    defer single.deinit(gpa);
    try validateAndNormalize(gpa, &single);
    try std.testing.expect((try exciseNode(gpa, &single, nodeId(7))) == null);

    // 1-of-{self, other} → 0-of-{other}: threshold fell to 0 → null
    var pair = try ownedFlat(gpa, 1, &.{ 7, 8 });
    defer pair.deinit(gpa);
    try validateAndNormalize(gpa, &pair);
    try std.testing.expect((try exciseNode(gpa, &pair, nodeId(7))) == null);

    // inner 1-of-{self, A} inside 2-of-{B, C, inner} → inner 0-of-{A}
    // → validateAndNormalize rejects → null
    var nested: QuorumSetOwned = blk: {
        const vals = try gpa.alloc(NodeId, 2);
        vals[0] = nodeId(2);
        vals[1] = nodeId(3);
        const inners = try gpa.alloc(QuorumSetOwned, 1);
        inners[0] = try ownedFlat(gpa, 1, &.{ 7, 8 });
        break :blk .{ .threshold = 2, .validators = vals, .inner_sets = inners };
    };
    defer nested.deinit(gpa);
    try validateAndNormalize(gpa, &nested);
    try std.testing.expect((try exciseNode(gpa, &nested, nodeId(7))) == null);
}

test "exciseNode: re-normalization flattens an inner set reduced to 1-of-1" {
    const gpa = std.testing.allocator;
    // 2-of-{B, {2-of-{self, A}}}: excision leaves inner 1-of-{A}, which
    // re-normalization flattens into the parent (oracle's singleton-inner
    // merge, QuorumSetUtils.cpp:154-166) → 2-of-{A, B} flat.
    var qs: QuorumSetOwned = blk: {
        const vals = try gpa.alloc(NodeId, 1);
        vals[0] = nodeId(2);
        const inners = try gpa.alloc(QuorumSetOwned, 1);
        inners[0] = try ownedFlat(gpa, 2, &.{ 7, 1 });
        break :blk .{ .threshold = 2, .validators = vals, .inner_sets = inners };
    };
    defer qs.deinit(gpa);
    try validateAndNormalize(gpa, &qs);

    var out = (try exciseNode(gpa, &qs, nodeId(7))).?;
    defer out.deinit(gpa);
    try std.testing.expectEqual(@as(u32, 2), out.threshold);
    try std.testing.expectEqual(@as(usize, 2), out.validators.len);
    try std.testing.expectEqual(@as(usize, 0), out.inner_sets.len);
    try std.testing.expectEqualSlices(u8, &nodeId(1), &out.validators[0]);
    try std.testing.expectEqualSlices(u8, &nodeId(2), &out.validators[1]);
}

// Non-vacuity: dropping the `critical_node` loop in `lint` → the 3-of-3 case
// has 1 finding, not 4, and 1-of-1 has 0; setting `node` on every finding →
// the `node == null` checks on the first findings go red.
test "lint: 2-of-3 warns below-two-thirds is absent, 1-of-3 is sub-majority, 3-of-3 critical" {
    const gpa = std.testing.allocator;

    var two_of_three = try ownedFlat(gpa, 2, &.{ 1, 2, 3 });
    defer two_of_three.deinit(gpa);
    try validateAndNormalize(gpa, &two_of_three);
    const f1 = try lint(gpa, &two_of_three);
    defer gpa.free(f1);
    try std.testing.expectEqual(@as(usize, 0), f1.len); // ceil(2*3/3)=2, t=2: ok

    var one_of_three = try ownedFlat(gpa, 1, &.{ 1, 2, 3 });
    defer one_of_three.deinit(gpa);
    try validateAndNormalize(gpa, &one_of_three);
    const f2 = try lint(gpa, &one_of_three);
    defer gpa.free(f2);
    try std.testing.expectEqual(@as(usize, 2), f2.len);
    try std.testing.expectEqual(LintLevel.err, f2[0].level);
    try std.testing.expectEqual(LintCode.sub_majority_threshold, f2[0].code);
    try std.testing.expectEqual(LintCode.below_two_thirds, f2[1].code);
    try std.testing.expect(f2[0].node == null and f2[1].node == null);

    // 3-of-3: the top-level finding first, then one critical_node per
    // validator in ascending byte order, `node` set only on those.
    var all_of_three = try ownedFlat(gpa, 3, &.{ 3, 1, 2 });
    defer all_of_three.deinit(gpa);
    try validateAndNormalize(gpa, &all_of_three);
    const f3 = try lint(gpa, &all_of_three);
    defer gpa.free(f3);
    try std.testing.expectEqual(@as(usize, 4), f3.len);
    try std.testing.expectEqual(LintCode.all_members_critical, f3[0].code);
    try std.testing.expect(f3[0].node == null);
    for (f3[1..], 1..) |f, i| {
        try std.testing.expectEqual(LintLevel.warning, f.level);
        try std.testing.expectEqual(LintCode.critical_node, f.code);
        try std.testing.expectEqual(@as(u32, 3), f.members);
        try std.testing.expectEqual(@as(u32, 3), f.threshold);
        try std.testing.expectEqualSlices(u8, &nodeId(@intCast(i)), &f.node.?);
    }

    // 1-of-1: no top-level finding, exactly one critical_node.
    var single = try ownedFlat(gpa, 1, &.{7});
    defer single.deinit(gpa);
    try validateAndNormalize(gpa, &single);
    const f4 = try lint(gpa, &single);
    defer gpa.free(f4);
    try std.testing.expectEqual(@as(usize, 1), f4.len);
    try std.testing.expectEqual(LintCode.critical_node, f4[0].code);
    try std.testing.expectEqualSlices(u8, &nodeId(7), &f4[0].node.?);

    // 3-of-5: unchanged first finding, no critical nodes.
    var three_of_five = try ownedFlat(gpa, 3, &.{ 1, 2, 3, 4, 5 });
    defer three_of_five.deinit(gpa);
    try validateAndNormalize(gpa, &three_of_five);
    const f5 = try lint(gpa, &three_of_five);
    defer gpa.free(f5);
    try std.testing.expectEqual(@as(usize, 1), f5.len);
    try std.testing.expectEqual(LintCode.below_two_thirds, f5[0].code);
}

/// Test-only nested builder: `threshold`-of-{validators..., inner sets...}.
fn ownedNested(gpa: std.mem.Allocator, threshold: u32, validator_bytes: []const u8, inners: []const QuorumSetOwned) !QuorumSetOwned {
    const vals = try gpa.alloc(NodeId, validator_bytes.len);
    for (validator_bytes, 0..) |b, i| vals[i] = nodeId(b);
    return .{ .threshold = threshold, .validators = vals, .inner_sets = try gpa.dupe(QuorumSetOwned, inners) };
}

/// Reference for `minBlockingSize`: the smallest |S| over ALL subsets S of the
/// tree's validators such that the tree is unsatisfiable with S offline
/// (direct counting over the complement). n <= 9 validators → 512 subsets.
fn bruteMinBlocking(gpa: std.mem.Allocator, qs: *const QuorumSetOwned) !u32 {
    var all: std.ArrayList(NodeId) = .empty;
    defer all.deinit(gpa);
    try collectValidators(gpa, qs, &all);
    std.debug.assert(all.items.len <= 9);
    var best: u32 = std.math.maxInt(u32);
    var mask: u32 = 0;
    while (mask < (@as(u32, 1) << @intCast(all.items.len))) : (mask += 1) {
        var offline: [9]NodeId = undefined;
        var k: usize = 0;
        for (all.items, 0..) |id, i| {
            if ((mask >> @intCast(i)) & 1 == 1) {
                offline[k] = id;
                k += 1;
            }
        }
        if (k < best and !satisfiableWithoutSet(qs, offline[0..k])) best = @intCast(k);
    }
    return best;
}

fn satisfiableWithoutSet(qs: *const QuorumSetOwned, offline: []const NodeId) bool {
    var sat: u32 = 0;
    for (qs.validators) |*v| {
        var off = false;
        for (offline) |*o| {
            if (std.mem.eql(u8, v, o)) off = true;
        }
        if (!off) sat += 1;
    }
    for (qs.inner_sets) |*inner| {
        if (satisfiableWithoutSet(inner, offline)) sat += 1;
    }
    return sat >= qs.threshold;
}

// Non-vacuity: changing `need` to n − t (dropping the +1) makes 2-of-3 → 1
// and 3-of-3 → 0; summing the LARGEST members instead of the smallest makes
// 3-of-{A, org, org} → 2. Both diverge from the brute-force reference.
test "minBlockingSize: hand table and brute-force subset reference agree" {
    const gpa = std.testing.allocator;

    const Flat = struct { t: u32, vals: []const u8, want: u32 };
    const flats = [_]Flat{
        .{ .t = 2, .vals = &.{ 1, 2, 3 }, .want = 2 },
        .{ .t = 4, .vals = &.{ 1, 2, 3, 4, 5 }, .want = 2 },
        .{ .t = 3, .vals = &.{ 1, 2, 3 }, .want = 1 },
        .{ .t = 1, .vals = &.{1}, .want = 1 },
        .{ .t = 1, .vals = &.{ 1, 2, 3 }, .want = 3 },
    };
    for (flats) |c| {
        var qs = try ownedFlat(gpa, c.t, c.vals);
        defer qs.deinit(gpa);
        try validateAndNormalize(gpa, &qs);
        try std.testing.expectEqual(c.want, minBlockingSize(&qs));
        try std.testing.expectEqual(c.want, try bruteMinBlocking(gpa, &qs));
    }

    // 2-of-{org(2-of-3) × 3} → 2 + 2 = 4
    var orgs = try ownedNested(gpa, 2, &.{}, &.{
        try ownedFlat(gpa, 2, &.{ 0x10, 0x11, 0x12 }),
        try ownedFlat(gpa, 2, &.{ 0x20, 0x21, 0x22 }),
        try ownedFlat(gpa, 2, &.{ 0x30, 0x31, 0x32 }),
    });
    defer orgs.deinit(gpa);
    try validateAndNormalize(gpa, &orgs);
    try std.testing.expectEqual(@as(u32, 4), minBlockingSize(&orgs));
    try std.testing.expectEqual(@as(u32, 4), try bruteMinBlocking(gpa, &orgs));

    // 3-of-{A, org1(2-of-3), org2(2-of-3)} → smallest single member = A → 1
    var mixed = try ownedNested(gpa, 3, &.{1}, &.{
        try ownedFlat(gpa, 2, &.{ 0x10, 0x11, 0x12 }),
        try ownedFlat(gpa, 2, &.{ 0x20, 0x21, 0x22 }),
    });
    defer mixed.deinit(gpa);
    try validateAndNormalize(gpa, &mixed);
    try std.testing.expectEqual(@as(u32, 1), minBlockingSize(&mixed));
    try std.testing.expectEqual(@as(u32, 1), try bruteMinBlocking(gpa, &mixed));

    // 2-of-{A, org1(2-of-3), org2(2-of-3)} → two smallest = 1 + 2 = 3
    var mixed2 = try ownedNested(gpa, 2, &.{1}, &.{
        try ownedFlat(gpa, 2, &.{ 0x10, 0x11, 0x12 }),
        try ownedFlat(gpa, 2, &.{ 0x20, 0x21, 0x22 }),
    });
    defer mixed2.deinit(gpa);
    try validateAndNormalize(gpa, &mixed2);
    try std.testing.expectEqual(@as(u32, 3), minBlockingSize(&mixed2));
    try std.testing.expectEqual(@as(u32, 3), try bruteMinBlocking(gpa, &mixed2));
}

// Non-vacuity: making `isSatisfiableWithout` ignore `node` (count every
// validator) → no node is ever critical → the 3-of-3 and 2-of-{2-of-2 × 2}
// expectations go red; dropping the sort → the ascending check on 3-of-3
// built from {3,1,2} input still passes only because normalization sorted
// the validators, but 2-of-{2-of-2 × 2} interleaves orgs and goes red.
test "criticalNodes: none / all ascending / lone validator / every org member" {
    const gpa = std.testing.allocator;

    var two_of_three = try ownedFlat(gpa, 2, &.{ 1, 2, 3 });
    defer two_of_three.deinit(gpa);
    try validateAndNormalize(gpa, &two_of_three);
    const c1 = try criticalNodes(gpa, &two_of_three);
    defer gpa.free(c1);
    try std.testing.expectEqual(@as(usize, 0), c1.len);

    var all_of_three = try ownedFlat(gpa, 3, &.{ 3, 1, 2 });
    defer all_of_three.deinit(gpa);
    try validateAndNormalize(gpa, &all_of_three);
    const c2 = try criticalNodes(gpa, &all_of_three);
    defer gpa.free(c2);
    try std.testing.expectEqual(@as(usize, 3), c2.len);
    for (c2, 1..) |id, i| try std.testing.expectEqualSlices(u8, &nodeId(@intCast(i)), &id);

    var mixed = try ownedNested(gpa, 3, &.{1}, &.{
        try ownedFlat(gpa, 2, &.{ 0x10, 0x11, 0x12 }),
        try ownedFlat(gpa, 2, &.{ 0x20, 0x21, 0x22 }),
    });
    defer mixed.deinit(gpa);
    try validateAndNormalize(gpa, &mixed);
    const c3 = try criticalNodes(gpa, &mixed);
    defer gpa.free(c3);
    try std.testing.expectEqual(@as(usize, 1), c3.len);
    try std.testing.expectEqualSlices(u8, &nodeId(1), &c3[0]);
    try std.testing.expect(containsNode(&mixed, nodeId(0x21)));
    try std.testing.expect(!containsNode(&mixed, nodeId(0x99)));

    // 2-of-{org(2-of-2) × 2}: every org member is critical (orgs are 2-of-2
    // and both orgs are needed). Input orgs deliberately hold interleaved
    // byte values so the ascending-by-bytes order is observable.
    var pairs = try ownedNested(gpa, 2, &.{}, &.{
        try ownedFlat(gpa, 2, &.{ 0x10, 0x30 }),
        try ownedFlat(gpa, 2, &.{ 0x20, 0x40 }),
    });
    defer pairs.deinit(gpa);
    try validateAndNormalize(gpa, &pairs);
    const c4 = try criticalNodes(gpa, &pairs);
    defer gpa.free(c4);
    try std.testing.expectEqual(@as(usize, 4), c4.len);
    const want4 = [_]u8{ 0x10, 0x20, 0x30, 0x40 };
    for (c4, want4) |id, b| try std.testing.expectEqualSlices(u8, &nodeId(b), &id);
}

/// Deep copy; an already-normalized set stays normalized.
pub fn clone(gpa: std.mem.Allocator, qs: *const QuorumSetOwned) std.mem.Allocator.Error!QuorumSetOwned {
    const vals = try gpa.dupe(NodeId, qs.validators);
    errdefer gpa.free(vals);
    const inners = try gpa.alloc(QuorumSetOwned, qs.inner_sets.len);
    var built: usize = 0;
    errdefer {
        for (inners[0..built]) |*inner| inner.deinit(gpa);
        gpa.free(inners);
    }
    for (qs.inner_sets, 0..) |*inner, i| {
        inners[i] = try clone(gpa, inner);
        built += 1;
    }
    return .{ .threshold = qs.threshold, .validators = vals, .inner_sets = inners };
}

test "clone: deep, hash-identical, independent lifetime" {
    const gpa = std.testing.allocator;
    var a = try ownedFlat(gpa, 2, &.{ 1, 2, 3 });
    defer a.deinit(gpa);
    try validateAndNormalize(gpa, &a);
    var b = try clone(gpa, &a);
    const ha = try hashNormalized(gpa, &a);
    const hb = try hashNormalized(gpa, &b);
    try std.testing.expectEqualSlices(u8, &ha, &hb);
    b.deinit(gpa); // a must stay usable
    const ha2 = try hashNormalized(gpa, &a);
    try std.testing.expectEqualSlices(u8, &ha, &ha2);
}
