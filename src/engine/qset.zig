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

/// qsetHash of an already-normalized set (§4.3).
pub fn hashNormalized(gpa: std.mem.Allocator, qs: *const QuorumSetOwned) ![32]u8 {
    const flat = try canonicalBytes(gpa, qs);
    defer gpa.free(flat);
    return crypto.qsetHash(flat);
}

// ---------------------------------------------------------------------------
// Lint (§12) — first cut, M0 scope. Judges the LOCAL top-level configuration;
// deeper slice analysis is M6 polish. Findings are emitted in a fixed order
// so lint output is byte-stable for the lint.json vectors.
// ---------------------------------------------------------------------------

pub const LintLevel = enum { err, warning };

pub const LintCode = enum {
    sub_majority_threshold, // error: two disjoint "quorums" can exist in your own slice
    below_two_thirds, // warning: threshold < ceil(2n/3) — weak Byzantine margin
    all_members_critical, // warning: threshold == n — any single member offline halts you
};

pub const LintFinding = struct {
    level: LintLevel,
    code: LintCode,
    members: u32, // top-level member count n
    threshold: u32,
};

/// Lint a NORMALIZED local quorum set. Caller frees the returned slice.
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

    return findings.toOwnedSlice(gpa);
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

    var all_of_three = try ownedFlat(gpa, 3, &.{ 1, 2, 3 });
    defer all_of_three.deinit(gpa);
    try validateAndNormalize(gpa, &all_of_three);
    const f3 = try lint(gpa, &all_of_three);
    defer gpa.free(f3);
    try std.testing.expectEqual(@as(usize, 1), f3.len);
    try std.testing.expectEqual(LintCode.all_members_critical, f3[0].code);
}
