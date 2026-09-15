//! A fixed trust floor for locally selected quorum sets.
//!
//! Every admitted slice contains at least `min_slice_anchors` identities from
//! the same immutable anchor pool. If at most `max_faulty_anchors` anchors are
//! Byzantine and 2 * floor > anchors + faulty, any two admitted slices overlap
//! in an honest anchor, including slices from different selection histories.
//! All honest participants must enforce the same floor. This is conditional
//! quorum analysis, not evidence that an identity is honest or an activation,
//! persistence, membership-migration, or transport protocol.
//!
//! Availability is assessed separately. Nonanchors cost zero to fail, so a
//! promised anchor-only availability budget never relies on an outsider being
//! responsive. Selecting a safe but unavailable set is possible only when the
//! policy explicitly disables the availability requirement.

const std = @import("std");
const qset = @import("../engine/qset.zig");

pub const NodeId = qset.NodeId;
pub const max_anchors: usize = qset.max_total_validators;

pub const Config = struct {
    anchors: []const NodeId,
    max_faulty_anchors: u16,
    min_slice_anchors: u16,
    require_availability: bool = true,
};

pub const InitError = error{
    EmptyAnchorPool,
    TooManyAnchors,
    DuplicateAnchor,
    InvalidFaultBudget,
    InvalidSliceFloor,
    UnsafeSliceFloor,
    InfeasibleAvailability,
    OutOfMemory,
};

pub const AssessError = error{
    EmptyQuorumSet,
    ThresholdOutOfRange,
    DepthExceeded,
    TooManyValidators,
    DuplicateNode,
};

pub const Assessment = struct {
    /// Smallest number of anchors in any satisfying slice.
    minimum_slice_anchors: u16,
    /// Smallest number of failed anchors that can make the set unsatisfied,
    /// allowing every nonanchor to be unavailable at no additional cost.
    minimum_blocking_anchors: u16,
    safe: bool,
    available: bool,
    permitted: bool,
};

pub const Policy = struct {
    gpa: std.mem.Allocator,
    /// Owned, canonical bytewise order. Read-only for the Policy's lifetime:
    /// mutation would invalidate the trust floor and its fingerprint.
    anchors: []const NodeId,
    max_faulty_anchors: u16,
    min_slice_anchors: u16,
    require_availability: bool,

    /// Copies the anchor pool; the caller retains its input on every path.
    pub fn init(gpa: std.mem.Allocator, cfg: Config) InitError!Policy {
        if (cfg.anchors.len == 0) return error.EmptyAnchorPool;
        if (cfg.anchors.len > max_anchors) return error.TooManyAnchors;
        const n: u16 = @intCast(cfg.anchors.len);
        if (cfg.max_faulty_anchors >= n) return error.InvalidFaultBudget;
        if (cfg.min_slice_anchors == 0 or cfg.min_slice_anchors > n) return error.InvalidSliceFloor;
        if (2 * cfg.min_slice_anchors <= n + cfg.max_faulty_anchors) return error.UnsafeSliceFloor;
        if (cfg.require_availability and cfg.min_slice_anchors > n - cfg.max_faulty_anchors) return error.InfeasibleAvailability;

        const anchors = try gpa.dupe(NodeId, cfg.anchors);
        errdefer gpa.free(anchors);
        std.mem.sort(NodeId, anchors, {}, nodeLessThan);
        for (anchors[1..], anchors[0 .. anchors.len - 1]) |a, b| {
            if (std.mem.eql(u8, &a, &b)) return error.DuplicateAnchor;
        }
        return .{
            .gpa = gpa,
            .anchors = anchors,
            .max_faulty_anchors = cfg.max_faulty_anchors,
            .min_slice_anchors = cfg.min_slice_anchors,
            .require_availability = cfg.require_availability,
        };
    }

    pub fn deinit(self: *Policy) void {
        self.gpa.free(self.anchors);
        self.* = undefined;
    }

    /// SHA-256 over an explicit version domain, big-endian u16 anchor count,
    /// fault budget and slice floor, a one-byte availability flag, and sorted
    /// 32-byte anchor identities. This is a policy identity, not authorization.
    pub fn fingerprint(self: *const Policy) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("SLCP-ADAPTIVITY-POLICY-V1\x00");
        var fields: [7]u8 = undefined;
        std.mem.writeInt(u16, fields[0..2], @intCast(self.anchors.len), .big);
        std.mem.writeInt(u16, fields[2..4], self.max_faulty_anchors, .big);
        std.mem.writeInt(u16, fields[4..6], self.min_slice_anchors, .big);
        fields[6] = @intFromBool(self.require_availability);
        h.update(&fields);
        for (self.anchors) |*anchor| h.update(anchor);
        return h.finalResult();
    }

    /// Bounded, allocation-free analysis. Equivalent ordering/normalization
    /// shapes are accepted; every threshold, depth, size, and globally unique
    /// node requirement is checked before the disjoint-child calculation.
    /// The implicit local signer is not counted, making this conservative for
    /// hosts whose quorum semantics add that signer to every slice.
    pub fn assess(self: *const Policy, qs: *const qset.QuorumSetOwned) AssessError!Assessment {
        var seen: [qset.max_total_validators]NodeId = undefined;
        var count: usize = 0;
        try validateTree(qs, 1, &seen, &count);
        const costs = self.measure(qs);
        const safe = costs.slice >= self.min_slice_anchors;
        const available = costs.blocking > self.max_faulty_anchors;
        return .{
            .minimum_slice_anchors = costs.slice,
            .minimum_blocking_anchors = costs.blocking,
            .safe = safe,
            .available = available,
            .permitted = safe and (!self.require_availability or available),
        };
    }

    fn isAnchor(self: *const Policy, id: NodeId) bool {
        for (self.anchors) |*anchor| {
            if (std.mem.eql(u8, anchor, &id)) return true;
        }
        return false;
    }

    const Costs = struct { slice: u16, blocking: u16 };

    fn measure(self: *const Policy, qs: *const qset.QuorumSetOwned) Costs {
        var slices: [qset.max_total_validators]u16 = undefined;
        var blockers: [qset.max_total_validators]u16 = undefined;
        var count: usize = 0;
        for (qs.validators) |id| {
            const cost: u16 = @intFromBool(self.isAnchor(id));
            slices[count] = cost;
            blockers[count] = cost;
            count += 1;
        }
        for (qs.inner_sets) |*inner| {
            const costs = self.measure(inner);
            slices[count] = costs.slice;
            blockers[count] = costs.blocking;
            count += 1;
        }
        std.mem.sort(u16, slices[0..count], {}, std.sort.asc(u16));
        std.mem.sort(u16, blockers[0..count], {}, std.sort.asc(u16));
        var result: Costs = .{ .slice = 0, .blocking = 0 };
        for (slices[0..qs.threshold]) |cost| result.slice += cost;
        for (blockers[0 .. count - qs.threshold + 1]) |cost| result.blocking += cost;
        return result;
    }
};

fn nodeLessThan(_: void, a: NodeId, b: NodeId) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

fn validateTree(qs: *const qset.QuorumSetOwned, depth: usize, seen: *[qset.max_total_validators]NodeId, count: *usize) AssessError!void {
    if (depth > qset.max_depth) return error.DepthExceeded;
    if (qs.validators.len > qset.max_total_validators or qs.inner_sets.len > qset.max_total_validators) return error.TooManyValidators;
    const members = qs.validators.len + qs.inner_sets.len;
    if (members == 0) return error.EmptyQuorumSet;
    if (members > qset.max_total_validators) return error.TooManyValidators;
    if (qs.threshold == 0 or qs.threshold > members) return error.ThresholdOutOfRange;
    for (qs.validators) |id| {
        if (count.* == qset.max_total_validators) return error.TooManyValidators;
        for (seen[0..count.*]) |*previous| {
            if (std.mem.eql(u8, previous, &id)) return error.DuplicateNode;
        }
        seen[count.*] = id;
        count.* += 1;
    }
    for (qs.inner_sets) |*inner| try validateTree(inner, depth + 1, seen, count);
}

fn testId(n: u8) NodeId {
    return @splat(n);
}

fn testTree(threshold: u32, validators: []NodeId, inner_sets: []qset.QuorumSetOwned) qset.QuorumSetOwned {
    return .{ .threshold = threshold, .validators = validators, .inner_sets = inner_sets };
}

test "anchor policy distinguishes safety, availability, and explicit degraded admission" {
    const gpa = std.testing.allocator;
    var anchors = [_]NodeId{ testId(0), testId(1), testId(2), testId(3) };
    var policy = try Policy.init(gpa, .{ .anchors = &anchors, .max_faulty_anchors = 1, .min_slice_anchors = 3 });
    defer policy.deinit();
    try std.testing.expectEqualStrings("fa495793e4d75ea23ad1fe3e0d9006653c938611a5937837a875d786ee8f796f", &std.fmt.bytesToHex(policy.fingerprint(), .lower));
    var qs = testTree(3, &anchors, &.{});
    var report = try policy.assess(&qs);
    try std.testing.expect(report.safe and report.available and report.permitted);
    try std.testing.expectEqual(@as(u16, 3), report.minimum_slice_anchors);
    try std.testing.expectEqual(@as(u16, 2), report.minimum_blocking_anchors);
    qs.validators = anchors[0..3];
    report = try policy.assess(&qs);
    try std.testing.expect(report.safe and !report.available and !report.permitted);
    var degraded = try Policy.init(gpa, .{ .anchors = &anchors, .max_faulty_anchors = 1, .min_slice_anchors = 3, .require_availability = false });
    defer degraded.deinit();
    try std.testing.expect((try degraded.assess(&qs)).permitted);
    qs.threshold = 2;
    try std.testing.expect(!(try degraded.assess(&qs)).safe);
}

test "outsider dependencies cost zero in the anchor availability budget" {
    var anchors = [_]NodeId{ testId(0), testId(1), testId(2), testId(3) };
    var outsiders = [_]NodeId{testId(4)};
    var inner = [_]qset.QuorumSetOwned{testTree(3, &anchors, &.{})};
    var qs = testTree(2, &outsiders, &inner);
    var policy = try Policy.init(std.testing.allocator, .{ .anchors = &anchors, .max_faulty_anchors = 1, .min_slice_anchors = 3 });
    defer policy.deinit();
    const report = try policy.assess(&qs);
    try std.testing.expect(report.safe);
    try std.testing.expect(!report.available);
    try std.testing.expectEqual(@as(u16, 0), report.minimum_blocking_anchors);
}

test "policy fingerprint canonicalizes anchors and binds every policy field" {
    const gpa = std.testing.allocator;
    var anchors = [_]NodeId{ testId(0), testId(1), testId(2), testId(3), testId(4), testId(5), testId(6) };
    var reordered = [_]NodeId{ anchors[4], anchors[2], anchors[0], anchors[6], anchors[3], anchors[5], anchors[1] };
    const cfg: Config = .{ .anchors = &anchors, .max_faulty_anchors = 1, .min_slice_anchors = 5 };
    var a = try Policy.init(gpa, cfg);
    defer a.deinit();
    var other = cfg;
    other.anchors = &reordered;
    var b = try Policy.init(gpa, other);
    defer b.deinit();
    try std.testing.expectEqual(a.fingerprint(), b.fingerprint());
    for (0..4) |field| {
        other = cfg;
        switch (field) {
            0 => other.anchors = anchors[0..6],
            1 => other.max_faulty_anchors = 0,
            2 => other.min_slice_anchors = 6,
            3 => other.require_availability = false,
            else => unreachable,
        }
        var changed = try Policy.init(gpa, other);
        defer changed.deinit();
        try std.testing.expect(!std.mem.eql(u8, &a.fingerprint(), &changed.fingerprint()));
    }
    reordered[0] = testId(99);
    try std.testing.expectEqual(a.fingerprint(), b.fingerprint()); // owned copy
}

test "policy rejects invalid and impossible trust floors" {
    const gpa = std.testing.allocator;
    var anchors = [_]NodeId{ testId(0), testId(1), testId(2), testId(3) };
    var cfg: Config = .{ .anchors = &.{}, .max_faulty_anchors = 0, .min_slice_anchors = 1 };
    try std.testing.expectError(error.EmptyAnchorPool, Policy.init(gpa, cfg));
    cfg.anchors = &anchors;
    cfg.max_faulty_anchors = 4;
    try std.testing.expectError(error.InvalidFaultBudget, Policy.init(gpa, cfg));
    cfg.max_faulty_anchors = 1;
    cfg.min_slice_anchors = 0;
    try std.testing.expectError(error.InvalidSliceFloor, Policy.init(gpa, cfg));
    cfg.min_slice_anchors = 5;
    try std.testing.expectError(error.InvalidSliceFloor, Policy.init(gpa, cfg));
    cfg.min_slice_anchors = 2;
    try std.testing.expectError(error.UnsafeSliceFloor, Policy.init(gpa, cfg));
    cfg.min_slice_anchors = 4;
    try std.testing.expectError(error.InfeasibleAvailability, Policy.init(gpa, cfg));
    cfg.min_slice_anchors = 3;
    anchors[3] = anchors[0];
    try std.testing.expectError(error.DuplicateAnchor, Policy.init(gpa, cfg));
    var too_many: [max_anchors + 1]NodeId = undefined;
    cfg.anchors = &too_many;
    try std.testing.expectError(error.TooManyAnchors, Policy.init(gpa, cfg));
}

test "assessment validates the entire tree before disjoint-child arithmetic" {
    var anchors = [_]NodeId{ testId(0), testId(1), testId(2), testId(3) };
    var policy = try Policy.init(std.testing.allocator, .{ .anchors = &anchors, .max_faulty_anchors = 1, .min_slice_anchors = 3 });
    defer policy.deinit();
    var qs = testTree(0, &anchors, &.{});
    try std.testing.expectError(error.ThresholdOutOfRange, policy.assess(&qs));
    qs.threshold = 5;
    try std.testing.expectError(error.ThresholdOutOfRange, policy.assess(&qs));
    qs = testTree(1, &.{}, &.{});
    try std.testing.expectError(error.EmptyQuorumSet, policy.assess(&qs));
    var inner = [_]qset.QuorumSetOwned{testTree(1, anchors[0..1], &.{})};
    qs = testTree(2, anchors[0..2], &inner);
    try std.testing.expectError(error.DuplicateNode, policy.assess(&qs));
    var levels: [5]qset.QuorumSetOwned = undefined;
    levels[4] = testTree(1, anchors[0..1], &.{});
    var i: usize = 4;
    while (i > 0) {
        i -= 1;
        levels[i] = testTree(1, &.{}, levels[i + 1 .. i + 2]);
    }
    try std.testing.expectError(error.DepthExceeded, policy.assess(&levels[0]));
    var too_many: [qset.max_total_validators + 1]NodeId = undefined;
    qs = testTree(1, &too_many, &.{});
    try std.testing.expectError(error.TooManyValidators, policy.assess(&qs));
}

fn truthSatisfied(qs: *const qset.QuorumSetOwned, present: u8) bool {
    var satisfied: usize = 0;
    for (qs.validators) |id| {
        if (present & (@as(u8, 1) << @intCast(id[0])) != 0) satisfied += 1;
    }
    for (qs.inner_sets) |*inner| {
        if (truthSatisfied(inner, present)) satisfied += 1;
    }
    return satisfied >= qs.threshold;
}

fn checkTruthTable(qs: *const qset.QuorumSetOwned) !void {
    const gpa = std.testing.allocator;
    // Enumerate every anchor assignment and every possible satisfying/failing
    // set on a five-identity universe. Outside identities can appear in both.
    for (1..32) |mask| {
        const anchor_mask: u8 = @intCast(mask);
        var anchors: [5]NodeId = undefined;
        var n: usize = 0;
        for (0..5) |i| {
            if (anchor_mask & (@as(u8, 1) << @intCast(i)) != 0) {
                anchors[n] = testId(@intCast(i));
                n += 1;
            }
        }
        var minimum_slice: u16 = 255;
        var minimum_blocking: u16 = 255;
        for (0..32) |bits| {
            const present: u8 = @intCast(bits);
            if (truthSatisfied(qs, present)) {
                minimum_slice = @min(minimum_slice, @as(u16, @popCount(present & anchor_mask)));
            } else {
                minimum_blocking = @min(minimum_blocking, @as(u16, @popCount((~present) & anchor_mask)));
            }
        }
        for (0..n) |faults| {
            const floor: u16 = @intCast((n + faults) / 2 + 1);
            var policy = try Policy.init(gpa, .{ .anchors = anchors[0..n], .max_faulty_anchors = @intCast(faults), .min_slice_anchors = floor, .require_availability = false });
            defer policy.deinit();
            const report = try policy.assess(qs);
            try std.testing.expectEqual(minimum_slice, report.minimum_slice_anchors);
            try std.testing.expectEqual(minimum_blocking, report.minimum_blocking_anchors);
            try std.testing.expectEqual(minimum_slice >= floor, report.safe);
            try std.testing.expectEqual(minimum_blocking > faults, report.available);
            try std.testing.expectEqual(report.safe, report.permitted);
        }
    }
}

test "exact nested anchor costs match exhaustive truth tables" {
    var nodes = [_]NodeId{ testId(0), testId(1), testId(2), testId(3), testId(4) };
    for (1..6) |threshold| {
        var flat = testTree(@intCast(threshold), &nodes, &.{});
        try checkTruthTable(&flat);
    }
    for (1..3) |a| {
        for (1..3) |b| {
            var inner = [_]qset.QuorumSetOwned{
                testTree(@intCast(a), nodes[0..2], &.{}),
                testTree(@intCast(b), nodes[2..4], &.{}),
            };
            for (1..4) |threshold| {
                var nested = testTree(@intCast(threshold), nodes[4..5], &inner);
                try checkTruthTable(&nested);
            }
        }
    }
    // A third level, unequal child costs, and a non-normalized singleton.
    var bottom = [_]qset.QuorumSetOwned{testTree(1, nodes[0..1], &.{})};
    var middle = [_]qset.QuorumSetOwned{testTree(2, nodes[1..3], &bottom)};
    var deep = testTree(2, nodes[3..5], &middle);
    try checkTruthTable(&deep);
}

fn allocationProbe(gpa: std.mem.Allocator) !void {
    const anchors = [_]NodeId{ testId(3), testId(1), testId(2), testId(0) };
    var policy = try Policy.init(gpa, .{ .anchors = &anchors, .max_faulty_anchors = 1, .min_slice_anchors = 3 });
    defer policy.deinit();
    try std.testing.expectEqual(testId(0), policy.anchors[0]);
}

test "policy initialization preserves ownership at every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationProbe, .{});
}
