//! Human-readable quorum lint report (design §12). The same text serves
//! `Node.create` (warnings go to the log, errors into the diagnostic) and
//! `slcp lint-quorum` (stdout — the docs smoke byte-compares it), so every
//! line is deterministic: lower-case hex, fixed wording, no timestamps.
//!
//! The availability framing on every finding — "if any n−t+1 of these n
//! nodes are offline, your network halts" — is the May-2019 Stellar halt
//! failure class stated in the operator's own numbers.

const std = @import("std");
const core = @import("slcp-core");
const qset = core.qset;

pub const Report = struct {
    /// Validated + normalized tree (what the hash was computed over).
    qs: *const qset.QuorumSetOwned,
    findings: []const qset.LintFinding,
    /// `qset.hashNormalized(qs)`.
    hash: [32]u8,
};

/// The full report: the tree with per-level "t-of-n, halts if any K of
/// these are offline" lines, the hash, the minimum blocking-set size, the
/// critical nodes, every finding, and a one-line result.
pub fn write(w: *std.Io.Writer, r: Report) std.Io.Writer.Error!void {
    try writeLevel(w, r.qs, 0);
    try w.print("hash: {s}\n", .{&std.fmt.bytesToHex(r.hash, .lower)});
    try w.print("min blocking set: {d} node(s)\n", .{qset.minBlockingSize(r.qs)});

    var any_critical = false;
    for (r.findings) |f| {
        if (f.code != .critical_node) continue;
        const id = f.node orelse continue;
        if (!any_critical) try w.writeAll("critical nodes:");
        any_critical = true;
        try w.print(" {s}", .{&std.fmt.bytesToHex(id, .lower)});
    }
    if (any_critical) try w.writeByte('\n') else try w.writeAll("critical nodes: none\n");

    var errors: usize = 0;
    var warnings: usize = 0;
    for (r.findings) |f| {
        try writeFinding(w, f);
        switch (f.level) {
            .err => errors += 1,
            .warning => warnings += 1,
        }
    }
    if (errors == 0 and warnings == 0) {
        try w.writeAll("result: OK\n");
    } else {
        try w.print("result: {d} error(s), {d} warning(s)\n", .{ errors, warnings });
    }
}

fn writeLevel(w: *std.Io.Writer, qs: *const qset.QuorumSetOwned, level: usize) std.Io.Writer.Error!void {
    const n: u32 = @intCast(qs.validators.len + qs.inner_sets.len);
    const t = qs.threshold;
    try w.splatByteAll(' ', level * 2);
    if (level == 0) try w.writeAll("quorum: ") else try w.writeAll("set: ");
    try w.print("{d}-of-{d}", .{ t, n });
    if (t <= n) try w.print("; halts if any {d} of these {d} are offline", .{ n - t + 1, n });
    try w.writeByte('\n');
    for (qs.validators) |*v| {
        try w.splatByteAll(' ', level * 2 + 2);
        try w.print("{s}\n", .{&std.fmt.bytesToHex(v.*, .lower)});
    }
    for (qs.inner_sets) |*inner| try writeLevel(w, inner, level + 1);
}

/// One finding on one line. Errors start with `ERROR <code>:`, warnings
/// with `WARNING <code>:`; every line ends with the availability framing.
pub fn writeFinding(w: *std.Io.Writer, f: qset.LintFinding) std.Io.Writer.Error!void {
    const n = f.members;
    const t = f.threshold;
    switch (f.level) {
        .err => try w.writeAll("ERROR "),
        .warning => try w.writeAll("WARNING "),
    }
    try w.print("{t}: ", .{f.code});
    switch (f.code) {
        .sub_majority_threshold => try w.print(
            "{d}-of-{d} is below a majority, so two disjoint \"quorums\" can form inside your own slice (a fork machine); use a threshold of at least {d}",
            .{ t, n, n / 2 + 1 },
        ),
        .below_two_thirds => {
            const two_thirds = std.math.divCeil(u32, 2 * n, 3) catch unreachable;
            try w.print(
                "threshold {d} is below ceil(2n/3) = {d} — with {d} validators and threshold {d} you tolerate {d} Byzantine nodes, {d} crashes",
                .{ t, two_thirds, n, t, byzantineTolerance(n, t), n -| t },
            );
        },
        .all_members_critical => try w.print(
            "threshold {d} equals the member count, so every one of the {d} members is critical",
            .{ t, n },
        ),
        .critical_node => {
            if (f.node) |id| {
                try w.print("{s} is in every slice; it alone offline halts you", .{&std.fmt.bytesToHex(id, .lower)});
            } else {
                try w.writeAll("a validator is in every slice; it alone offline halts you");
            }
        },
    }
    try w.print("; if any {d} of these {d} nodes are offline, your network halts\n", .{ (n + 1) -| t, n });
}

/// Byzantine members tolerated with BOTH safety and liveness: safety needs
/// 2t − n > f (every two quorums overlap in an honest node), liveness needs
/// n − t ≥ f (the honest remainder still reaches t). Clamped at 0.
pub fn byzantineTolerance(n: u32, t: u32) u32 {
    const safety: u32 = (2 * t) -| n -| 1;
    const liveness: u32 = n -| t;
    return @min(safety, liveness);
}

/// The opt-out warning: `.include_self = false` and the local node is
/// absent from the whole tree. Not a lint finding (the wire codes are
/// frozen) but written in the same voice so the log reads uniformly.
pub fn writeSelfAbsent(w: *std.Io.Writer, node_id: qset.NodeId) std.Io.Writer.Error!void {
    try w.print(
        "WARNING self_not_in_quorum: .include_self = false and this node ({s}) is not in .quorum; it will track the listed validators' slices but they will not count it, so its own statements never form part of any quorum (fine for a follower, wrong for a validator you expect others to rely on)\n",
        .{&std.fmt.bytesToHex(node_id, .lower)},
    );
}

pub fn hasErrors(findings: []const qset.LintFinding) bool {
    for (findings) |f| {
        if (f.level == .err) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Tree facts for `qset.validateAndNormalize` failures (the validator reports
// WHICH rule broke, not where; these locate the offending value so the
// message can name it).
// ---------------------------------------------------------------------------

pub const Level = struct { threshold: u32, members: u32 };

/// The first (pre-order) level whose threshold is outside [1, members].
pub fn firstBadThreshold(qs: *const qset.QuorumSetOwned) ?Level {
    const n: u32 = @intCast(qs.validators.len + qs.inner_sets.len);
    if (qs.threshold < 1 or qs.threshold > n) return .{ .threshold = qs.threshold, .members = n };
    for (qs.inner_sets) |*inner| {
        if (firstBadThreshold(inner)) |bad| return bad;
    }
    return null;
}

/// A validator that appears more than once anywhere in the tree.
pub fn firstDuplicate(gpa: std.mem.Allocator, qs: *const qset.QuorumSetOwned) std.mem.Allocator.Error!?qset.NodeId {
    var all: std.ArrayList(qset.NodeId) = .empty;
    defer all.deinit(gpa);
    try collectValidators(gpa, qs, &all);
    for (all.items, 0..) |*a, i| {
        for (all.items[i + 1 ..]) |*b| {
            if (std.mem.eql(u8, a, b)) return a.*;
        }
    }
    return null;
}

fn collectValidators(gpa: std.mem.Allocator, qs: *const qset.QuorumSetOwned, out: *std.ArrayList(qset.NodeId)) std.mem.Allocator.Error!void {
    try out.appendSlice(gpa, qs.validators);
    for (qs.inner_sets) |*inner| try collectValidators(gpa, inner, out);
}

/// Nesting depth (a flat set is 1).
pub fn depth(qs: *const qset.QuorumSetOwned) u32 {
    var deepest: u32 = 0;
    for (qs.inner_sets) |*inner| deepest = @max(deepest, depth(inner));
    return deepest + 1;
}

/// Validators anywhere in the tree (with multiplicity).
pub fn totalValidators(qs: *const qset.QuorumSetOwned) usize {
    var total: usize = qs.validators.len;
    for (qs.inner_sets) |*inner| total += totalValidators(inner);
    return total;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const Quorum = core.quorum.Quorum;

fn splatId(byte: u8) qset.NodeId {
    return @splat(byte);
}

fn render(gpa: std.mem.Allocator, spec: Quorum) ![]u8 {
    var owned = try spec.toOwned(gpa);
    defer owned.deinit(gpa);
    try qset.validateAndNormalize(gpa, &owned);
    const hash = try qset.hashNormalized(gpa, &owned);
    const findings = try qset.lint(gpa, &owned);
    defer gpa.free(findings);
    var sink = std.Io.Writer.Allocating.init(gpa);
    defer sink.deinit();
    try write(&sink.writer, .{ .qs = &owned, .findings = findings, .hash = hash });
    return sink.toOwnedSlice();
}

// Non-vacuity: changing the availability framing's `n − t + 1` to `n − t`
// turns "if any 3 of these 3" into "if any 2" (red); dropping the
// `critical_node` hex from `writeFinding` makes the three-hex check red;
// removing the `depth` indentation collapses the per-level "set:" lines.
test "lint_report golden strings: 1-of-3, 3-of-3, and the 3-org tree" {
    const gpa = testing.allocator;
    const ids = [_]qset.NodeId{ splatId(0x01), splatId(0x02), splatId(0x03) };

    const one_of_three = try render(gpa, Quorum.of(1, &ids));
    defer gpa.free(one_of_three);
    try testing.expect(std.mem.indexOf(u8, one_of_three, "ERROR sub_majority_threshold") != null);
    try testing.expect(std.mem.indexOf(u8, one_of_three, "if any 3 of these 3 nodes are offline, your network halts") != null);
    try testing.expect(std.mem.indexOf(u8, one_of_three, "you tolerate 0 Byzantine nodes, 2 crashes") != null);
    try testing.expect(std.mem.indexOf(u8, one_of_three, "result: 1 error(s), 1 warning(s)") != null);

    const three_of_three = try render(gpa, Quorum.of(3, &ids));
    defer gpa.free(three_of_three);
    try testing.expect(std.mem.indexOf(u8, three_of_three, "if any 1 of these 3") != null);
    try testing.expect(std.mem.indexOf(u8, three_of_three, "WARNING all_members_critical") != null);
    for (ids) |id| {
        const hex = std.fmt.bytesToHex(id, .lower);
        // once in the tree, once in "critical nodes:", once per critical_node finding
        try testing.expectEqual(@as(usize, 3), std.mem.count(u8, three_of_three, &hex));
    }
    try testing.expect(std.mem.indexOf(u8, three_of_three, "critical nodes: 0101") != null);

    const more = [_]qset.NodeId{ splatId(0x04), splatId(0x05), splatId(0x06) };
    const orgs = [_]Quorum{
        Quorum.of(2, ids[0..2]),
        Quorum.of(2, &.{ ids[2], more[0] }),
        Quorum.of(2, more[1..3]),
    };
    const three_orgs = try render(gpa, Quorum.ofSets(2, &orgs));
    defer gpa.free(three_orgs);
    try testing.expect(std.mem.startsWith(u8, three_orgs, "quorum: 2-of-3; halts if any 2 of these 3 are offline\n"));
    try testing.expectEqual(@as(usize, 3), std.mem.count(u8, three_orgs, "\n  set: 2-of-2; halts if any 1 of these 2 are offline\n"));
    // 2-of-3 orgs with 2-of-2 inside: losing any ONE node loses one org and
    // the other two still form a quorum, so no node is critical (the plan's
    // "six critical_node warnings" guess does not hold for the S1a lint).
    try testing.expect(std.mem.endsWith(u8, three_orgs, "critical nodes: none\nresult: OK\n"));
    try testing.expect(std.mem.indexOf(u8, three_orgs, "min blocking set: 2 node(s)") != null);

    const four = [_]qset.NodeId{ ids[0], ids[1], ids[2], more[0] };
    const clean = try render(gpa, Quorum.twoThirdsOf(&four));
    defer gpa.free(clean);
    try testing.expect(std.mem.endsWith(u8, clean, "critical nodes: none\nresult: OK\n"));
    try testing.expect(std.mem.indexOf(u8, clean, "min blocking set: 2 node(s)") != null);
}

// Non-vacuity: swapping the safety/liveness terms (or dropping the clamp)
// changes the 3-of-5 / 4-of-5 rows.
test "byzantineTolerance and the tree-fact helpers" {
    const gpa = testing.allocator;
    try testing.expectEqual(@as(u32, 0), byzantineTolerance(3, 2));
    try testing.expectEqual(@as(u32, 1), byzantineTolerance(4, 3));
    try testing.expectEqual(@as(u32, 1), byzantineTolerance(5, 4));
    try testing.expectEqual(@as(u32, 0), byzantineTolerance(5, 3));
    try testing.expectEqual(@as(u32, 0), byzantineTolerance(3, 1));

    const ids = [_]qset.NodeId{ splatId(0x01), splatId(0x02), splatId(0x01) };
    var dup = try Quorum.of(4, &ids).toOwned(gpa);
    defer dup.deinit(gpa);
    try testing.expectEqual(Level{ .threshold = 4, .members = 3 }, firstBadThreshold(&dup).?);
    try testing.expectEqualSlices(u8, &splatId(0x01), &(try firstDuplicate(gpa, &dup)).?);
    try testing.expectEqual(@as(u32, 1), depth(&dup));
    try testing.expectEqual(@as(usize, 3), totalValidators(&dup));

    const inner = [_]Quorum{Quorum.of(1, ids[0..1])};
    var nested = try Quorum.ofSets(1, &.{Quorum.ofSets(1, &inner)}).toOwned(gpa);
    defer nested.deinit(gpa);
    try testing.expectEqual(@as(u32, 3), depth(&nested));
    try testing.expect(firstBadThreshold(&nested) == null);
    try testing.expect((try firstDuplicate(gpa, &nested)) == null);
}
