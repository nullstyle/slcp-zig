//! Application driver interface (design §8.1–§8.2, §8.4).
//!
//! The contract, identical in every host language: synchronous, pure,
//! deterministic. validateValue is called at most once per distinct value per
//! slot (the engine caches verdicts in values.zig); combineCandidates must be
//! total over arbitrary candidate sets and its result must self-validate
//! `.valid` and respect max_value_bytes.

const std = @import("std");

pub const Validity = enum(u2) { invalid = 0, maybe_valid = 1, valid = 2 };

pub const DriverError = error{ OutOfMemory, DriverFault };

pub const Driver = struct {
    ctx: *anyopaque,
    validate_value: *const fn (ctx: *anyopaque, slot: u64, value: []const u8, is_nomination: bool) Validity,
    combine_candidates: *const fn (ctx: *anyopaque, slot: u64, candidates: []const []const u8, gpa: std.mem.Allocator, out: *std.ArrayList(u8)) DriverError!void,
    extract_valid_value: ?*const fn (ctx: *anyopaque, slot: u64, value: []const u8, gpa: std.mem.Allocator, out: *std.ArrayList(u8)) DriverError!bool = null,

    /// The omakase default (§8.4): valid iff 0 < len <= max_value_bytes
    /// (length policy enforced by the engine before the driver is consulted),
    /// combine = lexicographic max ("highest proposal wins"), extract = none.
    pub fn default() Driver {
        return .{
            .ctx = @ptrCast(@constCast(&default_ctx)),
            .validate_value = defaultValidate,
            .combine_candidates = defaultCombine,
        };
    }
};

const default_ctx: u8 = 0;

fn defaultValidate(ctx: *anyopaque, slot: u64, value: []const u8, is_nomination: bool) Validity {
    _ = ctx;
    _ = slot;
    _ = is_nomination;
    return if (value.len > 0) .valid else .invalid;
}

fn defaultCombine(ctx: *anyopaque, slot: u64, candidates: []const []const u8, gpa: std.mem.Allocator, out: *std.ArrayList(u8)) DriverError!void {
    _ = ctx;
    _ = slot;
    if (candidates.len == 0) return error.DriverFault;
    var best = candidates[0];
    for (candidates[1..]) |c| {
        if (std.mem.order(u8, c, best) == .gt) best = c;
    }
    try out.appendSlice(gpa, best);
}

// ---------------------------------------------------------------------------
// Checked: the double-call determinism detector (design §7.3 (b), as-built M6)
// ---------------------------------------------------------------------------

/// Debug double-call wrapper: forwards every `validate_value` and
/// `combine_candidates` call to `inner` TWICE and compares the answers. A
/// divergence is the cheapest possible proof of a nondeterministic driver
/// (clock, floats, map iteration order, I/O, hidden mutable state) — the
/// failure class that forks a network silently (docs/determinism.md).
///
/// Opt-in and debug-grade: it doubles driver work, so use it in tests,
/// staging and the sim/e2e harnesses, never as the production driver. It is
/// wasm-safe (no std.Io, `@panic` only) but is never part of the wasm ABI
/// graph. `extract_valid_value` is forwarded once, unchecked. Experimental
/// tier (plan R16): the frozen surface is `Driver` / `Validity` /
/// `DriverError`.
pub const Checked = struct {
    inner: Driver,
    /// Count of divergent call pairs seen. Read it in tests.
    divergences: u32 = 0,
    /// true (default): `@panic` on the first divergence with the message
    /// `slcp: nondeterministic driver: validate_value gave different answers for the same (slot, value)`
    /// or `slcp: nondeterministic driver: combine_candidates gave different bytes for the same candidate set`.
    /// false: count only (for the unit test of this wrapper).
    panic_on_divergence: bool = true,

    pub const validate_divergence_msg = "slcp: nondeterministic driver: validate_value gave different answers for the same (slot, value)";
    pub const combine_divergence_msg = "slcp: nondeterministic driver: combine_candidates gave different bytes for the same candidate set";

    /// The Driver to hand to `Node.Options.driver` / `Engine.init`. `self`
    /// must outlive it (the vtable ctx is `self`).
    pub fn driver(self: *Checked) Driver {
        return .{
            .ctx = @ptrCast(self),
            .validate_value = checkedValidate,
            .combine_candidates = checkedCombine,
            .extract_valid_value = if (self.inner.extract_valid_value != null) checkedExtract else null,
        };
    }

    fn diverged(self: *Checked, comptime msg: []const u8) void {
        self.divergences += 1;
        if (self.panic_on_divergence) @panic(msg);
    }
};

fn checkedValidate(ctx: *anyopaque, slot: u64, value: []const u8, is_nomination: bool) Validity {
    const self: *Checked = @ptrCast(@alignCast(ctx));
    const d = self.inner;
    const first = d.validate_value(d.ctx, slot, value, is_nomination);
    const second = d.validate_value(d.ctx, slot, value, is_nomination);
    if (first != second) self.diverged(Checked.validate_divergence_msg);
    return first;
}

fn checkedCombine(ctx: *anyopaque, slot: u64, candidates: []const []const u8, gpa: std.mem.Allocator, out: *std.ArrayList(u8)) DriverError!void {
    const self: *Checked = @ptrCast(@alignCast(ctx));
    const d = self.inner;
    const start = out.items.len;
    const first: DriverError!void = d.combine_candidates(d.ctx, slot, candidates, gpa, out);

    var again: std.ArrayList(u8) = .empty;
    defer again.deinit(gpa);
    const second: DriverError!void = d.combine_candidates(d.ctx, slot, candidates, gpa, &again);

    const same = blk: {
        if (first) |_| {
            if (second) |_| {
                break :blk std.mem.eql(u8, out.items[start..], again.items);
            } else |_| break :blk false;
        } else |e1| {
            if (second) |_| {
                break :blk false;
            } else |e2| break :blk e1 == e2;
        }
    };
    if (!same) self.diverged(Checked.combine_divergence_msg);
    return first;
}

fn checkedExtract(ctx: *anyopaque, slot: u64, value: []const u8, gpa: std.mem.Allocator, out: *std.ArrayList(u8)) DriverError!bool {
    const self: *Checked = @ptrCast(@alignCast(ctx));
    const d = self.inner;
    const f = d.extract_valid_value orelse return false;
    return f(d.ctx, slot, value, gpa, out);
}

/// Test stub: a deliberately nondeterministic driver. `validate` alternates
/// `.valid` / `.invalid` per call; `combine` appends the running call count.
const FlakyStub = struct {
    calls: u32 = 0,

    fn validate(ctx: *anyopaque, slot: u64, value: []const u8, is_nomination: bool) Validity {
        _ = slot;
        _ = value;
        _ = is_nomination;
        const self: *FlakyStub = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        return if (self.calls % 2 == 1) .valid else .invalid;
    }

    fn combine(ctx: *anyopaque, slot: u64, candidates: []const []const u8, gpa: std.mem.Allocator, out: *std.ArrayList(u8)) DriverError!void {
        _ = slot;
        _ = candidates;
        const self: *FlakyStub = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        try out.append(gpa, @intCast(self.calls));
    }

    fn driver(self: *FlakyStub) Driver {
        return .{ .ctx = @ptrCast(self), .validate_value = validate, .combine_candidates = combine };
    }
};

// Non-vacuity: dropping the SECOND inner call (or the comparison) in
// checkedValidate / checkedCombine leaves `divergences` at 0 for the flaky
// stub → the `1` / `2` expectations go red; the default-driver half pins
// that a deterministic inner passes through unchanged (wrong forwarding of
// the result → the expectEqual on `.valid` / "b" fails).
test "Checked: deterministic inner passes through, divergent inner is counted" {
    const gpa = std.testing.allocator;

    // (1) A deterministic inner: identical results, zero divergences.
    var ok: Checked = .{ .inner = Driver.default() };
    const okd = ok.driver();
    try std.testing.expectEqual(Validity.valid, okd.validate_value(okd.ctx, 1, "abc", true));
    try std.testing.expectEqual(Validity.invalid, okd.validate_value(okd.ctx, 1, "", false));
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const cands = [_][]const u8{ "aa", "b", "ab" };
    try okd.combine_candidates(okd.ctx, 1, &cands, gpa, &out);
    try std.testing.expectEqualSlices(u8, "b", out.items);
    try std.testing.expectEqual(@as(u32, 0), ok.divergences);
    try std.testing.expect(okd.extract_valid_value == null);

    // (2) A flaky inner, counting mode: one validate → 1, one combine → 2.
    var stub: FlakyStub = .{};
    var checked: Checked = .{ .inner = stub.driver(), .panic_on_divergence = false };
    const cd = checked.driver();
    // The first answer is what the caller sees (the stub's first call says .valid).
    try std.testing.expectEqual(Validity.valid, cd.validate_value(cd.ctx, 7, "x", true));
    try std.testing.expectEqual(@as(u32, 1), checked.divergences);
    var out2: std.ArrayList(u8) = .empty;
    defer out2.deinit(gpa);
    try cd.combine_candidates(cd.ctx, 7, &cands, gpa, &out2);
    try std.testing.expectEqual(@as(u32, 2), checked.divergences);
    // The caller's buffer holds the FIRST call's bytes (call #3 of the stub).
    try std.testing.expectEqualSlices(u8, &.{3}, out2.items);
    try std.testing.expectEqual(@as(u32, 4), stub.calls);
}

test "default driver: highest proposal wins, total, deterministic" {
    const gpa = std.testing.allocator;
    const d = Driver.default();
    try std.testing.expectEqual(Validity.valid, d.validate_value(d.ctx, 1, "abc", true));
    try std.testing.expectEqual(Validity.invalid, d.validate_value(d.ctx, 1, "", true));

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const cands = [_][]const u8{ "aa", "b", "ab" };
    try d.combine_candidates(d.ctx, 1, &cands, gpa, &out);
    try std.testing.expectEqualSlices(u8, "b", out.items);
}
