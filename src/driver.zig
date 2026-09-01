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
