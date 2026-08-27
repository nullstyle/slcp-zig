//! Value handling (design §4.4, §5.4 values.zig bullet): gpa-owned opaque
//! byte values, byte-lexicographic ordering, sorted-unique value sets, and
//! the per-slot driver-validation cache keyed by SHA-256(value) so each
//! distinct value crosses the driver boundary at most once per slot.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const driver_mod = @import("../driver.zig");

pub fn order(a: []const u8, b: []const u8) std.math.Order {
    return std.mem.order(u8, a, b);
}

pub fn dupe(gpa: std.mem.Allocator, bytes: []const u8) ![]u8 {
    return gpa.dupe(u8, bytes);
}

/// Sorted-unique set of owned values (the X/Y/Z sets of §5.4). Insertion
/// copies; the set owns its bytes.
pub const ValueSet = struct {
    items: std.ArrayList([]u8) = .empty,

    pub fn deinit(self: *ValueSet, gpa: std.mem.Allocator) void {
        for (self.items.items) |v| gpa.free(v);
        self.items.deinit(gpa);
        self.* = undefined;
    }

    pub fn len(self: *const ValueSet) usize {
        return self.items.items.len;
    }

    /// Index of the first element >= bytes.
    fn lowerBound(self: *const ValueSet, bytes: []const u8) usize {
        var lo: usize = 0;
        var hi: usize = self.items.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (order(self.items.items[mid], bytes) == .lt) lo = mid + 1 else hi = mid;
        }
        return lo;
    }

    pub fn contains(self: *const ValueSet, bytes: []const u8) bool {
        const i = self.lowerBound(bytes);
        return i < self.items.items.len and order(self.items.items[i], bytes) == .eq;
    }

    /// Insert a copy, keeping sorted-unique order. Returns true if inserted.
    pub fn insert(self: *ValueSet, gpa: std.mem.Allocator, bytes: []const u8) !bool {
        const i = self.lowerBound(bytes);
        if (i < self.items.items.len and order(self.items.items[i], bytes) == .eq) return false;
        const copy = try gpa.dupe(u8, bytes);
        errdefer gpa.free(copy);
        try self.items.insert(gpa, i, copy);
        return true;
    }

    pub fn slice(self: *const ValueSet) []const []u8 {
        return self.items.items;
    }

    /// True iff other ⊆ self.
    pub fn isSupersetOf(self: *const ValueSet, other: *const ValueSet) bool {
        for (other.items.items) |v| {
            if (!self.contains(v)) return false;
        }
        return true;
    }
};

/// Per-slot driver-verdict cache: SHA-256(value) → Validity.
/// BOUNDED (adversary-fillable: ballot counter-churn with fresh values would
/// otherwise grow it without limit — M2 safety review F1; the §16 wasm
/// budget counts it at max_entries × ~40 B). FIFO eviction, deterministic;
/// a re-validated evictee gets the same verdict (drivers are deterministic).
pub const ValidationCache = struct {
    pub const max_entries: usize = 4096;

    map: std.AutoHashMapUnmanaged([32]u8, driver_mod.Validity) = .empty,
    order: std.ArrayList([32]u8) = .empty,

    pub fn deinit(self: *ValidationCache, gpa: std.mem.Allocator) void {
        self.map.deinit(gpa);
        self.order.deinit(gpa);
        self.* = undefined;
    }

    pub fn key(bytes: []const u8) [32]u8 {
        var h = Sha256.init(.{});
        h.update(bytes);
        return h.finalResult();
    }

    pub fn get(self: *const ValidationCache, bytes: []const u8) ?driver_mod.Validity {
        return self.map.get(key(bytes));
    }

    pub fn put(self: *ValidationCache, gpa: std.mem.Allocator, bytes: []const u8, v: driver_mod.Validity) !void {
        const k = key(bytes);
        const gop = try self.map.getOrPut(gpa, k);
        if (gop.found_existing) {
            gop.value_ptr.* = v;
            return;
        }
        gop.value_ptr.* = v;
        self.order.append(gpa, k) catch |err| {
            _ = self.map.remove(k);
            return err;
        };
        while (self.map.count() > max_entries and self.order.items.len > 0) {
            const victim = self.order.orderedRemove(0);
            _ = self.map.remove(victim);
        }
    }
};

test "ValueSet keeps sorted-unique order and superset semantics" {
    const gpa = std.testing.allocator;
    var s: ValueSet = .{};
    defer s.deinit(gpa);
    try std.testing.expect(try s.insert(gpa, "bb"));
    try std.testing.expect(try s.insert(gpa, "aa"));
    try std.testing.expect(!try s.insert(gpa, "bb")); // dup
    try std.testing.expect(try s.insert(gpa, "ab"));
    try std.testing.expectEqualSlices(u8, "aa", s.slice()[0]);
    try std.testing.expectEqualSlices(u8, "ab", s.slice()[1]);
    try std.testing.expectEqualSlices(u8, "bb", s.slice()[2]);
    try std.testing.expect(s.contains("ab"));
    try std.testing.expect(!s.contains("zz"));

    var sub: ValueSet = .{};
    defer sub.deinit(gpa);
    _ = try sub.insert(gpa, "aa");
    _ = try sub.insert(gpa, "bb");
    try std.testing.expect(s.isSupersetOf(&sub));
    try std.testing.expect(!sub.isSupersetOf(&s));
}

test "ValidationCache round-trips verdicts" {
    const gpa = std.testing.allocator;
    var c: ValidationCache = .{};
    defer c.deinit(gpa);
    try std.testing.expectEqual(@as(?driver_mod.Validity, null), c.get("v1"));
    try c.put(gpa, "v1", .valid);
    try c.put(gpa, "v2", .maybe_valid);
    try std.testing.expectEqual(driver_mod.Validity.valid, c.get("v1").?);
    try std.testing.expectEqual(driver_mod.Validity.maybe_valid, c.get("v2").?);
}
