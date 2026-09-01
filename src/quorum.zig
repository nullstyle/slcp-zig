//! Quorum spec — the user-facing quorum-set shape (design §12).
//!
//! `Quorum` is a BORROWED spec: two slices the caller owns (typically
//! literals), no allocator, no deinit. `toOwned` deep-copies it into the
//! engine's `qset.QuorumSetOwned` (un-normalized — run
//! `qset.validateAndNormalize` afterwards, which is what `Node.create` does).
//!
//! This file is also the ONE JSON parser/writer for quorum sets — the CLI
//! (`slcp lint-quorum`), the tests and the vector generator all speak the
//! vectors spelling `{"threshold":T,"validators":[hex64...],"innerSets":[...]}`
//! through `fromJson` / `writeJson`.
//!
//! slcp-core: pure, Io-free, wasm-safe; std.json only.

const std = @import("std");
const qset = @import("engine/qset.zig");

pub const NodeId = qset.NodeId;

/// Comptime public key from its 64-char hex spelling (the output of
/// `slcp key show`). A bad string is a compile error naming the string.
pub fn nodeId(comptime hex: *const [64]u8) NodeId {
    const out = comptime blk: {
        var id: NodeId = undefined;
        for (0..32) |i| {
            const hi = hexNibble(hex[2 * i]) orelse
                @compileError("slcp.nodeId: not a 64-character hex string: \"" ++ hex ++ "\"");
            const lo = hexNibble(hex[2 * i + 1]) orelse
                @compileError("slcp.nodeId: not a 64-character hex string: \"" ++ hex ++ "\"");
            id[i] = (hi << 4) | lo;
        }
        break :blk id;
    };
    return out;
}

fn hexNibble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

pub const ParseNodeIdError = error{ BadNodeIdLength, BadNodeIdHex };

/// Runtime public key from 64 hex chars (either case, no `0x` prefix).
pub fn parseNodeId(hex: []const u8) ParseNodeIdError!NodeId {
    if (hex.len != 64) return error.BadNodeIdLength;
    var out: NodeId = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch return error.BadNodeIdHex;
    return out;
}

/// Lower-case hex spelling of a public key.
pub fn nodeIdHex(id: NodeId) [64]u8 {
    return std.fmt.bytesToHex(id, .lower);
}

pub const Quorum = struct {
    threshold: u32,
    validators: []const NodeId = &.{},
    inner_sets: []const Quorum = &.{},

    /// The blessed default: ceil(2n/3)-of-n. Tolerates floor((n-1)/3)
    /// Byzantine members while staying a majority.
    pub fn twoThirdsOf(validators: []const NodeId) Quorum {
        return .{ .threshold = twoThirds(validators.len), .validators = validators };
    }

    /// floor(n/2)+1 of n.
    pub fn majorityOf(validators: []const NodeId) Quorum {
        return .{ .threshold = majority(validators.len), .validators = validators };
    }

    pub fn of(threshold: u32, validators: []const NodeId) Quorum {
        return .{ .threshold = threshold, .validators = validators };
    }

    pub fn twoThirdsOfSets(inner_sets: []const Quorum) Quorum {
        return .{ .threshold = twoThirds(inner_sets.len), .inner_sets = inner_sets };
    }

    pub fn ofSets(threshold: u32, inner_sets: []const Quorum) Quorum {
        return .{ .threshold = threshold, .inner_sets = inner_sets };
    }

    /// Deep copy into the engine's owned tree. NOT normalized/validated —
    /// that is `qset.validateAndNormalize`'s job. Caller deinits.
    pub fn toOwned(self: Quorum, gpa: std.mem.Allocator) std.mem.Allocator.Error!qset.QuorumSetOwned {
        const vals = try gpa.dupe(NodeId, self.validators);
        errdefer gpa.free(vals);
        const inners = try gpa.alloc(qset.QuorumSetOwned, self.inner_sets.len);
        var built: usize = 0;
        errdefer {
            for (inners[0..built]) |*inner| inner.deinit(gpa);
            gpa.free(inners);
        }
        for (self.inner_sets, 0..) |inner, i| {
            inners[i] = try inner.toOwned(gpa);
            built += 1;
        }
        return .{ .threshold = self.threshold, .validators = vals, .inner_sets = inners };
    }

    /// Top-level member count n — the n in "t-of-n" (validators + inner sets).
    pub fn memberCount(self: Quorum) usize {
        return self.validators.len + self.inner_sets.len;
    }

    /// Is `id` a validator anywhere in the tree?
    pub fn containsNode(self: Quorum, id: NodeId) bool {
        for (self.validators) |*v| {
            if (std.mem.eql(u8, v, &id)) return true;
        }
        for (self.inner_sets) |inner| {
            if (inner.containsNode(id)) return true;
        }
        return false;
    }

    pub const JsonError = error{ BadJson, MissingField, BadThreshold, BadValidator, BadInnerSets, TooDeep } ||
        ParseNodeIdError || std.mem.Allocator.Error;

    /// Parse `{"threshold":T,"validators":[hex64...],"innerSets":[...]}`.
    /// `innerSets` is optional; unknown keys are ignored. The result borrows
    /// from `arena` (the caller's arena; nothing to free individually).
    /// Depth is capped at `qset.max_depth` (4) — the wire limit — so
    /// `TooDeep` surfaces here rather than as a hash-time rejection.
    pub fn fromJson(arena: std.mem.Allocator, bytes: []const u8) JsonError!Quorum {
        const root = std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.BadJson,
        };
        if (root != .object) return error.BadJson;
        return fromObject(arena, root.object, 1);
    }

    fn fromObject(arena: std.mem.Allocator, obj: std.json.ObjectMap, depth: u32) JsonError!Quorum {
        if (depth > qset.max_depth) return error.TooDeep;

        const t = obj.get("threshold") orelse return error.MissingField;
        if (t != .integer or t.integer < 0 or t.integer > std.math.maxInt(u32)) return error.BadThreshold;

        const vals_v = obj.get("validators") orelse return error.MissingField;
        if (vals_v != .array) return error.BadValidator;
        const vals = try arena.alloc(NodeId, vals_v.array.items.len);
        for (vals_v.array.items, 0..) |v, i| {
            if (v != .string) return error.BadValidator;
            vals[i] = try parseNodeId(v.string);
        }

        var inners: []Quorum = &.{};
        if (obj.get("innerSets")) |inner_v| {
            if (inner_v != .array) return error.BadInnerSets;
            inners = try arena.alloc(Quorum, inner_v.array.items.len);
            for (inner_v.array.items, 0..) |v, i| {
                if (v != .object) return error.BadInnerSets;
                inners[i] = try fromObject(arena, v.object, depth + 1);
            }
        }

        return .{ .threshold = @intCast(t.integer), .validators = vals, .inner_sets = inners };
    }

    /// Write an owned tree in the vectors spelling (compact, lower-case hex,
    /// `innerSets` always present). Byte-stable by construction.
    pub fn writeJson(w: *std.Io.Writer, qs: *const qset.QuorumSetOwned) std.Io.Writer.Error!void {
        try w.print("{{\"threshold\":{d},\"validators\":[", .{qs.threshold});
        for (qs.validators, 0..) |*v, i| {
            if (i > 0) try w.writeByte(',');
            try w.writeByte('"');
            try w.writeAll(&nodeIdHex(v.*));
            try w.writeByte('"');
        }
        try w.writeAll("],\"innerSets\":[");
        for (qs.inner_sets, 0..) |*inner, i| {
            if (i > 0) try w.writeByte(',');
            try writeJson(w, inner);
        }
        try w.writeAll("]}");
    }
};

fn twoThirds(n: usize) u32 {
    return @intCast((2 * n + 2) / 3); // ceil(2n/3)
}

fn majority(n: usize) u32 {
    return @intCast(n / 2 + 1);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn splatId(byte: u8) NodeId {
    return @splat(byte);
}

// Non-vacuity: changing `twoThirds` to `(2 * n) / 3` (floor) → n=1 gives 0,
// n=4 gives 2, red against the table; changing `majority` to `n / 2` → red.
test "twoThirdsOf / majorityOf thresholds for n = 1..12 match the hand table" {
    const two_thirds_table = [_]u32{ 1, 2, 2, 3, 4, 4, 5, 6, 6, 7, 8, 8 };
    const majority_table = [_]u32{ 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7 };
    var ids: [12]NodeId = undefined;
    for (&ids, 0..) |*id, i| id.* = splatId(@intCast(i + 1));
    for (two_thirds_table, majority_table, 1..) |want_tt, want_maj, n| {
        const tt = Quorum.twoThirdsOf(ids[0..n]);
        try testing.expectEqual(want_tt, tt.threshold);
        try testing.expectEqual(n, tt.memberCount());
        try testing.expectEqual(want_maj, Quorum.majorityOf(ids[0..n]).threshold);
    }
    // Set-level variants use the same formulas over inner sets.
    const sets = [_]Quorum{ Quorum.of(1, ids[0..1]), Quorum.of(1, ids[1..2]), Quorum.of(1, ids[2..3]) };
    try testing.expectEqual(@as(u32, 2), Quorum.twoThirdsOfSets(&sets).threshold);
    try testing.expectEqual(@as(u32, 3), Quorum.ofSets(3, &sets).threshold);
    try testing.expectEqual(@as(usize, 3), Quorum.ofSets(3, &sets).memberCount());
}

// Non-vacuity: making `parseNodeId` skip the length check → the 63/65-char
// cases return `BadNodeIdHex` (or succeed) instead of `BadNodeIdLength`;
// upper-casing `nodeIdHex` → the round-trip literal comparison goes red.
test "nodeId / parseNodeId / nodeIdHex round-trip and reject bad input" {
    const hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const id = nodeId(hex);
    try testing.expectEqual(@as(u8, 0x00), id[0]);
    try testing.expectEqual(@as(u8, 0x11), id[1]);
    try testing.expectEqual(@as(u8, 0xff), id[31]);
    try testing.expectEqualStrings(hex, &nodeIdHex(id));
    try testing.expectEqualSlices(u8, &id, &(try parseNodeId(hex)));
    // upper case accepted, canonical spelling is lower
    const upper = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF";
    try testing.expectEqualSlices(u8, &id, &(try parseNodeId(upper)));
    try testing.expectEqualStrings(hex, &nodeIdHex(try parseNodeId(upper)));

    try testing.expectError(error.BadNodeIdLength, parseNodeId(hex[0..63]));
    try testing.expectError(error.BadNodeIdLength, parseNodeId(hex ++ "0"));
    try testing.expectError(error.BadNodeIdLength, parseNodeId(""));
    const zz = "zz" ++ hex[2..];
    try testing.expectError(error.BadNodeIdHex, parseNodeId(zz));
    try testing.expectError(error.BadNodeIdHex, parseNodeId("0x" ++ hex[2..]));
}

// Inline copy of vectors/qset.json "nested 3 orgs, 2-of-3 orgs, majority
// within each" — input spelling and pinned hash.
const nested_three_orgs_json =
    \\{"threshold":2,"validators":[],"innerSets":[
    \\ {"threshold":2,"validators":["1010101010101010101010101010101010101010101010101010101010101010","1111111111111111111111111111111111111111111111111111111111111111","1212121212121212121212121212121212121212121212121212121212121212"],"innerSets":[]},
    \\ {"threshold":2,"validators":["2020202020202020202020202020202020202020202020202020202020202020","2121212121212121212121212121212121212121212121212121212121212121","2222222222222222222222222222222222222222222222222222222222222222"],"innerSets":[]},
    \\ {"threshold":2,"validators":["3030303030303030303030303030303030303030303030303030303030303030","3131313131313131313131313131313131313131313131313131313131313131","3232323232323232323232323232323232323232323232323232323232323232"],"innerSets":[]}]}
;
const nested_three_orgs_hash = "fc7b82b2cb45a596201727b30861a2a3e79c623cf7cb26120e7e7b09dfc3b35d";

// Non-vacuity: a wrong hash literal (or parsing "threshold" of an inner set
// as the root's) fails the pinned-hash comparison; skipping
// `validateAndNormalize` changes the inner-set order and the hash.
test "fromJson → toOwned → validateAndNormalize → hashNormalized equals the vectors/qset.json pin" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const q = try Quorum.fromJson(arena, nested_three_orgs_json);
    try testing.expectEqual(@as(u32, 2), q.threshold);
    try testing.expectEqual(@as(usize, 0), q.validators.len);
    try testing.expectEqual(@as(usize, 3), q.inner_sets.len);
    try testing.expectEqual(@as(usize, 3), q.memberCount());
    try testing.expect(q.containsNode(splatId(0x31)));
    try testing.expect(!q.containsNode(splatId(0x01)));

    var owned = try q.toOwned(gpa);
    defer owned.deinit(gpa);
    // toOwned is a deep copy: the spec's memory is not referenced.
    try testing.expect(owned.inner_sets[0].validators.ptr != q.inner_sets[0].validators.ptr);
    try qset.validateAndNormalize(gpa, &owned);
    const h = try qset.hashNormalized(gpa, &owned);
    try testing.expectEqualStrings(nested_three_orgs_hash, &std.fmt.bytesToHex(h, .lower));
}

// Non-vacuity: removing the `MissingField` check makes the first case
// `BadThreshold`-or-crash; removing the depth guard makes the 5-deep chain
// parse (and later fail at validateAndNormalize instead).
test "fromJson errors: missing threshold, validators not array, 5-deep, 62-char key, bad json" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectError(error.MissingField, Quorum.fromJson(arena, "{\"validators\":[]}"));
    try testing.expectError(error.MissingField, Quorum.fromJson(arena, "{\"threshold\":1}"));
    try testing.expectError(error.BadValidator, Quorum.fromJson(arena, "{\"threshold\":1,\"validators\":\"x\"}"));
    try testing.expectError(error.BadValidator, Quorum.fromJson(arena, "{\"threshold\":1,\"validators\":[1]}"));
    try testing.expectError(error.BadThreshold, Quorum.fromJson(arena, "{\"threshold\":-1,\"validators\":[]}"));
    try testing.expectError(error.BadThreshold, Quorum.fromJson(arena, "{\"threshold\":\"2\",\"validators\":[]}"));
    try testing.expectError(error.BadInnerSets, Quorum.fromJson(arena, "{\"threshold\":1,\"validators\":[],\"innerSets\":{}}"));
    try testing.expectError(error.BadInnerSets, Quorum.fromJson(arena, "{\"threshold\":1,\"validators\":[],\"innerSets\":[7]}"));
    try testing.expectError(error.BadJson, Quorum.fromJson(arena, "{\"threshold\":1,"));
    try testing.expectError(error.BadJson, Quorum.fromJson(arena, "[1,2]"));

    // 5-deep chain of {threshold 1, no validators, one inner}.
    const five_deep =
        "{\"threshold\":1,\"validators\":[],\"innerSets\":[" ++
        "{\"threshold\":1,\"validators\":[],\"innerSets\":[" ++
        "{\"threshold\":1,\"validators\":[],\"innerSets\":[" ++
        "{\"threshold\":1,\"validators\":[],\"innerSets\":[" ++
        "{\"threshold\":1,\"validators\":[\"0707070707070707070707070707070707070707070707070707070707070707\"]}" ++
        "]}]}]}]}";
    try testing.expectError(error.TooDeep, Quorum.fromJson(arena, five_deep));
    // 4-deep is fine (the wire limit).
    const four_deep =
        "{\"threshold\":1,\"validators\":[],\"innerSets\":[" ++
        "{\"threshold\":1,\"validators\":[],\"innerSets\":[" ++
        "{\"threshold\":1,\"validators\":[],\"innerSets\":[" ++
        "{\"threshold\":1,\"validators\":[\"0707070707070707070707070707070707070707070707070707070707070707\"]}" ++
        "]}]}]}";
    _ = try Quorum.fromJson(arena, four_deep);

    const short_key = "{\"threshold\":1,\"validators\":[\"07070707070707070707070707070707070707070707070707070707070707\"]}";
    try testing.expectError(error.BadNodeIdLength, Quorum.fromJson(arena, short_key));
    const bad_hex = "{\"threshold\":1,\"validators\":[\"zz07070707070707070707070707070707070707070707070707070707070707\"]}";
    try testing.expectError(error.BadNodeIdHex, Quorum.fromJson(arena, bad_hex));
}

const flat_two_of_three_json =
    "{\"threshold\":2,\"validators\":[" ++
    "\"0101010101010101010101010101010101010101010101010101010101010101\"," ++
    "\"0202020202020202020202020202020202020202020202020202020202020202\"," ++
    "\"0303030303030303030303030303030303030303030303030303030303030303\"" ++
    "],\"innerSets\":[]}";

// Non-vacuity: any spelling drift in `writeJson` (a space after ':', upper
// hex, omitting an empty `innerSets`) breaks byte-equality with the
// vectors literal; a lossy `fromJson` breaks the round-trip.
test "writeJson round-trips fromJson and is byte-equal to the vectors spelling (flat 2-of-3)" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Spec-built and JSON-parsed forms write identical bytes.
    const ids = [_]NodeId{ splatId(1), splatId(2), splatId(3) };
    var from_spec = try Quorum.of(2, &ids).toOwned(gpa);
    defer from_spec.deinit(gpa);
    var sink_a = std.Io.Writer.Allocating.init(gpa);
    defer sink_a.deinit();
    try Quorum.writeJson(&sink_a.writer, &from_spec);
    try testing.expectEqualStrings(flat_two_of_three_json, sink_a.written());

    var parsed = try (try Quorum.fromJson(arena, flat_two_of_three_json)).toOwned(gpa);
    defer parsed.deinit(gpa);
    var sink_b = std.Io.Writer.Allocating.init(gpa);
    defer sink_b.deinit();
    try Quorum.writeJson(&sink_b.writer, &parsed);
    try testing.expectEqualStrings(flat_two_of_three_json, sink_b.written());

    // Nested round-trip: parse → write → parse → same hash.
    var nested = try (try Quorum.fromJson(arena, nested_three_orgs_json)).toOwned(gpa);
    defer nested.deinit(gpa);
    var sink_c = std.Io.Writer.Allocating.init(gpa);
    defer sink_c.deinit();
    try Quorum.writeJson(&sink_c.writer, &nested);
    var again = try (try Quorum.fromJson(arena, sink_c.written())).toOwned(gpa);
    defer again.deinit(gpa);
    try qset.validateAndNormalize(gpa, &nested);
    try qset.validateAndNormalize(gpa, &again);
    try testing.expectEqualSlices(u8, &(try qset.hashNormalized(gpa, &nested)), &(try qset.hashNormalized(gpa, &again)));
}
