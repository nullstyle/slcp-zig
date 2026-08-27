//! Canonicalization for signed SLCP types (design §4.2–§4.3).
//!
//! SLCP signs the OFFICIAL Cap'n Proto canonical form via
//! `capnpc.canonical.canonicalizeFlat`: schema-free, bare single segment, no
//! segment table, byte-identical to `capnp convert binary:canonical`.
//! statementBytes and hashed qset bytes are FLAT. As of capnp-zig v0.14.0
//! (which delivered all three M0 upstream asks) flat bytes decode directly
//! through the validating zero-copy `Message.initFlat`, and the signing hot
//! path canonicalizes straight from a MessageBuilder — the synthetic
//! segment-table workaround is gone from the decode path (`frameFlat`
//! survives only as an interop utility for tools that need framed bytes).

const std = @import("std");
const capnpc = @import("capnpc-zig");

pub const Message = capnpc.message.Message;
pub const ValidationOptions = capnpc.message.Message.ValidationOptions;

pub const seg_table_len = 8;

pub const Error = error{InvalidFlatBytes};

/// Canonical flat bytes of a parsed message. The single canonicalization
/// call for both Statement preimages (§4.2) and normalized qset hashing (§4.3).
pub fn canonicalFlat(gpa: std.mem.Allocator, msg: *const Message) ![]u8 {
    return capnpc.canonical.canonicalizeFlat(gpa, msg);
}

/// Prepend the standard single-segment table: two little-endian u32s —
/// segment count − 1 = 0, then segment size in words. Caller owns the result.
/// No longer on the decode path (Message.initFlat, capnp-zig v0.14.0); kept
/// for interop tooling that must hand framed bytes to other consumers.
pub fn frameFlat(gpa: std.mem.Allocator, flat: []const u8) ![]u8 {
    if (flat.len == 0 or flat.len % 8 != 0) return Error.InvalidFlatBytes;
    const framed = try gpa.alloc(u8, seg_table_len + flat.len);
    std.mem.writeInt(u32, framed[0..4], 0, .little);
    std.mem.writeInt(u32, framed[4..8], @intCast(flat.len / 8), .little);
    @memcpy(framed[seg_table_len..], flat);
    return framed;
}

/// Validating decode of flat bytes (e.g. received statementBytes) via the
/// zero-copy `Message.initFlat` (capnp-zig v0.14.0 — the delivered
/// docs/upstream/03 ask). The returned Message BORROWS `flat`: keep the
/// bytes alive and unmoved for the Message's whole lifetime. Caller deinits.
pub fn decodeFlat(gpa: std.mem.Allocator, flat: []const u8, options: ValidationOptions) !Message {
    if (flat.len == 0 or flat.len % 8 != 0) return Error.InvalidFlatBytes;
    return Message.initFlat(gpa, flat, options);
}

/// Receive-side canonicality check (§4.2; `strictCanonical` defaults on).
/// A cheap structural walk — no re-canonicalization, no compare.
pub fn isCanonicalFlat(gpa: std.mem.Allocator, flat: []const u8) bool {
    var msg = decodeFlat(gpa, flat, .{}) catch return false;
    defer msg.deinit();
    return capnpc.canonical.isCanonical(&msg);
}

/// Canonical flat bytes straight from a MessageBuilder — the signing hot
/// path (the delivered docs/upstream/02 ask: no toBytes→init→canonicalize
/// hop, no redundant validation walk). Caller owns the result.
pub fn canonicalFlatFromBuilder(gpa: std.mem.Allocator, mb: *const capnpc.message.MessageBuilder) ![]u8 {
    return capnpc.canonical.canonicalizeFlatFromBuilder(gpa, mb);
}

test "decodeFlat borrows flat bytes; canonical bytes pass isCanonicalFlat" {
    const gpa = std.testing.allocator;
    // Smallest canonical message: a root empty-struct pointer (offset -1),
    // one word. canonicalizeFlat of any all-default root produces it.
    const empty_root: [8]u8 = .{ 0xfc, 0xff, 0xff, 0xff, 0, 0, 0, 0 };
    try std.testing.expect(isCanonicalFlat(gpa, &empty_root));
    var msg = try decodeFlat(gpa, &empty_root, .{});
    defer msg.deinit();
    try std.testing.expect(capnpc.canonical.isCanonical(&msg));
}

test "canonicalFlatFromBuilder matches the framed round-trip path" {
    const gen_slcp = @import("gen/slcp.zig");
    const gpa = std.testing.allocator;
    var mb = capnpc.message.MessageBuilder.init(gpa);
    defer mb.deinit();
    var ballot = try gen_slcp.Ballot.Builder.init(&mb);
    try ballot.setCounter(42);
    try ballot.setValue("val");
    const direct = try canonicalFlatFromBuilder(gpa, &mb);
    defer gpa.free(direct);
    const framed = try mb.toBytes();
    defer gpa.free(framed);
    const hop = try canonicalFlatFromFramed(gpa, framed);
    defer gpa.free(hop);
    try std.testing.expectEqualSlices(u8, direct, hop);
}

/// Canonicalize a message built via MessageBuilder: toBytes (framed) →
/// validating init → canonicalizeFlat. The allocating hop in the middle is
/// the upstream canonicalize-from-Builder ask (§15 M0).
pub fn canonicalFlatFromFramed(gpa: std.mem.Allocator, framed: []const u8) ![]u8 {
    var msg = try Message.init(gpa, framed, .{});
    defer msg.deinit();
    return canonicalFlat(gpa, &msg);
}

test "frameFlat rejects empty and non-word-aligned input" {
    const gpa = std.testing.allocator;
    try std.testing.expectError(Error.InvalidFlatBytes, frameFlat(gpa, &.{}));
    try std.testing.expectError(Error.InvalidFlatBytes, frameFlat(gpa, &.{ 1, 2, 3 }));
}

test "frameFlat writes the synthetic single-segment table" {
    const gpa = std.testing.allocator;
    const flat: [16]u8 = @splat(0);
    const framed = try frameFlat(gpa, &flat);
    defer gpa.free(framed);
    try std.testing.expectEqual(@as(usize, 24), framed.len);
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, framed[0..4], .little));
    try std.testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, framed[4..8], .little));
}
