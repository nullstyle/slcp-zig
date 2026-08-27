//! Canonicalization for signed SLCP types (design §4.2–§4.3).
//!
//! SLCP signs the OFFICIAL Cap'n Proto canonical form via
//! `capnpc.canonical.canonicalizeFlat`: schema-free, bare single segment, no
//! segment table, byte-identical to `capnp convert binary:canonical`.
//! statementBytes and hashed qset bytes are FLAT; capnp-zig's validating
//! `Message.init` parses framed messages, so `frameFlat` prepends the
//! synthetic single-segment table before any decode.

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

/// Prepend the synthetic single-segment table (§4.2): two little-endian u32s —
/// segment count − 1 = 0, then segment size in words. Caller owns the result.
pub fn frameFlat(gpa: std.mem.Allocator, flat: []const u8) ![]u8 {
    if (flat.len == 0 or flat.len % 8 != 0) return Error.InvalidFlatBytes;
    const framed = try gpa.alloc(u8, seg_table_len + flat.len);
    std.mem.writeInt(u32, framed[0..4], 0, .little);
    std.mem.writeInt(u32, framed[4..8], @intCast(flat.len / 8), .little);
    @memcpy(framed[seg_table_len..], flat);
    return framed;
}

/// A decoded flat message plus the synthetic-table buffer it borrows into.
/// `Message.init` BORROWS the framed bytes (it does not copy), so the buffer
/// must outlive the Message — freeing it early is a use-after-free (found by
/// the M0 vector work; the real fix is the upstream flat validating-decode
/// entry point, docs/upstream/03).
pub const FlatMessage = struct {
    msg: Message,
    framed: []u8,

    pub fn deinit(self: *FlatMessage, gpa: std.mem.Allocator) void {
        self.msg.deinit();
        gpa.free(self.framed);
        self.* = undefined;
    }
};

/// Validating decode of flat bytes (e.g. received statementBytes).
/// Caller owns the result (call deinit).
pub fn decodeFlat(gpa: std.mem.Allocator, flat: []const u8, options: ValidationOptions) !FlatMessage {
    const framed = try frameFlat(gpa, flat);
    errdefer gpa.free(framed);
    const msg = try Message.init(gpa, framed, options);
    return .{ .msg = msg, .framed = framed };
}

/// Receive-side canonicality check (§4.2; `strictCanonical` defaults on).
/// A cheap structural walk — no re-canonicalization, no compare.
pub fn isCanonicalFlat(gpa: std.mem.Allocator, flat: []const u8) bool {
    var fm = decodeFlat(gpa, flat, .{}) catch return false;
    defer fm.deinit(gpa);
    return capnpc.canonical.isCanonical(&fm.msg);
}

test "decodeFlat keeps the framed buffer alive; canonical bytes pass isCanonicalFlat" {
    const gpa = std.testing.allocator;
    // Smallest canonical message: a root empty-struct pointer (offset -1),
    // one word. canonicalizeFlat of any all-default root produces it.
    const empty_root: [8]u8 = .{ 0xfc, 0xff, 0xff, 0xff, 0, 0, 0, 0 };
    try std.testing.expect(isCanonicalFlat(gpa, &empty_root));
    var fm = try decodeFlat(gpa, &empty_root, .{});
    defer fm.deinit(gpa);
    try std.testing.expect(capnpc.canonical.isCanonical(&fm.msg));
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
