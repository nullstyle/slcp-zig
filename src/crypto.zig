//! Preimage construction, digests, Ed25519, and Gi leader-election hashing
//! (design §4.2, §4.3, §5.4, §6). std.crypto only — wasm32-freestanding-safe;
//! Ed25519 signing is deterministic (RFC 8032), so no RNG lives here.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Ed25519 = std.crypto.sign.Ed25519;

/// Frozen 12-byte ASCII domain-tag registry (§4.2). Never reuse, never resize.
pub const tag_statement: *const [12]u8 = "SLCP-STMT-V1";
pub const tag_qset: *const [12]u8 = "SLCP-QSET-V1";
pub const tag_gi: *const [12]u8 = "SLCP-GI-V1\x00\x00";
pub const tag_network: *const [12]u8 = "SLCP-NET-V1\x00";

/// networkId = SHA-256("SLCP-NET-V1\x00" ‖ passphraseUtf8). Pure configuration;
/// mixed into every statement preimage, never transmitted (§4.2).
pub fn networkIdFromPassphrase(passphrase: []const u8) [32]u8 {
    var h = Sha256.init(.{});
    h.update(tag_network);
    h.update(passphrase);
    return h.finalResult();
}

/// digest = SHA-256("SLCP-STMT-V1" ‖ networkId ‖ statementBytes) (§4.2).
pub fn statementDigest(network_id: [32]u8, statement_bytes: []const u8) [32]u8 {
    var h = Sha256.init(.{});
    h.update(tag_statement);
    h.update(&network_id);
    h.update(statement_bytes);
    return h.finalResult();
}

/// qsetHash = SHA-256("SLCP-QSET-V1" ‖ canonicalFlat(normalized qset)) (§4.3).
/// No networkId — qsets are network-independent, cacheable data.
pub fn qsetHash(canonical_qset_bytes: []const u8) [32]u8 {
    var h = Sha256.init(.{});
    h.update(tag_qset);
    h.update(canonical_qset_bytes);
    return h.finalResult();
}

pub const GiTag = enum(u32) { neighbor = 1, priority = 2, value_hash = 3 };

/// Gi(tag, m) = first 8 bytes big-endian of
/// SHA-256("SLCP-GI-V1\x00\x00" ‖ slot:u64be ‖ prevValue ‖ tag:u32be ‖ round:u32be ‖ m).
/// The byte layout is normative and pinned by vector set 3 (§5.4).
pub fn gi(tag: GiTag, slot: u64, prev_value: []const u8, round: u32, m: []const u8) u64 {
    var h = Sha256.init(.{});
    h.update(tag_gi);
    var slot_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &slot_be, slot, .big);
    h.update(&slot_be);
    h.update(prev_value);
    var tag_be: [4]u8 = undefined;
    std.mem.writeInt(u32, &tag_be, @backingInt(tag), .big);
    h.update(&tag_be);
    var round_be: [4]u8 = undefined;
    std.mem.writeInt(u32, &round_be, round, .big);
    h.update(&round_be);
    h.update(m);
    const digest = h.finalResult();
    return std.mem.readInt(u64, digest[0..8], .big);
}

pub fn keypairFromSeed(seed: [32]u8) !Ed25519.KeyPair {
    return Ed25519.KeyPair.generateDeterministic(seed);
}

pub fn publicKeyFromSeed(seed: [32]u8) ![32]u8 {
    const kp = try keypairFromSeed(seed);
    return kp.public_key.toBytes();
}

/// Sign the 32-byte digest (never the raw preimage — §4.2). Deterministic.
pub fn sign(seed: [32]u8, digest: [32]u8) ![64]u8 {
    const kp = try keypairFromSeed(seed);
    const sig = try kp.sign(&digest, null);
    return sig.toBytes();
}

pub fn verify(public_key: [32]u8, digest: [32]u8, signature: [64]u8) bool {
    const pk = Ed25519.PublicKey.fromBytes(public_key) catch return false;
    const sig = Ed25519.Signature.fromBytes(signature);
    sig.verify(&digest, pk) catch return false;
    return true;
}

test "sign→verify roundtrip; wrong digest and wrong key fail" {
    const seed: [32]u8 = @splat(7);
    const pk = try publicKeyFromSeed(seed);
    const network_id = networkIdFromPassphrase("test-net v1");
    const digest = statementDigest(network_id, "statement-bytes");
    const sig = try sign(seed, digest);
    try std.testing.expect(verify(pk, digest, sig));

    var other = digest;
    other[0] ^= 1;
    try std.testing.expect(!verify(pk, other, sig));

    const other_pk = try publicKeyFromSeed(@as([32]u8, @splat(8)));
    try std.testing.expect(!verify(other_pk, digest, sig));
}

test "signing is deterministic (RFC 8032)" {
    const seed: [32]u8 = @splat(42);
    const digest = statementDigest(@splat(1), "abc");
    const a = try sign(seed, digest);
    const b = try sign(seed, digest);
    try std.testing.expectEqualSlices(u8, &a, &b);
}

test "domain tags are 12 bytes and distinct" {
    const tags = [_]*const [12]u8{ tag_statement, tag_qset, tag_gi, tag_network };
    for (tags, 0..) |a, i| {
        for (tags[i + 1 ..]) |b| {
            try std.testing.expect(!std.mem.eql(u8, a, b));
        }
    }
}

test "gi byte layout pinned against hand-derived literal" {
    // Pins the §5.4 preimage LAYOUT against the spec, independently of this
    // file: the expected value was derived with python3 hashlib, NOT by
    // running crypto.zig. Inputs: tag = priority (2), slot = 1,
    // prevValue = "prev", round = 0, m = "node".
    //
    // preimage = "SLCP-GI-V1\x00\x00" ‖ slot:u64be ‖ prevValue ‖ tag:u32be
    //            ‖ round:u32be ‖ m
    //          = 534c43502d47492d56310000              ("SLCP-GI-V1\0\0")
    //            0000000000000001                      (slot 1, u64 BE)
    //            70726576                              ("prev")
    //            00000002                              (tag 2 priority, u32 BE)
    //            00000000                              (round 0, u32 BE)
    //            6e6f6465                              ("node")
    // sha256(preimage) =
    //   e5f9611891f28bf7ca6316e709df83dc02b3212692be2db991b15dfa46186914
    // gi = first 8 bytes big-endian = 0xe5f9611891f28bf7
    try std.testing.expectEqual(
        @as(u64, 0xe5f9611891f28bf7), // = 16571383062042151927
        gi(.priority, 1, "prev", 0, "node"),
    );
}

test "statementDigest pinned against hand-derived literal" {
    // Same discipline as the gi literal test: expected digest derived with
    // python3 hashlib from the §4.2 preimage, not from this file.
    // Inputs: networkId = 32 bytes of 0x11, statementBytes = "stmt".
    //
    // preimage = "SLCP-STMT-V1" ‖ networkId ‖ statementBytes
    //          = 534c43502d53544d542d5631              ("SLCP-STMT-V1")
    //            1111…11 (32 bytes)                    (networkId)
    //            73746d74                              ("stmt")
    // sha256(preimage) =
    //   e9b5a5aa3dafd809a9962d23ad267915127bd5e2fcb329a60d2a2c88d9343d74
    const expected: [32]u8 = .{
        0xe9, 0xb5, 0xa5, 0xaa, 0x3d, 0xaf, 0xd8, 0x09,
        0xa9, 0x96, 0x2d, 0x23, 0xad, 0x26, 0x79, 0x15,
        0x12, 0x7b, 0xd5, 0xe2, 0xfc, 0xb3, 0x29, 0xa6,
        0x0d, 0x2a, 0x2c, 0x88, 0xd9, 0x34, 0x3d, 0x74,
    };
    const actual = statementDigest(@splat(0x11), "stmt");
    try std.testing.expectEqualSlices(u8, &expected, &actual);
}

test "gi depends on every layout component" {
    const base = gi(.priority, 1, "prev", 0, "node");
    try std.testing.expect(base != gi(.neighbor, 1, "prev", 0, "node"));
    try std.testing.expect(base != gi(.priority, 2, "prev", 0, "node"));
    try std.testing.expect(base != gi(.priority, 1, "othr", 0, "node"));
    try std.testing.expect(base != gi(.priority, 1, "prev", 1, "node"));
    try std.testing.expect(base != gi(.priority, 1, "prev", 0, "edon"));
}
