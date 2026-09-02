//! Auto-codec fuzz target (design §8.5, §13.5): arbitrary bytes against
//! `slcp.Codec(Command)` for a kitchen-sink Command, with the three
//! properties that make the codec safe to put under consensus:
//!
//!   (1) strict length — any buffer whose length is not `size` decodes to null;
//!   (2) strict canonicality — whatever decodes re-encodes byte-identically
//!       (one spelling per value, so the codec is never a malleability source);
//!   (3) order preservation — for two decoding chunks, the typed `order`
//!       equals `std.mem.order(u8, …)` of their bytes (the §8.4 default
//!       combine, "highest proposal wins", is numerically meaningful).
//!
//! Fuzz API (zig 0.17): `std.testing.fuzz(context, testOne, .{ .corpus })`;
//! `Smith.slice` yields an arbitrary buffer. The deterministic `fuzz-smoke`
//! run (part of `zig build test`) drives the same property function with a
//! fixed-seed PRNG for 5000 iterations, mixing raw bytes with canonical
//! encodings (and one-byte mutants of them) so decodes actually happen — the
//! run asserts at least one non-null decode occurred, otherwise the strict
//! properties would be vacuous.

const std = @import("std");
const slcp = @import("slcp");

const Color = enum(u8) { red, green, blue };
/// Signed-tag enum: its own codec arm (the tag biases like a signed int);
/// `.neg` spells 0x7B, so an all-zero byte (-128) names no variant.
const Sign = enum(i8) { neg = -5, zero = 0, pos = 5 };

/// Same leaf coverage as app_node.zig's Kitchen: sub-byte int, signed wide
/// int, bool, unsigned-tag enum, fixed array, nested struct, signed-tag
/// enum. Encoded size 23.
const Cmd = struct {
    a: i8,
    b: u3,
    c: i64,
    d: bool,
    e: Color,
    f: [3]u16,
    g: struct { h: u16, i: i16 },
    s: Sign,
};
const C = slcp.Codec(Cmd);
const cmd_field_names = @typeInfo(Cmd).@"struct".field_names;

const max_fuzz_bytes = 8 * C.size + 3;

/// The three properties over one arbitrary buffer. Returns how many
/// `size`-byte chunks decoded (the smoke sums these for non-vacuity).
fn codecProperties(bytes: []const u8) !usize {
    // (1) wrong length ⇒ null, always.
    if (bytes.len != C.size and C.decode(bytes) != null) return error.WrongLengthDecoded;

    var decoded: usize = 0;
    var scratch: [C.size]u8 = undefined;
    var prev: ?struct { v: Cmd, bytes: []const u8 } = null;
    var i: usize = 0;
    while (i + C.size <= bytes.len) : (i += C.size) {
        const chunk = bytes[i..][0..C.size];
        const v = C.decode(chunk) orelse continue;
        decoded += 1;
        // (2) canonical: re-encoding reproduces the exact bytes.
        if (!std.mem.eql(u8, chunk, C.encode(v, &scratch))) return error.ReencodeMismatch;
        // (3) order-preserving against the previous decoding chunk.
        if (prev) |p| {
            if (C.order(p.v, v) != std.mem.order(u8, p.bytes, chunk)) return error.OrderMismatch;
        }
        prev = .{ .v = v, .bytes = chunk };
    }
    return decoded;
}

fn fuzzCodecOne(_: void, smith: *std.testing.Smith) anyerror!void {
    var buf: [max_fuzz_bytes]u8 = undefined;
    const len = smith.slice(&buf);
    _ = try codecProperties(buf[0..len]);
}

// ---------------------------------------------------------------------------
// zig build fuzz — corpus-driven std.testing.fuzz target
// ---------------------------------------------------------------------------

const zeros: [C.size]u8 = @splat(0);
const ones: [C.size]u8 = @splat(0xff);
/// Canonical encoding of the all-minimum value: 22 zero bytes, then 0x7B
/// (the biased spelling of `Sign.neg`). The all-zero buffer itself decodes
/// to null (its last byte unbiases to -128, which names no variant).
const minimum: [C.size]u8 = @as([C.size - 1]u8, @splat(0)) ++ [_]u8{0x7B};

/// Seeds: empty, the canonical minimum encoding (decodes: every field at its
/// minimum), an all-zero buffer (signed tag -128 ⇒ null), an all-0xff buffer
/// (u3 high bits ⇒ null), off-by-one lengths, two chunks.
const codec_corpus = [_][]const u8{
    &.{},
    &minimum,
    &zeros,
    &ones,
    minimum[0 .. C.size - 1],
    &(minimum ++ [_]u8{0}),
    &(minimum ++ ones),
};

// Non-vacuity: a decoder without the exact-length check fails (1) on the
// corpus's 22/24-byte entries; a `@enumFromInt` decode fails (2) on any
// chunk with tag byte >= 3; encoding the signed tag as its raw unsigned
// bits (the S1b bug) fails (3) on consecutive chunks that differ only in
// `s` — the smoke's shape 2 produces those on purpose.
test "fuzz: Codec strict length, canonical re-encode, order-preserving" {
    try std.testing.fuzz({}, fuzzCodecOne, .{ .corpus = &codec_corpus });
}

// ---------------------------------------------------------------------------
// fuzz-smoke — deterministic bounded run (part of `zig build test`)
// ---------------------------------------------------------------------------

pub const smoke_iterations: usize = 5000;
pub const smoke_seed: u64 = 0xc0de_c0de_5eed_0001;

fn randomValue(comptime T: type, rand: std.Random) T {
    switch (@typeInfo(T)) {
        .int => return rand.int(T),
        .bool => return rand.boolean(),
        .@"enum" => return rand.enumValue(T),
        .array => |a| {
            var out: T = undefined;
            for (&out) |*elem| elem.* = randomValue(a.child, rand);
            return out;
        },
        .@"struct" => |s| {
            var out: T = undefined;
            inline for (s.field_names, s.field_types) |fname, FT| @field(out, fname) = randomValue(FT, rand);
            return out;
        },
        else => unreachable,
    }
}

/// Copies the first `k` top-level fields of `src` into `dst`. Two
/// independent random values almost always differ in the leading field, so
/// without a shared prefix the order property (3) only ever exercises `a`;
/// sharing a random-length prefix lets every field, down to the trailing
/// signed-tag enum, decide the order of a consecutive pair.
fn sharePrefix(dst: *Cmd, src: Cmd, k: usize) void {
    inline for (cmd_field_names, 0..) |fname, idx| {
        if (idx < k) @field(dst, fname) = @field(src, fname);
    }
}

/// Fixed-seed PRNG replay of the properties. Four input shapes per cycle:
/// raw bytes of random length, raw bytes of exact size, one to eight
/// canonical encodings back to back, each sharing a random-length field
/// prefix with the previous one (order property across chunks, decided by
/// every field in turn), and a canonical encoding with one byte mutated
/// (strictness on near-misses).
/// Each buffer also goes through the Smith byte-replay path so the fuzz
/// entry point itself is exercised. Asserts >= 1 decode overall.
pub fn runSmoke() !void {
    var prng = std.Random.DefaultPrng.init(smoke_seed);
    const rand = prng.random();
    var scratch: [4 + max_fuzz_bytes]u8 = undefined;
    var decoded_total: usize = 0;

    for (0..smoke_iterations) |iter| {
        const payload = scratch[4..];
        var len: usize = 0;
        switch (iter % 4) {
            0 => {
                len = rand.uintLessThan(usize, max_fuzz_bytes + 1);
                rand.bytes(payload[0..len]);
            },
            1 => {
                len = C.size;
                rand.bytes(payload[0..len]);
            },
            2 => {
                const n = 1 + rand.uintLessThan(usize, 8);
                var prev: ?Cmd = null;
                for (0..n) |_| {
                    var v = randomValue(Cmd, rand);
                    if (prev) |p| sharePrefix(&v, p, rand.uintLessThan(usize, cmd_field_names.len + 1));
                    _ = C.encode(v, payload[len..]);
                    len += C.size;
                    prev = v;
                }
            },
            else => {
                _ = C.encode(randomValue(Cmd, rand), payload[0..C.size]);
                len = C.size;
                payload[rand.uintLessThan(usize, C.size)] = rand.int(u8);
            },
        }
        decoded_total += try codecProperties(payload[0..len]);

        // Same bytes via the fuzz entry point (length-prefixed Smith input:
        // Smith.slice reads a little-endian u32 length first).
        std.mem.writeInt(u32, scratch[0..4], @intCast(len), .little);
        var smith: std.testing.Smith = .{ .in = scratch[0 .. 4 + len] };
        try fuzzCodecOne({}, &smith);
    }
    // Shapes 2 and 3 (and shape 1 by chance) decode; without this the
    // canonical/order properties would never have fired.
    if (decoded_total == 0) return error.SmokeNeverDecoded;
}

// Non-vacuity: `error.SmokeNeverDecoded` goes red if shapes 2/3 stop
// producing canonical encodings; the properties go red under the same
// ablations as the fuzz test above.
test "fuzz-smoke: codec target, 5000 deterministic iterations, >= 1 decode" {
    try runSmoke();
}
