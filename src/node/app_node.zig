//! Typed app layer (design §8.5): the `Codec(T)` auto-codec and the comptime
//! contract of `AppNode(App)`.
//!
//! slcp-core stays bytes-only. `AppNode(App)` is a comptime adapter that
//! compiles a typed, pure state machine (`State`, `Command`, `validate`,
//! `apply`, optional `combine` / `initialState` / `encode` + `decode`) down to
//! the frozen §8.2 `Driver` vtable; the engine never learns it exists.
//!
//! Every contract violation is a teaching `@compileError` (want-vs-got and
//! the workaround), never a vtable type mismatch. Each message's first line
//! is pinned by `zig build appnode-errors` (tests/appnode_errors/*.zig): the
//! needle is the tail of that first line after the `<T>` / `<path>`
//! rendering (plan R12) — change a message here and its needle together.
//!
//! **Auto-codec** (`Codec(T)`): a canonical fixed-size encoding derived at
//! comptime — fields in declaration order, big-endian, signed ints
//! sign-bit-biased — so BYTE ORDER EQUALS NUMERIC ORDER and the §8.4 default
//! combine (lexicographic max, "highest proposal wins") is semantically
//! correct over auto-encoded commands. Allowed: ints (any width, rounded up
//! to whole bytes), bool, exhaustive enums, fixed `[N]T` arrays, nested
//! structs. Rejected at comptime with the rule spelled out: floats,
//! pointers/slices, optionals, unions, non-exhaustive enums, anything else.
//! Decode is strict-canonical (exact length, no non-canonical high bits,
//! bool ∈ {0,1}, enum tag must name a variant) so the codec cannot become a
//! value-malleability source.
//!
//! This stage (M6 S1b) ships the codec and the contract checks; `create` /
//! `propose` / `waitApplied` and the Driver compilation land in S3.

const std = @import("std");
const core = @import("slcp-core");
const node = @import("node.zig");

pub const Validity = core.driver.Validity;
pub const Driver = core.driver.Driver;
pub const DriverError = core.driver.DriverError;

/// The frozen §4.5 cap: an auto-encoded Command above it can never be a
/// legal value, so `Codec(T)` rejects it at comptime.
pub const max_encoded_bytes: usize = core.limits.frozen_max_value_bytes_cap;

// ---------------------------------------------------------------------------
// Auto-codec internals
// ---------------------------------------------------------------------------

fn ceilToByteBits(comptime bits: u16) u16 {
    return ((bits + 7) / 8) * 8;
}

fn unsupportedType(comptime T: type, comptime path: []const u8) noreturn {
    @compileError("slcp auto-codec: `" ++ path ++ "` has type " ++ @typeName(T) ++
        ", which the auto-codec does not cover. Provide your own encode/decode." ++
        "\n  `pub fn encode(cmd: Command, buf: []u8) []u8` + `pub fn decode(bytes: []const u8) ?Command`" ++
        "\n  on the app own the wire layout (design §8.5 \"Codec override\").");
}

/// Compile-time gate: is T allowed in an auto-encoded Command?
/// Every rejection message teaches the rule it enforces.
fn checkEncodable(comptime T: type, comptime path: []const u8) void {
    switch (@typeInfo(T)) {
        .int => {},
        .bool => {},
        .@"enum" => |e| {
            if (e.mode == .nonexhaustive)
                @compileError("slcp auto-codec: `" ++ path ++ "` is a non-exhaustive enum (" ++ @typeName(T) ++
                    ") — `_` admits every tag value, so there is no single canonical spelling; make the enum exhaustive." ++
                    "\n  Strict decode must reject unknown tags (§8.5); with `_` there is nothing to reject.");
        },
        .float => @compileError("slcp auto-codec: `" ++ path ++ "` is a " ++ @typeName(T) ++
            " — floats are NONDETERMINISTIC across nodes (NaN payloads, ±0, platform math differences)." ++
            "\n  Use fixed-point integers (e.g. cents as u64), or provide your own" ++
            "\n  `pub fn encode(cmd: Command, buf: []u8) []u8` + `pub fn decode(bytes: []const u8) ?Command`."),
        .pointer => |p| {
            // A function pointer is not data at all — it falls to the generic
            // "does not cover" rule rather than the variable-length-data rule.
            if (@typeInfo(p.child) == .@"fn") unsupportedType(T, path);
            @compileError("slcp auto-codec: `" ++ path ++ "` is a pointer/slice (" ++ @typeName(T) ++ ")." ++
                "\n  Variable-length data needs an explicit canonical layout: provide your own" ++
                "\n  `pub fn encode` / `pub fn decode` on the app, or use a bounded [N]u8 array.");
        },
        .optional => @compileError("slcp auto-codec: `" ++ path ++ "` is optional (" ++ @typeName(T) ++ ")." ++
            "\n  Optionality has no single canonical encoding; model it explicitly" ++
            "\n  (e.g. a tag enum + zeroed payload) or provide your own encode/decode."),
        .@"union" => @compileError("slcp auto-codec: `" ++ path ++ "` is a union (" ++ @typeName(T) ++
            ") — the v1 auto-codec does not encode unions." ++
            "\n  Workaround: a tag enum + a payload struct with every variant's fields (unused ones zeroed)," ++
            "\n  e.g. `struct { kind: enum(u8) { deposit, withdraw }, cents: u64 }`, or provide your own encode/decode." ++
            "\n  (Tag-prefixed fixed-size union encoding is the first v2 codec target.)"),
        .array => |a| checkEncodable(a.child, path ++ "[i]"),
        .@"struct" => |s| {
            inline for (s.field_names, s.field_types) |fname, FT| checkEncodable(FT, path ++ "." ++ fname);
        },
        else => unsupportedType(T, path),
    }
}

fn encodedSizeOf(comptime T: type) usize {
    return switch (@typeInfo(T)) {
        .int => |i| ceilToByteBits(i.bits) / 8,
        .bool => 1,
        .@"enum" => |e| ceilToByteBits(@typeInfo(e.tag_type).int.bits) / 8,
        .array => |a| a.len * encodedSizeOf(a.child),
        .@"struct" => |s| blk: {
            var sz: usize = 0;
            inline for (s.field_types) |FT| sz += encodedSizeOf(FT);
            break :blk sz;
        },
        else => unreachable, // checkEncodable already rejected it
    };
}

/// Big-endian, sign-bit-biased write of one integer (or enum tag) of `bits`
/// significant bits into ceil(bits/8) bytes. The bias flips the sign bit so
/// the unsigned byte string orders like the signed value.
fn encodeInt(comptime bits: u16, comptime signed: bool, v: anytype, buf: []u8) usize {
    if (bits == 0) return 0;
    const width = comptime ceilToByteBits(bits);
    const U = @Int(.unsigned, width);
    const u: U = if (signed)
        @as(U, @as(@Int(.unsigned, bits), @bitCast(v))) ^ (@as(U, 1) << (bits - 1))
    else
        @as(U, v);
    std.mem.writeInt(U, buf[0 .. width / 8], u, .big);
    return width / 8;
}

fn encodeValue(comptime T: type, v: T, buf: []u8) usize {
    switch (@typeInfo(T)) {
        .int => |i| return encodeInt(i.bits, i.signedness == .signed, v, buf),
        .bool => {
            buf[0] = @intFromBool(v);
            return 1;
        },
        .@"enum" => |e| {
            // The tag keeps its own signedness so a signed-tag enum biases
            // like any signed int (byte order == tag order, negatives decode).
            const ti = @typeInfo(e.tag_type).int;
            return encodeInt(ti.bits, ti.signedness == .signed, @backingInt(v), buf);
        },
        .array => |a| {
            var off: usize = 0;
            for (v) |elem| off += encodeValue(a.child, elem, buf[off..]);
            return off;
        },
        .@"struct" => |s| {
            var off: usize = 0;
            inline for (s.field_names, s.field_types) |fname, FT| off += encodeValue(FT, @field(v, fname), buf[off..]);
            return off;
        },
        else => unreachable,
    }
}

/// Strict inverse of `encodeInt`: null when the bytes are short or carry a
/// set bit above `bits` (the non-canonical spelling of an in-range value).
fn decodeInt(comptime bits: u16, comptime signed: bool, bytes: []const u8, off: *usize) ?@Int(if (signed) .signed else .unsigned, bits) {
    const R = @Int(if (signed) .signed else .unsigned, bits);
    if (bits == 0) return @as(R, 0);
    const width = comptime ceilToByteBits(bits);
    const U = @Int(.unsigned, width);
    if (bytes.len < off.* + width / 8) return null;
    const raw = std.mem.readInt(U, bytes[off.*..][0 .. width / 8], .big);
    off.* += width / 8;
    const N = @Int(.unsigned, bits);
    if (signed) {
        const unbiased = std.math.cast(N, raw ^ (@as(U, 1) << (bits - 1))) orelse return null;
        return @bitCast(unbiased);
    }
    return std.math.cast(R, raw); // null on non-canonical high bits
}

fn decodeValue(comptime T: type, bytes: []const u8, off: *usize) ?T {
    switch (@typeInfo(T)) {
        .int => |i| return decodeInt(i.bits, i.signedness == .signed, bytes, off),
        .bool => {
            if (bytes.len < off.* + 1) return null;
            const b = bytes[off.*];
            off.* += 1;
            return switch (b) { // canonical: only 0 or 1
                0 => false,
                1 => true,
                else => null,
            };
        },
        .@"enum" => |e| {
            const ti = @typeInfo(e.tag_type).int;
            const raw = decodeInt(ti.bits, ti.signedness == .signed, bytes, off) orelse return null;
            return std.enums.fromInt(T, raw); // null unless the tag names a variant
        },
        .array => |a| {
            var out: T = undefined;
            for (&out) |*elem| elem.* = decodeValue(a.child, bytes, off) orelse return null;
            return out;
        },
        .@"struct" => |s| {
            var out: T = undefined;
            inline for (s.field_names, s.field_types) |fname, FT| {
                @field(out, fname) = decodeValue(FT, bytes, off) orelse return null;
            }
            return out;
        },
        else => unreachable,
    }
}

/// The numeric oracle for order-preservation: compares typed values the way
/// the encoding is meant to order them (declaration order, then element
/// order; ints numerically, bool false < true, enums by tag).
fn orderValue(comptime T: type, a: T, b: T) std.math.Order {
    switch (@typeInfo(T)) {
        .int => return std.math.order(a, b),
        .bool => return std.math.order(@intFromBool(a), @intFromBool(b)),
        .@"enum" => return std.math.order(@backingInt(a), @backingInt(b)),
        .array => |arr| {
            for (a, b) |x, y| {
                const o = orderValue(arr.child, x, y);
                if (o != .eq) return o;
            }
            return .eq;
        },
        .@"struct" => |s| {
            inline for (s.field_names, s.field_types) |fname, FT| {
                const o = orderValue(FT, @field(a, fname), @field(b, fname));
                if (o != .eq) return o;
            }
            return .eq;
        },
        else => unreachable,
    }
}

/// The auto-codec for one Command type: fixed size, strict-canonical,
/// order-preserving (`order(a, b) == std.mem.order(u8, encode(a), encode(b))`).
/// Comptime-rejected when `T` contains a disallowed type, encodes to 0 bytes
/// (the engine rejects empty values, §8.4), or exceeds the frozen §4.5 cap.
pub fn Codec(comptime T: type) type {
    comptime checkEncodable(T, @typeName(T));
    const sz = comptime encodedSizeOf(T);
    if (sz == 0)
        @compileError("slcp auto-codec: " ++ @typeName(T) ++ " encodes to 0 bytes; the engine rejects empty values (§8.4) — add a field.");
    if (sz > max_encoded_bytes)
        @compileError(std.fmt.comptimePrint("slcp auto-codec: {s} encodes to {d} bytes, above the frozen {d}-byte value cap (§4.5).", .{ @typeName(T), sz, max_encoded_bytes }) ++
            "\n  Shrink the Command (commands are VALUES the network agrees on, not payloads), or provide your own encode/decode.");
    return struct {
        pub const Value = T;
        /// false: this is the derived codec, so byte order == numeric order.
        pub const is_custom = false;
        /// Every encoding is exactly this many bytes.
        pub const size: usize = sz;

        /// Writes the canonical encoding into `buf` (asserts `buf.len >= size`)
        /// and returns `buf[0..size]`.
        pub fn encode(v: T, buf: []u8) []u8 {
            std.debug.assert(buf.len >= size);
            const n = encodeValue(T, v, buf);
            std.debug.assert(n == size);
            return buf[0..size];
        }

        /// Strict-canonical decode: null unless `bytes.len == size` and every
        /// field is the one canonical spelling of an in-range value.
        pub fn decode(bytes: []const u8) ?T {
            if (bytes.len != size) return null;
            var off: usize = 0;
            const v = decodeValue(T, bytes, &off) orelse return null;
            std.debug.assert(off == size);
            return v;
        }

        /// Numeric order of two values; equals the byte order of their encodings.
        pub fn order(a: T, b: T) std.math.Order {
            return orderValue(T, a, b);
        }
    };
}

// ---------------------------------------------------------------------------
// AppNode(App): the comptime contract
// ---------------------------------------------------------------------------

fn contractError(comptime App: type, comptime msg: []const u8) noreturn {
    @compileError("slcp.AppNode(" ++ @typeName(App) ++ "): " ++ msg);
}

fn hasCustomCodec(comptime App: type) bool {
    return @hasDecl(App, "encode") or @hasDecl(App, "decode");
}

/// The comptime contract of §8.5. Checked in this order so a single
/// violation produces a single teaching message (each one is pinned by
/// tests/appnode_errors/). Every message's first line ends in its needle.
fn validateAppContract(comptime App: type) void {
    if (!@hasDecl(App, "State"))
        contractError(App, "missing `pub const State` — the replicated state type." ++
            "\n  Every node holds one State; it changes ONLY via apply().");
    if (!@hasDecl(App, "Command"))
        contractError(App, "missing `pub const Command` — the value type the network agrees on." ++
            "\n  Agree on VALUES (\"count becomes 3\"), never on OPS (\"add 1\"): ops break under" ++
            "\n  highest-wins combine and under replay (design §11.2).");
    const State = App.State;
    const Command = App.Command;

    if (!@hasDecl(App, "validate"))
        contractError(App, "missing `pub fn validate(state: State, cmd: Command) slcp.Validity`." ++
            "\n  Return .valid / .invalid, or .maybe_valid when this node cannot judge yet" ++
            "\n  (e.g. it is behind) — NOT .invalid. Must be pure and deterministic.");
    if (@TypeOf(App.validate) != fn (State, Command) Validity)
        contractError(App, "validate has the wrong signature." ++
            "\n  want: fn (State, Command) slcp.Validity" ++
            "\n  got:  " ++ @typeName(@TypeOf(App.validate)));

    if (!@hasDecl(App, "apply"))
        contractError(App, "missing `pub fn apply(state: State, cmd: Command) State`." ++
            "\n  apply is how an agreed command updates your replicated state." ++
            "\n  It runs on the engine thread; keep it pure — no I/O, no clock." ++
            "\n  Large-state alternative shape: `pub fn apply(state: *State, cmd: Command) void`.");
    if (@TypeOf(App.apply) != fn (State, Command) State and
        @TypeOf(App.apply) != fn (*State, Command) void)
        contractError(App, "apply has the wrong signature." ++
            "\n  want: fn (State, Command) State   (or fn (*State, Command) void)" ++
            "\n  got:  " ++ @typeName(@TypeOf(App.apply)));

    if (@hasDecl(App, "combine")) {
        if (@TypeOf(App.combine) != fn (State, []const Command) Command)
            contractError(App, "combine has the wrong signature." ++
                "\n  want: fn (State, []const Command) Command" ++
                "\n  got:  " ++ @typeName(@TypeOf(App.combine)) ++
                "\n  combine must be deterministic and total; its result must self-validate .valid.");
    }
    if (@hasDecl(App, "initialState")) {
        if (@TypeOf(App.initialState) != fn () State)
            contractError(App, "initialState has the wrong signature." ++
                "\n  want: fn () State" ++
                "\n  got:  " ++ @typeName(@TypeOf(App.initialState)));
    }

    if (hasCustomCodec(App)) {
        if (!@hasDecl(App, "encode") or !@hasDecl(App, "decode"))
            contractError(App, "a custom codec needs BOTH `pub fn encode(cmd: Command, buf: []u8) []u8` and `pub fn decode(bytes: []const u8) ?Command`." ++
                "\n  A lone half cannot round-trip. With a custom codec, strict canonicality (one" ++
                "\n  spelling per command) and numeric order are YOUR job — supply `combine` too.");
        if (@TypeOf(App.encode) != fn (Command, []u8) []u8)
            contractError(App, "encode has the wrong signature." ++
                "\n  want: fn (Command, []u8) []u8   (write into buf, return the written prefix)" ++
                "\n  got:  " ++ @typeName(@TypeOf(App.encode)));
        if (@TypeOf(App.decode) != fn ([]const u8) ?Command)
            contractError(App, "decode has the wrong signature." ++
                "\n  want: fn ([]const u8) ?Command   (null = not a canonical command)" ++
                "\n  got:  " ++ @typeName(@TypeOf(App.decode)));
    }

    // State must be constructible: initialState(), or every field defaulted.
    if (!@hasDecl(App, "initialState")) {
        const si = @typeInfo(State);
        if (si == .@"struct") {
            inline for (si.@"struct".field_names, si.@"struct".field_attrs) |fname, attrs| {
                if (attrs.default_value_ptr == null)
                    contractError(App, "State field `" ++ fname ++ "` has no default value." ++
                        "\n  Give every State field a default, or provide `pub fn initialState() State`.");
            }
        }
    }

    // The auto-codec's own rules (floats, pointers, …) fire here, after the
    // shape checks, so a bad Command type is reported once and in context.
    if (!hasCustomCodec(App)) _ = Codec(Command);
}

/// Wraps an app-supplied custom codec (`pub fn encode` + `pub fn decode`).
/// This is the escape hatch every auto-codec rejection points at. Strict
/// canonicality (one spelling per command) is the app's job here.
fn CustomCodec(comptime App: type) type {
    return struct {
        pub const Value = App.Command;
        /// true: byte order carries no numeric meaning; the app should
        /// supply `combine`.
        pub const is_custom = true;

        pub fn encode(v: App.Command, buf: []u8) []u8 {
            return App.encode(v, buf);
        }
        pub fn decode(bytes: []const u8) ?App.Command {
            return App.decode(bytes);
        }
    };
}

/// The typed node (§8.5, §11.2). This stage returns the contract-checked
/// type with its `State`, `Command`, `codec` and `Options`; `create` /
/// `propose` / `waitApplied` and the Driver compilation land in S3.
pub fn AppNode(comptime App: type) type {
    comptime validateAppContract(App);
    return struct {
        pub const State = App.State;
        pub const Command = App.Command;
        /// `Codec(Command)` (auto, order-preserving) or the app's own
        /// encode/decode pair (custom, `is_custom = true`).
        pub const codec = if (hasCustomCodec(App)) CustomCodec(App) else Codec(App.Command);
        /// true when `apply` uses the large-state shape `fn (*State, Command) void`.
        pub const apply_in_place = @TypeOf(App.apply) == fn (*State, Command) void;
        /// S1b placeholder: the bytes-level option set. S3 replaces this with
        /// the R8 mirror (every `node.Options` field except `driver` and
        /// `delivery`, enforced by a comptime parity check).
        pub const Options = node.Options;
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const Color = enum(u8) { red, green, blue };

/// Kitchen-sink Command: every allowed leaf kind, a sub-byte int, a signed
/// wide int, a fixed array and a nested struct. Encoded size 22.
const Kitchen = struct {
    a: i8,
    b: u3,
    c: i64,
    d: bool,
    e: Color,
    f: [3]u16,
    g: struct { h: u16, i: i16 },
};
const KitchenCodec = Codec(Kitchen);

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

const kitchen_extremes = [_]Kitchen{
    .{ .a = -128, .b = 0, .c = std.math.minInt(i64), .d = false, .e = .red, .f = .{ 0, 0, 0 }, .g = .{ .h = 0, .i = -32768 } },
    .{ .a = 127, .b = 7, .c = std.math.maxInt(i64), .d = true, .e = .blue, .f = .{ 65535, 65535, 65535 }, .g = .{ .h = 65535, .i = 32767 } },
    .{ .a = 0, .b = 0, .c = 0, .d = false, .e = .red, .f = .{ 0, 0, 0 }, .g = .{ .h = 0, .i = 0 } },
    .{ .a = -1, .b = 7, .c = -1, .d = true, .e = .green, .f = .{ 0, 65535, 0 }, .g = .{ .h = 1, .i = -1 } },
    .{ .a = 1, .b = 1, .c = 1, .d = false, .e = .green, .f = .{ 1, 0, 65535 }, .g = .{ .h = 0, .i = 1 } },
    .{ .a = -128, .b = 7, .c = std.math.maxInt(i64), .d = true, .e = .blue, .f = .{ 65535, 0, 0 }, .g = .{ .h = 65535, .i = -32768 } },
};

// Non-vacuity: dropping the sign-bit bias in `encodeInt` (or flipping the
// byte order to little-endian) changes the i8 / u64 golden bytes.
test "codec golden bytes: u64 big-endian, i8 sign-bit-biased" {
    const C = Codec(struct { next: u64 });
    try std.testing.expectEqual(@as(usize, 8), C.size);
    var buf: [8]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 1 }, C.encode(.{ .next = 1 }, &buf));

    const I = Codec(struct { v: i8 });
    var b1: [1]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &[_]u8{0x00}, I.encode(.{ .v = -128 }, &b1));
    try std.testing.expectEqualSlices(u8, &[_]u8{0x80}, I.encode(.{ .v = 0 }, &b1));
    try std.testing.expectEqualSlices(u8, &[_]u8{0xFF}, I.encode(.{ .v = 127 }, &b1));
    try std.testing.expectEqual(@as(usize, 22), KitchenCodec.size);
}

// Non-vacuity: removing the bias (signed ints encode as two's complement)
// makes a (-1, 1) pair order .gt in bytes while the oracle says .lt; the
// observed-set assertion goes red if the PRNG pairs never disagree.
test "codec order-preservation: byte order == numeric order over 10000 PRNG pairs + extremes" {
    var prng = std.Random.DefaultPrng.init(0x0c0d_ec0d_e0c0_de01);
    const rand = prng.random();
    var seen = [_]bool{ false, false, false }; // lt, eq, gt
    var ba: [KitchenCodec.size]u8 = undefined;
    var bb: [KitchenCodec.size]u8 = undefined;

    for (0..10_000) |_| {
        const a = randomValue(Kitchen, rand);
        // Half the pairs share a prefix so the deeper fields decide the order.
        var b = randomValue(Kitchen, rand);
        if (rand.boolean()) {
            b.a = a.a;
            b.b = a.b;
            b.c = a.c;
        }
        const want = KitchenCodec.order(a, b);
        const got = std.mem.order(u8, KitchenCodec.encode(a, &ba), KitchenCodec.encode(b, &bb));
        try std.testing.expectEqual(want, got);
        seen[@backingInt(want)] = true;
    }
    for (kitchen_extremes) |a| for (kitchen_extremes) |b| {
        const want = KitchenCodec.order(a, b);
        const got = std.mem.order(u8, KitchenCodec.encode(a, &ba), KitchenCodec.encode(b, &bb));
        try std.testing.expectEqual(want, got);
        seen[@backingInt(want)] = true;
    };
    try std.testing.expect(seen[@backingInt(std.math.Order.lt)]);
    try std.testing.expect(seen[@backingInt(std.math.Order.eq)]);
    try std.testing.expect(seen[@backingInt(std.math.Order.gt)]);
}

// Non-vacuity: an off-by-one in `decodeInt`'s unbias (xor the wrong bit)
// breaks decode(encode(a)) == a for negative values; a decoder that
// accepted non-canonical bytes would break encode(decode(b)) == b.
test "codec round-trip: decode(encode(a)) == a and encode(decode(b)) == b" {
    var prng = std.Random.DefaultPrng.init(0x0c0d_ec0d_e0c0_de02);
    const rand = prng.random();
    var buf: [KitchenCodec.size]u8 = undefined;
    var buf2: [KitchenCodec.size]u8 = undefined;
    var decoded_random: usize = 0;

    for (0..2000) |_| {
        const a = randomValue(Kitchen, rand);
        const bytes = KitchenCodec.encode(a, &buf);
        const back = KitchenCodec.decode(bytes) orelse return error.CanonicalDidNotDecode;
        try std.testing.expectEqualDeep(a, back);

        // Arbitrary exact-length bytes: whatever decodes must re-encode identically.
        var raw: [KitchenCodec.size]u8 = undefined;
        rand.bytes(&raw);
        // Force the sub-byte/bool/enum positions canonical often enough to decode.
        if (rand.boolean()) {
            raw[1] &= 0x07;
            raw[10] &= 0x01;
            raw[11] %= 3;
        }
        if (KitchenCodec.decode(&raw)) |v| {
            decoded_random += 1;
            try std.testing.expectEqualSlices(u8, &raw, KitchenCodec.encode(v, &buf2));
        }
    }
    for (kitchen_extremes) |a| {
        try std.testing.expectEqualDeep(a, KitchenCodec.decode(KitchenCodec.encode(a, &buf)).?);
    }
    try std.testing.expect(decoded_random > 0);
}

// Non-vacuity: dropping the `bytes.len != size` check accepts the ±1
// lengths; dropping `std.math.cast` accepts u3 byte 0x08; a bool decoded as
// `!= 0` accepts 2; `@enumFromInt` instead of `enums.fromInt` accepts 200.
test "codec strict rejections, each paired with a one-byte-fixed sibling that decodes" {
    const base_v = Kitchen{ .a = 3, .b = 5, .c = -9, .d = true, .e = .green, .f = .{ 1, 2, 3 }, .g = .{ .h = 4, .i = -5 } };
    var base: [KitchenCodec.size]u8 = undefined;
    _ = KitchenCodec.encode(base_v, &base);
    try std.testing.expect(KitchenCodec.decode(&base) != null);

    // length ±1
    var long: [KitchenCodec.size + 1]u8 = undefined;
    @memcpy(long[0..KitchenCodec.size], &base);
    long[KitchenCodec.size] = 0;
    try std.testing.expect(KitchenCodec.decode(&long) == null);
    try std.testing.expect(KitchenCodec.decode(base[0 .. KitchenCodec.size - 1]) == null);
    try std.testing.expect(KitchenCodec.decode(long[0..KitchenCodec.size]) != null);

    // u3 at offset 1: 0x08 has a non-canonical high bit; 0x07 is the max value.
    var m = base;
    m[1] = 0x08;
    try std.testing.expect(KitchenCodec.decode(&m) == null);
    m[1] = 0x07;
    try std.testing.expectEqual(@as(u3, 7), KitchenCodec.decode(&m).?.b);

    // bool at offset 10: 2 is not a spelling of true; 1 is.
    m = base;
    m[10] = 2;
    try std.testing.expect(KitchenCodec.decode(&m) == null);
    m[10] = 1;
    try std.testing.expectEqual(true, KitchenCodec.decode(&m).?.d);

    // enum tag at offset 11: 200 names no variant; 2 is .blue.
    m = base;
    m[11] = 200;
    try std.testing.expect(KitchenCodec.decode(&m) == null);
    m[11] = 2;
    try std.testing.expectEqual(Color.blue, KitchenCodec.decode(&m).?.e);
}

// Non-vacuity: encoding the tag as its raw unsigned bits (instead of with the
// tag type's own signedness) makes the negative tag decode to null and orders
// its byte .gt while the oracle says .lt.
test "codec signed-tag enum: negative tags round-trip and order like their backing int" {
    const S = enum(i8) { neg = -5, zero = 0, pos = 5 };
    const C = Codec(struct { s: S });
    var b1: [1]u8 = undefined;
    var b2: [1]u8 = undefined;
    const all = [_]S{ .neg, .zero, .pos };
    for (all) |x| {
        try std.testing.expectEqual(x, C.decode(C.encode(.{ .s = x }, &b1)).?.s);
        for (all) |y| {
            const want = C.order(.{ .s = x }, .{ .s = y });
            const got = std.mem.order(u8, C.encode(.{ .s = x }, &b1), C.encode(.{ .s = y }, &b2));
            try std.testing.expectEqual(want, got);
        }
    }
    // Biased spelling of -5 is 0x7B; 0x81 unbiases to 1, which names no variant.
    try std.testing.expectEqual(S.neg, C.decode(&[_]u8{0x7B}).?.s);
    try std.testing.expect(C.decode(&[_]u8{0x81}) == null);
}

// -- contract acceptance ------------------------------------------------------

const Counter = struct {
    pub const State = struct { count: u64 = 0 };
    pub const Command = struct { next: u64 };
    pub fn validate(state: State, cmd: Command) Validity {
        if (cmd.next == state.count + 1) return .valid;
        if (cmd.next > state.count + 1) return .maybe_valid;
        return .invalid;
    }
    pub fn apply(state: State, cmd: Command) State {
        _ = state;
        return .{ .count = cmd.next };
    }
};

const PtrApply = struct {
    pub const State = struct { total: u64 = 0, hist: [4]u8 = @splat(0) };
    pub const Command = struct { add: u8 };
    pub fn validate(state: State, cmd: Command) Validity {
        _ = state;
        return if (cmd.add > 0) .valid else .invalid;
    }
    pub fn apply(state: *State, cmd: Command) void {
        state.total += cmd.add;
    }
};

const Explicit = struct {
    pub const State = struct { owner: [8]u8, n: u32 }; // no defaults: initialState() supplies them
    pub const Command = struct { n: u32 };
    pub fn initialState() State {
        return .{ .owner = @splat('x'), .n = 0 };
    }
    pub fn validate(state: State, cmd: Command) Validity {
        return if (cmd.n > state.n) .valid else .invalid;
    }
    pub fn apply(state: State, cmd: Command) State {
        return .{ .owner = state.owner, .n = cmd.n };
    }
};

const Memo = struct {
    pub const State = struct { len: u8 = 0, text: [16]u8 = @splat(' ') };
    pub const Command = struct { len: u8, text: [16]u8 };
    pub fn validate(state: State, cmd: Command) Validity {
        _ = state;
        return if (cmd.len >= 1 and cmd.len <= 16) .valid else .invalid;
    }
    pub fn apply(state: State, cmd: Command) State {
        _ = state;
        return .{ .len = cmd.len, .text = cmd.text };
    }
    pub fn encode(cmd: Command, buf: []u8) []u8 {
        @memcpy(buf[0..cmd.len], cmd.text[0..cmd.len]);
        return buf[0..cmd.len];
    }
    pub fn decode(bytes: []const u8) ?Command {
        if (bytes.len < 1 or bytes.len > 16) return null;
        var cmd = Command{ .len = @intCast(bytes.len), .text = @splat(' ') };
        @memcpy(cmd.text[0..bytes.len], bytes);
        return cmd;
    }
    pub fn combine(state: State, cmds: []const Command) Command {
        _ = state;
        var best = cmds[0];
        for (cmds[1..]) |c| {
            if (c.len > best.len) best = c;
        }
        return best;
    }
};

// Non-vacuity: removing the `fn (*State, Command) void` arm of the apply
// check turns `AppNode(PtrApply)` into a compile error; removing the
// `initialState` exemption from the defaultless-field check breaks
// `AppNode(Explicit)`; routing custom-codec apps through `Codec(Command)`
// would still compile Memo (fixed-size Command) but `is_custom` flips.
test "contract acceptance: Counter, pointer-apply, initialState + defaultless State, custom codec + combine" {
    const CounterNode = AppNode(Counter);
    try std.testing.expectEqual(Counter.State, CounterNode.State);
    try std.testing.expectEqual(Counter.Command, CounterNode.Command);
    try std.testing.expectEqual(@as(usize, 8), CounterNode.codec.size);
    try std.testing.expect(!CounterNode.codec.is_custom);
    try std.testing.expect(!CounterNode.apply_in_place);
    try std.testing.expect(@hasField(CounterNode.Options, "network"));

    const PtrNode = AppNode(PtrApply);
    try std.testing.expect(PtrNode.apply_in_place);
    try std.testing.expectEqual(@as(usize, 1), PtrNode.codec.size);

    const ExplicitNode = AppNode(Explicit);
    try std.testing.expectEqual(@as(u32, 0), Explicit.initialState().n);
    try std.testing.expectEqual(@as(usize, 4), ExplicitNode.codec.size);

    const MemoNode = AppNode(Memo);
    try std.testing.expect(MemoNode.codec.is_custom);
    var buf: [16]u8 = undefined;
    const wire = MemoNode.codec.encode(Memo.decode("hello").?, &buf);
    try std.testing.expectEqualSlices(u8, "hello", wire);
    try std.testing.expectEqual(@as(u8, 5), MemoNode.codec.decode(wire).?.len);
    try std.testing.expect(MemoNode.codec.decode("") == null);
}
