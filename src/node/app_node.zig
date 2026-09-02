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
//! correct over auto-encoded commands. Allowed: ints (up to 65528 bits,
//! rounded up to whole bytes), bool, exhaustive enums, fixed `[N]T` arrays,
//! nested structs. Rejected at comptime with the rule spelled out: floats,
//! pointers/slices, optionals, unions, non-exhaustive enums, wider ints,
//! anything else.
//! Decode is strict-canonical (exact length, no non-canonical high bits,
//! bool ∈ {0,1}, enum tag must name a variant) so the codec cannot become a
//! value-malleability source.
//!
//! **The node** (`AppNode(App)`, M6 S3): `create` forwards every bytes-level
//! option except `driver` / `delivery` (the R8 mirror `Options`), compiles
//! `validate` / `combine` into the driver, and installs a `DeliveryHook` so
//! `apply` runs on the engine thread at the externalize effect — the same
//! thread that runs `validate`, so the typed state needs no lock. The user
//! thread sees value copies through `waitApplied`, which never hangs: null on
//! timeout / deinit, `error.NodeHalted` once the node latched inert.

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

/// The widest integer the auto-codec encodes: 65535 is a legal Zig width,
/// but its whole-byte rounding (65536) is not representable by `@Int`'s
/// `u16` bit count. `checkEncodable` rejects wider ints with a teaching
/// error instead of letting `ceilToByteBits` overflow.
const max_int_bits: u16 = 65528;

fn ceilToByteBits(comptime bits: u16) u16 {
    comptime std.debug.assert(bits <= max_int_bits);
    return ((bits + 7) / 8) * 8;
}

fn checkIntWidth(comptime T: type, comptime bits: u16, comptime path: []const u8) void {
    if (bits > max_int_bits)
        @compileError("slcp auto-codec: `" ++ path ++ "` (" ++ @typeName(T) ++ ") is wider than 65528 bits, the widest whole-byte integer the auto-codec can encode." ++
            "\n  Split the field into narrower ints, or provide your own encode/decode." ++
            "\n  (A single field this wide is 8 KiB of value bytes; commands are VALUES the network agrees on, not payloads.)");
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
        .int => |i| checkIntWidth(T, i.bits, path),
        .bool => {},
        .@"enum" => |e| {
            checkIntWidth(e.tag_type, @typeInfo(e.tag_type).int.bits, path);
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
            inline for (s.field_names, s.field_types, s.field_attrs) |fname, FT, attrs| {
                // A comptime field has an ordinary type, so the leaf rules
                // would accept it — but decode cannot store a wire value
                // into it (the compiler would object deep inside decodeValue).
                if (attrs.@"comptime")
                    @compileError("slcp auto-codec: `" ++ path ++ "." ++ fname ++ "` is a comptime field — it has one fixed value and no wire representation." ++
                        "\n  Drop it, or make it a runtime field (decode must be able to store the wire value into it).");
                checkEncodable(FT, path ++ "." ++ fname);
            }
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
    if (@hasDecl(App, "initialSlot")) {
        if (@TypeOf(App.initialSlot) != fn () u64)
            contractError(App, "initialSlot has the wrong signature." ++
                "\n  want: fn () u64   (the slot your persisted initialState() already includes; 0 = none)" ++
                "\n  got:  " ++ @typeName(@TypeOf(App.initialSlot)));
    }

    if (hasCustomCodec(App)) {
        if (!@hasDecl(App, "encode") or !@hasDecl(App, "decode"))
            contractError(App, "a custom codec needs BOTH `pub fn encode(cmd: Command, buf: []u8) []u8` and `pub fn decode(bytes: []const u8) ?Command`." ++
                "\n  A lone half cannot round-trip. With a custom codec, strict canonicality (one" ++
                "\n  spelling per command) and numeric order are YOUR job — supply `combine` too.");
        if (@TypeOf(App.encode) != fn (Command, []u8) []u8)
            contractError(App, "encode has the wrong signature." ++
                "\n  want: fn (Command, []u8) []u8   (write into buf, return the encoded bytes — normally buf[0..n])" ++
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

// ---------------------------------------------------------------------------
// Options mirror (plan R8)
// ---------------------------------------------------------------------------

/// The two `node.Options` fields `AppNode` owns itself: it compiles the
/// app into the driver and installs its own delivery hook.
const owned_option_fields = [_][]const u8{ "driver", "delivery" };

fn isOwnedOptionField(comptime name: []const u8) bool {
    inline for (owned_option_fields) |o| if (std.mem.eql(u8, name, o)) return true;
    return false;
}

/// The field lists of `AppNode.Options`: every `node.Options` field except
/// `driver` and `delivery`, with the SAME types and defaults — taken from
/// `node.Options` itself, so a field added to the bytes-level node appears
/// in the mirror automatically. The `@Struct` call itself lives in
/// `AppNode(App).Options` (not here) so the reified type's `@typeName` is
/// the public path `…AppNode(App).Options…`, not a private helper's name:
/// the Stable API snapshot pins that spelling on the `create` line.
/// `checkOptionsParity` is the comptime guard that the mirror really is
/// field-for-field the bytes-level set minus the two.
const MirrorFields = struct {
    names: []const [:0]const u8,
    types: []const type,
    attrs: []const std.builtin.Type.Struct.FieldAttributes,
};

fn mirrorOptionFields() MirrorFields {
    const info = @typeInfo(node.Options).@"struct";
    comptime var names: []const [:0]const u8 = &.{};
    comptime var types: []const type = &.{};
    comptime var attrs: []const std.builtin.Type.Struct.FieldAttributes = &.{};
    inline for (info.field_names, info.field_types, info.field_attrs) |name, FT, attr| {
        if (isOwnedOptionField(name)) continue;
        names = names ++ [_][:0]const u8{name};
        types = types ++ [_]type{FT};
        attrs = attrs ++ [_]std.builtin.Type.Struct.FieldAttributes{attr};
    }
    return .{ .names = names, .types = types, .attrs = attrs };
}

/// Comptime parity: (a) every non-owned `node.Options` field exists in the
/// mirror with an identical type and an identical default (or identically
/// none); (b) the mirror has no other fields; (c) the two owned fields are
/// really absent. A drift in either direction is a compile error naming
/// the field.
fn checkOptionsParity(comptime Mirror: type) void {
    const src = @typeInfo(node.Options).@"struct";
    const dst = @typeInfo(Mirror).@"struct";
    comptime var expected: usize = 0;
    inline for (src.field_names, src.field_types, src.field_attrs) |name, FT, attr| {
        if (isOwnedOptionField(name)) {
            if (@hasField(Mirror, name))
                @compileError("AppNode.Options must not carry `" ++ name ++ "` (AppNode supplies it).");
            continue;
        }
        expected += 1;
        if (!@hasField(Mirror, name))
            @compileError("AppNode.Options is missing node.Options field `" ++ name ++ "`.");
        const idx = std.meta.fieldIndex(Mirror, name).?;
        if (dst.field_types[idx] != FT)
            @compileError("AppNode.Options field `" ++ name ++ "` has type " ++ @typeName(dst.field_types[idx]) ++ ", node.Options has " ++ @typeName(FT) ++ ".");
        const have_default = dst.field_attrs[idx].default_value_ptr != null;
        const want_default = attr.default_value_ptr != null;
        if (have_default != want_default)
            @compileError("AppNode.Options field `" ++ name ++ "` default presence differs from node.Options.");
        if (want_default) {
            const a = attr.defaultValue(FT).?;
            const b = dst.field_attrs[idx].defaultValue(FT).?;
            if (!std.meta.eql(a, b))
                @compileError("AppNode.Options field `" ++ name ++ "` default differs from node.Options.");
        }
    }
    if (dst.field_names.len != expected)
        @compileError("AppNode.Options carries a field node.Options does not have.");
}

const create_log = std.log.scoped(.slcp_create);
const log = std.log.scoped(.slcp_app_node);

/// `AppNode.create`'s failure reporter: same contract as the Node's — the
/// paragraph goes into `diagnostic` when given, else to the create log at
/// err level. Generic over the error so each `AppNode(App).CreateError`
/// member coerces at the `return`.
fn fail(diag: ?*node.Diagnostic, err: anytype, comptime fmt: []const u8, args: anytype) @TypeOf(err) {
    var local: node.Diagnostic = .{};
    const d = diag orelse &local;
    d.set(fmt, args);
    if (diag == null) create_log.err("{s}", .{d.message()});
    return err;
}

/// §8.5 delta-app recipe: can a `State` persisted at slot `s0` be caught up
/// from the retained journal tail? A snapshot at 0 claims nothing.
fn initialSlotWithinTail(s0: u64, tail: ?node.Node.JournalTail) bool {
    if (s0 == 0) return true;
    const t = tail orelse return false;
    return t.first <= s0 + 1 and s0 <= t.last;
}

/// The teaching text for a journaled value the current `Command` cannot
/// decode (design §8.5: command evolution is consensus surface).
const undecodable_fmt = "slot {d}: journaled value ({d} bytes) does not decode as {s} — the Command type changed since this data_dir was written. Restore the old Command definition, or start a fresh data_dir under a NEW `network` passphrase (command evolution is consensus surface, §8.5).";

/// The teaching text for a `combine` whose result does not self-validate
/// (§8.5: the composite must be `.valid`, or `.maybe_valid` when this node is
/// behind); the node goes inert with DriverFault rather than balloting a
/// value every peer rejects.
const bad_composite_fmt = "{s}.combine returned a Command that its own validate judges .invalid (slot {d}) — the composite must self-validate (§8.5); the node goes inert (DriverFault) instead of balloting a value every peer would reject.";

/// The typed node (§8.5, §11.2): a comptime adapter that compiles `App` into
/// the frozen §8.2 `Driver` and a §8.5 delivery hook over the bytes-level
/// `node.Node`.
///
/// Threading: `validate` (driver) and `apply` (hook) both run on the engine
/// thread and read/write the one `state` — no lock, no tearing. The user
/// thread only ever sees value copies via `waitApplied`.
///
/// Restart (v1 limitation, plan R17): `State` is NOT persisted. After
/// `create`, `state` = `initialState()` + `apply` over the replayed journal
/// tail (compaction-bounded: the last ≥16 slots), so commands must be full
/// VALUES ("count becomes 3"), never deltas. An app with delta semantics
/// persists State itself, keyed by the slot it was taken at (every
/// `waitApplied` item carries one), and declares BOTH `initialState()` (the
/// snapshot) and `pub fn initialSlot() u64` (that slot): `create` seeds its
/// dedup floor from `initialSlot()` before the tail replays, so journaled
/// slots at or below it are skipped, not re-applied (S8 D2). A snapshot the
/// retained tail cannot catch up (older than its first slot, ahead of its
/// last, or without a journal) is `InitialSlotOutsideJournal`, so persist at
/// least every 16 applied slots. Either way the first proposal after a
/// restart is usually STALE (computed from `initialState()`): the network
/// rejects it and the §0 loop catches up from the applied stream.
pub fn AppNode(comptime App: type) type {
    comptime validateAppContract(App);
    return struct {
        const Self = @This();

        pub const State = App.State;
        pub const Command = App.Command;
        /// `Codec(Command)` (auto, order-preserving) or the app's own
        /// encode/decode pair (custom, `is_custom = true`).
        pub const codec = if (hasCustomCodec(App)) CustomCodec(App) else Codec(App.Command);
        /// true when `apply` uses the large-state shape `fn (*State, Command) void`.
        pub const apply_in_place = @TypeOf(App.apply) == fn (*State, Command) void;
        /// Every `node.Options` field except `driver` and `delivery`
        /// (same types, same defaults; comptime parity-checked). Reified
        /// here so its `@typeName` is this public path (see
        /// `mirrorOptionFields`).
        pub const Options = blk: {
            const f = mirrorOptionFields();
            break :blk @Struct(.auto, null, f.names, f.types, f.attrs);
        };
        comptime {
            checkOptionsParity(Options);
        }
        pub const WaitOptions = node.Node.WaitOptions;
        /// One applied slot: the value copy of `State` taken on the engine
        /// thread right after `apply`.
        pub const Applied = struct { slot: u64, state: State };
        pub const CreateError = error{ CommandExceedsMaxValueBytes, InitialSlotOutsideJournal, UndecodableExternalizedValue } || node.CreateError;
        pub const ProposeError = node.ProposeError;
        pub const WaitError = error{NodeHalted};

        gpa: std.mem.Allocator,
        io: std.Io,
        /// The bytes-level node; null only for a detached (test) instance.
        n: ?*node.Node = null,
        /// Engine-thread-only (and the creating thread during the journal
        /// replay): the replicated state.
        state: State,
        /// Engine-thread-only: highest slot applied. A slot at or below it
        /// is a re-delivery (journal overlap) and is a no-op.
        applied_hwm: u64 = 0,
        max_value_bytes: u32,
        /// Set once `create` has returned; the hook logs a decode failure
        /// loudly only then (inside `create` it becomes the diagnostic).
        created: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        /// Recorded by the hook for `create`'s codec-mismatch diagnostic.
        undecodable: ?struct { slot: u64, len: usize } = null,

        // waitApplied queue (same shape as Node's externalized queue).
        mu: std.Io.Mutex = .init,
        cond: std.Io.Condition = .init,
        queue: std.ArrayList(Applied) = .empty,
        head: usize = 0,
        closed: bool = false,
        halt_err: ?anyerror = null,
        /// Threads currently inside `waitApplied` (under `mu`). `deinit`
        /// wakes them and then waits on `drained` for this to reach zero
        /// BEFORE freeing, so a woken waiter never re-locks a freed `mu`.
        waiters: usize = 0,
        drained: std.Io.Condition = .init,

        fn initialState() State {
            if (@hasDecl(App, "initialState")) return App.initialState();
            return State{};
        }

        /// The slot `initialState()` already includes (§8.5 delta-app
        /// recipe); 0 when the app declares no `initialSlot()`.
        fn initialSlot() u64 {
            if (@hasDecl(App, "initialSlot")) return App.initialSlot();
            return 0;
        }

        /// Allocate the adapter without a Node (the driver / hook can be
        /// exercised directly). `deinit` handles both shapes.
        fn createDetached(gpa: std.mem.Allocator, io: std.Io, max_value_bytes: u32) std.mem.Allocator.Error!*Self {
            const self = try gpa.create(Self);
            // The dedup floor starts at the snapshot's slot, BEFORE any
            // journal tail is replayed through the hook.
            self.* = .{ .gpa = gpa, .io = io, .state = initialState(), .applied_hwm = initialSlot(), .max_value_bytes = max_value_bytes };
            return self;
        }

        /// Start the typed node: forwards `opts` to `node.Node.create` with
        /// the compiled driver and the delivery hook, replaying the journal
        /// tail through `apply` before returning. `*Self` is the driver and
        /// hook ctx (stable address). Adds two members to the bytes-level
        /// `CreateError`: an auto-encoded Command larger than
        /// `max_value_bytes`, and a journaled value the Command cannot decode;
        /// a third for a persisted `State` whose `initialSlot()` the retained
        /// journal tail cannot catch up.
        pub fn create(gpa: std.mem.Allocator, io: std.Io, opts: Options) CreateError!*Self {
            // Same contract as Node.create: a reused Diagnostic never keeps
            // a previous failure's text, and OutOfMemory gets a message too
            // (the adapter allocation fails before Node.create runs).
            if (opts.diagnostic) |d| d.len = 0;
            return createChecked(gpa, io, opts) catch |e| switch (e) {
                error.OutOfMemory => fail(opts.diagnostic, error.OutOfMemory, "out of memory while creating the node; nothing was started — free memory or raise the process limit and try again.", .{}),
                else => e,
            };
        }

        fn createChecked(gpa: std.mem.Allocator, io: std.Io, opts: Options) CreateError!*Self {
            const diag = opts.diagnostic;
            if (comptime !codec.is_custom) {
                // Only once the range itself is sane: an out-of-range value
                // is the Node's MaxValueBytesOutOfRange, not ours.
                if (opts.max_value_bytes >= 1 and opts.max_value_bytes <= 65536 and codec.size > opts.max_value_bytes) {
                    return fail(diag, error.CommandExceedsMaxValueBytes, "Command encodes to {d} bytes but max_value_bytes is {d}; raise max_value_bytes (<= 65536) or shrink Command.", .{ codec.size, opts.max_value_bytes });
                }
            }

            const self = try createDetached(gpa, io, opts.max_value_bytes);
            errdefer {
                self.queue.deinit(gpa);
                gpa.destroy(self);
            }

            var nopts: node.Options = .{
                .network = opts.network,
                .quorum = opts.quorum,
                .listen_port = opts.listen_port,
                .data_dir = opts.data_dir,
                .driver = self.driver(),
                .delivery = self.hook(),
            };
            inline for (@typeInfo(Options).@"struct".field_names) |name| {
                @field(nopts, name) = @field(opts, name);
            }

            const n = node.Node.create(gpa, io, nopts) catch |e| {
                if (self.undecodable) |u| {
                    // The hook refused a journaled value during the tail
                    // replay: report OUR member with the teaching text
                    // (the Node's generic "hook refused" paragraph is
                    // superseded).
                    return fail(diag, error.UndecodableExternalizedValue, undecodable_fmt, .{ u.slot, u.len, @typeName(Command) });
                }
                return e;
            };
            self.n = n;
            // §8.5 delta-app recipe: a persisted State is only as good as the
            // journal that continues it. Refuse a snapshot the retained tail
            // cannot catch up — ahead of the journal (or with no journal at
            // all: a snapshot from somewhere else), or older than the tail's
            // first slot (the slots in between are gone) — rather than start
            // on a silently wrong State.
            const s0 = initialSlot();
            if (s0 != 0 and !initialSlotWithinTail(s0, n.journal_tail)) {
                const tail = n.journal_tail;
                n.deinit();
                self.n = null;
                if (tail) |t| {
                    return fail(diag, error.InitialSlotOutsideJournal, "initialSlot() = {d} but the journal in {s} retains slots {d}..{d}; a persisted State must come from this data_dir and be no older than the retained tail (persist it at least every 16 applied slots, from the waitApplied stream) — or return 0 and use full-value commands.", .{ s0, opts.data_dir, t.first, t.last });
                }
                return fail(diag, error.InitialSlotOutsideJournal, "initialSlot() = {d} but the journal in {s} is empty; a persisted State cannot be caught up without the journal it was taken from — start this data_dir from initialSlot() = 0 (a snapshot from elsewhere cannot be used), or restore its journal alongside it.", .{ s0, opts.data_dir });
            }
            self.created.store(true, .release);
            return self;
        }

        /// Stop the node (joins the engine thread — no hook call can be in
        /// flight afterwards), wake `waitApplied` callers with null, wait
        /// for every one of them to leave `waitApplied`, then free. A thread
        /// may therefore be parked in `waitApplied` when `deinit` runs; it
        /// must not call anything on the adapter after `waitApplied` returns
        /// null.
        pub fn deinit(self: *Self) void {
            if (self.n) |n| n.deinit();
            self.mu.lockUncancelable(self.io);
            self.closed = true;
            self.cond.broadcast(self.io);
            while (self.waiters > 0) self.drained.waitUncancelable(self.io, &self.mu);
            self.mu.unlock(self.io);
            const gpa = self.gpa;
            self.queue.deinit(gpa);
            self.* = undefined;
            gpa.destroy(self);
        }

        /// Encode `cmd` with the codec and queue it for nomination. A custom
        /// codec returning zero bytes is `ValueEmpty`; one returning more
        /// than `max_value_bytes` is `ValueTooLarge`.
        pub fn propose(self: *Self, cmd: Command) ProposeError!void {
            const n = self.n orelse return error.WatcherCannotPropose;
            if (comptime codec.is_custom) {
                // Sized to the frozen cap so an oversize custom encoding is
                // reported (ValueTooLarge), not a buffer overrun.
                const buf = try self.gpa.alloc(u8, max_encoded_bytes);
                defer self.gpa.free(buf);
                return n.propose(codec.encode(cmd, buf));
            } else {
                var buf: [codec.size]u8 = undefined;
                return n.propose(codec.encode(cmd, &buf));
            }
        }

        /// Block for the next applied slot in order. Returns null on timeout
        /// or after `deinit`; after the node has halted (`on_failed`), the
        /// already-applied items are still drained first, then
        /// `error.NodeHalted` — immediately, even with `timeout_ms = null`.
        pub fn waitApplied(self: *Self, wopts: WaitOptions) WaitError!?Applied {
            self.mu.lockUncancelable(self.io);
            defer self.mu.unlock(self.io);
            self.waiters += 1;
            defer { // runs before the unlock above (reverse order)
                self.waiters -= 1;
                if (self.waiters == 0) self.drained.signal(self.io);
            }
            while (self.head >= self.queue.items.len and !self.closed) {
                if (wopts.timeout_ms) |ms| {
                    self.cond.waitTimeout(self.io, &self.mu, node.msTimeout(ms)) catch return null;
                } else {
                    self.cond.waitUncancelable(self.io, &self.mu);
                }
            }
            if (self.head < self.queue.items.len) {
                const item = self.queue.items[self.head];
                self.head += 1;
                if (self.head == self.queue.items.len) {
                    self.queue.clearRetainingCapacity();
                    self.head = 0;
                }
                return item;
            }
            if (self.halt_err != null) return error.NodeHalted;
            return null;
        }

        /// The error the node halted with (after `on_failed`), else null.
        pub fn haltError(self: *Self) ?anyerror {
            self.mu.lockUncancelable(self.io);
            defer self.mu.unlock(self.io);
            return self.halt_err;
        }

        /// The compiled §8.2 driver (ctx = this adapter).
        pub fn driver(self: *Self) Driver {
            return .{
                .ctx = @ptrCast(self),
                .validate_value = driverValidate,
                .combine_candidates = driverCombine,
            };
        }

        /// The bytes-level node underneath (stats, boundPort, …).
        pub fn raw(self: *Self) *node.Node {
            return self.n.?;
        }

        fn hook(self: *Self) node.DeliveryHook {
            return .{
                .ctx = @ptrCast(self),
                .on_externalized = hookExternalized,
                .on_failed = hookFailed,
            };
        }

        // ---- driver vtable (engine thread) ----

        fn driverValidate(ctx: *anyopaque, slot: u64, value: []const u8, is_nomination: bool) Validity {
            _ = slot;
            _ = is_nomination;
            const self: *Self = @ptrCast(@alignCast(ctx));
            const cmd = codec.decode(value) orelse return .invalid;
            return App.validate(self.state, cmd);
        }

        fn driverCombine(ctx: *anyopaque, slot: u64, candidates: []const []const u8, gpa: std.mem.Allocator, out: *std.ArrayList(u8)) DriverError!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            if (candidates.len == 0) return error.DriverFault;
            if (comptime @hasDecl(App, "combine")) {
                // Sized by the candidate slice (never a fixed array).
                const cmds = try gpa.alloc(Command, candidates.len);
                defer gpa.free(cmds);
                var n: usize = 0;
                for (candidates) |c| {
                    if (codec.decode(c)) |cmd| {
                        cmds[n] = cmd;
                        n += 1;
                    }
                }
                if (n == 0) return error.DriverFault;
                const best = App.combine(self.state, cmds[0..n]);
                // §8.5: the composite must self-validate. A `.invalid`
                // composite would be balloted by this node and rejected by
                // every peer — a silent stall with only `insane` counters as
                // evidence — so it is the contract violation DriverFault is
                // for (docs/determinism.md §6). `.maybe_valid` stays legal:
                // a node behind on State cannot judge what it combines.
                if (App.validate(self.state, best) == .invalid) {
                    if (self.created.load(.acquire)) log.err(bad_composite_fmt, .{ @typeName(App), slot });
                    return error.DriverFault;
                }
                if (comptime codec.is_custom) {
                    // Ship the slice `encode` RETURNS (what `propose` sends),
                    // not a prefix of the scratch: an encoder may return a
                    // window of `buf` or static storage. Sized to the frozen
                    // cap like `propose`'s scratch.
                    const scratch = try gpa.alloc(u8, max_encoded_bytes);
                    defer gpa.free(scratch);
                    const written = codec.encode(best, scratch);
                    out.clearRetainingCapacity();
                    try out.appendSlice(gpa, written);
                } else {
                    try out.resize(gpa, codec.size);
                    const written = codec.encode(best, out.items);
                    std.debug.assert(written.len == codec.size);
                }
            } else {
                // §8.4 default: lexicographic max — numerically the largest
                // under the order-preserving auto-codec ("highest wins").
                var best = candidates[0];
                for (candidates[1..]) |c| {
                    if (std.mem.order(u8, c, best) == .gt) best = c;
                }
                try out.appendSlice(gpa, best);
            }
        }

        // ---- delivery hook (engine thread; creating thread during replay) ----

        fn hookExternalized(ctx: *anyopaque, slot: u64, value: []const u8) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const cmd = codec.decode(value) orelse {
                // §8.5's one fatal rule: bytes the network agreed on must
                // decode. Inside create this becomes the diagnostic; at
                // runtime the node halts loudly (the Node logs + latches).
                self.undecodable = .{ .slot = slot, .len = value.len };
                if (self.created.load(.acquire)) log.err(undecodable_fmt, .{ slot, value.len, @typeName(Command) });
                return error.UndecodableExternalizedValue;
            };
            if (slot <= self.applied_hwm) return; // re-delivery: no-op
            if (comptime apply_in_place) {
                App.apply(&self.state, cmd);
            } else {
                self.state = App.apply(self.state, cmd);
            }
            self.applied_hwm = slot;

            self.mu.lockUncancelable(self.io);
            defer self.mu.unlock(self.io);
            if (self.closed) return;
            try self.queue.append(self.gpa, .{ .slot = slot, .state = self.state });
            self.cond.signal(self.io);
        }

        fn hookFailed(ctx: *anyopaque, err: anyerror) void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.mu.lockUncancelable(self.io);
            defer self.mu.unlock(self.io);
            if (self.halt_err == null) self.halt_err = err;
            self.closed = true;
            self.cond.broadcast(self.io);
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const Color = enum(u8) { red, green, blue };
/// Signed-tag enum: its own codec arm (the tag biases like a signed int);
/// `.neg` spells 0x7B, `.zero` 0x80, `.pos` 0x85.
const Sign = enum(i8) { neg = -5, zero = 0, pos = 5 };

/// Kitchen-sink Command: every allowed leaf kind, a sub-byte int, a signed
/// wide int, a fixed array, a nested struct and a trailing signed-tag enum.
/// Encoded size 23.
const Kitchen = struct {
    a: i8,
    b: u3,
    c: i64,
    d: bool,
    e: Color,
    f: [3]u16,
    g: struct { h: u16, i: i16 },
    s: Sign,
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
    .{ .a = -128, .b = 0, .c = std.math.minInt(i64), .d = false, .e = .red, .f = .{ 0, 0, 0 }, .g = .{ .h = 0, .i = -32768 }, .s = .neg },
    .{ .a = 127, .b = 7, .c = std.math.maxInt(i64), .d = true, .e = .blue, .f = .{ 65535, 65535, 65535 }, .g = .{ .h = 65535, .i = 32767 }, .s = .pos },
    .{ .a = 0, .b = 0, .c = 0, .d = false, .e = .red, .f = .{ 0, 0, 0 }, .g = .{ .h = 0, .i = 0 }, .s = .zero },
    .{ .a = -1, .b = 7, .c = -1, .d = true, .e = .green, .f = .{ 0, 65535, 0 }, .g = .{ .h = 1, .i = -1 }, .s = .neg },
    .{ .a = 1, .b = 1, .c = 1, .d = false, .e = .green, .f = .{ 1, 0, 65535 }, .g = .{ .h = 0, .i = 1 }, .s = .pos },
    .{ .a = -128, .b = 7, .c = std.math.maxInt(i64), .d = true, .e = .blue, .f = .{ 65535, 0, 0 }, .g = .{ .h = 65535, .i = -32768 }, .s = .zero },
    // Same prefix as the first entry, differing only in the trailing signed
    // tag: the order of this pair is decided by the enum arm alone.
    .{ .a = -128, .b = 0, .c = std.math.minInt(i64), .d = false, .e = .red, .f = .{ 0, 0, 0 }, .g = .{ .h = 0, .i = -32768 }, .s = .zero },
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
    try std.testing.expectEqual(@as(usize, 23), KitchenCodec.size);
}

// Non-vacuity: removing the bias (signed ints encode as two's complement)
// makes a (-1, 1) pair order .gt in bytes while the oracle says .lt; the
// observed-set assertion goes red if the PRNG pairs never disagree; encoding
// the signed enum tag as raw unsigned bits goes red on the quarter of the
// pairs that share every field but `s` (and on the extremes' last pair).
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
            // A quarter share everything but the trailing signed-tag enum.
            if (rand.boolean()) {
                b.d = a.d;
                b.e = a.e;
                b.f = a.f;
                b.g = a.g;
            }
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
            raw[22] = ([_]u8{ 0x7B, 0x80, 0x85 })[raw[22] % 3];
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
// `!= 0` accepts 2; `@enumFromInt` instead of `enums.fromInt` accepts 200;
// a signed tag decoded as raw unsigned bits makes 0x7B (-5 biased) name no
// variant (123) and 0x81 (biased 1) decode instead of being rejected.
test "codec strict rejections, each paired with a one-byte-fixed sibling that decodes" {
    const base_v = Kitchen{ .a = 3, .b = 5, .c = -9, .d = true, .e = .green, .f = .{ 1, 2, 3 }, .g = .{ .h = 4, .i = -5 }, .s = .zero };
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

    // signed enum tag at offset 22: 0x81 unbiases to 1, which names no
    // variant; 0x7B is the biased spelling of .neg (-5).
    m = base;
    m[22] = 0x81;
    try std.testing.expect(KitchenCodec.decode(&m) == null);
    m[22] = 0x7B;
    try std.testing.expectEqual(Sign.neg, KitchenCodec.decode(&m).?.s);
}

// Non-vacuity: encoding the tag as its raw unsigned bits (instead of with the
// tag type's own signedness) makes the negative tag decode to null and orders
// its byte .gt while the oracle says .lt.
test "codec signed-tag enum: negative tags round-trip and order like their backing int" {
    const S = Sign;
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
    const CN = AppNode(Counter);
    try std.testing.expectEqual(Counter.State, CN.State);
    try std.testing.expectEqual(Counter.Command, CN.Command);
    try std.testing.expectEqual(@as(usize, 8), CN.codec.size);
    try std.testing.expect(!CN.codec.is_custom);
    try std.testing.expect(!CN.apply_in_place);
    try std.testing.expect(@hasField(CN.Options, "network"));

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

// Non-vacuity: this is the README's narrowing idiom. `node.explain` takes
// `node.CreateError`, and `AppNode(App).CreateError` is a strict superset
// (+CommandExceedsMaxValueBytes, +InitialSlotOutsideJournal,
// +UndecodableExternalizedValue): pass `c.err` to `node.explain` directly and
// this is a compile error ("not a member of destination error set"); drop any
// arm of the switch and the `else` capture stops coercing. The needles pin that the narrowed call reaches the
// real static text.
test "README idiom: AppNode(Counter).CreateError narrows to node.explain via a switch on its three extra members" {
    const CN = AppNode(Counter);
    const cases = [_]struct { err: CN.CreateError, needle: []const u8 }{
        .{ .err = error.NoIdentity, .needle = "no identity" },
        .{ .err = error.CommandExceedsMaxValueBytes, .needle = "app-level" },
        .{ .err = error.InitialSlotOutsideJournal, .needle = "app-level" },
        .{ .err = error.UndecodableExternalizedValue, .needle = "app-level" },
    };
    for (cases) |c| {
        const text: []const u8 = switch (c.err) {
            error.CommandExceedsMaxValueBytes, error.InitialSlotOutsideJournal, error.UndecodableExternalizedValue => "app-level",
            else => |e| node.explain(e),
        };
        try std.testing.expect(std.mem.indexOf(u8, text, c.needle) != null);
    }
}

// -- AppNode over the Node (M6 S3) ---------------------------------------------

const Quorum = core.quorum.Quorum;
const crypto = core.crypto;
const testing = std.testing;

/// Highest bid wins; ties break toward the LOWER bidder id (the default
/// byte-max would pick the higher id — that is what makes the custom
/// combine observable).
const Auction = struct {
    pub const State = struct { bid: u32 = 0, bidder: u8 = 0 };
    pub const Command = struct { bid: u32, bidder: u8 };
    pub fn validate(state: State, cmd: Command) Validity {
        return if (cmd.bid > state.bid) .valid else .invalid;
    }
    pub fn apply(state: State, cmd: Command) State {
        _ = state;
        return .{ .bid = cmd.bid, .bidder = cmd.bidder };
    }
    pub fn combine(state: State, cmds: []const Command) Command {
        _ = state;
        var best = cmds[0];
        for (cmds[1..]) |c| {
            if (c.bid > best.bid or (c.bid == best.bid and c.bidder < best.bidder)) best = c;
        }
        return best;
    }
};

const CounterNode = AppNode(Counter);

fn encodeCounter(buf: *[8]u8, next: u64) []u8 {
    return CounterNode.codec.encode(.{ .next = next }, buf);
}

/// A tmpDir-backed data_dir path (absolute) for one test.
const TestDir = struct {
    tmp: testing.TmpDir,
    buf: [std.fs.max_path_bytes]u8 = undefined,
    len: usize = 0,

    fn init() !TestDir {
        var d: TestDir = .{ .tmp = testing.tmpDir(.{}) };
        d.len = try d.tmp.dir.realPath(testing.io, &d.buf);
        return d;
    }
    fn path(self: *TestDir) []const u8 {
        return self.buf[0..self.len];
    }
    /// `<tmp>/<name>` into `out`.
    fn sub(self: *TestDir, out: []u8, name: []const u8) ![]const u8 {
        return std.fmt.bufPrint(out, "{s}/{s}", .{ self.path(), name });
    }
    fn deinit(self: *TestDir) void {
        self.tmp.cleanup();
    }
};

fn seedOf(byte: u8) [32]u8 {
    return @splat(byte);
}

// Non-vacuity: removing the `slot <= applied_hwm` guard makes the
// re-deliveries queue a third and fourth Applied (the two-item drain then
// sees slot 2 twice); decoding AFTER the guard, or applying before decoding,
// changes `state` on the junk delivery; dropping the `halt_err` check in
// `waitApplied` returns null instead of NodeHalted after the drain.
test "hook semantics without a Node: ascending applies, re-deliveries are no-ops, junk is UndecodableExternalizedValue, drain then NodeHalted" {
    const gpa = testing.allocator;
    const io = testing.io;
    const n = try CounterNode.createDetached(gpa, io, 4096);
    defer n.deinit();
    const ctx: *anyopaque = @ptrCast(n);
    var buf: [8]u8 = undefined;

    try CounterNode.hookExternalized(ctx, 1, encodeCounter(&buf, 1));
    try CounterNode.hookExternalized(ctx, 2, encodeCounter(&buf, 2));
    try testing.expectEqual(@as(u64, 2), n.state.count);
    // Re-delivery (journal overlap) of 2 and of 1: no-ops.
    try CounterNode.hookExternalized(ctx, 2, encodeCounter(&buf, 2));
    try CounterNode.hookExternalized(ctx, 1, encodeCounter(&buf, 1));
    try testing.expectEqual(@as(u64, 2), n.state.count);
    // Junk on the agreed stream: the one fatal rule, state untouched.
    try testing.expectError(error.UndecodableExternalizedValue, CounterNode.hookExternalized(ctx, 3, "junk"));
    try testing.expectEqual(@as(u64, 2), n.state.count);
    try testing.expectEqual(@as(u64, 3), n.undecodable.?.slot);
    try testing.expect(n.haltError() == null);

    CounterNode.hookFailed(ctx, error.DiskFull);
    try testing.expectEqual(@as(?anyerror, error.DiskFull), n.haltError());
    // Drain the two applied items first, then NodeHalted — immediately,
    // with no timeout.
    const a1 = (try n.waitApplied(.{ .timeout_ms = null })).?;
    try testing.expectEqual(@as(u64, 1), a1.slot);
    try testing.expectEqual(@as(u64, 1), a1.state.count);
    const a2 = (try n.waitApplied(.{ .timeout_ms = null })).?;
    try testing.expectEqual(@as(u64, 2), a2.slot);
    try testing.expectEqual(@as(u64, 2), a2.state.count);
    try testing.expectError(error.NodeHalted, n.waitApplied(.{ .timeout_ms = null }));
    try testing.expectError(error.NodeHalted, n.waitApplied(.{ .timeout_ms = 10 }));
}

// Non-vacuity: a driver that skips `App.validate` (returns .valid for any
// decodable value) fails the .invalid / .maybe_valid arms; feeding
// candidates in a fixed array capped below 64 (or a combine that ignores
// `App.combine`) fails the Auction tie-break; returning an empty `out` on
// zero candidates instead of DriverFault fails the last arm.
test "driver vtable: validate reaches all three verdicts, junk is invalid, default combine is numeric max, custom combine breaks ties, 64 candidates, zero is DriverFault" {
    const gpa = testing.allocator;
    const io = testing.io;
    const n = try CounterNode.createDetached(gpa, io, 4096);
    defer n.deinit();
    const d = n.driver();
    var buf: [8]u8 = undefined;

    try testing.expectEqual(Validity.valid, d.validate_value(d.ctx, 1, encodeCounter(&buf, 1), true));
    try testing.expectEqual(Validity.maybe_valid, d.validate_value(d.ctx, 1, encodeCounter(&buf, 2), false));
    try testing.expectEqual(Validity.invalid, d.validate_value(d.ctx, 1, encodeCounter(&buf, 0), true));
    try testing.expectEqual(Validity.invalid, d.validate_value(d.ctx, 1, "junk", true));

    // Default combine: numerically the largest, over 64 candidates whose
    // byte order is deliberately not their insertion order.
    var cands: [64][8]u8 = undefined;
    var cand_slices: [64][]const u8 = undefined;
    for (&cands, 0..) |*c, i| {
        const v: u64 = @intCast((i * 37) % 64 + 1); // a permutation of 1..64
        _ = CounterNode.codec.encode(.{ .next = v }, c);
        cand_slices[i] = c;
    }
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try d.combine_candidates(d.ctx, 1, &cand_slices, gpa, &out);
    try testing.expectEqual(@as(usize, CounterNode.codec.size), out.items.len);
    try testing.expectEqual(@as(u64, 64), CounterNode.codec.decode(out.items).?.next);

    out.clearRetainingCapacity();
    try testing.expectError(error.DriverFault, d.combine_candidates(d.ctx, 1, &.{}, gpa, &out));

    // Custom combine (Auction): equal bids, the LOWER bidder wins — the
    // byte-max default would have picked bidder 9.
    const AuctionNode = AppNode(Auction);
    const a = try AuctionNode.createDetached(gpa, io, 4096);
    defer a.deinit();
    const ad = a.driver();
    var b1: [5]u8 = undefined;
    var b2: [5]u8 = undefined;
    var b3: [5]u8 = undefined;
    const acands = [_][]const u8{
        AuctionNode.codec.encode(.{ .bid = 100, .bidder = 9 }, &b1),
        AuctionNode.codec.encode(.{ .bid = 100, .bidder = 2 }, &b2),
        AuctionNode.codec.encode(.{ .bid = 50, .bidder = 1 }, &b3),
    };
    out.clearRetainingCapacity();
    try ad.combine_candidates(ad.ctx, 1, &acands, gpa, &out);
    const won = AuctionNode.codec.decode(out.items).?;
    try testing.expectEqual(@as(u32, 100), won.bid);
    try testing.expectEqual(@as(u8, 2), won.bidder);
    out.clearRetainingCapacity();
    try testing.expectError(error.DriverFault, ad.combine_candidates(ad.ctx, 1, &.{}, gpa, &out));
}

// Non-vacuity: adding `driver` or `delivery` to the mirror (or dropping
// `diagnostic` / `allow_unsafe_quorum` from it), changing a field's type,
// or changing a default (e.g. `max_value_bytes = 4095`) fails the
// field-by-field comparison; the count check catches an extra field.
test "Options parity: AppNode.Options is node.Options minus driver/delivery, same types and defaults" {
    const src = @typeInfo(node.Options).@"struct";
    const dst = @typeInfo(CounterNode.Options).@"struct";
    var expected: usize = 0;
    inline for (src.field_names, src.field_types, src.field_attrs) |name, FT, attr| {
        if (comptime std.mem.eql(u8, name, "driver") or std.mem.eql(u8, name, "delivery")) {
            try testing.expect(!@hasField(CounterNode.Options, name));
        } else {
            expected += 1;
            try testing.expect(@hasField(CounterNode.Options, name));
            const idx = comptime std.meta.fieldIndex(CounterNode.Options, name).?;
            try testing.expect(dst.field_types[idx] == FT);
            const want = comptime attr.defaultValue(FT);
            const have = comptime dst.field_attrs[idx].defaultValue(FT);
            try testing.expect((want == null) == (have == null));
            if (want) |w| try testing.expect(std.meta.eql(w, have.?));
        }
    }
    try testing.expectEqual(expected, dst.field_names.len);
    try testing.expectEqual(src.field_names.len - 2, dst.field_names.len);
    try testing.expect(@hasField(CounterNode.Options, "diagnostic"));
    try testing.expect(@hasField(CounterNode.Options, "allow_unsafe_quorum"));
}

// Non-vacuity: dropping the `codec.size > max_value_bytes` pre-check lets
// the 8-byte Command start under max_value_bytes = 4 (and every propose then
// fails with ValueTooLarge); forwarding a watcher's propose to the Node
// without the `n == null` guard is unchanged here, but removing the Node's
// own watcher check makes the first arm succeed; an encode-to-empty that is
// not passed through Node.propose fails the ValueEmpty arm.
test "propose errors: watcher, custom codec encoding to empty, Command wider than max_value_bytes at create" {
    const gpa = testing.allocator;
    const io = testing.io;
    var td = try TestDir.init();
    defer td.deinit();
    var diag: node.Diagnostic = .{};
    const seed = seedOf(0x51);
    const me = try crypto.publicKeyFromSeed(seed);
    const other = seedOf(0x52);

    // max_value_bytes = 4 for an 8-byte Command: refused at create, with
    // the sizes in the message.
    try testing.expectError(error.CommandExceedsMaxValueBytes, CounterNode.create(gpa, io, .{
        .network = "propose-errors v1",
        .secret_seed = seed,
        .quorum = Quorum.twoThirdsOf(&.{ me, other, seedOf(0x53) }),
        .listen_port = 0,
        .data_dir = td.path(),
        .max_value_bytes = 4,
        .diagnostic = &diag,
    }));
    try testing.expect(std.mem.indexOf(u8, diag.message(), "encodes to 8 bytes but max_value_bytes is 4") != null);

    // A watcher never proposes.
    var wbuf: [std.fs.max_path_bytes]u8 = undefined;
    const w = try CounterNode.create(gpa, io, .{
        .network = "propose-errors v1",
        .watcher = true,
        .quorum = Quorum.twoThirdsOf(&.{ me, other, seedOf(0x53) }),
        .listen_port = 0,
        .data_dir = try td.sub(&wbuf, "watcher"),
        .diagnostic = &diag,
    });
    defer w.deinit();
    try testing.expectError(error.WatcherCannotPropose, w.propose(.{ .next = 1 }));
    try testing.expect(w.raw().watcher);

    // A custom codec that encodes to zero bytes is ValueEmpty; a normal one
    // is accepted.
    var mbuf: [std.fs.max_path_bytes]u8 = undefined;
    const MemoNode = AppNode(Memo);
    const m = try MemoNode.create(gpa, io, .{
        .network = "propose-errors v1",
        .secret_seed = seed,
        .quorum = Quorum.twoThirdsOf(&.{ me, other, seedOf(0x53) }),
        .listen_port = 0,
        .data_dir = try td.sub(&mbuf, "memo"),
        .diagnostic = &diag,
    });
    defer m.deinit();
    try testing.expectError(error.ValueEmpty, m.propose(.{ .len = 0, .text = @splat(' ') }));
    try m.propose(Memo.decode("hello").?);
}

/// Wait until `pred(state)` holds on `n`, driving the §0 loop (propose
/// count + 1 after every applied slot) on every node in `peers` meanwhile.
/// Returns the last applied state on `n`, or error.Timeout.
fn driveUntil(io: std.Io, n: *CounterNode, peers: []const *CounterNode, deadline_ms: u64, target: u64) !Counter.State {
    var waited: u64 = 0;
    var last: ?Counter.State = null;
    while (waited < deadline_ms) {
        if (try n.waitApplied(.{ .timeout_ms = 50 })) |ext| {
            last = ext.state;
            if (ext.state.count >= target) return ext.state;
            try n.propose(.{ .next = ext.state.count + 1 });
        }
        for (peers) |p| {
            if (try p.waitApplied(.{ .timeout_ms = 1 })) |ext| {
                try p.propose(.{ .next = ext.state.count + 1 });
            }
        }
        waited += 50;
        _ = io;
    }
    if (last) |l| std.debug.print("\ndriveUntil: timed out at count {d} (target {d})\n", .{ l.count, target });
    return error.Timeout;
}

// Non-vacuity: a driver that never reaches `App.validate` (or a hook that
// never `apply`s) leaves count at 0 — the 10 s wait returns null; encoding
// through anything but `codec` (e.g. little-endian) makes the singleton
// externalize a value that decodes to a different count.
test "AppNode over the real Node (1-of-1 self quorum): propose {next=1} applies count 1, then 2" {
    const gpa = testing.allocator;
    const io = testing.io;
    var td = try TestDir.init();
    defer td.deinit();
    var diag: node.Diagnostic = .{};
    const seed = seedOf(0x61);
    const me = try crypto.publicKeyFromSeed(seed);

    const n = try CounterNode.create(gpa, io, .{
        .network = "appnode-singleton v1",
        .secret_seed = seed,
        .quorum = Quorum.of(1, &.{me}),
        .listen_port = 0,
        .data_dir = td.path(),
        .diagnostic = &diag,
    });
    defer n.deinit();
    try testing.expect(n.raw().boundPort() != 0);

    try n.propose(.{ .next = 1 });
    const a1 = (try n.waitApplied(.{ .timeout_ms = 10_000 })) orelse return error.SingletonNeverExternalized;
    try testing.expectEqual(@as(u64, 1), a1.slot);
    try testing.expectEqual(@as(u64, 1), a1.state.count);
    try n.propose(.{ .next = 2 });
    const a2 = (try n.waitApplied(.{ .timeout_ms = 10_000 })) orelse return error.SingletonNeverExternalized;
    try testing.expectEqual(@as(u64, 2), a2.slot);
    try testing.expectEqual(@as(u64, 2), a2.state.count);
    try testing.expect(n.haltError() == null);
}

/// Two typed nodes on loopback, 2-of-2: `a` listens on an ephemeral port
/// with no peers, `b` dials it. `create` order matters (b needs a's port).
const Pair = struct {
    seed_a: [32]u8,
    seed_b: [32]u8,
    ids: [2][32]u8,
    dir_a: [std.fs.max_path_bytes]u8 = undefined,
    dir_b: [std.fs.max_path_bytes]u8 = undefined,
    dir_a_len: usize = 0,
    dir_b_len: usize = 0,
    diag: node.Diagnostic = .{},

    const network = "appnode-restart v1";

    fn init(td: *TestDir) !Pair {
        var p: Pair = .{ .seed_a = seedOf(0x71), .seed_b = seedOf(0x72), .ids = undefined };
        p.ids[0] = try crypto.publicKeyFromSeed(p.seed_a);
        p.ids[1] = try crypto.publicKeyFromSeed(p.seed_b);
        p.dir_a_len = (try td.sub(&p.dir_a, "a")).len;
        p.dir_b_len = (try td.sub(&p.dir_b, "b")).len;
        return p;
    }

    fn createA(self: *Pair, gpa: std.mem.Allocator, io: std.Io, peers: []const []const u8) !*CounterNode {
        return CounterNode.create(gpa, io, .{
            .network = network,
            .secret_seed = self.seed_a,
            .quorum = Quorum.of(2, &self.ids),
            .listen_port = 0,
            .peers = peers,
            .data_dir = self.dir_a[0..self.dir_a_len],
            .diagnostic = &self.diag,
        });
    }

    fn createB(self: *Pair, gpa: std.mem.Allocator, io: std.Io, peers: []const []const u8) !*CounterNode {
        return CounterNode.create(gpa, io, .{
            .network = network,
            .secret_seed = self.seed_b,
            .quorum = Quorum.of(2, &self.ids),
            .listen_port = 0,
            .peers = peers,
            .data_dir = self.dir_b[0..self.dir_b_len],
            .diagnostic = &self.diag,
        });
    }
};

fn loopbackSpec(buf: []u8, port: u16) ![]const u8 {
    return std.fmt.bufPrint(buf, "127.0.0.1:{d}", .{port});
}

// Non-vacuity: skipping the journal-tail replay in `Node.create` (the M6 S3
// reorder's second step) leaves the restarted node at count 0 with nothing
// on `waitApplied` — the "tail ends at count 2" assertions go red and, with
// only stale proposals, the convergence wait times out; replaying the tail
// through `ext_queue` instead of the hook does the same (the hook never
// applies). Exactly the §0 program's restart: stale `{next=1}` FIRST.
test "restart replay (2-of-2 loopback): deinit, create on the same data_dir, stale propose first, tail replays to count 2, converges to 3" {
    const gpa = testing.allocator;
    const io = testing.io;
    var td = try TestDir.init();
    defer td.deinit();
    var pair = try Pair.init(&td);
    var spec_buf: [32]u8 = undefined;

    const b = blk: {
        const a = try pair.createA(gpa, io, &.{});
        defer a.deinit();
        const b = try pair.createB(gpa, io, &.{try loopbackSpec(&spec_buf, a.raw().boundPort())});
        errdefer b.deinit();

        // Phase 1 — the §0 program on both nodes until a has applied count 2.
        try a.propose(.{ .next = 1 });
        try b.propose(.{ .next = 1 });
        const s = try driveUntil(io, a, &.{b}, 60_000, 2);
        try testing.expectEqual(@as(u64, 2), s.count);
        break :blk b;
        // `a` goes down here (deinit joins its threads; its data_dir stays).
    };
    defer b.deinit();

    // Phase 2 — restart a on the same data_dir (dialing b: a's port changed).
    const a2 = try pair.createA(gpa, io, &.{try loopbackSpec(&spec_buf, b.raw().boundPort())});
    defer a2.deinit();
    // State is initialState() + the replayed tail (R17): the first proposal
    // is computed from a fresh State and is STALE — the network rejects it.
    try a2.propose(.{ .next = 1 });
    // The replayed tail arrives through waitApplied, ending at count 2 …
    const r1 = (try a2.waitApplied(.{ .timeout_ms = 1000 })) orelse return error.TailNotReplayed;
    try testing.expectEqual(@as(u64, 1), r1.slot);
    try testing.expectEqual(@as(u64, 1), r1.state.count);
    try a2.propose(.{ .next = r1.state.count + 1 });
    const r2 = (try a2.waitApplied(.{ .timeout_ms = 1000 })) orelse return error.TailNotReplayed;
    try testing.expectEqual(@as(u64, 2), r2.slot);
    try testing.expectEqual(@as(u64, 2), r2.state.count);
    try a2.propose(.{ .next = r2.state.count + 1 });
    // … and the loop converges to count 3 (slot 3 carries {next=3}).
    const s3 = try driveUntil(io, a2, &.{b}, 90_000, 3);
    try testing.expectEqual(@as(u64, 3), s3.count);
    try testing.expect(a2.haltError() == null);
    try testing.expect(b.haltError() == null);
}

// Non-vacuity: a hook that treats an undecodable journaled value as a no-op
// (or maps it to any other error) lets AppNode.create succeed on the "abc"
// dir; dropping the `undecodable` rewrite in `create` reports the Node's
// generic EngineFailed instead of UndecodableExternalizedValue.
test "codec mismatch at create: a bytes-level Node journals \"abc\"; AppNode(Counter).create refuses with UndecodableExternalizedValue; the bytes-level Node reopens fine" {
    const gpa = testing.allocator;
    const io = testing.io;
    var td = try TestDir.init();
    defer td.deinit();
    var diag: node.Diagnostic = .{};
    const seed = seedOf(0x81);
    const me = try crypto.publicKeyFromSeed(seed);
    const opts = node.Options{
        .network = "codec-mismatch v1",
        .secret_seed = seed,
        .quorum = Quorum.of(1, &.{me}),
        .listen_port = 0,
        .data_dir = td.path(),
        .diagnostic = &diag,
    };

    // A bytes-level singleton agrees on "abc" (3 bytes: never a Counter command).
    {
        const n = try node.Node.create(gpa, io, opts);
        defer n.deinit();
        try n.propose("abc");
        const e = n.waitExternalized(.{ .timeout_ms = 10_000 }) orelse return error.SingletonNeverExternalized;
        defer gpa.free(e.value);
        try testing.expectEqual(@as(u64, 1), e.slot);
        try testing.expectEqualSlices(u8, "abc", e.value);
    }

    // The typed node cannot decode what the network agreed on: refuse to start.
    try testing.expectError(error.UndecodableExternalizedValue, CounterNode.create(gpa, io, .{
        .network = "codec-mismatch v1",
        .secret_seed = seed,
        .quorum = Quorum.of(1, &.{me}),
        .listen_port = 0,
        .data_dir = td.path(),
        .diagnostic = &diag,
    }));
    try testing.expect(std.mem.indexOf(u8, diag.message(), "slot 1: journaled value (3 bytes) does not decode as") != null);
    try testing.expect(std.mem.indexOf(u8, diag.message(), "command evolution is consensus surface") != null);

    // The bytes-level node still reopens the dir and replays the tail.
    {
        const n = try node.Node.create(gpa, io, opts);
        defer n.deinit();
        const e = n.waitExternalized(.{ .timeout_ms = 1000 }) orelse return error.TailNotReplayed;
        defer gpa.free(e.value);
        try testing.expectEqual(@as(u64, 1), e.slot);
        try testing.expectEqualSlices(u8, "abc", e.value);
    }
}

// ---- S8 D2: the delta-app recipe (§8.5) must be implementable ----

/// A DELTA app: the network agrees on "add k", never on "sum becomes k", so
/// `validate` cannot judge a command against `State` and a replayed slot
/// applied twice is silently wrong.
const Delta = struct {
    pub const State = struct { sum: i64 = 0 };
    pub const Command = struct { add: i64 };
    pub fn validate(state: State, cmd: Command) Validity {
        _ = state;
        return if (cmd.add > 0) .valid else .invalid;
    }
    pub fn apply(state: State, cmd: Command) State {
        return .{ .sum = state.sum + cmd.add };
    }
};
const DeltaNode = AppNode(Delta);

/// The §8.5 recipe for delta apps: persist `State` keyed by the slot it was
/// taken at, rebuild it in `initialState()` and name that slot in
/// `initialSlot()`. The "persisted" snapshot is a test global.
var delta_snapshot: struct { state: Delta.State, slot: u64 } = .{ .state = .{}, .slot = 0 };
const DeltaSnap = struct {
    pub const State = Delta.State;
    pub const Command = Delta.Command;
    pub const validate = Delta.validate;
    pub const apply = Delta.apply;
    pub fn initialState() State {
        return delta_snapshot.state;
    }
    pub fn initialSlot() u64 {
        return delta_snapshot.slot;
    }
};
const DeltaSnapNode = AppNode(DeltaSnap);

/// Pump the delta loop ("add 1" after every applied slot) on `peer` until
/// `n` applies its next slot; returns that first applied item. `n` is
/// re-proposed too, so 2-of-2 keeps moving whichever side is behind. The
/// peer's applied items consumed here are appended to `peer_seen` (if
/// given) — a caller that waits for a specific peer slot afterwards must
/// not lose it to this pump (S8b skeptic: `PeerNeverAppliedSlot4` under
/// CPU load, when the peer externalized slot 4 > 50 ms before `n` did).
fn nextDeltaApplied(n: anytype, peer: *DeltaNode, deadline_ms: u64, peer_seen: ?*std.ArrayList(DeltaNode.Applied)) !@TypeOf(n.*).Applied {
    var waited: u64 = 0;
    while (waited < deadline_ms) {
        if (try n.waitApplied(.{ .timeout_ms = 50 })) |a| return a;
        if (try peer.waitApplied(.{ .timeout_ms = 1 })) |x| {
            if (peer_seen) |list| try list.append(testing.allocator, x);
            try peer.propose(.{ .add = 1 });
        }
        waited += 50;
    }
    return error.Timeout;
}

// Non-vacuity (S8 D2 finding "the documented delta-app workaround cannot be
// implemented correctly under AppNode"): without `initialSlot()` seeding the
// dedup floor before the tail replays, the restarted node re-applies slots
// 1..3 on top of the slot-3 snapshot — its first applied item is slot 1 with
// sum 4 (then 5, 6 …) instead of slot 4 with sum 4, and it diverges from the
// live peer with haltError == null on both. Seeding AFTER `Node.create` (or
// in the hook's re-delivery branch) also goes red: the tail has replayed by
// then. Dropping the outside-journal check lets a snapshot "from slot 99"
// (nothing in this journal) or one with no journal at all start silently.
test "restart of a DELTA app from a persisted snapshot (2-of-2 loopback): initialSlot() skips the replayed tail; sum matches the live peer; a snapshot outside the journal is refused" {
    const gpa = testing.allocator;
    const io = testing.io;
    var td = try TestDir.init();
    defer td.deinit();
    var pair = try Pair.init(&td);
    var spec_buf: [32]u8 = undefined;
    delta_snapshot = .{ .state = .{}, .slot = 0 };

    const b = blk: {
        const a = try DeltaSnapNode.create(gpa, io, .{
            .network = Pair.network,
            .secret_seed = pair.seed_a,
            .quorum = Quorum.of(2, &pair.ids),
            .listen_port = 0,
            .data_dir = pair.dir_a[0..pair.dir_a_len],
            .diagnostic = &pair.diag,
        });
        defer a.deinit();
        const b = try DeltaNode.create(gpa, io, .{
            .network = Pair.network,
            .secret_seed = pair.seed_b,
            .quorum = Quorum.of(2, &pair.ids),
            .listen_port = 0,
            .peers = &.{try loopbackSpec(&spec_buf, a.raw().boundPort())},
            .data_dir = pair.dir_b[0..pair.dir_b_len],
            .diagnostic = &pair.diag,
        });
        errdefer b.deinit();

        // Phase 1 — "add 1" on both until a has applied slot 3 (sum 3).
        try a.propose(.{ .add = 1 });
        try b.propose(.{ .add = 1 });
        var last: DeltaSnapNode.Applied = undefined;
        while (true) {
            last = try nextDeltaApplied(a, b, 60_000, null);
            try testing.expectEqual(@as(i64, @intCast(last.slot)), last.state.sum);
            if (last.slot >= 3) break;
            try a.propose(.{ .add = 1 });
        }
        try testing.expectEqual(@as(u64, 3), last.slot);
        // The app "persists" State keyed by the slot it was taken at.
        delta_snapshot = .{ .state = last.state, .slot = last.slot };
        break :blk b;
        // `a` goes down here; its data_dir (journal slots 1..3) stays.
    };
    defer b.deinit();

    // Phase 2 — restart a from the snapshot. The journal tail (1..3) must be
    // skipped, not re-applied: the first applied item is slot 4 with sum 4.
    const a2 = try DeltaSnapNode.create(gpa, io, .{
        .network = Pair.network,
        .secret_seed = pair.seed_a,
        .quorum = Quorum.of(2, &pair.ids),
        .listen_port = 0,
        .peers = &.{try loopbackSpec(&spec_buf, b.raw().boundPort())},
        .data_dir = pair.dir_a[0..pair.dir_a_len],
        .diagnostic = &pair.diag,
    });
    defer a2.deinit();
    try a2.propose(.{ .add = 1 });
    try b.propose(.{ .add = 1 });
    var b_seen: std.ArrayList(DeltaNode.Applied) = .empty;
    defer b_seen.deinit(gpa);
    const r4 = try nextDeltaApplied(a2, b, 90_000, &b_seen);
    try testing.expectEqual(@as(u64, 4), r4.slot);
    try testing.expectEqual(@as(i64, 4), r4.state.sum);
    // The live peer agrees on slot 4's state (its item may already have
    // been consumed by the pump above).
    var b4: ?DeltaNode.Applied = null;
    for (b_seen.items) |x| if (x.slot == 4) {
        b4 = x;
    };
    var waited: u64 = 0;
    while (b4 == null and waited < 30_000) : (waited += 50) {
        if (try b.waitApplied(.{ .timeout_ms = 50 })) |x| {
            if (x.slot == 4) b4 = x;
        }
    }
    try testing.expectEqual(@as(i64, 4), (b4 orelse return error.PeerNeverAppliedSlot4).state.sum);
    try testing.expect(a2.haltError() == null);
    try testing.expect(b.haltError() == null);

    // A snapshot the journal cannot catch up is refused, not started blind:
    // (a) "taken at slot 99" on a journal that ends at 4 (or not yet 4 — the
    //     snapshot is ahead either way); (b) any nonzero slot on a fresh
    //     data_dir (no journal at all — a snapshot from somewhere else).
    var d2: node.Diagnostic = .{};
    var cbuf: [std.fs.max_path_bytes]u8 = undefined;
    delta_snapshot = .{ .state = .{ .sum = 99 }, .slot = 99 };
    try testing.expectError(error.InitialSlotOutsideJournal, DeltaSnapNode.create(gpa, io, .{
        .network = Pair.network,
        .secret_seed = seedOf(0x73),
        .quorum = Quorum.of(2, &pair.ids),
        .listen_port = 0,
        .data_dir = try td.sub(&cbuf, "c"),
        .diagnostic = &d2,
    }));
    try testing.expect(std.mem.indexOf(u8, d2.message(), "initialSlot() = 99") != null);
    try testing.expect(std.mem.indexOf(u8, d2.message(), "empty") != null);
}

// Non-vacuity: the predicate is the whole outside-journal rule; flipping
// either comparison (or the empty-journal arm) fails one of the arms below.
test "initialSlot vs the retained journal tail: within, at either edge, ahead, behind, no journal" {
    // tail 49..70: a snapshot at 48 (tail starts right after it) through 70.
    try testing.expect(initialSlotWithinTail(48, .{ .first = 49, .last = 70 }));
    try testing.expect(initialSlotWithinTail(60, .{ .first = 49, .last = 70 }));
    try testing.expect(initialSlotWithinTail(70, .{ .first = 49, .last = 70 }));
    try testing.expect(!initialSlotWithinTail(71, .{ .first = 49, .last = 70 })); // ahead
    try testing.expect(!initialSlotWithinTail(47, .{ .first = 49, .last = 70 })); // behind: 48 lost
    try testing.expect(!initialSlotWithinTail(1, null)); // no journal
    try testing.expect(initialSlotWithinTail(0, null)); // the default: nothing claimed
    try testing.expect(initialSlotWithinTail(0, .{ .first = 49, .last = 70 }));
}

// Non-vacuity: without the reset at the top of AppNode.create and the OOM
// mapping through `fail`, the adapter allocation failing returns
// OutOfMemory with the Diagnostic untouched — the reused buffer still says
// "STALE ..." (red on the indexOf check).
test "AppNode.create: OutOfMemory writes its own message into a reused Diagnostic" {
    const io = testing.io;
    var td = try TestDir.init();
    defer td.deinit();
    var diag: node.Diagnostic = .{};
    const seed = seedOf(0x63);
    const me = try crypto.publicKeyFromSeed(seed);

    diag.set("STALE MESSAGE FROM A PREVIOUS FAILURE", .{});
    var fa = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.OutOfMemory, CounterNode.create(fa.allocator(), io, .{
        .network = "appnode-oom-diag v1",
        .secret_seed = seed,
        .quorum = Quorum.of(1, &.{me}),
        .listen_port = 0,
        .data_dir = td.path(),
        .diagnostic = &diag,
    }));
    try testing.expect(std.mem.indexOf(u8, diag.message(), "STALE") == null);
    try testing.expect(std.mem.indexOf(u8, diag.message(), "out of memory") != null);
}

// -- deinit vs. a parked waiter (S8 review, D4/D13) ----------------------------

/// A thread parked in `waitApplied` until `deinit` wakes it; records what it
/// got back.
const DeinitWaiter = struct {
    n: *CounterNode,
    timeout_ms: ?u64,
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    saw_null: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn run(self: *DeinitWaiter) void {
        const r = self.n.waitApplied(.{ .timeout_ms = self.timeout_ms }) catch null;
        self.saw_null.store(r == null, .release);
        self.done.store(true, .release);
    }
};

// Non-vacuity: reverting `deinit` to broadcast-then-free (no `waiters`
// drain) lets the woken waiter re-lock `mu` inside the freed adapter: it
// never returns (`WaiterHungAfterDeinit` after the 2 s poll) and the testing
// allocator reports a write after free at teardown. Both the untimed and the
// timed wait paths park on `cond`, so both are driven.
test "deinit while another thread is parked in waitApplied: the waiter returns null before the adapter is freed (untimed and timed waits)" {
    const gpa = testing.allocator;
    const io = testing.io;
    const timeouts = [_]?u64{ null, 30_000, null, 30_000 };
    for (timeouts) |timeout_ms| {
        const n = try CounterNode.createDetached(gpa, io, 4096);
        var w: DeinitWaiter = .{ .n = n, .timeout_ms = timeout_ms };
        const t = try std.Thread.spawn(.{}, DeinitWaiter.run, .{&w});
        // Let the waiter park (an early deinit is still a valid run).
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(20), .awake);
        n.deinit();
        var waited_ms: u64 = 0;
        while (!w.done.load(.acquire) and waited_ms < 2000) : (waited_ms += 10) {
            try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .awake);
        }
        if (!w.done.load(.acquire)) {
            std.debug.print("\ndeinit/waitApplied(timeout_ms={?d}): waiter never returned 2 s after deinit (parked on the freed mutex)\n", .{timeout_ms});
            return error.WaiterHungAfterDeinit; // parked for good: it cannot be joined
        }
        t.join();
        try testing.expect(w.saw_null.load(.acquire));
    }
}

// -- combine result must self-validate (S8 review, D1) --------------------------

/// The README Counter with a `combine` that violates the §8.5 contract: its
/// result never self-validates (`{next=0}` is `.invalid` for every State).
const BadCombine = struct {
    pub const State = Counter.State;
    pub const Command = Counter.Command;
    pub const validate = Counter.validate;
    pub const apply = Counter.apply;
    pub fn combine(state: State, cmds: []const Command) Command {
        _ = state;
        _ = cmds;
        return .{ .next = 0 };
    }
};

/// A lagging node's combine: the composite is ahead of this node's State,
/// so `validate` says `.maybe_valid` — legitimate, never a fault.
const AheadCombine = struct {
    pub const State = Counter.State;
    pub const Command = Counter.Command;
    pub const validate = Counter.validate;
    pub const apply = Counter.apply;
    pub fn combine(state: State, cmds: []const Command) Command {
        _ = state;
        _ = cmds;
        return .{ .next = 5 };
    }
};

// Non-vacuity: dropping the `App.validate(self.state, best)` check in
// `driverCombine` (the shipped M6 code) encodes `{next=0}` and returns
// success — every peer then rejects the composite as `.invalid` and the
// network stalls with only `insane` counters as evidence; treating
// `.maybe_valid` as a fault fails the AheadCombine arm.
test "driverCombine: a composite that self-validates .invalid is DriverFault, .maybe_valid (lagging node) is not" {
    const gpa = testing.allocator;
    const io = testing.io;
    var b1: [8]u8 = undefined;
    const cands = [_][]const u8{CounterNode.codec.encode(.{ .next = 1 }, &b1)};
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    const BadNode = AppNode(BadCombine);
    const bad = try BadNode.createDetached(gpa, io, 4096);
    defer bad.deinit();
    const bd = bad.driver();
    try testing.expectError(error.DriverFault, bd.combine_candidates(bd.ctx, 1, &cands, gpa, &out));

    const AheadNode = AppNode(AheadCombine);
    const ahead = try AheadNode.createDetached(gpa, io, 4096);
    defer ahead.deinit();
    const ad = ahead.driver();
    out.clearRetainingCapacity();
    try ad.combine_candidates(ad.ctx, 1, &cands, gpa, &out);
    try testing.expectEqual(@as(u64, 5), CounterNode.codec.decode(out.items).?.next);
    try testing.expectEqual(Validity.maybe_valid, ad.validate_value(ad.ctx, 1, out.items, false));
}

// -- custom encode: propose and combine trust the same bytes (S8 review, D3) ---

/// A custom codec whose `encode` returns a slice into static storage and
/// ignores `buf` entirely.
const StaticEncode = struct {
    pub const State = struct { k: u8 = 0 };
    pub const Command = struct { k: u8 };
    const table = [_][2]u8{ "aa".*, "bb".*, "cc".* };
    pub fn validate(state: State, cmd: Command) Validity {
        _ = state;
        return if (cmd.k < 3) .valid else .invalid;
    }
    pub fn apply(state: State, cmd: Command) State {
        _ = state;
        return .{ .k = cmd.k };
    }
    pub fn encode(cmd: Command, buf: []u8) []u8 {
        _ = buf;
        return @constCast(&table[cmd.k]);
    }
    pub fn decode(bytes: []const u8) ?Command {
        if (bytes.len != 2 or bytes[0] != bytes[1] or bytes[0] < 'a' or bytes[0] > 'c') return null;
        return .{ .k = bytes[0] - 'a' };
    }
    pub fn combine(state: State, cmds: []const Command) Command {
        _ = state;
        var best = cmds[0];
        for (cmds[1..]) |c| if (c.k > best.k) {
            best = c;
        };
        return best;
    }
};

/// A custom codec whose `encode` writes a marker at `buf[0]` and returns
/// the window `buf[1..3]` (not a prefix of `buf`).
const OffsetEncode = struct {
    pub const State = StaticEncode.State;
    pub const Command = StaticEncode.Command;
    pub const validate = StaticEncode.validate;
    pub const apply = StaticEncode.apply;
    pub const decode = StaticEncode.decode;
    pub const combine = StaticEncode.combine;
    pub fn encode(cmd: Command, buf: []u8) []u8 {
        buf[0] = 0xEE;
        buf[1] = 'a' + cmd.k;
        buf[2] = 'a' + cmd.k;
        return buf[1..3];
    }
};

fn combineBytesOf(comptime N: type, gpa: std.mem.Allocator, io: std.Io, cands: []const []const u8, out: *std.ArrayList(u8)) !void {
    const n = try N.createDetached(gpa, io, 4096);
    defer n.deinit();
    const d = n.driver();
    out.clearRetainingCapacity();
    try d.combine_candidates(d.ctx, 1, cands, gpa, out);
}

// Non-vacuity: shipping `out.items[0..written.len]` instead of the slice
// `encode` returned (the M6 code) makes the static-storage app's composite
// the scratch buffer's uninitialized bytes (0xAA 0xAA under the testing
// allocator) and the offset app's `EE 63` — while `propose` sends "cc" for
// the same winning command.
test "custom encode: driverCombine ships the slice encode returns, byte-equal to what propose sends, for static-storage and non-prefix encoders" {
    const gpa = testing.allocator;
    const io = testing.io;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const cands = [_][]const u8{ "aa", "cc", "bb" };

    const SN = AppNode(StaticEncode);
    var sbuf: [8]u8 = undefined;
    const s_propose = SN.codec.encode(.{ .k = 2 }, &sbuf);
    try testing.expectEqualSlices(u8, "cc", s_propose);
    try combineBytesOf(SN, gpa, io, &cands, &out);
    try testing.expectEqualSlices(u8, s_propose, out.items);

    const ON = AppNode(OffsetEncode);
    var obuf: [8]u8 = undefined;
    const o_propose = ON.codec.encode(.{ .k = 2 }, &obuf);
    try testing.expectEqualSlices(u8, "cc", o_propose);
    try combineBytesOf(ON, gpa, io, &cands, &out);
    try testing.expectEqualSlices(u8, o_propose, out.items);
}

// -- per-leaf exhaustive canonicality (S8 review, D3) --------------------------

/// Every byte string of `Codec(struct { x: T }).size` bytes (≤ 2, so the
/// space is enumerable) either fails to decode or re-encodes byte-identically,
/// and exactly `cardinality` of them decode — one spelling per value, no
/// spelling for anything else.
fn probeExhaustive(comptime T: type, comptime cardinality: usize) !void {
    const C = Codec(struct { x: T });
    comptime std.debug.assert(C.size <= 2);
    const total: usize = @as(usize, 1) << @intCast(8 * C.size);
    var accepted: usize = 0;
    var i: usize = 0;
    while (i < total) : (i += 1) {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, @intCast(i), .big);
        const in = bytes[2 - C.size ..];
        if (C.decode(in)) |v| {
            accepted += 1;
            var re: [2]u8 = undefined;
            const out = C.encode(v, re[0..C.size]);
            if (!std.mem.eql(u8, in, out)) {
                std.debug.print("\n{s}: bytes {x} decode -> re-encode {x} (non-canonical spelling accepted)\n", .{ @typeName(T), in, out });
                return error.NonCanonicalAccepted;
            }
        }
    }
    try testing.expectEqual(cardinality, accepted);
}

// Non-vacuity: replacing `std.math.cast` in decodeInt's SIGNED arm with a
// `@truncate` (the arm no other test reaches: Kitchen/Cmd carry only
// byte-multiple signed ints, where the cast is a no-op) makes i1 accept
// 0x02 as 0, i3 accept 0x08, i9 0x0200, i12 0x1000 and enum(i4) 0x10 — every
// one a second spelling of an in-range value, the malleability §8.5 forbids;
// the unsigned controls (u3, u12) and the byte-multiple ones (i8, i16) pass
// under that ablation, which is why the signed sub-byte leaves are listed
// explicitly. The cardinality check catches a decoder that rejects too much.
test "codec exhaustive per-leaf canonicality: i1, i3, u3, i8, i9, i12, u12, i16, bool, enum(u2), enum(i4)" {
    try probeExhaustive(i1, 2);
    try probeExhaustive(i3, 8);
    try probeExhaustive(u3, 8);
    try probeExhaustive(i8, 256);
    try probeExhaustive(i9, 512);
    try probeExhaustive(i12, 4096);
    try probeExhaustive(u12, 4096);
    try probeExhaustive(i16, 65536);
    try probeExhaustive(bool, 2);
    try probeExhaustive(enum(u2) { a, b, c }, 3);
    try probeExhaustive(enum(i4) { lo = -8, zero = 0, hi = 7 }, 3);
}

// -- Options is spelled by its public path (S8 review, D10) --------------------

// Non-vacuity: reifying the mirror inside a private helper (`fn
// MirrorOptions() type { ... @Struct(...) }`, the M6 code) spells the type
// `node.app_node.MirrorOptions.Mirror` — a private name the Stable API
// snapshot then pins on the `create` line, so renaming that helper is a
// "breaking change" with no consumer-visible effect.
test "AppNode(App).Options: @typeName is the public AppNode(...) path, not a private helper's" {
    const name = @typeName(CounterNode.Options);
    try testing.expect(std.mem.indexOf(u8, name, "AppNode(") != null);
    try testing.expect(std.mem.indexOf(u8, name, "Mirror") == null);
}
