//! ============================================================================
//! PROTOTYPE — THROWAWAY CODE. This is NOT slcp-zig source.
//! ============================================================================
//! Question this answers: does the comptime `AppNode(App)` driver DX feel
//! right, and can comptime enforce the determinism rules with friendly
//! compile errors?
//!
//! Run the demo:        zig run appnode_proto.zig
//! See compile errors:  sh show_errors.sh        (each case SHOULD fail)
//!
//! What is real here: the `AppNode` comptime adapter, the contract checks,
//! the auto-codec, and the raw byte-level `Driver` vtable it compiles down to
//! (mirrors claude-design.md §8.2).
//! What is fake here: `StubEngine` is NOT SCP — it just pumps the driver
//! path (validate → combine → apply) so the DX can be felt end to end.
//! ============================================================================

const std = @import("std");

// ---------------------------------------------------------------------------
// The frozen low-level contract (mirrors design §8.2, trimmed for the proto).
// AppNode compiles down to THIS; the engine only ever sees bytes.
// ---------------------------------------------------------------------------

pub const Validity = enum(u2) { invalid = 0, maybe_valid = 1, valid = 2 };

pub const DriverError = error{ OutOfMemory, DriverFault };

pub const Driver = struct {
    ctx: *anyopaque,
    validate_value: *const fn (ctx: *anyopaque, slot: u64, value: []const u8) Validity,
    combine_candidates: *const fn (ctx: *anyopaque, slot: u64, candidates: []const []const u8, gpa: std.mem.Allocator, out: *std.ArrayList(u8)) DriverError!void,
};

// ---------------------------------------------------------------------------
// Auto-codec: comptime-derived canonical fixed-size encoding for Command
// types. Big-endian, sign-bit-biased ints => byte order == numeric order,
// so the default combine ("highest wins") is correct for free.
// Floats and pointers are REJECTED at compile time — that is the point.
// ---------------------------------------------------------------------------

fn ceilToByteBits(comptime bits: u16) u16 {
    return ((bits + 7) / 8) * 8;
}

/// Compile-time gate: is T allowed in an auto-encoded Command?
/// Every rejection message teaches the rule it enforces.
fn checkEncodable(comptime T: type, comptime path: []const u8) void {
    switch (@typeInfo(T)) {
        .int => {},
        .bool => {},
        .@"enum" => {},
        .float => @compileError("slcp auto-codec: `" ++ path ++ "` is a " ++ @typeName(T) ++
            " — floats are NONDETERMINISTIC across nodes (NaN payloads, ±0, platform math differences)." ++
            "\n  Use fixed-point integers (e.g. cents as u64), or provide your own" ++
            "\n  `pub fn encode(cmd: Command, buf: []u8) []u8` + `pub fn decode(bytes: []const u8) ?Command`."),
        .pointer => @compileError("slcp auto-codec: `" ++ path ++ "` is a pointer/slice (" ++ @typeName(T) ++ ")." ++
            "\n  Variable-length data needs an explicit canonical layout: provide your own" ++
            "\n  `pub fn encode` / `pub fn decode` on the app, or use a bounded [N]u8 array."),
        .optional => @compileError("slcp auto-codec: `" ++ path ++ "` is optional (" ++ @typeName(T) ++ ")." ++
            "\n  Optionality has no single canonical encoding; model it explicitly" ++
            "\n  (e.g. a tag enum + zeroed payload) or provide your own encode/decode."),
        .array => |a| checkEncodable(a.child, path ++ "[i]"),
        .@"struct" => |s| {
            inline for (s.field_names, s.field_types) |fname, FT| checkEncodable(FT, path ++ "." ++ fname);
        },
        else => @compileError("slcp auto-codec: `" ++ path ++ "` has type " ++ @typeName(T) ++
            ", which the auto-codec does not cover. Provide your own encode/decode."),
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

fn encodeValue(comptime T: type, v: T, buf: []u8) usize {
    switch (@typeInfo(T)) {
        .int => |i| {
            const bits = comptime ceilToByteBits(i.bits);
            const U = @Int(.unsigned, bits);
            const u: U = if (i.signedness == .signed)
                // bias: flip the sign bit so byte order == numeric order
                @as(U, @as(@Int(.unsigned, i.bits), @bitCast(v))) ^ (@as(U, 1) << (i.bits - 1))
            else
                @as(U, v);
            std.mem.writeInt(U, buf[0 .. bits / 8], u, .big);
            return bits / 8;
        },
        .bool => {
            buf[0] = @intFromBool(v);
            return 1;
        },
        .@"enum" => |e| {
            const TagBits = comptime ceilToByteBits(@typeInfo(e.tag_type).int.bits);
            const U = @Int(.unsigned, TagBits);
            std.mem.writeInt(U, buf[0 .. TagBits / 8], @as(U, @intFromEnum(v)), .big);
            return TagBits / 8;
        },
        .array => {
            var off: usize = 0;
            for (v) |elem| off += encodeValue(@TypeOf(elem), elem, buf[off..]);
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

fn decodeValue(comptime T: type, bytes: []const u8, off: *usize) ?T {
    switch (@typeInfo(T)) {
        .int => |i| {
            const bits = comptime ceilToByteBits(i.bits);
            const U = @Int(.unsigned, bits);
            if (bytes.len < off.* + bits / 8) return null;
            const raw = std.mem.readInt(U, bytes[off.*..][0 .. bits / 8], .big);
            off.* += bits / 8;
            if (i.signedness == .signed) {
                const N = @Int(.unsigned, i.bits);
                const unbiased = std.math.cast(N, raw ^ (@as(U, 1) << (i.bits - 1))) orelse return null;
                return @bitCast(unbiased);
            }
            return std.math.cast(T, raw); // null on non-canonical high bits
        },
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
            const TagBits = comptime ceilToByteBits(@typeInfo(e.tag_type).int.bits);
            const U = @Int(.unsigned, TagBits);
            if (bytes.len < off.* + TagBits / 8) return null;
            const raw = std.mem.readInt(U, bytes[off.*..][0 .. TagBits / 8], .big);
            off.* += TagBits / 8;
            return std.enums.fromInt(T, raw);
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

/// The codec for one Command type: fixed size, canonical, order-preserving.
pub fn Codec(comptime T: type) type {
    comptime checkEncodable(T, @typeName(T));
    return struct {
        pub const size = encodedSizeOf(T);
        pub fn encode(v: T, buf: []u8) []u8 {
            const n = encodeValue(T, v, buf);
            std.debug.assert(n == size);
            return buf[0..n];
        }
        pub fn decode(bytes: []const u8) ?T {
            if (bytes.len != size) return null; // canonical: exact length
            var off: usize = 0;
            return decodeValue(T, bytes, &off);
        }
    };
}

// ---------------------------------------------------------------------------
// AppNode(App): the comptime adapter. You write a pure state machine;
// this builds the byte-level Driver and owns the replicated State.
// ---------------------------------------------------------------------------

fn contractError(comptime app: []const u8, comptime msg: []const u8) noreturn {
    @compileError("slcp.AppNode(" ++ app ++ "): " ++ msg);
}

fn validateAppContract(comptime App: type) void {
    const name = @typeName(App);
    if (!@hasDecl(App, "State"))
        contractError(name, "missing `pub const State` — the replicated state type." ++
            "\n  Every node holds one State; it only changes via apply().");
    if (!@hasDecl(App, "Command"))
        contractError(name, "missing `pub const Command` — the value type the network agrees on.");
    if (!@hasDecl(App, "validate"))
        contractError(name, "missing `pub fn validate(state: State, cmd: Command) slcp.Validity`." ++
            "\n  Return .valid / .invalid, or .maybe_valid when this node cannot judge yet" ++
            "\n  (e.g. it is behind). Must be pure and deterministic.");
    if (@TypeOf(App.validate) != fn (App.State, App.Command) Validity)
        contractError(name, "validate has the wrong signature." ++
            "\n  want: fn (State, Command) slcp.Validity" ++
            "\n  got:  " ++ @typeName(@TypeOf(App.validate)));
    if (!@hasDecl(App, "apply"))
        contractError(name, "missing `pub fn apply(state: State, cmd: Command) State`." ++
            "\n  apply is how an agreed command updates your replicated state." ++
            "\n  It runs on the engine thread; keep it pure — no I/O, no clock.");
    if (@TypeOf(App.apply) != fn (App.State, App.Command) App.State)
        contractError(name, "apply has the wrong signature." ++
            "\n  want: fn (State, Command) State" ++
            "\n  got:  " ++ @typeName(@TypeOf(App.apply)));
    if (@hasDecl(App, "combine")) {
        if (@TypeOf(App.combine) != fn (App.State, []const App.Command) App.Command)
            contractError(name, "combine has the wrong signature." ++
                "\n  want: fn (State, []const Command) Command" ++
                "\n  got:  " ++ @typeName(@TypeOf(App.combine)) ++
                "\n  combine must be deterministic and total; its result must self-validate .valid.");
    }
    // State must be constructible: initialState(), or every field defaulted.
    if (!@hasDecl(App, "initialState")) {
        const si = @typeInfo(App.State);
        if (si == .@"struct") {
            inline for (si.@"struct".field_names, si.@"struct".field_attrs) |fname, attrs| {
                if (attrs.default_value_ptr == null)
                    contractError(name, "State field `" ++ fname ++ "` has no default value." ++
                        "\n  Give every State field a default, or provide `pub fn initialState() State`.");
            }
        }
    }
}

/// Wraps an app-supplied custom codec (`pub fn encode` + `pub fn decode`).
/// This is the escape hatch every auto-codec rejection points at.
fn CustomCodec(comptime App: type) type {
    if (!@hasDecl(App, "encode") or !@hasDecl(App, "decode"))
        contractError(@typeName(App), "a custom codec needs BOTH" ++
            "\n  `pub fn encode(cmd: Command, buf: []u8) []u8` and" ++
            "\n  `pub fn decode(bytes: []const u8) ?Command`.");
    return struct {
        pub const size = 64; // proto: scratch bound for custom (possibly variable-length) codecs
        pub fn encode(v: App.Command, buf: []u8) []u8 {
            return App.encode(v, buf);
        }
        pub fn decode(bytes: []const u8) ?App.Command {
            // strict canonicality is the app's job here (exact length, one spelling)
            return App.decode(bytes);
        }
    };
}

pub fn AppNode(comptime App: type) type {
    comptime validateAppContract(App);
    const C = if (@hasDecl(App, "encode") or @hasDecl(App, "decode"))
        CustomCodec(App)
    else
        Codec(App.Command);

    return struct {
        const Self = @This();
        pub const max_candidates = 16; // proto-only; real impl allocates up to the frozen 64-entry limit (§4.5)

        name: []const u8,
        state: App.State,
        applied_slots: u64 = 0,

        pub fn init(name: []const u8) Self {
            return .{ .name = name, .state = if (@hasDecl(App, "initialState")) App.initialState() else App.State{} };
        }

        /// The byte-level vtable the engine sees. All typed sugar ends here.
        pub fn driver(self: *Self) Driver {
            return .{
                .ctx = self,
                .validate_value = vtValidate,
                .combine_candidates = vtCombine,
            };
        }

        pub fn encodeCommand(cmd: App.Command, buf: []u8) []u8 {
            return C.encode(cmd, buf);
        }

        /// In the real node this runs on the engine thread when a slot
        /// externalizes — that is what makes shared state race-free.
        pub fn applyExternalized(self: *Self, bytes: []const u8) void {
            // A decode failure HERE is an invariant break: the network already
            // agreed on these bytes. Never silent — a real node must halt loudly.
            const cmd = C.decode(bytes) orelse @panic("applyExternalized: agreed value failed to decode (codec/version mismatch)");
            self.state = App.apply(self.state, cmd);
            self.applied_slots += 1;
        }

        fn vtValidate(ctx: *anyopaque, slot: u64, value: []const u8) Validity {
            _ = slot;
            const self: *Self = @ptrCast(@alignCast(ctx));
            const cmd = C.decode(value) orelse return .invalid;
            return App.validate(self.state, cmd);
        }

        fn vtCombine(ctx: *anyopaque, slot: u64, candidates: []const []const u8, gpa: std.mem.Allocator, out: *std.ArrayList(u8)) DriverError!void {
            _ = slot;
            const self: *Self = @ptrCast(@alignCast(ctx));
            if (candidates.len == 0) return error.DriverFault;
            if (@hasDecl(App, "combine")) {
                var cmds: [max_candidates]App.Command = undefined;
                var n: usize = 0;
                for (candidates) |c| {
                    if (n == max_candidates) break;
                    // candidates were validated ⇒ decodable; failure = codec bug, be loud
                    cmds[n] = C.decode(c) orelse return error.DriverFault;
                    n += 1;
                }
                if (n == 0) return error.DriverFault;
                const winner = App.combine(self.state, cmds[0..n]);
                var buf: [C.size]u8 = undefined;
                try out.appendSlice(gpa, C.encode(winner, &buf));
            } else {
                // Default: highest command wins. The codec is order-preserving,
                // so a byte compare IS the numeric compare.
                var best = candidates[0];
                for (candidates[1..]) |c| {
                    if (std.mem.order(u8, c, best) == .gt) best = c;
                }
                try out.appendSlice(gpa, best);
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Demo app 1: the counter. Smallest possible integration.
// ---------------------------------------------------------------------------

const Counter = struct {
    pub const State = struct { count: u64 = 0 };
    // DX lesson: agree on the VALUE ("count becomes 3"), never the OP ("add 1").
    // Ops break under the default highest-wins combine and under replay;
    // values are idempotent and totally ordered for free.
    pub const Command = struct { next: u64 };

    pub fn validate(state: State, cmd: Command) Validity {
        if (cmd.next == state.count + 1) return .valid;
        if (cmd.next > state.count + 1) return .maybe_valid; // we may be behind
        return .invalid;
    }

    pub fn apply(state: State, cmd: Command) State {
        _ = state;
        return .{ .count = cmd.next };
    }
    // no combine: default "highest command wins" is fine for a counter
};

// ---------------------------------------------------------------------------
// Demo app 2: an auction. Richer Command (enum field), custom combine.
// ---------------------------------------------------------------------------

const Auction = struct {
    pub const Bidder = enum(u8) { alice, bob, carol };
    pub const State = struct { high_cents: u64 = 0, holder: Bidder = .alice };
    pub const Command = struct { bid_cents: u64, bidder: Bidder };

    pub fn validate(state: State, cmd: Command) Validity {
        return if (cmd.bid_cents > state.high_cents) .valid else .invalid;
    }

    pub fn apply(state: State, cmd: Command) State {
        _ = state;
        return .{ .high_cents = cmd.bid_cents, .holder = cmd.bidder };
    }

    pub fn combine(state: State, cmds: []const Command) Command {
        _ = state;
        var best = cmds[0];
        for (cmds[1..]) |c| {
            if (c.bid_cents > best.bid_cents or
                (c.bid_cents == best.bid_cents and @intFromEnum(c.bidder) > @intFromEnum(best.bidder)))
                best = c;
        }
        return best;
    }
};

// ---------------------------------------------------------------------------
// Demo app 3: a memo board — proves the custom-codec escape hatch the
// auto-codec errors point at. Fixed-size Command value, VARIABLE-LENGTH wire.
// ---------------------------------------------------------------------------

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

    // custom codec: wire bytes are just the used prefix
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

    // custom bytes have no numeric order, so supply combine (longest memo wins)
    pub fn combine(state: State, cmds: []const Command) Command {
        _ = state;
        var best = cmds[0];
        for (cmds[1..]) |c| {
            if (c.len > best.len) best = c;
        }
        return best;
    }
};

fn memoCmd(text: []const u8) Memo.Command {
    var cmd = Memo.Command{ .len = @intCast(text.len), .text = @splat(' ') };
    @memcpy(cmd.text[0..text.len], text);
    return cmd;
}

// ---------------------------------------------------------------------------
// StubEngine: NOT SCP. Pumps validate → combine → apply across N fake nodes
// so the driver path can be watched. Real ordering/quorum logic is absent.
// ---------------------------------------------------------------------------

fn StubNet(comptime App: type, comptime n_nodes: usize) type {
    const Node = AppNode(App);
    return struct {
        const Self = @This();
        nodes: [n_nodes]Node,
        slot: u64 = 1,

        fn init(names: [n_nodes][]const u8) Self {
            var s: Self = .{ .nodes = undefined };
            for (&s.nodes, names) |*node, name| node.* = Node.init(name);
            return s;
        }

        /// One consensus round: proposals in, one winner applied everywhere
        /// (except nodes listed in `offline`, who miss it — to demo catch-up).
        fn runSlot(self: *Self, gpa: std.mem.Allocator, proposals: []const App.Command, offline: []const usize) !void {
            std.debug.print("\n=== slot {d} ===\n", .{self.slot});
            var bufs: [Node.max_candidates][64]u8 = undefined;
            var encoded: [Node.max_candidates][]const u8 = undefined;
            for (proposals, 0..) |p, i| {
                encoded[i] = Node.encodeCommand(p, &bufs[i]);
                std.debug.print("  proposal {any}  ({d} bytes)\n", .{ p, encoded[i].len });
            }
            const cands = encoded[0..proposals.len];

            // every node's driver judges every proposal
            for (&self.nodes) |*node| {
                var d = node.driver();
                for (cands, proposals) |c, p| {
                    const v = d.validate_value(d.ctx, self.slot, c);
                    std.debug.print("  validate @{s}: {any} -> {s}\n", .{ node.name, p, @tagName(v) });
                }
            }

            // node 0 combines (stub-leader)
            var d0 = self.nodes[0].driver();
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(gpa);
            try d0.combine_candidates(d0.ctx, self.slot, cands, gpa, &out);
            std.debug.print("  combined winner: {any}\n", .{Codec(App.Command).decode(out.items).?});

            // externalize: everyone online applies
            for (&self.nodes, 0..) |*node, i| {
                if (std.mem.indexOfScalar(usize, offline, i) != null) {
                    std.debug.print("  apply    @{s}: OFFLINE (missed this slot)\n", .{node.name});
                    continue;
                }
                node.applyExternalized(out.items);
                std.debug.print("  apply    @{s}: state = {any}\n", .{ node.name, node.state });
            }
            self.slot += 1;
        }
    };
}

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    std.debug.print("appnode_proto: comptime AppNode(App) DX demo (stub engine, NOT SCP)\n", .{});

    // ---- Counter: 3 nodes, happy path, then a node falls behind ----
    var net = StubNet(Counter, 3).init(.{ "A", "B", "C" });
    try net.runSlot(gpa, &.{ .{ .next = 1 }, .{ .next = 1 } }, &.{}); // agreement on identical proposals
    try net.runSlot(gpa, &.{.{ .next = 2 }}, &.{2}); // C offline: misses slot 2
    // C is now behind: watch it answer maybe_valid instead of vetoing
    try net.runSlot(gpa, &.{.{ .next = 3 }}, &.{});
    std.debug.print("\n  note: C said maybe_valid for {{next=3}} (it is behind), never invalid.\n", .{});
    std.debug.print("  final: A={any} B={any} C={any} (C catches up via slot replay in the real node)\n", .{ net.nodes[0].state, net.nodes[1].state, net.nodes[2].state });

    // ---- Auction: richer commands, custom combine ----
    var auction = StubNet(Auction, 3).init(.{ "A", "B", "C" });
    try auction.runSlot(gpa, &.{
        .{ .bid_cents = 500, .bidder = .alice },
        .{ .bid_cents = 725, .bidder = .bob },
        .{ .bid_cents = 725, .bidder = .carol }, // tie: custom combine breaks it
    }, &.{});

    // ---- Memo: the custom-codec escape hatch, end to end ----
    {
        var buf: [64]u8 = undefined;
        const wire = Memo.encode(memoCmd("hello"), &buf);
        var node = AppNode(Memo).init("M");
        node.applyExternalized(wire);
        std.debug.print("\ncustom codec: \"hello\" -> {d} wire bytes -> node state \"{s}\"\n", .{ wire.len, node.state.text[0..node.state.len] });
    }

    std.debug.print("\nall demos done.\n", .{});
}
