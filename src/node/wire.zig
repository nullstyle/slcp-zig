//! Overlay frame codec (design §9.1): a typed `OverlayFrame` union ⇄ the
//! `overlay.capnp` `Frame` message bytes that travel on the wire.
//!
//! The seam between the overlay's socket plumbing and the engine's byte
//! contracts. Two protocol-critical conversions live here and nowhere else:
//!
//!   * An `envelope` frame carries a nested `Slcp.Envelope`. The engine,
//!     though, speaks *standalone framed Envelope message bytes* (what
//!     `envelope_received` / `broadcast_envelope` use). So encode COPIES the
//!     two Data fields (statementBytes, signature) out of a standalone
//!     envelope message into the Frame's nested struct, and decode
//!     re-serializes the nested struct back into a standalone message. The
//!     envelope frame is never signed over its own framing — only
//!     statementBytes are — so this re-serialization is safe by construction.
//!
//!   * A `qset` frame carries a nested recursive `Slcp.QuorumSet`. Same idea:
//!     encode copies a standalone QuorumSet message into the nested struct
//!     (bounded: depth ≤ 4, ≤ 255 validators — the §4.5 wire limits), decode
//!     re-serializes it back out.
//!
//! Everything here is pure (allocator in, bytes out) and single-threaded per
//! call. Decoded frames own their heap slices; free them with `deinit`.

const std = @import("std");
const core = @import("slcp-core");

const capnpc = core.capnpc;
const gen_overlay = core.gen.overlay;
const gen_slcp = core.gen.slcp;
const Message = capnpc.message.Message;
const MessageBuilder = capnpc.message.MessageBuilder;

/// §9.1 frame-shape limits (also enforced by the schema comments).
pub const max_slot_state_envelopes = 64;
pub const max_app_message_bytes: usize = 64 * 1024;
pub const protocol_version: u32 = 1;
/// Hello feature bit 0: the peer can send and receive `app_message` frames.
pub const feature_app_messages: u64 = 1 << 0;

pub const Error = error{
    MalformedFrame,
    UnsetUnion,
    InvalidEnumValue,
    TooManyEnvelopes,
    AppMessageTooLarge,
    BadFieldLength,
    OutOfMemory,
};

pub const Hello = struct {
    protocol_version: u32,
    /// Append-only capability bits. Unknown bits are preserved by the codec.
    feature_flags: u64 = 0,
    network_id_prefix: [8]u8,
    node_id: [32]u8,
    current_slot: u64,
    listen_port: u16,
};

pub const DontHave = struct {
    kind: u8,
    /// 32-byte content hash on decode; borrowed on encode.
    id: []const u8,
};

pub const SlotState = struct {
    slot: u64,
    /// Each entry is standalone framed Envelope message bytes.
    envelopes: []const []const u8,
};

/// A decoded/decodable overlay frame. On decode the byte-bearing arms own
/// heap; call `deinit` to release them.
pub const OverlayFrame = union(enum) {
    hello: Hello,
    /// Standalone framed Envelope message bytes.
    envelope: []const u8,
    /// 32-byte qset content hash.
    get_qset: [32]u8,
    /// Standalone framed QuorumSet message bytes.
    qset: []const u8,
    dont_have: DontHave,
    get_slot_state: u64,
    slot_state: SlotState,
    ping: u64,
    pong: u64,
    /// Opaque application payload. Owned on decode; borrowed on encode.
    app_message: []const u8,

    pub fn deinit(self: *OverlayFrame, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .envelope => |b| gpa.free(b),
            .qset => |b| gpa.free(b),
            .dont_have => |dh| gpa.free(dh.id),
            .app_message => |payload| gpa.free(payload),
            .slot_state => |ss| {
                for (ss.envelopes) |e| gpa.free(e);
                gpa.free(ss.envelopes);
            },
            else => {},
        }
        self.* = undefined;
    }
};

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

/// Encode a typed frame into framed `Frame` message bytes (owned by caller).
/// Borrows all slices in `frame`; makes its own copies.
pub fn encode(gpa: std.mem.Allocator, frame: OverlayFrame) Error![]u8 {
    var mb = MessageBuilder.init(gpa);
    defer mb.deinit();
    var fb = gen_overlay.Frame.Builder.init(&mb) catch return error.OutOfMemory;

    switch (frame) {
        .hello => |h| {
            var hb = fb.initHello() catch return error.OutOfMemory;
            hb.setProtocolVersion(h.protocol_version) catch return error.OutOfMemory;
            hb.setFeatureFlags(h.feature_flags) catch return error.OutOfMemory;
            hb.setNetworkIdPrefix(&h.network_id_prefix) catch return error.OutOfMemory;
            hb.setNodeId(&h.node_id) catch return error.OutOfMemory;
            hb.setCurrentSlot(h.current_slot) catch return error.OutOfMemory;
            hb.setListenPort(h.listen_port) catch return error.OutOfMemory;
        },
        .envelope => |env_bytes| {
            var eb = fb.initEnvelope() catch return error.OutOfMemory;
            try copyEnvelopeInto(gpa, &eb, env_bytes);
        },
        .get_qset => |hash| fb.setGetQset(&hash) catch return error.OutOfMemory,
        .qset => |qset_bytes| {
            var qb = fb.initQset() catch return error.OutOfMemory;
            try copyQsetInto(gpa, &qb, qset_bytes);
        },
        .dont_have => |dh| {
            var db = fb.initDontHave() catch return error.OutOfMemory;
            db.setKind(dh.kind) catch return error.OutOfMemory;
            db.setId(dh.id) catch return error.OutOfMemory;
        },
        .get_slot_state => |slot| fb.setGetSlotState(slot) catch return error.OutOfMemory,
        .slot_state => |ss| {
            if (ss.envelopes.len > max_slot_state_envelopes) return error.TooManyEnvelopes;
            var sb = fb.initSlotState() catch return error.OutOfMemory;
            sb.setSlot(ss.slot) catch return error.OutOfMemory;
            var list = sb.initEnvelopes(@intCast(ss.envelopes.len)) catch return error.OutOfMemory;
            for (ss.envelopes, 0..) |env_bytes, i| {
                var eb = list.get(@intCast(i)) catch return error.OutOfMemory;
                try copyEnvelopeInto(gpa, &eb, env_bytes);
            }
        },
        .ping => |n| fb.setPing(n) catch return error.OutOfMemory,
        .pong => |n| fb.setPong(n) catch return error.OutOfMemory,
        .app_message => |payload| {
            if (payload.len > max_app_message_bytes) return error.AppMessageTooLarge;
            fb.setAppMessage(payload) catch return error.OutOfMemory;
        },
    }

    return @constCast(mb.toBytes() catch return error.OutOfMemory);
}

/// Copy statementBytes + signature out of a standalone framed Envelope
/// message into an Envelope struct builder.
fn copyEnvelopeInto(gpa: std.mem.Allocator, eb: *gen_slcp.Envelope.Builder, env_bytes: []const u8) Error!void {
    var msg = Message.init(gpa, env_bytes, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedFrame,
    };
    defer msg.deinit();
    const r = gen_slcp.Envelope.Reader.init(&msg) catch return error.MalformedFrame;
    const sb = r.getStatementBytes() catch return error.MalformedFrame;
    const sig = r.getSignature() catch return error.MalformedFrame;
    eb.setStatementBytes(sb) catch return error.OutOfMemory;
    eb.setSignature(sig) catch return error.OutOfMemory;
}

/// Copy a standalone framed QuorumSet message into a QuorumSet struct
/// builder (recursive; bounded by §4.5 limits).
fn copyQsetInto(gpa: std.mem.Allocator, qb: *gen_slcp.QuorumSet.Builder, qset_bytes: []const u8) Error!void {
    var msg = Message.init(gpa, qset_bytes, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedFrame,
    };
    defer msg.deinit();
    const r = gen_slcp.QuorumSet.Reader.init(&msg) catch return error.MalformedFrame;
    try copyQsetReaderInto(qb, r, core.qset.max_depth);
}

fn copyQsetReaderInto(qb: *gen_slcp.QuorumSet.Builder, r: gen_slcp.QuorumSet.Reader, depth_left: u32) Error!void {
    if (depth_left == 0) return error.MalformedFrame;
    qb.setThreshold(r.getThreshold() catch return error.MalformedFrame) catch return error.OutOfMemory;

    const vr = r.getValidators() catch return error.MalformedFrame;
    const vn = vr.len();
    if (vn > 0) {
        var vb = qb.initValidators(vn) catch return error.OutOfMemory;
        var i: u32 = 0;
        while (i < vn) : (i += 1) {
            const v = vr.get(i) catch return error.MalformedFrame;
            vb.set(i, v) catch return error.OutOfMemory;
        }
    }

    const ir = r.getInnerSets() catch return error.MalformedFrame;
    const inn = ir.len();
    if (inn > 0) {
        var ib = qb.initInnerSets(inn) catch return error.OutOfMemory;
        var i: u32 = 0;
        while (i < inn) : (i += 1) {
            const child_r = ir.get(i) catch return error.MalformedFrame;
            var child_b = ib.get(i) catch return error.OutOfMemory;
            try copyQsetReaderInto(&child_b, child_r, depth_left - 1);
        }
    }
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

/// Decode framed `Frame` message bytes into a typed frame. The returned
/// frame owns any heap slices; free with `OverlayFrame.deinit`.
pub fn decode(gpa: std.mem.Allocator, bytes: []const u8) Error!OverlayFrame {
    var msg = Message.init(gpa, bytes, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedFrame,
    };
    defer msg.deinit();
    const fr = gen_overlay.Frame.Reader.init(&msg) catch return error.MalformedFrame;

    switch (fr.which() catch return error.InvalidEnumValue) {
        .unset => return error.UnsetUnion,
        .hello => {
            const h = fr.getHello() catch return error.MalformedFrame;
            const prefix = h.getNetworkIdPrefix() catch return error.MalformedFrame;
            const node_id = h.getNodeId() catch return error.MalformedFrame;
            if (prefix.len != 8 or node_id.len != 32) return error.BadFieldLength;
            var out = Hello{
                .protocol_version = h.getProtocolVersion() catch return error.MalformedFrame,
                .feature_flags = h.getFeatureFlags() catch return error.MalformedFrame,
                .network_id_prefix = undefined,
                .node_id = undefined,
                .current_slot = h.getCurrentSlot() catch return error.MalformedFrame,
                .listen_port = h.getListenPort() catch return error.MalformedFrame,
            };
            @memcpy(&out.network_id_prefix, prefix);
            @memcpy(&out.node_id, node_id);
            return .{ .hello = out };
        },
        .envelope => {
            const env_r = fr.getEnvelope() catch return error.MalformedFrame;
            const standalone = try reserializeEnvelope(gpa, env_r);
            return .{ .envelope = standalone };
        },
        .getQset => {
            const id = fr.getGetQset() catch return error.MalformedFrame;
            if (id.len != 32) return error.BadFieldLength;
            var hash: [32]u8 = undefined;
            @memcpy(&hash, id);
            return .{ .get_qset = hash };
        },
        .qset => {
            const qr = fr.getQset() catch return error.MalformedFrame;
            const standalone = try reserializeQset(gpa, qr);
            return .{ .qset = standalone };
        },
        .dontHave => {
            const dh = fr.getDontHave() catch return error.MalformedFrame;
            const id = dh.getId() catch return error.MalformedFrame;
            const owned = gpa.dupe(u8, id) catch return error.OutOfMemory;
            return .{ .dont_have = .{ .kind = dh.getKind() catch return error.MalformedFrame, .id = owned } };
        },
        .getSlotState => return .{ .get_slot_state = fr.getGetSlotState() catch return error.MalformedFrame },
        .slotState => {
            const ss = fr.getSlotState() catch return error.MalformedFrame;
            const list = ss.getEnvelopes() catch return error.MalformedFrame;
            const n = list.len();
            if (n > max_slot_state_envelopes) return error.TooManyEnvelopes;
            const out = gpa.alloc([]const u8, n) catch return error.OutOfMemory;
            var filled: u32 = 0;
            errdefer {
                for (out[0..filled]) |e| gpa.free(e);
                gpa.free(out);
            }
            while (filled < n) : (filled += 1) {
                const env_r = list.get(filled) catch return error.MalformedFrame;
                out[filled] = try reserializeEnvelope(gpa, env_r);
            }
            return .{ .slot_state = .{ .slot = ss.getSlot() catch return error.MalformedFrame, .envelopes = out } };
        },
        .ping => return .{ .ping = fr.getPing() catch return error.MalformedFrame },
        .pong => return .{ .pong = fr.getPong() catch return error.MalformedFrame },
        .appMessage => {
            const payload = fr.getAppMessage() catch return error.MalformedFrame;
            if (payload.len > max_app_message_bytes) return error.AppMessageTooLarge;
            const owned = gpa.dupe(u8, payload) catch return error.OutOfMemory;
            return .{ .app_message = owned };
        },
    }
}

/// Re-serialize a nested Envelope reader into standalone framed message bytes.
fn reserializeEnvelope(gpa: std.mem.Allocator, r: gen_slcp.Envelope.Reader) Error![]u8 {
    const sb = r.getStatementBytes() catch return error.MalformedFrame;
    const sig = r.getSignature() catch return error.MalformedFrame;
    var mb = MessageBuilder.init(gpa);
    defer mb.deinit();
    var eb = gen_slcp.Envelope.Builder.init(&mb) catch return error.OutOfMemory;
    eb.setStatementBytes(sb) catch return error.OutOfMemory;
    eb.setSignature(sig) catch return error.OutOfMemory;
    return @constCast(mb.toBytes() catch return error.OutOfMemory);
}

/// Re-serialize a nested QuorumSet reader into standalone framed message bytes.
fn reserializeQset(gpa: std.mem.Allocator, r: gen_slcp.QuorumSet.Reader) Error![]u8 {
    var mb = MessageBuilder.init(gpa);
    defer mb.deinit();
    var qb = gen_slcp.QuorumSet.Builder.init(&mb) catch return error.OutOfMemory;
    try copyQsetReaderInto(&qb, r, core.qset.max_depth);
    return @constCast(mb.toBytes() catch return error.OutOfMemory);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Build standalone framed Envelope bytes with arbitrary Data fields (wire.zig
/// only copies the two blobs; they need not be a valid statement).
fn fakeEnvelope(gpa: std.mem.Allocator, stmt: []const u8, sig: []const u8) ![]u8 {
    var mb = MessageBuilder.init(gpa);
    defer mb.deinit();
    var eb = try gen_slcp.Envelope.Builder.init(&mb);
    try eb.setStatementBytes(stmt);
    try eb.setSignature(sig);
    return @constCast(try mb.toBytes());
}

fn envStatement(gpa: std.mem.Allocator, framed_env: []const u8) ![]u8 {
    var msg = try Message.init(gpa, framed_env, .{});
    defer msg.deinit();
    const r = try gen_slcp.Envelope.Reader.init(&msg);
    return gpa.dupe(u8, try r.getStatementBytes());
}

test "wire: scalar frames round-trip" {
    const gpa = testing.allocator;
    const cases = [_]OverlayFrame{
        .{ .ping = 0xDEADBEEF },
        .{ .pong = 42 },
        .{ .get_slot_state = 123456789 },
        .{ .get_qset = @splat(7) },
        .{ .hello = .{
            .protocol_version = 1,
            .feature_flags = 0x8000_0000_0000_0001,
            .network_id_prefix = .{ 1, 2, 3, 4, 5, 6, 7, 8 },
            .node_id = @splat(9),
            .current_slot = 77,
            .listen_port = 7311,
        } },
    };
    for (cases) |c| {
        const bytes = try encode(gpa, c);
        defer gpa.free(bytes);
        var got = try decode(gpa, bytes);
        defer got.deinit(gpa);
        try testing.expectEqual(std.meta.activeTag(c), std.meta.activeTag(got));
        switch (c) {
            .ping => |n| try testing.expectEqual(n, got.ping),
            .pong => |n| try testing.expectEqual(n, got.pong),
            .get_slot_state => |n| try testing.expectEqual(n, got.get_slot_state),
            .get_qset => |h| try testing.expectEqualSlices(u8, &h, &got.get_qset),
            .hello => |h| {
                try testing.expectEqual(h.protocol_version, got.hello.protocol_version);
                try testing.expectEqual(h.feature_flags, got.hello.feature_flags);
                try testing.expectEqualSlices(u8, &h.network_id_prefix, &got.hello.network_id_prefix);
                try testing.expectEqualSlices(u8, &h.node_id, &got.hello.node_id);
                try testing.expectEqual(h.current_slot, got.hello.current_slot);
                try testing.expectEqual(h.listen_port, got.hello.listen_port);
            },
            else => unreachable,
        }
    }
}

test "wire: dont_have round-trips its id" {
    const gpa = testing.allocator;
    const id: [32]u8 = @splat(0xAB);
    const bytes = try encode(gpa, .{ .dont_have = .{ .kind = 3, .id = &id } });
    defer gpa.free(bytes);
    var got = try decode(gpa, bytes);
    defer got.deinit(gpa);
    try testing.expectEqual(@as(u8, 3), got.dont_have.kind);
    try testing.expectEqualSlices(u8, &id, got.dont_have.id);
}

test "wire: app_message decode owns the opaque payload" {
    const gpa = testing.allocator;
    const encoded = try encode(gpa, .{ .app_message = "opaque-application-message" });
    defer gpa.free(encoded);

    var got = try decode(gpa, encoded);
    defer got.deinit(gpa);
    @memset(encoded, 0xA5);

    try testing.expectEqualSlices(u8, "opaque-application-message", got.app_message);
}

test "wire: app_message encode accepts 64 KiB and rejects one byte more" {
    const gpa = testing.allocator;
    const at_cap = try gpa.alloc(u8, max_app_message_bytes);
    defer gpa.free(at_cap);
    @memset(at_cap, 0x3C);
    const encoded = try encode(gpa, .{ .app_message = at_cap });
    defer gpa.free(encoded);
    var decoded = try decode(gpa, encoded);
    defer decoded.deinit(gpa);
    try testing.expectEqual(@as(usize, max_app_message_bytes), decoded.app_message.len);

    const over_cap = try gpa.alloc(u8, max_app_message_bytes + 1);
    defer gpa.free(over_cap);
    try testing.expectError(error.AppMessageTooLarge, encode(gpa, .{ .app_message = over_cap }));
}

test "wire: app_message decode rejects a raw payload over 64 KiB" {
    const gpa = testing.allocator;
    const over_cap = try gpa.alloc(u8, max_app_message_bytes + 1);
    defer gpa.free(over_cap);

    var mb = MessageBuilder.init(gpa);
    defer mb.deinit();
    var fb = try gen_overlay.Frame.Builder.init(&mb);
    try fb.setAppMessage(over_cap);
    const raw = @constCast(try mb.toBytes());
    defer gpa.free(raw);

    var decoded = decode(gpa, raw) catch |err| {
        try testing.expectEqual(error.AppMessageTooLarge, err);
        return;
    };
    defer decoded.deinit(gpa);
    return error.TestExpectedError;
}

test "wire: envelope frame preserves statement + signature bytes" {
    const gpa = testing.allocator;
    const sig: [64]u8 = @splat(0x5A);
    const env = try fakeEnvelope(gpa, "statement-bytes-here", &sig);
    defer gpa.free(env);

    const frame = try encode(gpa, .{ .envelope = env });
    defer gpa.free(frame);
    var got = try decode(gpa, frame);
    defer got.deinit(gpa);

    const got_stmt = try envStatement(gpa, got.envelope);
    defer gpa.free(got_stmt);
    try testing.expectEqualSlices(u8, "statement-bytes-here", got_stmt);
}

test "wire: qset frame preserves a nested tree" {
    const gpa = testing.allocator;
    // Build { threshold=2, validators=[a,b], inner=[{threshold=1, [c]}] }.
    var mb = MessageBuilder.init(gpa);
    defer mb.deinit();
    const va: [32]u8 = @splat(0xA1);
    const vb_val: [32]u8 = @splat(0xB2);
    const vc: [32]u8 = @splat(0xC3);
    var qb = try gen_slcp.QuorumSet.Builder.init(&mb);
    try qb.setThreshold(2);
    var vb = try qb.initValidators(2);
    try vb.set(0, &va);
    try vb.set(1, &vb_val);
    var ib = try qb.initInnerSets(1);
    var child = try ib.get(0);
    try child.setThreshold(1);
    var cvb = try child.initValidators(1);
    try cvb.set(0, &vc);
    const qbytes = @constCast(try mb.toBytes());
    defer gpa.free(qbytes);

    const frame = try encode(gpa, .{ .qset = qbytes });
    defer gpa.free(frame);
    var got = try decode(gpa, frame);
    defer got.deinit(gpa);

    var msg = try Message.init(gpa, got.qset, .{});
    defer msg.deinit();
    const r = try gen_slcp.QuorumSet.Reader.init(&msg);
    try testing.expectEqual(@as(u32, 2), try r.getThreshold());
    const vr = try r.getValidators();
    try testing.expectEqual(@as(u32, 2), vr.len());
    try testing.expectEqualSlices(u8, &va, try vr.get(0));
    const ir = try r.getInnerSets();
    try testing.expectEqual(@as(u32, 1), ir.len());
    const cr = try ir.get(0);
    try testing.expectEqual(@as(u32, 1), try cr.getThreshold());
}

test "wire: slot_state carries multiple envelopes; over-cap rejected" {
    const gpa = testing.allocator;
    const sig0: [64]u8 = @splat(1);
    const sig1: [64]u8 = @splat(2);
    const e0 = try fakeEnvelope(gpa, "s0", &sig0);
    defer gpa.free(e0);
    const e1 = try fakeEnvelope(gpa, "s1", &sig1);
    defer gpa.free(e1);
    const envs = [_][]const u8{ e0, e1 };

    const frame = try encode(gpa, .{ .slot_state = .{ .slot = 9, .envelopes = &envs } });
    defer gpa.free(frame);
    var got = try decode(gpa, frame);
    defer got.deinit(gpa);
    try testing.expectEqual(@as(u64, 9), got.slot_state.slot);
    try testing.expectEqual(@as(usize, 2), got.slot_state.envelopes.len);
    const s0 = try envStatement(gpa, got.slot_state.envelopes[0]);
    defer gpa.free(s0);
    try testing.expectEqualSlices(u8, "s0", s0);

    // Over-cap on encode is rejected.
    var big: [max_slot_state_envelopes + 1][]const u8 = undefined;
    for (&big) |*p| p.* = e0;
    try testing.expectError(error.TooManyEnvelopes, encode(gpa, .{ .slot_state = .{ .slot = 1, .envelopes = &big } }));
}

test "wire: unset union and garbage are rejected, not UB" {
    const gpa = testing.allocator;
    // A Frame with the union left at member 0 (unset) must be rejected.
    var mb = MessageBuilder.init(gpa);
    defer mb.deinit();
    var fb = try gen_overlay.Frame.Builder.init(&mb);
    try fb.setUnset({});
    const bytes = @constCast(try mb.toBytes());
    defer gpa.free(bytes);
    try testing.expectError(error.UnsetUnion, decode(gpa, bytes));

    try testing.expectError(error.MalformedFrame, decode(gpa, &[_]u8{ 0, 1, 2, 3 }));
}
