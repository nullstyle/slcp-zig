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
pub const protocol_version: u32 = 1;

pub const Error = error{
    MalformedFrame,
    UnsetUnion,
    InvalidEnumValue,
    TooManyEnvelopes,
    BadFieldLength,
    OutOfMemory,
};

pub const Hello = struct {
    protocol_version: u32,
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

    pub fn deinit(self: *OverlayFrame, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .envelope => |b| gpa.free(b),
            .qset => |b| gpa.free(b),
            .dont_have => |dh| gpa.free(dh.id),
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
