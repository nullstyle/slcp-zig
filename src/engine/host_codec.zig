//! host.capnp codec (design §7.1): the bidirectional mapping between the
//! engine's Zig unions (engine.Input / engine.Effect / engine.Config) and
//! framed host.capnp messages. This file is the byte-level engine contract —
//! the M4 WASM ABI (§7.2) moves exactly these frames across the boundary,
//! and the trace vectors (§13.4 set 6) record them verbatim.
//!
//! Trace format `vectors/traces/<name>.bin` (defined here AND in
//! vectors/traces/FORMAT.md — keep in sync):
//!   magic: 8 bytes ASCII "SLCPTRC1"
//!   then records until EOF, each:
//!     kind : u8   — 0 = config (EngineConfig frame; exactly one, first)
//!                   1 = input  (Input frame)
//!                   2 = effect (Effect frame, NORMATIVE — byte-exact)
//!                   3 = effect (Effect frame, OBSERVABLE — phase_event
//!                       only; replay may pin or ignore, §13.4)
//!     len  : u32 little-endian — payload byte length
//!     payload: len bytes — a framed host.capnp message (segment table +
//!              content, MessageBuilder.toBytes framing)
//!   Effect records for one input appear between that input's record and
//!   the next input record, in normative queue order; the input's single
//!   input_status effect is always the last of them (§5.1).
//!
//! Field mapping notes (§7.1):
//!   - Limits: 0 on the wire = engine default. ENCODE writes the actual
//!     configured values (never 0 — defaults are nonzero); DECODE maps each
//!     0 field to the limits.zig default.
//!   - secretSeed: empty/absent Data = watcher (secret_seed = null).
//!   - strictCanonical: capnp default true (host.capnp is unsigned, so a
//!     non-zero default is allowed).
//!   - quorumSet decode runs the full receive pipeline: fromReader →
//!     validateAndNormalize (Config.quorum_set is pre-validated by
//!     contract, §5.1).
//!   - Empty Data fields are encoded as present zero-length Data (writeData
//!     always writes a pointer); readers treat absent and empty alike.

const std = @import("std");
const capnpc = @import("capnpc-zig");
const engine = @import("engine.zig");
const limits_mod = @import("limits.zig");
const qset = @import("qset.zig");
const gen_host = @import("../gen/host.zig");
const gen_slcp = @import("../gen/slcp.zig");

const Message = capnpc.message.Message;
const MessageBuilder = capnpc.message.MessageBuilder;

pub const CodecError = error{
    MalformedFrame,
    UnsetUnion,
    InvalidEnumValue,
    BadFieldLength,
};

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

/// Encode one engine Input as a framed host.capnp Input message. Caller
/// frees the returned bytes.
pub fn encodeInput(gpa: std.mem.Allocator, input: engine.Input) ![]u8 {
    var mb = MessageBuilder.init(gpa);
    defer mb.deinit();
    var b = try gen_host.Input.Builder.init(&mb);
    switch (input) {
        .envelope_received => |a| try b.setEnvelopeReceived(a.bytes),
        .timer_fired => |a| {
            var tk = try b.initTimerFired();
            try tk.setSlot(a.slot);
            try tk.setTimer(@intFromEnum(a.timer));
        },
        .nominate => |a| {
            var n = try b.initNominate();
            try n.setSlot(a.slot);
            try n.setValue(a.value);
            try n.setPrevValue(a.prev_value);
        },
        .qset_received => |a| try b.setQsetReceived(a.bytes),
        .restore_own_envelope => |a| try b.setRestoreOwnEnvelope(a.bytes),
        .purge_slots => |a| try b.setPurgeSlots(a.max_slot),
    }
    return @constCast(try mb.toBytes()); // toBytes allocates fresh bytes; caller owns/frees
}

/// Decode a framed host.capnp Input message into an engine Input whose byte
/// payloads are OWNED copies (free with deinitInput).
pub fn decodeInput(gpa: std.mem.Allocator, bytes: []const u8) !engine.Input {
    var msg = Message.init(gpa, bytes, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedFrame,
    };
    defer msg.deinit();
    const r = gen_host.Input.Reader.init(&msg) catch return error.MalformedFrame;
    switch (r.which() catch return error.InvalidEnumValue) {
        .unset => return error.UnsetUnion,
        .envelopeReceived => {
            const d = r.getEnvelopeReceived() catch return error.MalformedFrame;
            return .{ .envelope_received = .{ .bytes = try gpa.dupe(u8, d) } };
        },
        .timerFired => {
            const tk = r.getTimerFired() catch return error.MalformedFrame;
            return .{ .timer_fired = .{
                .slot = tk.getSlot() catch return error.MalformedFrame,
                .timer = try timerFromInt(tk.getTimer() catch return error.MalformedFrame),
            } };
        },
        .nominate => {
            const n = r.getNominate() catch return error.MalformedFrame;
            const value = try gpa.dupe(u8, n.getValue() catch return error.MalformedFrame);
            errdefer gpa.free(value);
            const prev = try gpa.dupe(u8, n.getPrevValue() catch return error.MalformedFrame);
            return .{ .nominate = .{
                .slot = n.getSlot() catch return error.MalformedFrame,
                .value = value,
                .prev_value = prev,
            } };
        },
        .qsetReceived => {
            const d = r.getQsetReceived() catch return error.MalformedFrame;
            return .{ .qset_received = .{ .bytes = try gpa.dupe(u8, d) } };
        },
        .restoreOwnEnvelope => {
            const d = r.getRestoreOwnEnvelope() catch return error.MalformedFrame;
            return .{ .restore_own_envelope = .{ .bytes = try gpa.dupe(u8, d) } };
        },
        .purgeSlots => {
            return .{ .purge_slots = .{ .max_slot = r.getPurgeSlots() catch return error.MalformedFrame } };
        },
    }
}

/// Free the owned payloads of a decodeInput result.
pub fn deinitInput(gpa: std.mem.Allocator, input: *engine.Input) void {
    switch (input.*) {
        .envelope_received => |a| gpa.free(a.bytes),
        .qset_received => |a| gpa.free(a.bytes),
        .restore_own_envelope => |a| gpa.free(a.bytes),
        .nominate => |a| {
            gpa.free(a.value);
            gpa.free(a.prev_value);
        },
        .timer_fired, .purge_slots => {},
    }
    input.* = undefined;
}

fn timerFromInt(v: u8) CodecError!engine.TimerId {
    return std.enums.fromInt(engine.TimerId, v) orelse error.InvalidEnumValue;
}

// ---------------------------------------------------------------------------
// Effect
// ---------------------------------------------------------------------------

/// Encode one engine Effect as a framed host.capnp Effect message. Caller
/// frees the returned bytes.
pub fn encodeEffect(gpa: std.mem.Allocator, effect: *const engine.Effect) ![]u8 {
    var mb = MessageBuilder.init(gpa);
    defer mb.deinit();
    var b = try gen_host.Effect.Builder.init(&mb);
    switch (effect.*) {
        .persist_own_envelope => |sb| {
            var s = try b.initPersistOwnEnvelope();
            try setSlotBytes(&s, sb);
        },
        .broadcast_envelope => |sb| {
            var s = try b.initBroadcastEnvelope();
            try setSlotBytes(&s, sb);
        },
        .forward_envelope => |sb| {
            var s = try b.initForwardEnvelope();
            try setSlotBytes(&s, sb);
        },
        .arm_timer => |t| {
            var a = try b.initArmTimer();
            try a.setSlot(t.slot);
            try a.setTimer(@intFromEnum(t.timer));
            try a.setDelayMs(t.delay_ms);
        },
        .cancel_timer => |t| {
            var tk = try b.initCancelTimer();
            try tk.setSlot(t.slot);
            try tk.setTimer(@intFromEnum(t.timer));
        },
        .request_qset => |rq| try b.setRequestQset(&rq.hash),
        .externalized => |sb| {
            var s = try b.initExternalized();
            try setSlotBytes(&s, sb);
        },
        .input_status => |st| try b.setInputStatus(@intFromEnum(st.code)),
        .phase_event => |p| {
            var pe = try b.initPhaseEvent();
            try pe.setSlot(p.slot);
            try pe.setKind(@intFromEnum(p.kind));
            try pe.setDetail(p.detail);
        },
    }
    return @constCast(try mb.toBytes()); // toBytes allocates fresh bytes; caller owns/frees
}

fn setSlotBytes(s: *gen_host.SlotBytes.Builder, sb: engine.Effect.SlotBytes) !void {
    try s.setSlot(sb.slot);
    try s.setBytes(sb.bytes);
}

/// Decode a framed host.capnp Effect message into an engine Effect whose
/// byte payloads are OWNED copies (free with Effect.deinitPayload).
pub fn decodeEffect(gpa: std.mem.Allocator, bytes: []const u8) !engine.Effect {
    var msg = Message.init(gpa, bytes, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedFrame,
    };
    defer msg.deinit();
    const r = gen_host.Effect.Reader.init(&msg) catch return error.MalformedFrame;
    switch (r.which() catch return error.InvalidEnumValue) {
        .unset => return error.UnsetUnion,
        .persistOwnEnvelope => {
            const sb = try readSlotBytes(gpa, r.getPersistOwnEnvelope() catch return error.MalformedFrame);
            return .{ .persist_own_envelope = sb };
        },
        .broadcastEnvelope => {
            const sb = try readSlotBytes(gpa, r.getBroadcastEnvelope() catch return error.MalformedFrame);
            return .{ .broadcast_envelope = sb };
        },
        .forwardEnvelope => {
            const sb = try readSlotBytes(gpa, r.getForwardEnvelope() catch return error.MalformedFrame);
            return .{ .forward_envelope = sb };
        },
        .armTimer => {
            const a = r.getArmTimer() catch return error.MalformedFrame;
            return .{ .arm_timer = .{
                .slot = a.getSlot() catch return error.MalformedFrame,
                .timer = try timerFromInt(a.getTimer() catch return error.MalformedFrame),
                .delay_ms = a.getDelayMs() catch return error.MalformedFrame,
            } };
        },
        .cancelTimer => {
            const tk = r.getCancelTimer() catch return error.MalformedFrame;
            return .{ .cancel_timer = .{
                .slot = tk.getSlot() catch return error.MalformedFrame,
                .timer = try timerFromInt(tk.getTimer() catch return error.MalformedFrame),
            } };
        },
        .requestQset => {
            const d = r.getRequestQset() catch return error.MalformedFrame;
            if (d.len != 32) return error.BadFieldLength;
            var hash: [32]u8 = undefined;
            @memcpy(&hash, d);
            return .{ .request_qset = .{ .hash = hash } };
        },
        .externalized => {
            const sb = try readSlotBytes(gpa, r.getExternalized() catch return error.MalformedFrame);
            return .{ .externalized = sb };
        },
        .inputStatus => {
            const code = r.getInputStatus() catch return error.MalformedFrame;
            const status = std.enums.fromInt(engine.InputStatus, code) orelse return error.InvalidEnumValue;
            return .{ .input_status = .{ .code = status } };
        },
        .phaseEvent => {
            const p = r.getPhaseEvent() catch return error.MalformedFrame;
            const kind_int = p.getKind() catch return error.MalformedFrame;
            return .{ .phase_event = .{
                .slot = p.getSlot() catch return error.MalformedFrame,
                .kind = std.enums.fromInt(engine.PhaseKind, kind_int) orelse return error.InvalidEnumValue,
                .detail = p.getDetail() catch return error.MalformedFrame,
            } };
        },
    }
}

fn readSlotBytes(gpa: std.mem.Allocator, r: gen_host.SlotBytes.Reader) !engine.Effect.SlotBytes {
    const d = r.getBytes() catch return error.MalformedFrame;
    return .{
        .slot = r.getSlot() catch return error.MalformedFrame,
        .bytes = try gpa.dupe(u8, d),
    };
}

// ---------------------------------------------------------------------------
// EngineConfig
// ---------------------------------------------------------------------------

/// Encode an engine Config as a framed host.capnp EngineConfig message.
/// Limits are written as the ACTUAL configured values (§7.1: 0 means
/// "engine default", and limits.zig defaults are all nonzero). Caller frees.
pub fn encodeEngineConfig(gpa: std.mem.Allocator, cfg: *const engine.Config) ![]u8 {
    var mb = MessageBuilder.init(gpa);
    defer mb.deinit();
    var b = try gen_host.EngineConfig.Builder.init(&mb);
    try b.setNetworkId(&cfg.network_id);
    try b.setNodeId(&cfg.node_id);
    if (cfg.secret_seed) |s| try b.setSecretSeed(&s);
    var qb = try b.initQuorumSet();
    try writeQsetInto(&qb, &cfg.quorum_set);
    var lb = try b.initLimits();
    try lb.setMaxValueBytes(cfg.limits.max_value_bytes);
    try lb.setMaxNominationValues(cfg.limits.max_nomination_values);
    try lb.setMaxPendingEnvelopes(cfg.limits.max_pending_envelopes);
    try lb.setMaxPendingBytes(cfg.limits.max_pending_bytes);
    try lb.setMaxLiveSlots(cfg.limits.max_live_slots);
    try lb.setMaxCachedQsets(cfg.limits.max_cached_qsets);
    try lb.setTimeoutCapMs(cfg.limits.timeout_cap_ms);
    try lb.setMaxStoredStatementBytes(cfg.limits.max_stored_statement_bytes);
    try b.setStrictCanonical(cfg.strict_canonical);
    return @constCast(try mb.toBytes()); // toBytes allocates fresh bytes; caller owns/frees
}

/// Decode a framed host.capnp EngineConfig into an engine Config ready for
/// Engine.init (which takes ownership of quorum_set). Limits fields of 0
/// decode to the engine defaults; empty secretSeed decodes to watcher mode.
pub fn decodeEngineConfig(gpa: std.mem.Allocator, bytes: []const u8) !engine.Config {
    var msg = Message.init(gpa, bytes, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedFrame,
    };
    defer msg.deinit();
    const r = gen_host.EngineConfig.Reader.init(&msg) catch return error.MalformedFrame;

    const nid = r.getNetworkId() catch return error.MalformedFrame;
    if (nid.len != 32) return error.BadFieldLength;
    var network_id: [32]u8 = undefined;
    @memcpy(&network_id, nid);

    const node = r.getNodeId() catch return error.MalformedFrame;
    if (node.len != 32) return error.BadFieldLength;
    var node_id: [32]u8 = undefined;
    @memcpy(&node_id, node);

    const seed_bytes = r.getSecretSeed() catch return error.MalformedFrame;
    var secret_seed: ?[32]u8 = null;
    if (seed_bytes.len == 32) {
        var s: [32]u8 = undefined;
        @memcpy(&s, seed_bytes);
        secret_seed = s;
    } else if (seed_bytes.len != 0) return error.BadFieldLength;

    const qr = r.getQuorumSet() catch return error.MalformedFrame;
    var owned = qset.fromReader(gpa, qr) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedFrame,
    };
    errdefer owned.deinit(gpa);
    qset.validateAndNormalize(gpa, &owned) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MalformedFrame,
    };

    const lr = r.getLimits() catch return error.MalformedFrame;
    const def = limits_mod.Limits{};
    const limits = limits_mod.Limits{
        .max_value_bytes = orDefault(lr.getMaxValueBytes() catch return error.MalformedFrame, def.max_value_bytes),
        .max_nomination_values = orDefault(lr.getMaxNominationValues() catch return error.MalformedFrame, def.max_nomination_values),
        .max_pending_envelopes = orDefault(lr.getMaxPendingEnvelopes() catch return error.MalformedFrame, def.max_pending_envelopes),
        .max_pending_bytes = orDefault(lr.getMaxPendingBytes() catch return error.MalformedFrame, def.max_pending_bytes),
        .max_live_slots = orDefault(lr.getMaxLiveSlots() catch return error.MalformedFrame, def.max_live_slots),
        .max_cached_qsets = orDefault(lr.getMaxCachedQsets() catch return error.MalformedFrame, def.max_cached_qsets),
        .timeout_cap_ms = orDefault(lr.getTimeoutCapMs() catch return error.MalformedFrame, def.timeout_cap_ms),
        .max_stored_statement_bytes = orDefault(lr.getMaxStoredStatementBytes() catch return error.MalformedFrame, def.max_stored_statement_bytes),
    };

    return .{
        .network_id = network_id,
        .node_id = node_id,
        .secret_seed = secret_seed,
        .quorum_set = owned,
        .strict_canonical = r.getStrictCanonical() catch return error.MalformedFrame,
        .limits = limits,
    };
}

fn orDefault(v: u32, default: u32) u32 {
    return if (v == 0) default else v;
}

/// Recursive QuorumSetOwned → wire builder (absent pointers for empty
/// lists, §4.3 discipline — same shape qset.canonicalBytes produces).
fn writeQsetInto(b: *gen_slcp.QuorumSet.Builder, qs: *const qset.QuorumSetOwned) !void {
    try b.setThreshold(qs.threshold);
    if (qs.validators.len > 0) {
        const vl = try b.initValidators(@intCast(qs.validators.len));
        for (qs.validators, 0..) |*v, i| try vl.set(@intCast(i), v);
    }
    if (qs.inner_sets.len > 0) {
        const il = try b.initInnerSets(@intCast(qs.inner_sets.len));
        for (qs.inner_sets, 0..) |*inner, i| {
            var ib = try il.get(@intCast(i));
            try writeQsetInto(&ib, inner);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — every arm of Input and Effect round-trips (leak-checked via
// std.testing.allocator), plus EngineConfig field mapping.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Round-trip one Input: encode → decode → re-encode. Byte-identical frames
/// prove the mapping is its own inverse at the wire level.
fn roundTripInput(gpa: std.mem.Allocator, input: engine.Input) !engine.Input {
    const frame = try encodeInput(gpa, input);
    defer gpa.free(frame);
    var decoded = try decodeInput(gpa, frame);
    errdefer deinitInput(gpa, &decoded);
    const frame2 = try encodeInput(gpa, decoded);
    defer gpa.free(frame2);
    try testing.expectEqualSlices(u8, frame, frame2);
    return decoded;
}

test "input round-trip: every arm" {
    const gpa = testing.allocator;

    {
        var d = try roundTripInput(gpa, .{ .envelope_received = .{ .bytes = "envelope-frame-bytes" } });
        defer deinitInput(gpa, &d);
        try testing.expectEqualSlices(u8, "envelope-frame-bytes", d.envelope_received.bytes);
    }
    {
        var d = try roundTripInput(gpa, .{ .timer_fired = .{ .slot = 7, .timer = .ballot } });
        defer deinitInput(gpa, &d);
        try testing.expectEqual(@as(u64, 7), d.timer_fired.slot);
        try testing.expectEqual(engine.TimerId.ballot, d.timer_fired.timer);
    }
    {
        var d = try roundTripInput(gpa, .{ .nominate = .{ .slot = 1, .value = "value-A", .prev_value = "genesis" } });
        defer deinitInput(gpa, &d);
        try testing.expectEqual(@as(u64, 1), d.nominate.slot);
        try testing.expectEqualSlices(u8, "value-A", d.nominate.value);
        try testing.expectEqualSlices(u8, "genesis", d.nominate.prev_value);
    }
    {
        // empty prev_value survives (present zero-length Data)
        var d = try roundTripInput(gpa, .{ .nominate = .{ .slot = 2, .value = "v", .prev_value = "" } });
        defer deinitInput(gpa, &d);
        try testing.expectEqual(@as(usize, 0), d.nominate.prev_value.len);
    }
    {
        var d = try roundTripInput(gpa, .{ .qset_received = .{ .bytes = "qset-frame" } });
        defer deinitInput(gpa, &d);
        try testing.expectEqualSlices(u8, "qset-frame", d.qset_received.bytes);
    }
    {
        var d = try roundTripInput(gpa, .{ .restore_own_envelope = .{ .bytes = "own-log-entry" } });
        defer deinitInput(gpa, &d);
        try testing.expectEqualSlices(u8, "own-log-entry", d.restore_own_envelope.bytes);
    }
    {
        var d = try roundTripInput(gpa, .{ .purge_slots = .{ .max_slot = 123456789 } });
        defer deinitInput(gpa, &d);
        try testing.expectEqual(@as(u64, 123456789), d.purge_slots.max_slot);
    }
}

/// Round-trip one Effect: encode → decode → re-encode, byte-identical.
fn roundTripEffect(gpa: std.mem.Allocator, effect: engine.Effect) !engine.Effect {
    const frame = try encodeEffect(gpa, &effect);
    defer gpa.free(frame);
    var decoded = try decodeEffect(gpa, frame);
    errdefer decoded.deinitPayload(gpa);
    const frame2 = try encodeEffect(gpa, &decoded);
    defer gpa.free(frame2);
    try testing.expectEqualSlices(u8, frame, frame2);
    return decoded;
}

test "effect round-trip: every arm" {
    const gpa = testing.allocator;

    const SB = engine.Effect.SlotBytes;
    const payload = "signed-envelope-frame";
    inline for (.{ "persist_own_envelope", "broadcast_envelope", "forward_envelope", "externalized" }) |arm| {
        var buf: [payload.len]u8 = undefined;
        @memcpy(&buf, payload);
        const eff = @unionInit(engine.Effect, arm, SB{ .slot = 9, .bytes = &buf });
        var d = try roundTripEffect(gpa, eff);
        defer d.deinitPayload(gpa);
        const sb = @field(d, arm);
        try testing.expectEqual(@as(u64, 9), sb.slot);
        try testing.expectEqualSlices(u8, payload, sb.bytes);
    }
    {
        var d = try roundTripEffect(gpa, .{ .arm_timer = .{ .slot = 4, .timer = .nomination, .delay_ms = 3000 } });
        defer d.deinitPayload(gpa);
        try testing.expectEqual(@as(u64, 4), d.arm_timer.slot);
        try testing.expectEqual(engine.TimerId.nomination, d.arm_timer.timer);
        try testing.expectEqual(@as(u32, 3000), d.arm_timer.delay_ms);
    }
    {
        var d = try roundTripEffect(gpa, .{ .cancel_timer = .{ .slot = 4, .timer = .ballot } });
        defer d.deinitPayload(gpa);
        try testing.expectEqual(engine.TimerId.ballot, d.cancel_timer.timer);
    }
    {
        const hash: [32]u8 = @splat(0xab);
        var d = try roundTripEffect(gpa, .{ .request_qset = .{ .hash = hash } });
        defer d.deinitPayload(gpa);
        try testing.expectEqualSlices(u8, &hash, &d.request_qset.hash);
    }
    {
        // every InputStatus code round-trips
        for (std.enums.values(engine.InputStatus)) |code| {
            var d = try roundTripEffect(gpa, .{ .input_status = .{ .code = code } });
            defer d.deinitPayload(gpa);
            try testing.expectEqual(code, d.input_status.code);
        }
    }
    {
        // every PhaseKind round-trips
        for (std.enums.values(engine.PhaseKind)) |kind| {
            var d = try roundTripEffect(gpa, .{ .phase_event = .{ .slot = 11, .kind = kind, .detail = 0xdeadbeef } });
            defer d.deinitPayload(gpa);
            try testing.expectEqual(kind, d.phase_event.kind);
            try testing.expectEqual(@as(u64, 0xdeadbeef), d.phase_event.detail);
        }
    }
}

test "effect round-trip: empty payload bytes" {
    const gpa = testing.allocator;
    var d = try roundTripEffect(gpa, .{ .externalized = .{ .slot = 1, .bytes = &.{} } });
    defer d.deinitPayload(gpa);
    try testing.expectEqual(@as(usize, 0), d.externalized.bytes.len);
}

fn testQset(gpa: std.mem.Allocator, members: []const [32]u8, threshold: u32) !qset.QuorumSetOwned {
    const vals = try gpa.alloc(qset.NodeId, members.len);
    errdefer gpa.free(vals);
    @memcpy(vals, members);
    var qs = qset.QuorumSetOwned{
        .threshold = threshold,
        .validators = vals,
        .inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0),
    };
    try qset.validateAndNormalize(gpa, &qs);
    return qs;
}

fn expectQsetEqual(a: *const qset.QuorumSetOwned, b: *const qset.QuorumSetOwned) !void {
    try testing.expectEqual(a.threshold, b.threshold);
    try testing.expectEqual(a.validators.len, b.validators.len);
    for (a.validators, b.validators) |*av, *bv| try testing.expectEqualSlices(u8, av, bv);
    try testing.expectEqual(a.inner_sets.len, b.inner_sets.len);
    for (a.inner_sets, b.inner_sets) |*ai, *bi| try expectQsetEqual(ai, bi);
}

test "engine config round-trip: validator, watcher, non-default fields" {
    const gpa = testing.allocator;
    const members = [_][32]u8{ @splat(0x01), @splat(0x02), @splat(0x03) };

    // validator with non-default limits and strict_canonical=false
    {
        var cfg = engine.Config{
            .network_id = @splat(0x10),
            .node_id = members[0],
            .secret_seed = @as([32]u8, @splat(0x77)),
            .quorum_set = try testQset(gpa, &members, 2),
            .strict_canonical = false,
            .limits = .{ .max_value_bytes = 2048, .max_live_slots = 8 },
        };
        defer cfg.quorum_set.deinit(gpa);
        const frame = try encodeEngineConfig(gpa, &cfg);
        defer gpa.free(frame);
        var decoded = try decodeEngineConfig(gpa, frame);
        defer decoded.quorum_set.deinit(gpa);
        try testing.expectEqualSlices(u8, &cfg.network_id, &decoded.network_id);
        try testing.expectEqualSlices(u8, &cfg.node_id, &decoded.node_id);
        try testing.expectEqualSlices(u8, &cfg.secret_seed.?, &decoded.secret_seed.?);
        try testing.expectEqual(false, decoded.strict_canonical);
        try testing.expectEqual(cfg.limits, decoded.limits);
        try expectQsetEqual(&cfg.quorum_set, &decoded.quorum_set);
        // re-encode is byte-identical
        const frame2 = try encodeEngineConfig(gpa, &decoded);
        defer gpa.free(frame2);
        try testing.expectEqualSlices(u8, frame, frame2);
    }

    // watcher: secret_seed null encodes as absent, decodes as null;
    // strictCanonical default true survives
    {
        var cfg = engine.Config{
            .network_id = @splat(0x20),
            .node_id = members[1],
            .secret_seed = null,
            .quorum_set = try testQset(gpa, &members, 2),
        };
        defer cfg.quorum_set.deinit(gpa);
        const frame = try encodeEngineConfig(gpa, &cfg);
        defer gpa.free(frame);
        var decoded = try decodeEngineConfig(gpa, frame);
        defer decoded.quorum_set.deinit(gpa);
        try testing.expect(decoded.secret_seed == null);
        try testing.expectEqual(true, decoded.strict_canonical);
        try testing.expectEqual(limits_mod.Limits{}, decoded.limits);
    }
}

test "engine config decode: zero limits mean engine defaults" {
    const gpa = testing.allocator;
    // Hand-build a frame with limits ABSENT (all-zero by capnp semantics).
    var mb = MessageBuilder.init(gpa);
    defer mb.deinit();
    var b = try gen_host.EngineConfig.Builder.init(&mb);
    const nid: [32]u8 = @splat(0x30);
    const node: [32]u8 = @splat(0x01);
    try b.setNetworkId(&nid);
    try b.setNodeId(&node);
    var qb = try b.initQuorumSet();
    try qb.setThreshold(1);
    const vl = try qb.initValidators(1);
    try vl.set(0, &node);
    const frame = try mb.toBytes();
    defer gpa.free(frame);

    var decoded = try decodeEngineConfig(gpa, frame);
    defer decoded.quorum_set.deinit(gpa);
    try testing.expectEqual(limits_mod.Limits{}, decoded.limits);
    try testing.expect(decoded.secret_seed == null);
    try testing.expectEqual(true, decoded.strict_canonical);
}

test "decode rejects malformed and unset frames" {
    const gpa = testing.allocator;
    try testing.expectError(error.MalformedFrame, decodeInput(gpa, &.{ 1, 2, 3 }));
    try testing.expectError(error.MalformedFrame, decodeEffect(gpa, &.{ 1, 2, 3 }));
    try testing.expectError(error.MalformedFrame, decodeEngineConfig(gpa, &.{ 1, 2, 3 }));

    // structurally valid but unset unions are rejected
    {
        var mb = MessageBuilder.init(gpa);
        defer mb.deinit();
        _ = try gen_host.Input.Builder.init(&mb);
        const frame = try mb.toBytes();
        defer gpa.free(frame);
        try testing.expectError(error.UnsetUnion, decodeInput(gpa, frame));
    }
    {
        var mb = MessageBuilder.init(gpa);
        defer mb.deinit();
        _ = try gen_host.Effect.Builder.init(&mb);
        const frame = try mb.toBytes();
        defer gpa.free(frame);
        try testing.expectError(error.UnsetUnion, decodeEffect(gpa, frame));
    }
}
