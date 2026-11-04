//! Versioned v1 compatibility witnesses. Expected bytes/verdicts are retained
//! independently of this runner; fixture files are mandatory, never skipped.
const std = @import("std");
const core = @import("slcp-core");
const slcp = @import("slcp");
const Message = core.canonical.Message;
const Builder = core.capnpc.message.MessageBuilder;
const Value = std.json.Value;
const testing = std.testing;

fn load(gpa: std.mem.Allocator, comptime name: []const u8) !Value {
    const contents = try std.Io.Dir.cwd().readFileAlloc(testing.io, "vectors/compatibility/" ++ name, gpa, .limited(8 * 1024 * 1024));
    const value = try std.json.parseFromSliceLeaky(Value, gpa, contents, .{});
    try testing.expectEqual(@as(i64, 1), field(value, "version").integer);
    try testing.expectEqualStrings("0.21.0", field(field(value, "provenance"), "capnpZigVersion").string);
    return value;
}

fn field(value: Value, name: []const u8) Value {
    return value.object.get(name).?;
}

fn number(value: Value, name: []const u8) usize {
    return @intCast(field(value, name).integer);
}

fn bytes(gpa: std.mem.Allocator, value: Value) ![]u8 {
    const hex = value.string;
    try testing.expectEqual(@as(usize, 0), hex.len % 2);
    const result = try gpa.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(result, hex);
    return result;
}

fn expectDigest(expected: []const u8, actual: [32]u8) !void {
    try testing.expectEqualStrings(expected, &std.fmt.bytesToHex(actual, .lower));
}

test "wire-compatibility: eager graph acceptance, work budgets and diagnostic provenance" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const corpus = try load(gpa, "decoder.json");
    const cases = field(corpus, "cases").array.items;
    try testing.expect(cases.len >= 20);
    for (cases) |case| {
        const id = field(case, "id").string;
        errdefer std.debug.print("decoder fixture: {s}\n", .{id});
        const data = try bytes(gpa, field(case, "bytes"));
        const opts = field(case, "options");
        const options: core.canonical.ValidationOptions = .{
            .nesting_limit = number(opts, "nestingLimit"),
            .traversal_limit_words = number(opts, "traversalLimitWords"),
        };
        const parsed = if (std.mem.eql(u8, field(case, "encoding").string, "flat"))
            core.canonical.decodeFlat(gpa, data, options)
        else
            Message.init(gpa, data, options);
        if (parsed) |value| {
            var message = value;
            defer message.deinit();
            try testing.expect(field(case, "expectedAccepted").bool);
        } else |err| {
            try testing.expect(!field(case, "expectedAccepted").bool);
            if (field(case, "zigDiagnostic") == .string) {
                try testing.expectEqualStrings(field(case, "zigDiagnostic").string, @errorName(err));
            }
        }
    }
}

fn qsetHash(gpa: std.mem.Allocator, data: []const u8, entry: []const u8) ![32]u8 {
    if (std.mem.eql(u8, entry, "config")) {
        var cfg = try core.host_codec.decodeEngineConfig(gpa, data);
        defer cfg.quorum_set.deinit(gpa);
        return core.qset.hashNormalized(gpa, &cfg.quorum_set);
    }
    var standalone = data;
    var overlay: ?slcp.wire.OverlayFrame = null;
    defer if (overlay) |*value| value.deinit(gpa);
    if (std.mem.eql(u8, entry, "overlay")) {
        overlay = try slcp.wire.decode(gpa, data);
        if (overlay.? != .qset) return error.WrongOverlayUnion;
        standalone = overlay.?.qset;
    }
    var msg = try Message.init(gpa, standalone, .{ .nesting_limit = 32, .traversal_limit_words = core.limits.frozen_max_frame_bytes / 8 });
    defer msg.deinit();
    var qs = try core.qset.fromReader(gpa, try core.gen.slcp.QuorumSet.Reader.init(&msg));
    defer qs.deinit(gpa);
    try core.qset.validateAndNormalize(gpa, &qs);
    return core.qset.hashNormalized(gpa, &qs);
}

test "wire-compatibility: historical and standard qsets at standalone and nested boundaries" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const corpus = try load(gpa, "qsets.json");
    for (field(corpus, "cases").array.items) |case| {
        const id = field(case, "id").string;
        errdefer std.debug.print("qset fixture: {s}\n", .{id});
        const data = try bytes(gpa, field(case, "bytes"));
        if (qsetHash(gpa, data, field(case, "entry").string)) |actual| {
            try testing.expect(field(case, "expectedAccepted").bool);
            try expectDigest(field(case, "normalizedHash").string, actual);
        } else |err| {
            try testing.expect(!field(case, "expectedAccepted").bool);
            if (field(case, "zigDiagnostic") == .string) {
                try testing.expectEqualStrings(field(case, "zigDiagnostic").string, @errorName(err));
            }
        }
    }
}

fn makeWrapper(gpa: std.mem.Allocator, case: Value) ![]u8 {
    const payload = try gpa.alloc(u8, number(case, "payloadLength"));
    @memset(payload, @intCast(number(case, "payloadByte")));
    const slot: u64 = @intCast(number(case, "slot"));
    const kind = field(case, "kind").string;
    if (std.mem.eql(u8, kind, "effect_externalized")) {
        const effect: core.engine.Effect = .{ .externalized = .{ .slot = slot, .bytes = payload } };
        const encoded = try core.host_codec.encodeEffect(gpa, &effect);
        const decoded = try core.host_codec.decodeEffect(gpa, encoded);
        try testing.expectEqual(slot, decoded.externalized.slot);
        try testing.expectEqualSlices(u8, payload, decoded.externalized.bytes);
        return encoded;
    }
    if (std.mem.eql(u8, kind, "input_nominate") or std.mem.eql(u8, kind, "input_nominate_absent_previous")) {
        const encoded = if (std.mem.eql(u8, kind, "input_nominate"))
            try core.host_codec.encodeInput(gpa, .{ .nominate = .{ .slot = slot, .value = payload, .prev_value = "" } })
        else blk: {
            var mb = Builder.init(gpa);
            defer mb.deinit();
            var input = try core.gen.host.Input.Builder.init(&mb);
            var nomination = try input.initNominate();
            try nomination.setSlot(slot);
            try nomination.setValue(payload);
            break :blk try mb.toBytes();
        };
        var msg = try Message.init(gpa, encoded, .{});
        defer msg.deinit();
        const root = try core.gen.host.Input.Reader.init(&msg);
        const nomination = try root.getNominate();
        try testing.expectEqual(field(case, "expectedPreviousPointerPresent").bool, nomination.hasPrevValue());
        try testing.expectEqual(@as(usize, 0), (try nomination.getPrevValue()).len);
        return @constCast(encoded);
    }
    if (std.mem.eql(u8, kind, "input_envelope")) {
        const encoded = try core.host_codec.encodeInput(gpa, .{ .envelope_received = .{ .bytes = payload } });
        const decoded = try core.host_codec.decodeInput(gpa, encoded);
        try testing.expectEqualSlices(u8, payload, decoded.envelope_received.bytes);
        try testing.expect(encoded.len > core.limits.frozen_max_frame_bytes);
        const ids = try gpa.alloc([32]u8, 1);
        ids[0] = @splat(1);
        var eng = try core.engine.Engine.init(gpa, .{
            .network_id = @splat(0),
            .node_id = ids[0],
            .secret_seed = null,
            .quorum_set = .{ .threshold = 1, .validators = ids, .inner_sets = try gpa.alloc(core.qset.QuorumSetOwned, 0) },
        }, core.driver.Driver.default());
        defer eng.deinit();
        try eng.pushInput(decoded);
        var status: ?core.engine.InputStatus = null;
        while (eng.popEffect()) |effect| {
            if (effect.* == .input_status) status = effect.input_status.code;
            eng.commitEffect();
        }
        try testing.expectEqualStrings(field(case, "expectedContainedStatus").string, @tagName(status.?));
        return encoded;
    }
    if (std.mem.eql(u8, kind, "overlay_slot_state")) {
        var mb = Builder.init(gpa);
        defer mb.deinit();
        var envelope = try core.gen.slcp.Envelope.Builder.init(&mb);
        try envelope.setStatementBytes(payload);
        const signature: [64]u8 = @splat(@intCast(number(case, "signatureByte")));
        try envelope.setSignature(&signature);
        const framed = try mb.toBytes();
        const envelopes = try gpa.alloc([]const u8, number(case, "envelopeCount"));
        @memset(envelopes, framed);
        const encoded = try slcp.wire.encode(gpa, .{ .slot_state = .{ .slot = slot, .envelopes = envelopes } });
        var decoded = try slcp.wire.decode(gpa, encoded);
        defer decoded.deinit(gpa);
        try testing.expectEqual(slot, decoded.slot_state.slot);
        try testing.expectEqual(envelopes.len, decoded.slot_state.envelopes.len);
        for (decoded.slot_state.envelopes) |entry| {
            var em = try Message.init(gpa, entry, .{});
            defer em.deinit();
            const er = try core.gen.slcp.Envelope.Reader.init(&em);
            try testing.expectEqualSlices(u8, payload, try er.getStatementBytes());
            try testing.expectEqualSlices(u8, &signature, try er.getSignature());
        }
        return encoded;
    }
    return error.UnknownWrapperRecipe;
}

test "wire-compatibility: exact unsigned wrapper construction beyond the frozen small traces" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const corpus = try load(gpa, "wrappers.json");
    for (field(corpus, "cases").array.items) |case| {
        errdefer std.debug.print("wrapper fixture: {s}\n", .{field(case, "id").string});
        const encoded = try makeWrapper(gpa, case);
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(encoded, &hash, .{});
        try testing.expect(number(case, "expectedLength") != 0);
        try testing.expectEqual(number(case, "expectedLength"), encoded.len);
        try expectDigest(field(case, "expectedSha256").string, hash);
        try testing.expectEqual(number(case, "expectedSegmentCount"), @as(usize, std.mem.readInt(u32, encoded[0..4], .little)) + 1);
        if (case.object.get("hex")) |hex| try testing.expectEqualSlices(u8, try bytes(gpa, hex), encoded);
    }
}

const Reject = struct {
    fn validate(_: *anyopaque, _: u64, _: []const u8, _: bool) core.driver.Validity {
        return .invalid;
    }
    fn combine(_: *anyopaque, _: u64, _: []const []const u8, _: std.mem.Allocator, _: *std.ArrayList(u8)) core.driver.DriverError!void {
        return error.DriverFault;
    }
};

test "wire-compatibility: receive and restore multi-fault status precedence" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const corpus = try load(gpa, "receive.json");
    const cases = field(corpus, "cases").array.items;
    try testing.expect(cases.len >= 10);
    for (cases) |case| {
        errdefer std.debug.print("receive fixture: {s}\n", .{field(case, "id").string});
        var cfg = try core.host_codec.decodeEngineConfig(gpa, try bytes(gpa, field(case, "config")));
        if (case.object.get("limitsOverride")) |overrides| {
            if (overrides.object.get("maxLiveSlots")) |value| cfg.limits.max_live_slots = @intCast(value.integer);
            if (overrides.object.get("maxStoredStatementBytes")) |value| cfg.limits.max_stored_statement_bytes = @intCast(value.integer);
        }
        var ctx: u8 = 0;
        const driver = if (std.mem.eql(u8, field(case, "driver").string, "reject")) core.driver.Driver{ .ctx = &ctx, .validate_value = Reject.validate, .combine_candidates = Reject.combine } else core.driver.Driver.default();
        var eng = try core.engine.Engine.init(gpa, cfg, driver);
        defer eng.deinit();
        var input = try core.host_codec.decodeInput(gpa, try bytes(gpa, field(case, "input")));
        defer core.host_codec.freeInput(gpa, &input);
        try eng.pushInput(input);
        var status: ?core.engine.InputStatus = null;
        var statuses: usize = 0;
        while (eng.popEffect()) |effect| {
            if (effect.* == .input_status) {
                status = effect.input_status.code;
                statuses += 1;
            } else try testing.expect(status == null); // status is the final effect
            eng.commitEffect();
        }
        try testing.expectEqual(@as(usize, 1), statuses);
        try testing.expectEqualStrings(field(case, "expectedStatus").string, @tagName(status.?));
    }
}
