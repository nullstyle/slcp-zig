//! Imported SLCP v1 signature-acceptance witnesses. These fixed inputs are
//! independent of tools/gen_vectors.zig; missing corpus files fail the gate.
const std = @import("std");
const slcp = @import("slcp-core");
const json = std.json;

fn load(gpa: std.mem.Allocator, name: []const u8) !json.Value {
    const path = try std.fmt.allocPrint(gpa, "vectors/compatibility/{s}", .{name});
    const bytes = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .unlimited);
    return json.parseFromSliceLeaky(json.Value, gpa, bytes, .{});
}

fn field(v: json.Value, name: []const u8) json.Value {
    return v.object.get(name).?;
}

fn hex(gpa: std.mem.Allocator, value: json.Value) ![]u8 {
    const s = value.string;
    if (s.len % 2 != 0) return error.InvalidHexLength;
    const out = try gpa.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

fn fixed(comptime n: usize, value: json.Value) ![n]u8 {
    var out: [n]u8 = undefined;
    try std.testing.expectEqual(@as(usize, n * 2), value.string.len);
    _ = try std.fmt.hexToBytes(&out, value.string);
    return out;
}

test "signature vectors: pinned hostile provider acceptance" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const root = try load(gpa, "ed25519-provider.json");
    const cases = field(root, "cases").array.items;
    try std.testing.expectEqual(@as(usize, 12), cases.len);
    try std.testing.expectEqualStrings(
        "2282a3629c14d498e25116dafc501c183de55fb6aa576764c36c9cb103878c4d",
        field(root, "sourceSha256").string,
    );
    var accepted_count: usize = 0;
    for (cases) |c| {
        errdefer std.debug.print("signature provider case: {s}\n", .{field(c, "case").string});
        const message = try hex(gpa, field(c, "message"));
        const key = try fixed(32, field(c, "publicKey"));
        const signature = try fixed(64, field(c, "signature"));
        const accepted = blk: {
            const pk = std.crypto.sign.Ed25519.PublicKey.fromBytes(key) catch break :blk false;
            const sig = std.crypto.sign.Ed25519.Signature.fromBytes(signature);
            sig.verify(message, pk) catch break :blk false;
            break :blk true;
        };
        try std.testing.expectEqual(field(c, "accepted").bool, accepted);
        accepted_count += @intFromBool(accepted);
    }
    try std.testing.expectEqual(@as(usize, 4), accepted_count);
    std.debug.print("[signature-vectors] provider cases=12 accepted=4 rejected=8\n", .{});
}

test "signature vectors: complete envelopes preserve signed bytes and receive status" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const root = try load(gpa, "envelope-signatures.json");
    try std.testing.expectEqual(@as(i64, 1), field(root, "version").integer);
    const cases = field(root, "cases").array.items;
    try std.testing.expectEqual(@as(usize, 5), cases.len);
    for (cases) |c| {
        errdefer std.debug.print("signature envelope case: {s}\n", .{field(c, "id").string});
        const cfg = try slcp.host_codec.decodeEngineConfig(gpa, try hex(gpa, field(c, "config")));
        const network = try fixed(32, field(c, "verifyingNetworkId"));
        try std.testing.expectEqualSlices(u8, &network, &cfg.network_id);
        try std.testing.expect(cfg.secret_seed == null);
        const envelope = try hex(gpa, field(c, "framedEnvelope"));
        const signed_bytes = try hex(gpa, field(c, "statementBytes"));
        const expected_sig = try fixed(64, field(c, "signature"));
        const node = try fixed(32, field(c, "nodeId"));
        var msg = try slcp.capnpc.message.Message.init(gpa, envelope, .{});
        defer msg.deinit();
        const env = try slcp.gen.slcp.Envelope.Reader.init(&msg);
        try std.testing.expectEqualSlices(u8, signed_bytes, try env.getStatementBytes());
        try std.testing.expectEqualSlices(u8, &expected_sig, try env.getSignature());
        var stmt_msg = try slcp.canonical.decodeFlat(gpa, signed_bytes, .{});
        defer stmt_msg.deinit();
        const stmt = try slcp.gen.slcp.Statement.Reader.init(&stmt_msg);
        try std.testing.expectEqualSlices(u8, &node, try stmt.getNodeId());
        const digest = slcp.crypto.statementDigest(network, signed_bytes);
        try std.testing.expectEqual(field(c, "expectedVerified").bool, slcp.crypto.verify(node, digest, expected_sig));

        // Independently construct the same unsigned Envelope wrapper. The
        // contained signed bytes are copied verbatim, never canonicalized.
        var builder = slcp.capnpc.message.MessageBuilder.init(gpa);
        defer builder.deinit();
        var rebuilt = try slcp.gen.slcp.Envelope.Builder.init(&builder);
        try rebuilt.setStatementBytes(signed_bytes);
        try rebuilt.setSignature(&expected_sig);
        try std.testing.expectEqualSlices(u8, envelope, try builder.toBytes());

        var input = try slcp.host_codec.decodeInput(gpa, try hex(gpa, field(c, "input")));
        defer slcp.host_codec.freeInput(gpa, &input);
        try std.testing.expect(input == .envelope_received);
        try std.testing.expectEqualSlices(u8, envelope, input.envelope_received.bytes);
        try std.testing.expectEqualSlices(u8, try hex(gpa, field(c, "input")), try slcp.host_codec.encodeInput(gpa, input));
        var eng = try slcp.engine.Engine.init(gpa, cfg, slcp.driver.Driver.default());
        defer eng.deinit();
        try eng.pushInput(input);
        var statuses: usize = 0;
        var status_was_last = false;
        while (eng.popEffect()) |effect| {
            if (status_was_last) return error.EffectAfterInputStatus;
            if (effect.* == .input_status) {
                statuses += 1;
                try std.testing.expectEqualStrings(field(c, "expectedStatus").string, @tagName(effect.input_status.code));
                status_was_last = true;
            }
            eng.commitEffect();
        }
        try std.testing.expectEqual(@as(usize, 1), statuses);
    }
    std.debug.print("[signature-vectors] envelopes=5 status-and-signed-bytes=PASS\n", .{});
}
