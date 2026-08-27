//! Deterministic conformance-vector generator (design §13.4).
//! Writes vectors/*.json. M0 scope: sets 1 (crypto), 2 (qset), 5 (lint),
//! 4-partial (sanity).
//!
//! Determinism contract: fixed inputs only, fixed iteration order, no
//! timestamps, hand-rolled JSON rendering — two runs must be byte-identical.
//! Every expectation in the output is DERIVED by calling slcp-core, never
//! hand-written.

const std = @import("std");
const slcp = @import("slcp-core");

const capnpc = slcp.capnpc;
const canonical = slcp.canonical;
const crypto = slcp.crypto;
const qset = slcp.qset;
const gen_slcp = slcp.gen.slcp;

const MessageBuilder = capnpc.message.MessageBuilder;
const Message = capnpc.message.Message;

// ---------------------------------------------------------------------------
// Fixed inputs
// ---------------------------------------------------------------------------

const passphrases = [_][]const u8{
    "my-counter-app v1",
    "slcp public test network ; august 2026",
    "",
};

const seeds = [_][32]u8{
    @splat(0x01),
    @splat(0x02),
    @splat(0xff),
};

const nominate_vote: [4]u8 = .{ 0xde, 0xad, 0xbe, 0xef };
const prepare_value: [4]u8 = .{ 0xca, 0xfe, 0xba, 0xbe };

// ---------------------------------------------------------------------------
// JSON rendering helpers (byte-stable by construction)
// ---------------------------------------------------------------------------

fn hexAppend(w: *std.Io.Writer, bytes: []const u8) !void {
    for (bytes) |b| try w.print("{x:0>2}", .{b});
}

fn jsonString(w: *std.Io.Writer, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        else => {
            std.debug.assert(c >= 0x20 and c < 0x7f); // fixed inputs are printable ASCII
            try w.writeByte(c);
        },
    };
    try w.writeByte('"');
}

fn jsonHex(w: *std.Io.Writer, bytes: []const u8) !void {
    try w.writeByte('"');
    try hexAppend(w, bytes);
    try w.writeByte('"');
}

fn writeFile(io: std.Io, path: []const u8, contents: []const u8) !void {
    var file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    try file.writeStreamingAll(io, contents);
}

// ---------------------------------------------------------------------------
// Quorum-set specs → wire messages → normalize/hash outcomes
// ---------------------------------------------------------------------------

const QSpec = struct {
    threshold: u32,
    validators: []const qset.NodeId,
    inners: []const QSpec = &.{},
};

fn writeSpecInto(b: *gen_slcp.QuorumSet.Builder, spec: QSpec) !void {
    try b.setThreshold(spec.threshold);
    if (spec.validators.len > 0) {
        const vl = try b.initValidators(@intCast(spec.validators.len));
        for (spec.validators, 0..) |*v, i| try vl.set(@intCast(i), v);
    }
    if (spec.inners.len > 0) {
        const il = try b.initInnerSets(@intCast(spec.inners.len));
        for (spec.inners, 0..) |inner, i| {
            var ib = try il.get(@intCast(i));
            try writeSpecInto(&ib, inner);
        }
    }
}

fn qsetFramedFromSpec(gpa: std.mem.Allocator, spec: QSpec) ![]const u8 {
    var mb = MessageBuilder.init(gpa);
    var root = try gen_slcp.QuorumSet.Builder.init(&mb);
    try writeSpecInto(&root, spec);
    return mb.toBytes();
}

const QsetOutcome = union(enum) {
    ok: struct { owned: qset.QuorumSetOwned, hash: [32]u8 },
    err: anyerror,
};

/// The full receive pipeline: wire build → validating parse → fromReader →
/// validateAndNormalize → hash. Errors from any stage become rejections.
fn processSpec(gpa: std.mem.Allocator, spec: QSpec) !QsetOutcome {
    const framed = try qsetFramedFromSpec(gpa, spec);
    var msg = try Message.init(gpa, framed, .{});
    const reader = try gen_slcp.QuorumSet.Reader.init(&msg);
    var owned = qset.fromReader(gpa, reader) catch |e| return .{ .err = e };
    qset.validateAndNormalize(gpa, &owned) catch |e| return .{ .err = e };
    const h = try qset.hashNormalized(gpa, &owned);
    return .{ .ok = .{ .owned = owned, .hash = h } };
}

fn writeSpecJson(w: *std.Io.Writer, spec: QSpec) !void {
    try w.print("{{\"threshold\":{d},\"validators\":[", .{spec.threshold});
    for (spec.validators, 0..) |*v, i| {
        if (i > 0) try w.writeByte(',');
        try jsonHex(w, v);
    }
    try w.writeAll("],\"innerSets\":[");
    for (spec.inners, 0..) |inner, i| {
        if (i > 0) try w.writeByte(',');
        try writeSpecJson(w, inner);
    }
    try w.writeAll("]}");
}

fn writeOwnedJson(w: *std.Io.Writer, owned: *const qset.QuorumSetOwned) !void {
    try w.print("{{\"threshold\":{d},\"validators\":[", .{owned.threshold});
    for (owned.validators, 0..) |*v, i| {
        if (i > 0) try w.writeByte(',');
        try jsonHex(w, v);
    }
    try w.writeAll("],\"innerSets\":[");
    for (owned.inner_sets, 0..) |*inner, i| {
        if (i > 0) try w.writeByte(',');
        try writeOwnedJson(w, inner);
    }
    try w.writeAll("]}");
}

fn ids(comptime bytes: []const u8) [bytes.len]qset.NodeId {
    var out: [bytes.len]qset.NodeId = undefined;
    for (bytes, 0..) |b, i| out[i] = @splat(b);
    return out;
}

// ---------------------------------------------------------------------------
// Statements
// ---------------------------------------------------------------------------

const StatementVector = struct {
    name: []const u8,
    network_id: [32]u8,
    seed: [32]u8,
    statement_bytes: []const u8,
    digest: [32]u8,
    signature: [64]u8,
};

/// 2-of-3 qset over the three fixed test pubkeys, normalized; its hash is the
/// quorumSetHash carried by both statement vectors.
fn testQsetHash(gpa: std.mem.Allocator) ![32]u8 {
    var validators = try gpa.alloc(qset.NodeId, seeds.len);
    for (seeds, 0..) |seed, i| validators[i] = try crypto.publicKeyFromSeed(seed);
    var owned: qset.QuorumSetOwned = .{
        .threshold = 2,
        .validators = validators,
        .inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0),
    };
    try qset.validateAndNormalize(gpa, &owned);
    return qset.hashNormalized(gpa, &owned);
}

/// Nominate: nodeId = pubkey(seed), slotIndex 1, one vote, accepted ABSENT
/// (per §4.3's no-present-but-default-pointer discipline: initAccepted(0) is
/// deliberately NOT called).
fn buildNominateBytes(gpa: std.mem.Allocator, node_id: [32]u8, qsh: [32]u8) ![]u8 {
    var mb = MessageBuilder.init(gpa);
    var st = try gen_slcp.Statement.Builder.init(&mb);
    try st.setNodeId(&node_id);
    try st.setSlotIndex(1);
    var pledges = st.getPledges();
    var nom = try pledges.initNominate();
    try nom.setQuorumSetHash(&qsh);
    const votes = try nom.initVotes(1);
    try votes.set(0, &nominate_vote);
    const framed = try mb.toBytes();
    return canonical.canonicalFlatFromFramed(gpa, framed);
}

/// Prepare: ballot{counter 1, value}; prepared/preparedPrime ABSENT pointers;
/// nC = nH = 0 (unset data fields stay zero).
fn buildPrepareBytes(gpa: std.mem.Allocator, node_id: [32]u8, qsh: [32]u8) ![]u8 {
    var mb = MessageBuilder.init(gpa);
    var st = try gen_slcp.Statement.Builder.init(&mb);
    try st.setNodeId(&node_id);
    try st.setSlotIndex(2);
    var pledges = st.getPledges();
    var prep = try pledges.initPrepare();
    try prep.setQuorumSetHash(&qsh);
    var ballot = try prep.initBallot();
    try ballot.setCounter(1);
    try ballot.setValue(&prepare_value);
    const framed = try mb.toBytes();
    return canonical.canonicalFlatFromFramed(gpa, framed);
}

fn makeStatementVector(
    gpa: std.mem.Allocator,
    name: []const u8,
    seed: [32]u8,
    statement_bytes: []const u8,
) !StatementVector {
    const network_id = crypto.networkIdFromPassphrase(passphrases[0]);
    const digest = crypto.statementDigest(network_id, statement_bytes);
    const signature = try crypto.sign(seed, digest);
    _ = gpa;
    return .{
        .name = name,
        .network_id = network_id,
        .seed = seed,
        .statement_bytes = statement_bytes,
        .digest = digest,
        .signature = signature,
    };
}

// ---------------------------------------------------------------------------
// crypto.json
// ---------------------------------------------------------------------------

const GiCase = struct {
    tag: u32,
    slot: u64,
    prev: []const u8,
    round: u32,
    m: []const u8,
};

fn renderCrypto(gpa: std.mem.Allocator, statements: []const StatementVector) ![]const u8 {
    var sink = std.Io.Writer.Allocating.init(gpa);
    const w = &sink.writer;

    try w.writeAll("{\n  \"version\": 1,\n  \"networkIds\": [\n");
    for (passphrases, 0..) |p, i| {
        try w.writeAll("    {\"passphrase\": ");
        try jsonString(w, p);
        try w.writeAll(", \"networkId\": ");
        const nid = crypto.networkIdFromPassphrase(p);
        try jsonHex(w, &nid);
        try w.writeAll(if (i + 1 < passphrases.len) "},\n" else "}\n");
    }

    try w.writeAll("  ],\n  \"keys\": [\n");
    for (seeds, 0..) |seed, i| {
        try w.writeAll("    {\"seed\": ");
        try jsonHex(w, &seed);
        try w.writeAll(", \"publicKey\": ");
        const pk = try crypto.publicKeyFromSeed(seed);
        try jsonHex(w, &pk);
        try w.writeAll(if (i + 1 < seeds.len) "},\n" else "}\n");
    }

    const pk1 = try crypto.publicKeyFromSeed(seeds[0]);
    const pk2 = try crypto.publicKeyFromSeed(seeds[1]);
    const prev_aa: [32]u8 = @splat(0xaa);
    const prev_bb: [32]u8 = @splat(0xbb);
    const gi_cases = [_]GiCase{
        .{ .tag = 1, .slot = 1, .prev = "", .round = 0, .m = &pk1 },
        .{ .tag = 1, .slot = 1, .prev = &prev_aa, .round = 3, .m = &pk2 },
        .{ .tag = 2, .slot = 1, .prev = &prev_aa, .round = 3, .m = &pk1 },
        .{ .tag = 2, .slot = 123456789, .prev = &nominate_vote, .round = 0, .m = "" },
        .{ .tag = 3, .slot = 42, .prev = &prev_bb, .round = 7, .m = &nominate_vote },
        .{ .tag = 3, .slot = 0, .prev = "", .round = 0, .m = "" },
    };

    try w.writeAll("  ],\n  \"gi\": [\n");
    for (gi_cases, 0..) |c, i| {
        const tag: crypto.GiTag = @enumFromInt(c.tag);
        const value = crypto.gi(tag, c.slot, c.prev, c.round, c.m);
        try w.print("    {{\"tag\": {d}, \"slot\": {d}, \"prevValue\": ", .{ c.tag, c.slot });
        try jsonHex(w, c.prev);
        try w.print(", \"round\": {d}, \"m\": ", .{c.round});
        try jsonHex(w, c.m);
        try w.print(", \"gi\": \"{d}\"", .{value});
        try w.writeAll(if (i + 1 < gi_cases.len) "},\n" else "}\n");
    }

    try w.writeAll("  ],\n  \"statements\": [\n");
    for (statements, 0..) |s, i| {
        try w.writeAll("    {\"name\": ");
        try jsonString(w, s.name);
        try w.writeAll(", \"networkId\": ");
        try jsonHex(w, &s.network_id);
        try w.writeAll(", \"seed\": ");
        try jsonHex(w, &s.seed);
        try w.writeAll(", \"statementBytes\": ");
        try jsonHex(w, s.statement_bytes);
        try w.writeAll(", \"digest\": ");
        try jsonHex(w, &s.digest);
        try w.writeAll(", \"signature\": ");
        try jsonHex(w, &s.signature);
        try w.writeAll(if (i + 1 < statements.len) "},\n" else "}\n");
    }
    try w.writeAll("  ]\n}\n");

    return sink.written();
}

// ---------------------------------------------------------------------------
// qset.json
// ---------------------------------------------------------------------------

fn renderQset(gpa: std.mem.Allocator) ![]const u8 {
    var sink = std.Io.Writer.Allocating.init(gpa);
    const w = &sink.writer;

    // -- normalization cases ------------------------------------------------
    const unsorted_vals = ids(&.{ 0x03, 0x01, 0x02 });
    const single_parent = ids(&.{0xbb});
    const single_inner = ids(&.{0xaa});
    const org1_vals = ids(&.{ 0x10, 0x11, 0x12 });
    const org2_vals = ids(&.{ 0x20, 0x21, 0x22 });
    const org3_vals = ids(&.{ 0x30, 0x31, 0x32 });
    const ord_a_vals = ids(&.{ 0x40, 0x41 });
    const ord_b_vals = ids(&.{ 0x50, 0x51 });

    const org1: QSpec = .{ .threshold = 2, .validators = &org1_vals };
    const org2: QSpec = .{ .threshold = 2, .validators = &org2_vals };
    const org3: QSpec = .{ .threshold = 2, .validators = &org3_vals };
    const ord_a: QSpec = .{ .threshold = 2, .validators = &ord_a_vals };
    const ord_b: QSpec = .{ .threshold = 2, .validators = &ord_b_vals };

    // Order the hash-ordering case's input DESCENDING by qsetHash so
    // normalization observably reorders it. Deterministic: derived from the
    // fixed validators, no other input.
    const ha = (try processSpec(gpa, ord_a)).ok.hash;
    const hb = (try processSpec(gpa, ord_b)).ok.hash;
    const ord_desc: [2]QSpec =
        if (std.mem.order(u8, &ha, &hb) == .gt) .{ ord_a, ord_b } else .{ ord_b, ord_a };

    const Case = struct { name: []const u8, spec: QSpec };
    const cases = [_]Case{
        .{ .name = "unsorted flat 2-of-3", .spec = .{ .threshold = 2, .validators = &unsorted_vals } },
        .{ .name = "singleton inner set flattened into parent", .spec = .{
            .threshold = 2,
            .validators = &single_parent,
            .inners = &.{.{ .threshold = 1, .validators = &single_inner }},
        } },
        .{ .name = "nested 3 orgs, 2-of-3 orgs, majority within each", .spec = .{
            .threshold = 2,
            .validators = &.{},
            .inners = &.{ org1, org2, org3 },
        } },
        .{ .name = "inner sets sorted by qsetHash", .spec = .{
            .threshold = 2,
            .validators = &.{},
            .inners = &ord_desc,
        } },
    };

    try w.writeAll("{\n  \"version\": 1,\n  \"cases\": [\n");
    for (cases, 0..) |c, i| {
        const outcome = try processSpec(gpa, c.spec);
        try w.writeAll("    {\"name\": ");
        try jsonString(w, c.name);
        try w.writeAll(",\n     \"input\": ");
        try writeSpecJson(w, c.spec);
        try w.writeAll(",\n     \"normalized\": ");
        try writeOwnedJson(w, &outcome.ok.owned);
        try w.writeAll(",\n     \"hash\": ");
        try jsonHex(w, &outcome.ok.hash);
        try w.writeAll(if (i + 1 < cases.len) "},\n" else "}\n");
    }

    // -- rejections ---------------------------------------------------------
    const dup_top = ids(&.{0x01});
    const dup_inner = ids(&.{ 0x01, 0x02 });
    const one_val = ids(&.{0x01});
    const two_vals = ids(&.{ 0x01, 0x02 });
    const deep_leaf = ids(&.{0x07});

    // Depth-5 chain: each wrapper is {threshold 1, no validators, one inner}.
    const level5: QSpec = .{ .threshold = 1, .validators = &deep_leaf };
    const level4: QSpec = .{ .threshold = 1, .validators = &.{}, .inners = &.{level5} };
    const level3: QSpec = .{ .threshold = 1, .validators = &.{}, .inners = &.{level4} };
    const level2: QSpec = .{ .threshold = 1, .validators = &.{}, .inners = &.{level3} };
    const level1: QSpec = .{ .threshold = 1, .validators = &.{}, .inners = &.{level2} };

    // 256 distinct validators (one splat byte each) breaches the 255 cap.
    const big_vals = try gpa.alloc(qset.NodeId, 256);
    for (big_vals, 0..) |*v, i| v.* = @splat(@intCast(i));

    const Rejection = struct { name: []const u8, spec: QSpec };
    const rejections = [_]Rejection{
        .{ .name = "empty quorum set", .spec = .{ .threshold = 1, .validators = &.{} } },
        .{ .name = "threshold zero", .spec = .{ .threshold = 0, .validators = &one_val } },
        .{ .name = "threshold above member count", .spec = .{ .threshold = 3, .validators = &two_vals } },
        .{ .name = "duplicate node across tree", .spec = .{
            .threshold = 2,
            .validators = &dup_top,
            .inners = &.{.{ .threshold = 1, .validators = &dup_inner }},
        } },
        .{ .name = "depth five", .spec = level1 },
        .{ .name = "256 validators", .spec = .{ .threshold = 200, .validators = big_vals } },
    };

    try w.writeAll("  ],\n  \"rejections\": [\n");
    for (rejections, 0..) |r, i| {
        const outcome = try processSpec(gpa, r.spec);
        try w.writeAll("    {\"name\": ");
        try jsonString(w, r.name);
        try w.writeAll(",\n     \"input\": ");
        try writeSpecJson(w, r.spec);
        try w.writeAll(",\n     \"error\": ");
        try jsonString(w, @errorName(outcome.err));
        try w.writeAll(if (i + 1 < rejections.len) "},\n" else "}\n");
    }
    try w.writeAll("  ]\n}\n");

    return sink.written();
}

// ---------------------------------------------------------------------------
// lint.json
// ---------------------------------------------------------------------------

fn renderLint(gpa: std.mem.Allocator) ![]const u8 {
    var sink = std.Io.Writer.Allocating.init(gpa);
    const w = &sink.writer;

    const three = ids(&.{ 0x01, 0x02, 0x03 });
    const five = ids(&.{ 0x01, 0x02, 0x03, 0x04, 0x05 });

    const Case = struct { name: []const u8, spec: QSpec };
    const cases = [_]Case{
        .{ .name = "clean 2-of-3", .spec = .{ .threshold = 2, .validators = &three } },
        .{ .name = "sub-majority 1-of-3", .spec = .{ .threshold = 1, .validators = &three } },
        .{ .name = "all-critical 3-of-3", .spec = .{ .threshold = 3, .validators = &three } },
        .{ .name = "below-two-thirds 3-of-5", .spec = .{ .threshold = 3, .validators = &five } },
    };

    try w.writeAll("{\n  \"version\": 1,\n  \"cases\": [\n");
    for (cases, 0..) |c, i| {
        const outcome = try processSpec(gpa, c.spec);
        var owned = outcome.ok.owned;
        const findings = try qset.lint(gpa, &owned);
        try w.writeAll("    {\"name\": ");
        try jsonString(w, c.name);
        try w.writeAll(",\n     \"input\": ");
        try writeSpecJson(w, c.spec);
        try w.writeAll(",\n     \"findings\": [");
        for (findings, 0..) |f, j| {
            if (j > 0) try w.writeByte(',');
            try w.writeAll("{\"level\": ");
            try jsonString(w, @tagName(f.level));
            try w.writeAll(", \"code\": ");
            try jsonString(w, @tagName(f.code));
            try w.print(", \"members\": {d}, \"threshold\": {d}}}", .{ f.members, f.threshold });
        }
        try w.writeAll("]");
        try w.writeAll(if (i + 1 < cases.len) "},\n" else "}\n");
    }
    try w.writeAll("  ]\n}\n");

    return sink.written();
}

// ---------------------------------------------------------------------------
// sanity.json (M0 partial: decode/canonicality level only)
// ---------------------------------------------------------------------------

/// Derived straight through the library helpers: decodeFlat returns a
/// FlatMessage that owns its framed buffer (the earlier use-after-free is
/// fixed in src/canonical.zig; the long-term fix is the upstream flat
/// validating-decode entry point, docs/upstream/03).
fn sanityFlags(gpa: std.mem.Allocator, flat: []const u8) !struct { decodes: bool, is_canonical: bool } {
    var fm = canonical.decodeFlat(gpa, flat, .{}) catch
        return .{ .decodes = false, .is_canonical = false };
    defer fm.deinit(gpa);
    return .{ .decodes = true, .is_canonical = capnpc.canonical.isCanonical(&fm.msg) };
}

fn renderSanity(gpa: std.mem.Allocator, statement_bytes: []const u8) ![]const u8 {
    var sink = std.Io.Writer.Allocating.init(gpa);
    const w = &sink.writer;

    const truncated = statement_bytes[0 .. statement_bytes.len - 8];
    const odd = statement_bytes[0 .. statement_bytes.len - 3];
    const padded = try gpa.alloc(u8, statement_bytes.len + 8);
    @memcpy(padded[0..statement_bytes.len], statement_bytes);
    @memset(padded[statement_bytes.len..], 0);

    const Case = struct { name: []const u8, flat: []const u8 };
    const cases = [_]Case{
        .{ .name = "canonical nominate statement bytes", .flat = statement_bytes },
        .{ .name = "truncated by one word", .flat = truncated },
        .{ .name = "trailing zero word appended", .flat = padded },
        .{ .name = "odd length (not word-aligned)", .flat = odd },
    };

    try w.writeAll("{\n  \"version\": 1,\n");
    try w.writeAll("  \"note\": \"M0 partial: decode/canonicality level only; engine input_status cases land at M2\",\n");
    try w.writeAll("  \"cases\": [\n");
    for (cases, 0..) |c, i| {
        const flags = try sanityFlags(gpa, c.flat);
        try w.writeAll("    {\"name\": ");
        try jsonString(w, c.name);
        try w.writeAll(", \"flat\": ");
        try jsonHex(w, c.flat);
        try w.print(", \"decodes\": {}, \"canonical\": {}", .{ flags.decodes, flags.is_canonical });
        try w.writeAll(if (i + 1 < cases.len) "},\n" else "}\n");
    }
    try w.writeAll("  ]\n}\n");

    return sink.written();
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();

    try std.Io.Dir.cwd().createDirPath(io, "vectors");

    const qsh = try testQsetHash(gpa);
    const nominate_bytes = try buildNominateBytes(gpa, try crypto.publicKeyFromSeed(seeds[0]), qsh);
    const prepare_bytes = try buildPrepareBytes(gpa, try crypto.publicKeyFromSeed(seeds[1]), qsh);
    const statements = [_]StatementVector{
        try makeStatementVector(gpa, "nominate slot1 single vote, accepted absent", seeds[0], nominate_bytes),
        try makeStatementVector(gpa, "prepare slot2 ballot counter1, no prepared", seeds[1], prepare_bytes),
    };

    try writeFile(io, "vectors/crypto.json", try renderCrypto(gpa, &statements));
    try writeFile(io, "vectors/qset.json", try renderQset(gpa));
    try writeFile(io, "vectors/lint.json", try renderLint(gpa));
    try writeFile(io, "vectors/sanity.json", try renderSanity(gpa, nominate_bytes));
}
