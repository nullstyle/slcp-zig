//! Deterministic conformance-vector generator (design §13.4).
//! Writes vectors/*.json. M0 scope: sets 1 (crypto), 2 (qset), 5 (lint),
//! 4-partial (sanity). M1 adds set 3 (leader — Gi leader election).
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
const nomination = slcp.nomination;
const qset = slcp.qset;
const statement = slcp.statement;
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
// sanity.json statements section (M1): canonical statement bytes → expected
// checkStatementSane outcome. Every "insane" expectation is DERIVED by
// calling statement.checkStatementSane, never hand-written.
// ---------------------------------------------------------------------------

const SanityB = struct { counter: u32, value: []const u8 };

const SanityPrepSpec = struct {
    ballot: SanityB,
    prepared: ?SanityB = null,
    prepared_prime: ?SanityB = null,
    n_c: u32 = 0,
    n_h: u32 = 0,
};

const StatementSanityCase = struct { name: []const u8, flat: []const u8 };

fn sanityStatementBuilder(mb: *MessageBuilder, node_id: []const u8) !gen_slcp.Statement.Builder {
    var st = try gen_slcp.Statement.Builder.init(mb);
    try st.setNodeId(node_id);
    try st.setSlotIndex(1);
    return st;
}

fn sanityNominateBytes(
    gpa: std.mem.Allocator,
    node_id: []const u8,
    qsh: []const u8,
    votes: []const []const u8,
    accepted: []const []const u8,
) ![]u8 {
    var mb = MessageBuilder.init(gpa);
    var st = try sanityStatementBuilder(&mb, node_id);
    var pledges = st.getPledges();
    var nom = try pledges.initNominate();
    try nom.setQuorumSetHash(qsh);
    if (votes.len > 0) {
        const vl = try nom.initVotes(@intCast(votes.len));
        for (votes, 0..) |v, i| try vl.set(@intCast(i), v);
    }
    if (accepted.len > 0) {
        const al = try nom.initAccepted(@intCast(accepted.len));
        for (accepted, 0..) |v, i| try al.set(@intCast(i), v);
    }
    const framed = try mb.toBytes();
    return canonical.canonicalFlatFromFramed(gpa, framed);
}

fn sanityPrepareBytes(
    gpa: std.mem.Allocator,
    node_id: []const u8,
    qsh: []const u8,
    spec: SanityPrepSpec,
) ![]u8 {
    var mb = MessageBuilder.init(gpa);
    var st = try sanityStatementBuilder(&mb, node_id);
    var pledges = st.getPledges();
    var prep = try pledges.initPrepare();
    try prep.setQuorumSetHash(qsh);
    var ballot = try prep.initBallot();
    try ballot.setCounter(spec.ballot.counter);
    try ballot.setValue(spec.ballot.value);
    if (spec.prepared) |b| {
        var pb = try prep.initPrepared();
        try pb.setCounter(b.counter);
        try pb.setValue(b.value);
    }
    if (spec.prepared_prime) |b| {
        var pb = try prep.initPreparedPrime();
        try pb.setCounter(b.counter);
        try pb.setValue(b.value);
    }
    try prep.setNC(spec.n_c);
    try prep.setNH(spec.n_h);
    const framed = try mb.toBytes();
    return canonical.canonicalFlatFromFramed(gpa, framed);
}

fn sanityConfirmBytes(
    gpa: std.mem.Allocator,
    node_id: []const u8,
    qsh: []const u8,
    ballot: SanityB,
    n_prepared: u32,
    n_commit: u32,
    n_h: u32,
) ![]u8 {
    var mb = MessageBuilder.init(gpa);
    var st = try sanityStatementBuilder(&mb, node_id);
    var pledges = st.getPledges();
    var conf = try pledges.initConfirm();
    try conf.setQuorumSetHash(qsh);
    var bb = try conf.initBallot();
    try bb.setCounter(ballot.counter);
    try bb.setValue(ballot.value);
    try conf.setNPrepared(n_prepared);
    try conf.setNCommit(n_commit);
    try conf.setNH(n_h);
    const framed = try mb.toBytes();
    return canonical.canonicalFlatFromFramed(gpa, framed);
}

fn sanityExternalizeBytes(
    gpa: std.mem.Allocator,
    node_id: []const u8,
    qsh: []const u8,
    commit: SanityB,
    n_h: u32,
) ![]u8 {
    var mb = MessageBuilder.init(gpa);
    var st = try sanityStatementBuilder(&mb, node_id);
    var pledges = st.getPledges();
    var ext = try pledges.initExternalize();
    var cb = try ext.initCommit();
    try cb.setCounter(commit.counter);
    try cb.setValue(commit.value);
    try ext.setNH(n_h);
    try ext.setCommitQuorumSetHash(qsh);
    const framed = try mb.toBytes();
    return canonical.canonicalFlatFromFramed(gpa, framed);
}

fn sanityUnsetBytes(gpa: std.mem.Allocator, node_id: []const u8) ![]u8 {
    var mb = MessageBuilder.init(gpa);
    _ = try sanityStatementBuilder(&mb, node_id);
    const framed = try mb.toBytes();
    return canonical.canonicalFlatFromFramed(gpa, framed);
}

/// Statement with the pledges discriminant written RAW and NO arm struct
/// initialized — unreachable through the normal builders. tag > 4 exercises
/// unknown_pledges_tag; tags 1-4 leave the pledges pointer null (review
/// finding #9): capnp readStruct on a null pointer fails, so today's expected
/// reason is decode_error — DERIVED below by calling checkStatementSane, like
/// every other expectation. Both shapes survive canonical re-encoding (the
/// discriminant is plain data; the never-written arm pointer is a trailing
/// zero pointer word that canonicalization simply trims).
fn sanityRawPledgesTagBytes(gpa: std.mem.Allocator, node_id: []const u8, tag: u16) ![]u8 {
    var mb = MessageBuilder.init(gpa);
    var st = try sanityStatementBuilder(&mb, node_id);
    st._builder.writeU16(8, tag);
    const framed = try mb.toBytes();
    return canonical.canonicalFlatFromFramed(gpa, framed);
}

/// The M1 statement-sanity case list. Sane cases reuse the crypto.json
/// statement bytes so both files pin the same encodings. EVERY InsaneReason
/// arm has at least one case (S2/S4/S7/#9), enforced by the replay test.
fn sanityStatementCases(
    gpa: std.mem.Allocator,
    qsh: [32]u8,
    nominate_bytes: []const u8,
    prepare_bytes: []const u8,
) ![]const StatementSanityCase {
    const node_id = try crypto.publicKeyFromSeed(seeds[0]);
    const node = try gpa.dupe(u8, &node_id);
    const qs = try gpa.dupe(u8, &qsh);

    // > default maxValueBytes (4096)
    const oversized = try gpa.alloc(u8, 4097);
    @memset(oversized, 0x77);

    // 65 one-byte strictly-ascending values: breaches the frozen
    // maxNominationValues = 64 (§4.5) with nothing else wrong.
    const many_storage = try gpa.alloc([1]u8, 65);
    const many = try gpa.alloc([]const u8, 65);
    for (many_storage, 0..) |*s, i| {
        s[0] = @intCast(i);
        many[i] = s;
    }

    var cases: std.ArrayList(StatementSanityCase) = .empty;
    try cases.append(gpa, .{ .name = "sane nominate", .flat = nominate_bytes });
    try cases.append(gpa, .{ .name = "sane prepare", .flat = prepare_bytes });
    try cases.append(gpa, .{
        .name = "prepare counter-0 ballot",
        .flat = try sanityPrepareBytes(gpa, node, qs, .{ .ballot = .{ .counter = 0, .value = &prepare_value } }),
    });
    try cases.append(gpa, .{
        .name = "nomination unsorted votes",
        // 0xde… before 0xca… — descending byte order
        .flat = try sanityNominateBytes(gpa, node, qs, &.{ &nominate_vote, &prepare_value }, &.{}),
    });
    try cases.append(gpa, .{
        .name = "nomination empty votes",
        .flat = try sanityNominateBytes(gpa, node, qs, &.{}, &.{}),
    });
    try cases.append(gpa, .{
        .name = "nomination duplicate vote",
        // equal adjacent = not strictly ascending
        .flat = try sanityNominateBytes(gpa, node, qs, &.{ &nominate_vote, &nominate_vote }, &.{}),
    });
    try cases.append(gpa, .{
        .name = "nomination oversized value",
        .flat = try sanityNominateBytes(gpa, node, qs, &.{oversized}, &.{}),
    });
    try cases.append(gpa, .{
        .name = "prepare bad nC nH relation",
        .flat = try sanityPrepareBytes(gpa, node, qs, .{
            .ballot = .{ .counter = 2, .value = &prepare_value },
            .prepared = .{ .counter = 2, .value = &prepare_value },
            .n_c = 2,
            .n_h = 1,
        }),
    });
    try cases.append(gpa, .{
        .name = "prepare preparedPrime without prepared",
        .flat = try sanityPrepareBytes(gpa, node, qs, .{
            .ballot = .{ .counter = 1, .value = &prepare_value },
            .prepared_prime = .{ .counter = 1, .value = &nominate_vote },
        }),
    });
    try cases.append(gpa, .{
        .name = "unset pledges",
        .flat = try sanityUnsetBytes(gpa, node),
    });
    try cases.append(gpa, .{
        .name = "wrong-length nodeId",
        .flat = try sanityNominateBytes(gpa, node[0..31], qs, &.{&nominate_vote}, &.{}),
    });
    try cases.append(gpa, .{
        .name = "confirm nPrepared zero",
        .flat = try sanityConfirmBytes(gpa, node, qs, .{ .counter = 1, .value = &prepare_value }, 0, 1, 1),
    });
    // -- S2/S4/S7/#9 coverage: the remaining InsaneReason arms ---------------
    try cases.append(gpa, .{
        // no sane Externalize existed in any vector file before this case —
        // it pins the Externalize wire encoding
        .name = "sane externalize",
        .flat = try sanityExternalizeBytes(gpa, node, qs, .{ .counter = 2, .value = &prepare_value }, 5),
    });
    try cases.append(gpa, .{
        .name = "externalize nH below commit counter",
        .flat = try sanityExternalizeBytes(gpa, node, qs, .{ .counter = 3, .value = &prepare_value }, 2),
    });
    try cases.append(gpa, .{
        .name = "nominate 16-byte quorumSetHash",
        .flat = try sanityNominateBytes(gpa, node, qs[0..16], &.{&nominate_vote}, &.{}),
    });
    try cases.append(gpa, .{
        .name = "nomination too many votes",
        .flat = try sanityNominateBytes(gpa, node, qs, many, &.{}),
    });
    try cases.append(gpa, .{
        .name = "nomination unsorted accepted",
        // votes fine; accepted 0xde… before 0xca… — descending byte order
        .flat = try sanityNominateBytes(gpa, node, qs, &.{&nominate_vote}, &.{ &nominate_vote, &prepare_value }),
    });
    try cases.append(gpa, .{
        .name = "nomination too many accepted",
        .flat = try sanityNominateBytes(gpa, node, qs, &.{&nominate_vote}, many),
    });
    try cases.append(gpa, .{
        .name = "prepare preparedPrime compatible with prepared",
        // pp < p but SAME value bytes: fails the ⋦ (less AND incompatible) rule
        .flat = try sanityPrepareBytes(gpa, node, qs, .{
            .ballot = .{ .counter = 3, .value = &prepare_value },
            .prepared = .{ .counter = 2, .value = &prepare_value },
            .prepared_prime = .{ .counter = 1, .value = &prepare_value },
        }),
    });
    try cases.append(gpa, .{
        .name = "prepare nH without prepared",
        .flat = try sanityPrepareBytes(gpa, node, qs, .{
            .ballot = .{ .counter = 1, .value = &prepare_value },
            .n_h = 1,
        }),
    });
    try cases.append(gpa, .{
        .name = "confirm nCommit zero",
        .flat = try sanityConfirmBytes(gpa, node, qs, .{ .counter = 1, .value = &prepare_value }, 1, 0, 1),
    });
    try cases.append(gpa, .{
        .name = "confirm nCommit above nH",
        .flat = try sanityConfirmBytes(gpa, node, qs, .{ .counter = 5, .value = &prepare_value }, 1, 3, 2),
    });
    try cases.append(gpa, .{
        .name = "unknown pledges discriminant 5 (raw tag write)",
        .flat = try sanityRawPledgesTagBytes(gpa, node, 5),
    });
    // finding #9: discriminant set, pledges arm pointer null — one per arm
    try cases.append(gpa, .{
        .name = "nominate discriminant with null pledges pointer",
        .flat = try sanityRawPledgesTagBytes(gpa, node, 1),
    });
    try cases.append(gpa, .{
        .name = "prepare discriminant with null pledges pointer",
        .flat = try sanityRawPledgesTagBytes(gpa, node, 2),
    });
    try cases.append(gpa, .{
        .name = "confirm discriminant with null pledges pointer",
        .flat = try sanityRawPledgesTagBytes(gpa, node, 3),
    });
    try cases.append(gpa, .{
        .name = "externalize discriminant with null pledges pointer",
        .flat = try sanityRawPledgesTagBytes(gpa, node, 4),
    });
    return cases.toOwnedSlice(gpa);
}

/// Derived by CALLING checkStatementSane on the decoded bytes.
fn statementInsaneName(gpa: std.mem.Allocator, flat: []const u8) !?[]const u8 {
    var fm = try canonical.decodeFlat(gpa, flat, .{});
    const reader = try gen_slcp.Statement.Reader.init(&fm.msg);
    return if (statement.checkStatementSane(reader, .{})) |r| @tagName(r) else null;
}

// ---------------------------------------------------------------------------
// sanity.json (M0 partial: decode/canonicality level; M1 adds statements)
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

fn renderSanity(
    gpa: std.mem.Allocator,
    statement_bytes: []const u8,
    stmt_cases: []const StatementSanityCase,
) ![]const u8 {
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
    try w.writeAll("  \"note\": \"M0 decode/canonicality cases; M1 extended with the statements section (checkStatementSane — every InsaneReason arm has at least one case; decode_error cases are discriminant-set-but-null-pledges-pointer shapes); full engine input_status cases land at M2\",\n");
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
    try w.writeAll("  ],\n  \"statements\": [\n");
    for (stmt_cases, 0..) |c, i| {
        const insane = try statementInsaneName(gpa, c.flat);
        try w.writeAll("    {\"name\": ");
        try jsonString(w, c.name);
        try w.writeAll(", \"statementBytes\": ");
        try jsonHex(w, c.flat);
        try w.writeAll(", \"insane\": ");
        if (insane) |n| try jsonString(w, n) else try w.writeAll("null");
        try w.writeAll(if (i + 1 < stmt_cases.len) "},\n" else "}\n");
    }
    try w.writeAll("  ]\n}\n");

    return sink.written();
}

// ---------------------------------------------------------------------------
// leader.json (M1, vector set 3): Gi leader election. Every expectation is
// DERIVED by calling src/engine/nomination.zig — weights, neighbors,
// priorities, the round leader, and the accumulated leader set. The "qset"
// field is the CONFIGURED set; the round is computed over
// qset.exciseNode(configured, localNode) (design §5.4/§12 self-excision),
// so these vectors pin exciseNode cross-implementation.
// ---------------------------------------------------------------------------

const LeaderCase = struct {
    name: []const u8,
    slot: u64,
    round: u32,
    local: qset.NodeId,
    spec: QSpec,
};

/// Dedup-append every node in `qs`'s tree in declaration order.
fn collectQsNodes(gpa: std.mem.Allocator, qs: *const qset.QuorumSetOwned, out: *std.ArrayList(qset.NodeId)) !void {
    for (qs.validators) |v| {
        var seen = false;
        for (out.items) |*n| {
            if (std.mem.eql(u8, n, &v)) {
                seen = true;
                break;
            }
        }
        if (!seen) try out.append(gpa, v);
    }
    for (qs.inner_sets) |*inner| try collectQsNodes(gpa, inner, out);
}

fn renderLeaderCase(
    gpa: std.mem.Allocator,
    w: *std.Io.Writer,
    c: LeaderCase,
    prev: []const u8,
) !void {
    const outcome = try processSpec(gpa, c.spec);
    // The round runs over the SELF-EXCISED local qset (F1: stellar-core
    // normalizeQSet(myQSet, &localID), NominationProtocol.cpp:226); null
    // when excision emptied it.
    var excised = try qset.exciseNode(gpa, &outcome.ok.owned, c.local);
    const r: nomination.LeaderRound = .{
        .slot = c.slot,
        .prev_value = prev,
        .round = c.round,
        .local_node = c.local,
        .qs = if (excised) |*e| e else null,
    };
    // Weights/neighbors/priorities are listed for every node in the
    // CONFIGURED normalized tree plus localNode (localNode first, dedup'd) —
    // NOT the excised tree — so a case where excision zeroes a node's weight
    // still lists that node.
    var member_list: std.ArrayList(qset.NodeId) = .empty;
    try member_list.append(gpa, c.local);
    try collectQsNodes(gpa, &outcome.ok.owned, &member_list);
    const members = member_list.items;

    try w.writeAll("    {\"name\": ");
    try jsonString(w, c.name);
    try w.print(",\n     \"slot\": {d}, \"prevValue\": ", .{c.slot});
    try jsonHex(w, prev);
    try w.print(", \"round\": {d}, \"localNode\": ", .{c.round});
    try jsonHex(w, &c.local);
    try w.writeAll(",\n     \"qset\": ");
    try writeSpecJson(w, c.spec);

    try w.writeAll(",\n     \"weights\": [");
    for (members, 0..) |node, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"node\": ");
        try jsonHex(w, &node);
        try w.print(", \"weight\": \"{d}\"}}", .{nomination.weight(r, node)});
    }

    try w.writeAll("],\n     \"neighbors\": [");
    var first = true;
    for (members) |node| {
        if (!nomination.isNeighbor(r, node)) continue;
        if (!first) try w.writeByte(',');
        first = false;
        try jsonHex(w, &node);
    }

    try w.writeAll("],\n     \"priorities\": [");
    for (members, 0..) |node, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"node\": ");
        try jsonHex(w, &node);
        try w.print(", \"priority\": \"{d}\"}}", .{nomination.priority(r, node)});
    }

    try w.writeAll("],\n     \"leader\": ");
    if (try nomination.roundLeader(gpa, r)) |leader| {
        try jsonHex(w, &leader);
    } else {
        try w.writeAll("null");
    }

    // accumulatedLeaders: RoundLeaders.advance over rounds 0..=round with the
    // same (slot, prevValue, localNode, qset) — see the file-level note.
    var rl: nomination.RoundLeaders = .{};
    var rr: u32 = 0;
    while (rr <= c.round) : (rr += 1) {
        var round_r = r;
        round_r.round = rr;
        _ = try rl.advance(gpa, round_r);
    }
    try w.writeAll(",\n     \"accumulatedLeaders\": [");
    for (rl.items(), 0..) |*node, i| {
        if (i > 0) try w.writeByte(',');
        try jsonHex(w, node);
    }
    try w.writeAll("]");
}

fn renderLeader(gpa: std.mem.Allocator) ![]const u8 {
    var sink = std.Io.Writer.Allocating.init(gpa);
    const w = &sink.writer;

    const prev: [32]u8 = @splat(0xaa);

    const flat_vals = ids(&.{ 0x01, 0x02, 0x03 });
    const flat: QSpec = .{ .threshold = 2, .validators = &flat_vals };

    const org1_vals = ids(&.{ 0x10, 0x11, 0x12 });
    const org2_vals = ids(&.{ 0x20, 0x21, 0x22 });
    const org3_vals = ids(&.{ 0x30, 0x31, 0x32 });
    const nested: QSpec = .{ .threshold = 2, .validators = &.{}, .inners = &.{
        .{ .threshold = 2, .validators = &org1_vals },
        .{ .threshold = 2, .validators = &org2_vals },
        .{ .threshold = 2, .validators = &org3_vals },
    } };

    var cases: std.ArrayList(LeaderCase) = .empty;
    try cases.append(gpa, .{ .name = "flat 2-of-3, local inside", .slot = 1, .round = 0, .local = @splat(0x02), .spec = flat });
    try cases.append(gpa, .{ .name = "flat 2-of-3, local outside", .slot = 1, .round = 0, .local = @splat(0x99), .spec = flat });
    try cases.append(gpa, .{ .name = "nested 2-of-3-orgs, local outside", .slot = 2, .round = 1, .local = @splat(0x99), .spec = nested });
    try cases.append(gpa, .{ .name = "nested 2-of-3-orgs, local inside org1", .slot = 2, .round = 0, .local = @splat(0x11), .spec = nested });
    // At (slot 6, round 0) the excision is decisive: over the unexcised
    // configured tree node 03 would be a neighbor (weight 2/3) and win, but
    // over the excised 1-of-{01,03} round qset (weight 1/2) it fails the
    // neighbor test and node 01 leads — this case pins the F1 fix.
    try cases.append(gpa, .{ .name = "flat 2-of-3, local inside, excision flips leader", .slot = 6, .round = 0, .local = @splat(0x02), .spec = flat });
    var rr: u32 = 0;
    while (rr <= 3) : (rr += 1) {
        const names = [_][]const u8{
            "accumulation flat 2-of-3, round 0",
            "accumulation flat 2-of-3, round 1",
            "accumulation flat 2-of-3, round 2",
            "accumulation flat 2-of-3, round 3",
        };
        try cases.append(gpa, .{ .name = names[rr], .slot = 3, .round = rr, .local = @splat(0x99), .spec = flat });
    }

    try w.writeAll("{\n  \"version\": 1,\n");
    try w.writeAll("  \"note\": \"qset is the CONFIGURED local set; every result is computed over the SELF-EXCISED round qset = exciseNode(configured, localNode) (self removed, that level's threshold decremented, re-normalized; null when excision empties it) — stellar-core normalizeQSet(myQSet, &localID) semantics, design section 5.4/12. weights/neighbors/priorities are listed localNode first, then every node of the normalized CONFIGURED tree in declaration order, dedup'd; accumulatedLeaders = RoundLeaders.advance over rounds 0..=round with the case's fixed slot/prevValue/localNode/excised qset, sorted ascending by NodeId. valuePicks pins pickLeaderValue: pickedIndex = argmax of Gi(tag=3 valueHash, slot, prevValue, round, value) over values, ties keeping the LATER index, null for an empty list — the qset plays no part in value hashing\",\n");
    try w.writeAll("  \"cases\": [\n");
    for (cases.items, 0..) |c, i| {
        try renderLeaderCase(gpa, w, c, &prev);
        try w.writeAll(if (i + 1 < cases.items.len) "},\n" else "}\n");
    }

    // -- valuePicks: pickLeaderValue coverage (review gap) -------------------
    // Every pickedIndex/pickedValue is DERIVED by calling
    // nomination.pickLeaderValue; the qset plays no part (qs = null).
    const vp_local: qset.NodeId = @splat(0x99);
    const distinct = [_][]const u8{ "alpha", "bravo", "charlie", "delta" };
    const single = [_][]const u8{"only"};
    const tie = [_][]const u8{ &nominate_vote, &nominate_vote };
    const VpCase = struct {
        name: []const u8,
        slot: u64,
        round: u32,
        values: []const []const u8,
    };
    const vp_cases = [_]VpCase{
        .{ .name = "four distinct values, max-Gi pick", .slot = 4, .round = 0, .values = &distinct },
        .{ .name = "four distinct values, later round reshuffles", .slot = 4, .round = 2, .values = &distinct },
        .{ .name = "single value", .slot = 4, .round = 0, .values = &single },
        .{ .name = "tie: identical values, later index wins", .slot = 4, .round = 0, .values = &tie },
        .{ .name = "empty list", .slot = 4, .round = 0, .values = &.{} },
    };
    try w.writeAll("  ],\n  \"valuePicks\": [\n");
    for (vp_cases, 0..) |c, i| {
        const r: nomination.LeaderRound = .{
            .slot = c.slot,
            .prev_value = &prev,
            .round = c.round,
            .local_node = vp_local,
            .qs = null,
        };
        const picked = nomination.pickLeaderValue(r, c.values);
        try w.writeAll("    {\"name\": ");
        try jsonString(w, c.name);
        try w.print(",\n     \"slot\": {d}, \"prevValue\": ", .{c.slot});
        try jsonHex(w, &prev);
        try w.print(", \"round\": {d}, \"localNode\": ", .{c.round});
        try jsonHex(w, &vp_local);
        try w.writeAll(",\n     \"values\": [");
        for (c.values, 0..) |v, j| {
            if (j > 0) try w.writeByte(',');
            try jsonHex(w, v);
        }
        try w.writeAll("], \"pickedIndex\": ");
        if (picked) |idx| {
            try w.print("{d}, \"pickedValue\": ", .{idx});
            try jsonHex(w, c.values[idx]);
        } else {
            try w.writeAll("null, \"pickedValue\": null");
        }
        try w.writeAll(if (i + 1 < vp_cases.len) "},\n" else "}\n");
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

    const stmt_cases = try sanityStatementCases(gpa, qsh, nominate_bytes, prepare_bytes);

    try writeFile(io, "vectors/crypto.json", try renderCrypto(gpa, &statements));
    try writeFile(io, "vectors/qset.json", try renderQset(gpa));
    try writeFile(io, "vectors/lint.json", try renderLint(gpa));
    try writeFile(io, "vectors/sanity.json", try renderSanity(gpa, nominate_bytes, stmt_cases));
    try writeFile(io, "vectors/leader.json", try renderLeader(gpa));
}
