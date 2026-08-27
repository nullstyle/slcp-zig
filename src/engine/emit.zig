//! Own-statement emission (design §4.2 sender path, §5.3 effect ordering):
//! build Statement → canonicalizeFlatFromBuilder (capnp-zig v0.14.0 hot
//! path) → digest → deterministic Ed25519 → Envelope frame → effects.
//! The normative order is enforced here: persist_own_envelope ALWAYS
//! precedes the broadcast_envelope for the same statement.
//!
//! Callers (nomination.zig / ballot.zig) gate on watcher mode and
//! fully_validated BEFORE calling; this module never checks.

const std = @import("std");
const capnpc = @import("capnpc-zig");
const canonical = @import("../canonical.zig");
const crypto = @import("../crypto.zig");
const gen_slcp = @import("../gen/slcp.zig");
const engine = @import("engine.zig");
const statement_mod = @import("statement.zig");
const stored = @import("stored.zig");

pub const BV = statement_mod.BallotView;

/// What a protocol wants to say. Slices are borrowed; emission copies.
pub const OwnStatement = union(enum) {
    nominate: struct {
        qset_hash: [32]u8,
        votes: []const []const u8, // strictly ascending (protocol invariant)
        accepted: []const []const u8,
    },
    prepare: struct {
        qset_hash: [32]u8,
        ballot: BV,
        prepared: ?BV,
        prepared_prime: ?BV,
        n_c: u32,
        n_h: u32,
    },
    confirm: struct {
        qset_hash: [32]u8,
        ballot: BV,
        n_prepared: u32,
        n_commit: u32,
        n_h: u32,
    },
    externalize: struct {
        commit: BV,
        n_h: u32,
        commit_qset_hash: [32]u8,
    },
};

fn setBallot(b: anytype, v: BV) !void {
    try b.setCounter(v.counter);
    try b.setValue(v.value);
}

fn writeValueList(list: anytype, vals: []const []const u8) !void {
    for (vals, 0..) |v, i| try list.set(@intCast(i), v);
}

/// Build, sign, and emit an own statement for `slot_index`:
/// persist_own_envelope then broadcast_envelope effects (queue-owned
/// copies), returning a StoredEnvelope (decoded + framed wire bytes) the
/// caller stores as the slot's own latest for that protocol.
/// Absent-pointer discipline (§4.3): empty lists / unset ballots are never
/// initialized.
pub fn emit(ctx: *engine.Ctx, slot_index: u64, own: OwnStatement) !stored.StoredEnvelope {
    const gpa = ctx.gpa;
    const seed = ctx.cfg.secret_seed orelse return error.WatcherCannotEmit;

    // 1. Build the Statement message.
    var mb = capnpc.message.MessageBuilder.init(gpa);
    defer mb.deinit();
    var st = try gen_slcp.Statement.Builder.init(&mb);
    try st.setNodeId(&ctx.cfg.node_id);
    try st.setSlotIndex(slot_index);
    var pledges = st.getPledges();
    switch (own) {
        .nominate => |n| {
            std.debug.assert(n.votes.len > 0); // wire-sane: votes nonempty
            var nom = try pledges.initNominate();
            try nom.setQuorumSetHash(&n.qset_hash);
            const votes = try nom.initVotes(@intCast(n.votes.len));
            try writeValueList(votes, n.votes);
            if (n.accepted.len > 0) {
                const acc = try nom.initAccepted(@intCast(n.accepted.len));
                try writeValueList(acc, n.accepted);
            }
        },
        .prepare => |p| {
            var prep = try pledges.initPrepare();
            try prep.setQuorumSetHash(&p.qset_hash);
            var ballot = try prep.initBallot();
            try setBallot(&ballot, p.ballot);
            if (p.prepared) |v| {
                var b = try prep.initPrepared();
                try setBallot(&b, v);
            }
            if (p.prepared_prime) |v| {
                var b = try prep.initPreparedPrime();
                try setBallot(&b, v);
            }
            try prep.setNC(p.n_c);
            try prep.setNH(p.n_h);
        },
        .confirm => |c| {
            var conf = try pledges.initConfirm();
            try conf.setQuorumSetHash(&c.qset_hash);
            var ballot = try conf.initBallot();
            try setBallot(&ballot, c.ballot);
            try conf.setNPrepared(c.n_prepared);
            try conf.setNCommit(c.n_commit);
            try conf.setNH(c.n_h);
        },
        .externalize => |e| {
            var ext = try pledges.initExternalize();
            var commit = try ext.initCommit();
            try setBallot(&commit, e.commit);
            try ext.setNH(e.n_h);
            try ext.setCommitQuorumSetHash(&e.commit_qset_hash);
        },
    }

    // 2. Canonicalize (the signed bytes), digest, sign.
    const statement_bytes = try canonical.canonicalFlatFromBuilder(gpa, &mb);
    defer gpa.free(statement_bytes);
    const digest = crypto.statementDigest(ctx.cfg.network_id, statement_bytes);
    const signature = try crypto.sign(seed, digest);

    // 3. Build the Envelope frame.
    var emb = capnpc.message.MessageBuilder.init(gpa);
    defer emb.deinit();
    var env = try gen_slcp.Envelope.Builder.init(&emb);
    try env.setStatementBytes(statement_bytes);
    try env.setSignature(&signature);
    const envelope_framed = try emb.toBytes();
    defer gpa.free(envelope_framed);

    // 4. Decode our own statement back into owned form (single source of
    // truth for stored state; also cross-checks the round trip in debug).
    var msg = try canonical.decodeFlat(gpa, statement_bytes, .{});
    defer msg.deinit();
    const reader = try gen_slcp.Statement.Reader.init(&msg);
    var own_statement = try stored.fromReader(gpa, reader);
    errdefer own_statement.deinit(gpa);

    // 5. Effects: persist strictly before broadcast (§5.3 / §10).
    const persist_copy = try gpa.dupe(u8, envelope_framed);
    try ctx.effects.push(.{ .persist_own_envelope = .{ .slot = slot_index, .bytes = persist_copy } });
    const bcast_copy = try gpa.dupe(u8, envelope_framed);
    try ctx.effects.push(.{ .broadcast_envelope = .{ .slot = slot_index, .bytes = bcast_copy } });

    return .{
        .envelope_framed = try gpa.dupe(u8, envelope_framed),
        .statement = own_statement,
    };
}

test "emit: persist precedes broadcast; envelope verifies and round-trips" {
    const gpa = std.testing.allocator;
    const qset = @import("qset.zig");
    const limits_mod = @import("limits.zig");
    const qset_store = @import("qset_store.zig");
    const driver_mod = @import("../driver.zig");

    var effects = engine.EffectQueue.init(gpa);
    defer effects.deinit();
    var store = qset_store.Store.init(gpa, 8);
    defer store.deinit();

    const seed: [32]u8 = @splat(9);
    const cfg = engine.Config{
        .network_id = crypto.networkIdFromPassphrase("emit-test"),
        .node_id = try crypto.publicKeyFromSeed(seed),
        .secret_seed = seed,
        .quorum_set = undefined, // not touched by emit
        .limits = limits_mod.Limits{},
    };
    _ = qset;
    const drv = driver_mod.Driver.default();
    var stored_bytes: usize = 0;
    var ctx = engine.Ctx{
        .gpa = gpa,
        .cfg = &cfg,
        .drv = &drv,
        .effects = &effects,
        .qsets = &store,
        .excised = null,
        .local_qset_hash = @splat(3),
        .stored_bytes = &stored_bytes,
    };

    var own = try emit(&ctx, 7, .{ .nominate = .{
        .qset_hash = @splat(3),
        .votes = &.{"vote-a"},
        .accepted = &.{},
    } });
    defer own.deinit(gpa);

    // effect order: persist, then broadcast, byte-identical payloads
    const first = effects.peek().?;
    try std.testing.expect(first.* == .persist_own_envelope);
    const persist_bytes = try gpa.dupe(u8, first.persist_own_envelope.bytes);
    defer gpa.free(persist_bytes);
    effects.commit();
    const second = effects.peek().?;
    try std.testing.expect(second.* == .broadcast_envelope);
    try std.testing.expectEqualSlices(u8, persist_bytes, second.broadcast_envelope.bytes);
    try std.testing.expectEqualSlices(u8, persist_bytes, own.envelope_framed);
    effects.commit();

    // signature verifies over the statement bytes; statement decodes sane
    var env_msg = try capnpc.message.Message.init(gpa, own.envelope_framed, .{});
    defer env_msg.deinit();
    const env_reader = try gen_slcp.Envelope.Reader.init(&env_msg);
    const stmt_bytes = try env_reader.getStatementBytes();
    const sig_bytes = try env_reader.getSignature();
    var sig: [64]u8 = undefined;
    @memcpy(&sig, sig_bytes);
    const digest = crypto.statementDigest(cfg.network_id, stmt_bytes);
    try std.testing.expect(crypto.verify(cfg.node_id, digest, sig));
    try std.testing.expect(canonical.isCanonicalFlat(gpa, stmt_bytes));

    // decoded own statement matches what we asked for
    try std.testing.expect(own.statement.pledges == .nominate);
    try std.testing.expectEqualSlices(u8, "vote-a", own.statement.pledges.nominate.votes[0]);
    try std.testing.expectEqual(@as(u64, 7), own.statement.slot);
}
