//! Byzantine envelope construction toolkit (design §13.2). A `Forger` holds a
//! real key and network context and mints envelope frames — both HONEST-shaped
//! ones with adversarial CONTENT (equivocation, stale replay, counter
//! inflation, qset lies, value spam) and MALFORMED ones (non-canonical
//! encodings, forged signatures). The engine's own emit path only ever
//! produces honest statements, so the adversary needs its own builder that
//! deliberately bypasses those invariants.
//!
//! Every frame this produces is a real Envelope over real bytes; where the
//! attack is "a valid signature over a non-canonical encoding" or "a wrong
//! signature", that is constructed explicitly and labeled. Safety of the
//! honest engines against all of these is the M3 acceptance property.

const std = @import("std");
const slcp = @import("slcp-core");

const capnpc = slcp.capnpc;
const canonical = slcp.canonical;
const crypto = slcp.crypto;
const gen_slcp = slcp.gen.slcp;

const MessageBuilder = capnpc.message.MessageBuilder;

pub const BV = struct { counter: u32, value: []const u8 };

/// A statement's fields, exactly as they go on the wire — no sanity gating,
/// so an adversary can build counter-0 ballots, unsorted lists, oversized
/// values, etc.
pub const RawStatement = union(enum) {
    nominate: struct {
        qset_hash: [32]u8,
        votes: []const []const u8,
        accepted: []const []const u8,
    },
    prepare: struct {
        qset_hash: [32]u8,
        ballot: BV,
        prepared: ?BV = null,
        prepared_prime: ?BV = null,
        n_c: u32 = 0,
        n_h: u32 = 0,
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

/// Build the raw (framed, NOT flat) Statement message for `st` signed by
/// `node_id`. Caller owns the result. Unlike emit.zig this initializes list
/// pointers even when empty when `honest_absent` is false, so the adversary
/// can also produce present-but-default pointer shapes.
fn buildStatementFramed(gpa: std.mem.Allocator, node_id: [32]u8, slot: u64, st: RawStatement) ![]const u8 {
    var mb = MessageBuilder.init(gpa);
    defer mb.deinit();
    var s = try gen_slcp.Statement.Builder.init(&mb);
    try s.setNodeId(&node_id);
    try s.setSlotIndex(slot);
    var pledges = s.getPledges();
    switch (st) {
        .nominate => |n| {
            var nom = try pledges.initNominate();
            try nom.setQuorumSetHash(&n.qset_hash);
            if (n.votes.len > 0) {
                const vl = try nom.initVotes(@intCast(n.votes.len));
                for (n.votes, 0..) |v, i| try vl.set(@intCast(i), v);
            }
            if (n.accepted.len > 0) {
                const al = try nom.initAccepted(@intCast(n.accepted.len));
                for (n.accepted, 0..) |v, i| try al.set(@intCast(i), v);
            }
        },
        .prepare => |p| {
            var prep = try pledges.initPrepare();
            try prep.setQuorumSetHash(&p.qset_hash);
            var b = try prep.initBallot();
            try setBallot(&b, p.ballot);
            if (p.prepared) |v| {
                var pb = try prep.initPrepared();
                try setBallot(&pb, v);
            }
            if (p.prepared_prime) |v| {
                var pb = try prep.initPreparedPrime();
                try setBallot(&pb, v);
            }
            try prep.setNC(p.n_c);
            try prep.setNH(p.n_h);
        },
        .confirm => |c| {
            var conf = try pledges.initConfirm();
            try conf.setQuorumSetHash(&c.qset_hash);
            var b = try conf.initBallot();
            try setBallot(&b, c.ballot);
            try conf.setNPrepared(c.n_prepared);
            try conf.setNCommit(c.n_commit);
            try conf.setNH(c.n_h);
        },
        .externalize => |e| {
            var ext = try pledges.initExternalize();
            var b = try ext.initCommit();
            try setBallot(&b, e.commit);
            try ext.setNH(e.n_h);
            try ext.setCommitQuorumSetHash(&e.commit_qset_hash);
        },
    }
    return mb.toBytes();
}

fn frameEnvelope(gpa: std.mem.Allocator, statement_bytes: []const u8, signature: [64]u8) ![]const u8 {
    var mb = MessageBuilder.init(gpa);
    defer mb.deinit();
    var env = try gen_slcp.Envelope.Builder.init(&mb);
    try env.setStatementBytes(statement_bytes);
    try env.setSignature(&signature);
    return mb.toBytes();
}

/// An adversary key-holder within a specific network.
pub const Forger = struct {
    gpa: std.mem.Allocator,
    seed: [32]u8,
    node_id: [32]u8,
    network_id: [32]u8,

    pub fn init(gpa: std.mem.Allocator, seed: [32]u8, network_id: [32]u8) !Forger {
        return .{
            .gpa = gpa,
            .seed = seed,
            .node_id = try crypto.publicKeyFromSeed(seed),
            .network_id = network_id,
        };
    }

    /// A correctly-signed envelope over the CANONICAL encoding of `st`.
    /// Honest wire shape; adversarial only in `st`'s content. Caller frees.
    pub fn sign(self: *Forger, slot: u64, st: RawStatement) ![]const u8 {
        const framed = try buildStatementFramed(self.gpa, self.node_id, slot, st);
        defer self.gpa.free(framed);
        const flat = try canonical.canonicalFlatFromFramed(self.gpa, framed);
        defer self.gpa.free(flat);
        const digest = crypto.statementDigest(self.network_id, flat);
        const sig = try crypto.sign(self.seed, digest);
        return frameEnvelope(self.gpa, flat, sig);
    }

    /// A validly-SIGNED envelope whose statementBytes are NON-CANONICAL: the
    /// signature covers exactly the transmitted (padded) bytes, so it
    /// verifies, but a trailing zero word makes them fail `isCanonical`.
    /// Exercises the strict_canonical=on rejection and the lenient path.
    pub fn signNonCanonical(self: *Forger, slot: u64, st: RawStatement) ![]const u8 {
        const framed = try buildStatementFramed(self.gpa, self.node_id, slot, st);
        defer self.gpa.free(framed);
        const flat = try canonical.canonicalFlatFromFramed(self.gpa, framed);
        defer self.gpa.free(flat);
        // Append one zero word: still decodes (the root pointer is unchanged),
        // but the segment has trailing slack ⇒ not canonical.
        const padded = try self.gpa.alloc(u8, flat.len + 8);
        defer self.gpa.free(padded);
        @memcpy(padded[0..flat.len], flat);
        @memset(padded[flat.len..], 0);
        const digest = crypto.statementDigest(self.network_id, padded);
        const sig = try crypto.sign(self.seed, digest);
        return frameEnvelope(self.gpa, padded, sig);
    }

    /// A WRONG-signature envelope: canonical statementBytes, but the
    /// signature is garbage (sig forgery / bit-flip attack). Must be rejected
    /// as invalid_signature.
    pub fn signForged(self: *Forger, slot: u64, st: RawStatement) ![]const u8 {
        const framed = try buildStatementFramed(self.gpa, self.node_id, slot, st);
        defer self.gpa.free(framed);
        const flat = try canonical.canonicalFlatFromFramed(self.gpa, framed);
        defer self.gpa.free(flat);
        const digest = crypto.statementDigest(self.network_id, flat);
        var sig = try crypto.sign(self.seed, digest);
        sig[0] ^= 0xff; // corrupt
        return frameEnvelope(self.gpa, flat, sig);
    }

    /// A cross-network replay: correctly signed, but under a DIFFERENT
    /// networkId, so the digest differs on the victim network → rejected as
    /// invalid_signature (the domain-separation guarantee, §4.2).
    pub fn signWrongNetwork(self: *Forger, other_network: [32]u8, slot: u64, st: RawStatement) ![]const u8 {
        var alt = self.*;
        alt.network_id = other_network;
        return alt.sign(slot, st);
    }
};

// ---------------------------------------------------------------------------
// Convenience builders for the common actor shapes (design §13.2)
// ---------------------------------------------------------------------------

/// Equivocation: two contradictory PREPAREs for the SAME (slot, counter)
/// with incompatible values. Both are individually valid + canonical.
pub fn equivocatingPrepares(
    f: *Forger,
    slot: u64,
    qset_hash: [32]u8,
    counter: u32,
    value_a: []const u8,
    value_b: []const u8,
) !struct { a: []const u8, b: []const u8 } {
    const a = try f.sign(slot, .{ .prepare = .{ .qset_hash = qset_hash, .ballot = .{ .counter = counter, .value = value_a } } });
    errdefer f.gpa.free(a);
    const b = try f.sign(slot, .{ .prepare = .{ .qset_hash = qset_hash, .ballot = .{ .counter = counter, .value = value_b } } });
    return .{ .a = a, .b = b };
}

test "forger: honest sign verifies, decodes sane, is canonical" {
    const gpa = std.testing.allocator;
    const net = crypto.networkIdFromPassphrase("adv-test");
    var f = try Forger.init(gpa, @splat(0xa1), net);

    const env = try f.sign(1, .{ .nominate = .{ .qset_hash = @splat(7), .votes = &.{"vote"}, .accepted = &.{} } });
    defer gpa.free(env);

    var msg = try capnpc.message.Message.init(gpa, env, .{});
    defer msg.deinit();
    const er = try gen_slcp.Envelope.Reader.init(&msg);
    const sb = try er.getStatementBytes();
    const sig_bytes = try er.getSignature();
    var sig: [64]u8 = undefined;
    @memcpy(&sig, sig_bytes);
    const digest = crypto.statementDigest(net, sb);
    try std.testing.expect(crypto.verify(f.node_id, digest, sig));
    try std.testing.expect(canonical.isCanonicalFlat(gpa, sb));

    var sm = try canonical.decodeFlat(gpa, sb, .{});
    defer sm.deinit();
    const sr = try gen_slcp.Statement.Reader.init(&sm);
    try std.testing.expect(slcp.statement.checkStatementSane(sr, .{}) == null);
}

test "forger: non-canonical verifies but fails isCanonical; forged fails verify" {
    const gpa = std.testing.allocator;
    const net = crypto.networkIdFromPassphrase("adv-test");
    var f = try Forger.init(gpa, @splat(0xa2), net);
    const st = RawStatement{ .prepare = .{ .qset_hash = @splat(3), .ballot = .{ .counter = 1, .value = "v" } } };

    const nc = try f.signNonCanonical(1, st);
    defer gpa.free(nc);
    {
        var msg = try capnpc.message.Message.init(gpa, nc, .{});
        defer msg.deinit();
        const er = try gen_slcp.Envelope.Reader.init(&msg);
        const sb = try er.getStatementBytes();
        const sig_bytes = try er.getSignature();
        var sig: [64]u8 = undefined;
        @memcpy(&sig, sig_bytes);
        try std.testing.expect(crypto.verify(f.node_id, crypto.statementDigest(net, sb), sig)); // signature valid
        try std.testing.expect(!canonical.isCanonicalFlat(gpa, sb)); // but not canonical
    }

    const forged = try f.signForged(1, st);
    defer gpa.free(forged);
    {
        var msg = try capnpc.message.Message.init(gpa, forged, .{});
        defer msg.deinit();
        const er = try gen_slcp.Envelope.Reader.init(&msg);
        const sb = try er.getStatementBytes();
        const sig_bytes = try er.getSignature();
        var sig: [64]u8 = undefined;
        @memcpy(&sig, sig_bytes);
        try std.testing.expect(!crypto.verify(f.node_id, crypto.statementDigest(net, sb), sig));
    }
}

test "equivocating prepares: two valid contradictory statements" {
    const gpa = std.testing.allocator;
    var f = try Forger.init(gpa, @splat(0xa3), crypto.networkIdFromPassphrase("adv-test"));
    const pair = try equivocatingPrepares(&f, 1, @splat(9), 3, "aaaa", "bbbb");
    defer gpa.free(pair.a);
    defer gpa.free(pair.b);
    try std.testing.expect(!std.mem.eql(u8, pair.a, pair.b));
}
