//! Canonical trust-pool transition values and old-pool retirement evidence.
//!
//! A certificate is meaningful only for a managed, strictly sequential host:
//! honest old anchors validate authorization/checkpoint state and durably retire
//! before releasing an EXTERNALIZE for this terminal value. The verifier cannot
//! establish those host obligations, current key honesty, checkpoint durability,
//! or protection against later compromise of an old signing-key quorum.

const std = @import("std");
const capnpc = @import("capnpc-zig");
const canonical = @import("../canonical.zig");
const crypto = @import("../crypto.zig");
const gen = @import("../gen/slcp.zig");
const statement = @import("../engine/statement.zig");
const limits = @import("../engine/limits.zig");
const policy = @import("policy.zig");

pub const magic = "SLCP-MIGRATE-V1\x00";
pub const header_bytes: usize = 103;
pub const max_manifest_bytes: usize = header_bytes + 32 * policy.max_anchors;
pub const max_envelope_bytes: usize = max_manifest_bytes + 1024;
pub const max_certificate_bytes: usize = max_envelope_bytes * policy.max_anchors;

pub const Config = struct {
    parent_network_id: [32]u8,
    /// Successor generation, strictly positive. Verification also requires the
    /// exact expected successor, preventing skipped/replayed generations.
    generation: u64,
    /// The terminal old-domain slot. The successor begins at terminal_slot+1.
    terminal_slot: u64,
    checkpoint_digest: [32]u8,
    successor_policy: policy.Config,
};

pub const ManifestError = policy.InitError || error{
    InvalidManifest,
    NonCanonicalManifest,
    GenerationZero,
    InvalidTerminalSlot,
};

pub const Manifest = struct {
    parent_network_id: [32]u8,
    generation: u64,
    terminal_slot: u64,
    checkpoint_digest: [32]u8,
    successor_policy: policy.Policy,

    pub fn init(gpa: std.mem.Allocator, cfg: Config) ManifestError!Manifest {
        if (cfg.generation == 0) return error.GenerationZero;
        if (cfg.terminal_slot == 0 or cfg.terminal_slot == std.math.maxInt(u64)) return error.InvalidTerminalSlot;
        return .{
            .parent_network_id = cfg.parent_network_id,
            .generation = cfg.generation,
            .terminal_slot = cfg.terminal_slot,
            .checkpoint_digest = cfg.checkpoint_digest,
            .successor_policy = try policy.Policy.init(gpa, cfg.successor_policy),
        };
    }

    pub fn deinit(self: *Manifest) void {
        self.successor_policy.deinit();
        self.* = undefined;
    }

    /// Owns its canonical anchor copy; does not retain `bytes`.
    pub fn parse(gpa: std.mem.Allocator, bytes: []const u8) ManifestError!Manifest {
        if (bytes.len < header_bytes or bytes.len > max_manifest_bytes or !isManifest(bytes)) return error.InvalidManifest;
        const n = std.mem.readInt(u16, bytes[96..98], .big);
        if (n == 0 or n > policy.max_anchors or bytes.len != header_bytes + @as(usize, n) * 32) return error.InvalidManifest;
        if (bytes[102] > 1) return error.NonCanonicalManifest;
        var anchors: [policy.max_anchors]policy.NodeId = undefined;
        for (0..n) |i| {
            @memcpy(&anchors[i], bytes[header_bytes + i * 32 ..][0..32]);
            if (i > 0 and std.mem.order(u8, &anchors[i - 1], &anchors[i]) != .lt) return error.NonCanonicalManifest;
        }
        return init(gpa, .{
            .parent_network_id = bytes[16..48].*,
            .generation = std.mem.readInt(u64, bytes[48..56], .big),
            .terminal_slot = std.mem.readInt(u64, bytes[56..64], .big),
            .checkpoint_digest = bytes[64..96].*,
            .successor_policy = .{
                .anchors = anchors[0..n],
                .max_faulty_anchors = std.mem.readInt(u16, bytes[98..100], .big),
                .min_slice_anchors = std.mem.readInt(u16, bytes[100..102], .big),
                .require_availability = bytes[102] == 1,
            },
        });
    }

    pub fn encode(self: *const Manifest, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        const bytes = try gpa.alloc(u8, header_bytes + self.successor_policy.anchors.len * 32);
        const header_value = self.header();
        @memcpy(bytes[0..header_bytes], &header_value);
        for (self.successor_policy.anchors, 0..) |*anchor, i| {
            @memcpy(bytes[header_bytes + i * 32 ..][0..32], anchor);
        }
        return bytes;
    }

    /// Domain-separated SHA-256 of the exact canonical terminal value.
    pub fn hash(self: *const Manifest) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("SLCP-MIGRATION-MANIFEST-V1\x00");
        const bytes = self.header();
        h.update(&bytes);
        for (self.successor_policy.anchors) |*anchor| h.update(anchor);
        return h.finalResult();
    }

    /// The parent domain, successor trust policy, generation, terminal slot and
    /// checkpoint all contribute through hash(). No circular embedded domain.
    pub fn successorNetworkId(self: *const Manifest) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("SLCP-MIGRATION-DOMAIN-V1\x00");
        h.update(&self.hash());
        return h.finalResult();
    }

    fn header(self: *const Manifest) [header_bytes]u8 {
        var bytes: [header_bytes]u8 = undefined;
        @memcpy(bytes[0..16], magic);
        @memcpy(bytes[16..48], &self.parent_network_id);
        std.mem.writeInt(u64, bytes[48..56], self.generation, .big);
        std.mem.writeInt(u64, bytes[56..64], self.terminal_slot, .big);
        @memcpy(bytes[64..96], &self.checkpoint_digest);
        std.mem.writeInt(u16, bytes[96..98], @intCast(self.successor_policy.anchors.len), .big);
        std.mem.writeInt(u16, bytes[98..100], self.successor_policy.max_faulty_anchors, .big);
        std.mem.writeInt(u16, bytes[100..102], self.successor_policy.min_slice_anchors, .big);
        bytes[102] = @intFromBool(self.successor_policy.require_availability);
        return bytes;
    }
};

/// A discriminator only. Call Manifest.parse to validate the whole value.
pub fn isManifest(bytes: []const u8) bool {
    return std.mem.startsWith(u8, bytes, magic);
}

pub const EnvelopeError = error{
    EnvelopeTooLarge,
    InvalidEnvelope,
    NonCanonicalStatement,
    NotExternalize,
    InvalidSignature,
    OutOfMemory,
};

pub const Externalize = struct {
    node_id: policy.NodeId,
    slot: u64,
    /// Borrows the original envelope bytes, which must remain alive/unmodified.
    value: []const u8,
    commit_qset_hash: [32]u8,
};

/// Verifies the normal SLCP signature and strict canonical signed statement.
/// Envelope framing itself is not signed, matching the Engine's wire contract.
pub fn verifyExternalize(gpa: std.mem.Allocator, expected_domain: [32]u8, envelope: []const u8) EnvelopeError!Externalize {
    if (envelope.len > limits.frozen_max_frame_bytes) return error.EnvelopeTooLarge;
    var env_msg = capnpc.message.Message.init(gpa, envelope, .{ .nesting_limit = 32, .traversal_limit_words = limits.frozen_max_frame_bytes / 8 }) catch |err| return mapEnvelopeError(err);
    defer env_msg.deinit();
    const env = gen.Envelope.Reader.init(&env_msg) catch return error.InvalidEnvelope;
    const stmt_bytes = env.getStatementBytes() catch return error.InvalidEnvelope;
    const signature = env.getSignature() catch return error.InvalidEnvelope;
    if (stmt_bytes.len == 0 or stmt_bytes.len > limits.frozen_max_statement_bytes or signature.len != 64) return error.InvalidEnvelope;
    var msg = canonical.decodeFlat(gpa, stmt_bytes, .{ .nesting_limit = 32, .traversal_limit_words = limits.frozen_max_statement_bytes / 8 }) catch |err| return mapEnvelopeError(err);
    defer msg.deinit();
    if (!capnpc.canonical.isCanonical(&msg)) return error.NonCanonicalStatement;
    const stmt = gen.Statement.Reader.init(&msg) catch return error.InvalidEnvelope;
    if (statement.checkStatementSane(stmt, .{ .max_value_bytes = limits.frozen_max_value_bytes_cap }) != null) return error.InvalidEnvelope;
    const node = stmt.getNodeId() catch return error.InvalidEnvelope;
    const node_id: [32]u8 = node[0..32].*; // sanity checked
    if (!crypto.verify(node_id, crypto.statementDigest(expected_domain, stmt_bytes), signature[0..64].*)) return error.InvalidSignature;
    const pledges = stmt.getPledges();
    if ((pledges.which() catch return error.InvalidEnvelope) != .externalize) return error.NotExternalize;
    const ext = pledges.getExternalize() catch return error.InvalidEnvelope;
    const commit = ext.getCommit() catch return error.InvalidEnvelope;
    const qset_hash = ext.getCommitQuorumSetHash() catch return error.InvalidEnvelope;
    return .{
        .node_id = node_id,
        .slot = stmt.getSlotIndex() catch return error.InvalidEnvelope,
        .value = commit.getValue() catch return error.InvalidEnvelope,
        .commit_qset_hash = qset_hash[0..32].*,
    };
}

fn mapEnvelopeError(err: anyerror) EnvelopeError {
    return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidEnvelope;
}

pub const VerifyError = ManifestError || EnvelopeError || error{
    WrongParentDomain,
    WrongGeneration,
    InsufficientSigners,
    TooManyEnvelopes,
    CertificateTooLarge,
    SignerNotAnchor,
    DuplicateSigner,
    UnsortedSigners,
    WrongTerminalSlot,
    WrongTerminalValue,
};

pub const Verified = struct {
    successor_network_id: [32]u8,
    manifest_hash: [32]u8,
    signers: u16,
};

/// Requires at least the old policy's slice floor of distinct old anchors.
/// Envelopes must be sorted by signer ID; extra, duplicate, or invalid entries
/// fail verification instead of being silently ignored. No advertised qset or
/// successor policy can reduce the OLD authorization threshold.
pub fn verifyCertificate(
    gpa: std.mem.Allocator,
    old_policy: *const policy.Policy,
    expected_parent_domain: [32]u8,
    expected_successor_generation: u64,
    manifest_bytes: []const u8,
    envelopes: []const []const u8,
) VerifyError!Verified {
    if (envelopes.len < old_policy.min_slice_anchors) return error.InsufficientSigners;
    if (envelopes.len > old_policy.anchors.len) return error.TooManyEnvelopes;
    var manifest = try Manifest.parse(gpa, manifest_bytes);
    defer manifest.deinit();
    if (!std.mem.eql(u8, &manifest.parent_network_id, &expected_parent_domain)) return error.WrongParentDomain;
    if (manifest.generation != expected_successor_generation) return error.WrongGeneration;
    var total_bytes: usize = 0;
    var previous: ?policy.NodeId = null;
    for (envelopes) |envelope| {
        if (envelope.len > max_envelope_bytes) return error.EnvelopeTooLarge;
        total_bytes = std.math.add(usize, total_bytes, envelope.len) catch return error.CertificateTooLarge;
        if (total_bytes > max_certificate_bytes) return error.CertificateTooLarge;
        const ext = try verifyExternalize(gpa, expected_parent_domain, envelope);
        if (previous) |*prev| {
            switch (std.mem.order(u8, prev, &ext.node_id)) {
                .lt => {},
                .eq => return error.DuplicateSigner,
                .gt => return error.UnsortedSigners,
            }
        }
        previous = ext.node_id;
        var is_anchor = false;
        for (old_policy.anchors) |*anchor| {
            if (std.mem.eql(u8, anchor, &ext.node_id)) {
                is_anchor = true;
                break;
            }
        }
        if (!is_anchor) return error.SignerNotAnchor;
        if (ext.slot != manifest.terminal_slot) return error.WrongTerminalSlot;
        if (!std.mem.eql(u8, ext.value, manifest_bytes)) return error.WrongTerminalValue;
    }
    return .{
        .successor_network_id = manifest.successorNetworkId(),
        .manifest_hash = manifest.hash(),
        .signers = @intCast(envelopes.len),
    };
}

fn testManifest(gpa: std.mem.Allocator) !Manifest {
    const anchors = [_]policy.NodeId{ @splat(11), @splat(12), @splat(13), @splat(14) };
    return Manifest.init(gpa, .{
        .parent_network_id = @splat(42),
        .generation = 1,
        .terminal_slot = 7,
        .checkpoint_digest = @splat(99),
        .successor_policy = .{ .anchors = &anchors, .max_faulty_anchors = 1, .min_slice_anchors = 3 },
    });
}

test "migration manifest roundtrip owns canonical state and binds the successor domain" {
    const gpa = std.testing.allocator;
    var manifest = try testManifest(gpa);
    defer manifest.deinit();
    const bytes = try manifest.encode(gpa);
    defer gpa.free(bytes);
    try std.testing.expect(isManifest(bytes));
    var parsed = try Manifest.parse(gpa, bytes);
    defer parsed.deinit();
    const roundtrip = try parsed.encode(gpa);
    defer gpa.free(roundtrip);
    try std.testing.expectEqualSlices(u8, bytes, roundtrip);
    try std.testing.expectEqual(manifest.hash(), parsed.hash());
    try std.testing.expectEqualStrings("9183bbe339c39fd2207f6f3cc279bddb25840da2e2dab12ad4751ac778aa7e08", &std.fmt.bytesToHex(manifest.hash(), .lower));
    try std.testing.expectEqualStrings("6d46bb04dabe7f954666406561c7410b8d97585b9e8a7cea50b94b52b82a30b7", &std.fmt.bytesToHex(manifest.successorNetworkId(), .lower));
    const original = parsed.successorNetworkId();
    parsed.generation += 1;
    try std.testing.expect(!std.mem.eql(u8, &original, &parsed.successorNetworkId()));
    parsed.generation -= 1;
    parsed.terminal_slot += 1;
    try std.testing.expect(!std.mem.eql(u8, &original, &parsed.successorNetworkId()));
    parsed.terminal_slot -= 1;
    parsed.parent_network_id[0] ^= 1;
    try std.testing.expect(!std.mem.eql(u8, &original, &parsed.successorNetworkId()));
    parsed.parent_network_id[0] ^= 1;
    parsed.checkpoint_digest[0] ^= 1;
    try std.testing.expect(!std.mem.eql(u8, &original, &parsed.successorNetworkId()));
    parsed.checkpoint_digest[0] ^= 1;
    parsed.successor_policy.require_availability = false;
    try std.testing.expect(!std.mem.eql(u8, &original, &parsed.successorNetworkId()));
    bytes[header_bytes] ^= 1;
    try std.testing.expectEqual(manifest.hash(), parsedHashWithoutAvailabilityMutation(&parsed));
}

fn parsedHashWithoutAvailabilityMutation(manifest: *Manifest) [32]u8 {
    manifest.successor_policy.require_availability = true;
    return manifest.hash();
}

test "migration manifest rejects noncanonical, malformed and overflowing successors" {
    const gpa = std.testing.allocator;
    var manifest = try testManifest(gpa);
    defer manifest.deinit();
    const bytes = try manifest.encode(gpa);
    defer gpa.free(bytes);
    try std.testing.expectError(error.InvalidManifest, Manifest.parse(gpa, bytes[0 .. bytes.len - 1]));
    bytes[102] = 2;
    try std.testing.expectError(error.NonCanonicalManifest, Manifest.parse(gpa, bytes));
    bytes[102] = 1;
    @memset(bytes[48..56], 0);
    try std.testing.expectError(error.GenerationZero, Manifest.parse(gpa, bytes));
    std.mem.writeInt(u64, bytes[48..56], 1, .big);
    @memset(bytes[56..64], 255);
    try std.testing.expectError(error.InvalidTerminalSlot, Manifest.parse(gpa, bytes));
    std.mem.writeInt(u64, bytes[56..64], 7, .big);
    @memcpy(bytes[header_bytes + 32 ..][0..32], bytes[header_bytes..][0..32]);
    try std.testing.expectError(error.NonCanonicalManifest, Manifest.parse(gpa, bytes));
}

fn signedTestEnvelope(gpa: std.mem.Allocator, seed: [32]u8, network_id: [32]u8, slot: u64, value: []const u8, externalize: bool) ![]u8 {
    var mb = capnpc.message.MessageBuilder.init(gpa);
    defer mb.deinit();
    var sb = try gen.Statement.Builder.init(&mb);
    try sb.setNodeId(&(try crypto.publicKeyFromSeed(seed)));
    try sb.setSlotIndex(slot);
    var pledges = sb.getPledges();
    if (externalize) {
        var eb = try pledges.initExternalize();
        var ballot = try eb.initCommit();
        try ballot.setCounter(1);
        try ballot.setValue(value);
        try eb.setNH(1);
        try eb.setCommitQuorumSetHash(&@as([32]u8, @splat(88)));
    } else {
        var pb = try pledges.initPrepare();
        try pb.setQuorumSetHash(&@as([32]u8, @splat(88)));
        var ballot = try pb.initBallot();
        try ballot.setCounter(1);
        try ballot.setValue(value);
    }
    const flat = try canonical.canonicalFlatFromBuilder(gpa, &mb);
    defer gpa.free(flat);
    return wrapTestEnvelope(gpa, seed, network_id, flat);
}

fn wrapTestEnvelope(gpa: std.mem.Allocator, seed: [32]u8, network_id: [32]u8, flat: []const u8) ![]u8 {
    const signature = try crypto.sign(seed, crypto.statementDigest(network_id, flat));
    var env_mb = capnpc.message.MessageBuilder.init(gpa);
    defer env_mb.deinit();
    var env = try gen.Envelope.Builder.init(&env_mb);
    try env.setStatementBytes(flat);
    try env.setSignature(&signature);
    return @constCast(try env_mb.toBytes());
}

const CertificateFixture = struct {
    gpa: std.mem.Allocator,
    manifest: Manifest,
    bytes: []u8,
    old_policy: policy.Policy,
    seeds: [4][32]u8,
    envelopes: [4][]const u8,

    fn init(gpa: std.mem.Allocator) !CertificateFixture {
        var manifest = try testManifest(gpa);
        errdefer manifest.deinit();
        const bytes = try manifest.encode(gpa);
        errdefer gpa.free(bytes);
        var pairs: [4]struct { id: policy.NodeId, seed: [32]u8 } = undefined;
        for (&pairs, 0..) |*pair, i| {
            pair.seed = @splat(@as(u8, @intCast(i + 1)));
            pair.id = try crypto.publicKeyFromSeed(pair.seed);
        }
        std.mem.sort(@TypeOf(pairs[0]), &pairs, {}, struct {
            fn less(_: void, a: @TypeOf(pairs[0]), b: @TypeOf(pairs[0])) bool {
                return std.mem.order(u8, &a.id, &b.id) == .lt;
            }
        }.less);
        var anchors: [4]policy.NodeId = undefined;
        for (pairs, 0..) |pair, i| anchors[i] = pair.id;
        var old_policy = try policy.Policy.init(gpa, .{ .anchors = &anchors, .max_faulty_anchors = 1, .min_slice_anchors = 3 });
        errdefer old_policy.deinit();
        var self: CertificateFixture = .{ .gpa = gpa, .manifest = manifest, .bytes = bytes, .old_policy = old_policy, .seeds = undefined, .envelopes = undefined };
        var built: usize = 0;
        errdefer for (self.envelopes[0..built]) |env| gpa.free(env);
        for (pairs, 0..) |pair, i| {
            self.seeds[i] = pair.seed;
            self.envelopes[i] = try signedTestEnvelope(gpa, pair.seed, manifest.parent_network_id, manifest.terminal_slot, bytes, true);
            built += 1;
        }
        return self;
    }

    fn deinit(self: *CertificateFixture) void {
        for (self.envelopes) |env| self.gpa.free(env);
        self.old_policy.deinit();
        self.gpa.free(self.bytes);
        self.manifest.deinit();
    }

    fn verify(self: *const CertificateFixture, envs: []const []const u8) VerifyError!Verified {
        return verifyCertificate(self.gpa, &self.old_policy, self.manifest.parent_network_id, self.manifest.generation, self.bytes, envs);
    }
};

test "migration certificate authorizes a disjoint successor pool under the old floor" {
    var f = try CertificateFixture.init(std.testing.allocator);
    defer f.deinit();
    const verified = try f.verify(f.envelopes[0..3]);
    try std.testing.expectEqual(@as(u16, 3), verified.signers);
    try std.testing.expectEqual(f.manifest.successorNetworkId(), verified.successor_network_id);
    try std.testing.expectEqual(f.manifest.hash(), verified.manifest_hash);
    try std.testing.expectError(error.InsufficientSigners, f.verify(f.envelopes[0..2]));
    try std.testing.expectError(error.DuplicateSigner, f.verify(&.{ f.envelopes[0], f.envelopes[0], f.envelopes[1] }));
    try std.testing.expectError(error.UnsortedSigners, f.verify(&.{ f.envelopes[1], f.envelopes[0], f.envelopes[2] }));
    try std.testing.expectError(error.WrongGeneration, verifyCertificate(f.gpa, &f.old_policy, f.manifest.parent_network_id, 2, f.bytes, f.envelopes[0..3]));
    try std.testing.expectError(error.WrongParentDomain, verifyCertificate(f.gpa, &f.old_policy, @splat(123), 1, f.bytes, f.envelopes[0..3]));
}

test "migration certificate rejects foreign signatures, slots, values and statement kinds" {
    var f = try CertificateFixture.init(std.testing.allocator);
    defer f.deinit();
    const wrong_slot = try signedTestEnvelope(f.gpa, f.seeds[0], f.manifest.parent_network_id, 8, f.bytes, true);
    defer f.gpa.free(wrong_slot);
    try std.testing.expectError(error.WrongTerminalSlot, f.verify(&.{ wrong_slot, f.envelopes[1], f.envelopes[2] }));
    const wrong_value = try signedTestEnvelope(f.gpa, f.seeds[0], f.manifest.parent_network_id, 7, "different", true);
    defer f.gpa.free(wrong_value);
    try std.testing.expectError(error.WrongTerminalValue, f.verify(&.{ wrong_value, f.envelopes[1], f.envelopes[2] }));
    const foreign = try signedTestEnvelope(f.gpa, f.seeds[0], @splat(123), 7, f.bytes, true);
    defer f.gpa.free(foreign);
    try std.testing.expectError(error.InvalidSignature, f.verify(&.{ foreign, f.envelopes[1], f.envelopes[2] }));
    const prepare = try signedTestEnvelope(f.gpa, f.seeds[0], f.manifest.parent_network_id, 7, f.bytes, false);
    defer f.gpa.free(prepare);
    try std.testing.expectError(error.NotExternalize, f.verify(&.{ prepare, f.envelopes[1], f.envelopes[2] }));
    const outsider = try signedTestEnvelope(f.gpa, @splat(201), f.manifest.parent_network_id, 7, f.bytes, true);
    defer f.gpa.free(outsider);
    try std.testing.expectError(error.SignerNotAnchor, f.verify(&.{ outsider, f.envelopes[1], f.envelopes[2] }));
    try std.testing.expectError(error.InvalidEnvelope, verifyExternalize(f.gpa, f.manifest.parent_network_id, "truncated"));
}

test "migration verification rejects noncanonical signed statements and bounded input abuse" {
    var f = try CertificateFixture.init(std.testing.allocator);
    defer f.deinit();
    var msg = try capnpc.message.Message.init(f.gpa, f.envelopes[0], .{});
    defer msg.deinit();
    const env = try gen.Envelope.Reader.init(&msg);
    const flat = try env.getStatementBytes();
    const padded = try f.gpa.alloc(u8, flat.len + 8);
    defer f.gpa.free(padded);
    @memcpy(padded[0..flat.len], flat);
    @memset(padded[flat.len..], 0);
    const noncanonical = try wrapTestEnvelope(f.gpa, f.seeds[0], f.manifest.parent_network_id, padded);
    defer f.gpa.free(noncanonical);
    try std.testing.expectError(error.NonCanonicalStatement, verifyExternalize(f.gpa, f.manifest.parent_network_id, noncanonical));
    const oversized = try f.gpa.alloc(u8, limits.frozen_max_frame_bytes + 1);
    defer f.gpa.free(oversized);
    try std.testing.expectError(error.EnvelopeTooLarge, verifyExternalize(f.gpa, f.manifest.parent_network_id, oversized));
    try std.testing.expectError(error.EnvelopeTooLarge, f.verify(&.{ oversized[0 .. max_envelope_bytes + 1], f.envelopes[1], f.envelopes[2] }));
    try std.testing.expectError(error.TooManyEnvelopes, f.verify(&.{ f.envelopes[0], f.envelopes[1], f.envelopes[2], f.envelopes[3], f.envelopes[0] }));
    // The successor is deliberately only one node here; its threshold must
    // not become the authorization threshold for the four-node old pool.
    const singleton = [_]policy.NodeId{@splat(101)};
    var weaker = try Manifest.init(f.gpa, .{
        .parent_network_id = f.manifest.parent_network_id,
        .generation = 1,
        .terminal_slot = 7,
        .checkpoint_digest = f.manifest.checkpoint_digest,
        .successor_policy = .{ .anchors = &singleton, .max_faulty_anchors = 0, .min_slice_anchors = 1 },
    });
    defer weaker.deinit();
    const weak_bytes = try weaker.encode(f.gpa);
    defer f.gpa.free(weak_bytes);
    try std.testing.expectError(error.InsufficientSigners, verifyCertificate(f.gpa, &f.old_policy, f.manifest.parent_network_id, 1, weak_bytes, f.envelopes[0..1]));
}

test "externalize inspection also accepts large ordinary application values" {
    const gpa = std.testing.allocator;
    const value = try gpa.alloc(u8, limits.frozen_max_value_bytes_cap);
    defer gpa.free(value);
    @memset(value, 77);
    const envelope = try signedTestEnvelope(gpa, @splat(2), @splat(42), 9, value, true);
    defer gpa.free(envelope);
    const ext = try verifyExternalize(gpa, @splat(42), envelope);
    try std.testing.expectEqualSlices(u8, value, ext.value);
}

fn manifestAllocationProbe(gpa: std.mem.Allocator) !void {
    var manifest = try testManifest(gpa);
    defer manifest.deinit();
    const bytes = try manifest.encode(gpa);
    defer gpa.free(bytes);
    var parsed = try Manifest.parse(gpa, bytes);
    defer parsed.deinit();
    try std.testing.expectEqual(manifest.hash(), parsed.hash());
}

test "migration manifest parse and encode preserve ownership through allocator failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, manifestAllocationProbe, .{});
}

fn certificateAllocationProbe(gpa: std.mem.Allocator, fixture: *const CertificateFixture) !void {
    const verified = try verifyCertificate(gpa, &fixture.old_policy, fixture.manifest.parent_network_id, 1, fixture.bytes, fixture.envelopes[0..3]);
    try std.testing.expectEqual(@as(u16, 3), verified.signers);
}

test "migration certificate verification preserves ownership at every allocation failure" {
    var f = try CertificateFixture.init(std.testing.allocator);
    defer f.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, certificateAllocationProbe, .{&f});
}
