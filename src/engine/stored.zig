//! Owned, decoded statement/envelope storage (design §5.4 slot.zig bullet).
//!
//! The envelope pipeline decodes each accepted statement ONCE into plain Zig
//! data (mirroring how stellar-core works on XDR structs by value); protocol
//! code never re-parses capnp readers on hot paths. A StoredEnvelope keeps
//! the original wire Envelope frame bytes alongside, for relay
//! (forward_envelope), persistence, and slot-state answering.

const std = @import("std");
const gen_slcp = @import("../gen/slcp.zig");
const statement_mod = @import("statement.zig");

pub const OwnedBallot = struct {
    counter: u32,
    value: []u8,

    pub fn deinit(self: *OwnedBallot, gpa: std.mem.Allocator) void {
        gpa.free(self.value);
        self.* = undefined;
    }

    pub fn clone(self: *const OwnedBallot, gpa: std.mem.Allocator) !OwnedBallot {
        return .{ .counter = self.counter, .value = try gpa.dupe(u8, self.value) };
    }

    pub fn view(self: *const OwnedBallot) statement_mod.BallotView {
        return .{ .counter = self.counter, .value = self.value };
    }
};

fn freeValues(gpa: std.mem.Allocator, vals: [][]u8) void {
    for (vals) |v| gpa.free(v);
    gpa.free(vals);
}

pub const OwnedNomination = struct {
    qset_hash: [32]u8,
    votes: [][]u8, // strictly ascending (wire-sane)
    accepted: [][]u8, // strictly ascending

    pub fn deinit(self: *OwnedNomination, gpa: std.mem.Allocator) void {
        freeValues(gpa, self.votes);
        freeValues(gpa, self.accepted);
        self.* = undefined;
    }
};

pub const OwnedPrepare = struct {
    qset_hash: [32]u8,
    ballot: OwnedBallot,
    prepared: ?OwnedBallot,
    prepared_prime: ?OwnedBallot,
    n_c: u32,
    n_h: u32,

    pub fn deinit(self: *OwnedPrepare, gpa: std.mem.Allocator) void {
        self.ballot.deinit(gpa);
        if (self.prepared) |*b| b.deinit(gpa);
        if (self.prepared_prime) |*b| b.deinit(gpa);
        self.* = undefined;
    }
};

pub const OwnedConfirm = struct {
    qset_hash: [32]u8,
    ballot: OwnedBallot,
    n_prepared: u32,
    n_commit: u32,
    n_h: u32,

    pub fn deinit(self: *OwnedConfirm, gpa: std.mem.Allocator) void {
        self.ballot.deinit(gpa);
        self.* = undefined;
    }
};

pub const OwnedExternalize = struct {
    commit: OwnedBallot,
    n_h: u32,
    commit_qset_hash: [32]u8,

    pub fn deinit(self: *OwnedExternalize, gpa: std.mem.Allocator) void {
        self.commit.deinit(gpa);
        self.* = undefined;
    }
};

pub const OwnedPledges = union(enum) {
    nominate: OwnedNomination,
    prepare: OwnedPrepare,
    confirm: OwnedConfirm,
    externalize: OwnedExternalize,

    pub fn deinit(self: *OwnedPledges, gpa: std.mem.Allocator) void {
        switch (self.*) {
            inline else => |*p| p.deinit(gpa),
        }
        self.* = undefined;
    }
};

pub const OwnedStatement = struct {
    node_id: [32]u8,
    slot: u64,
    pledges: OwnedPledges,

    pub fn deinit(self: *OwnedStatement, gpa: std.mem.Allocator) void {
        self.pledges.deinit(gpa);
        self.* = undefined;
    }

    /// The companion quorum-set hash used for quorum math over this
    /// statement (stellar-core getCompanionQuorumSetHashFromStatement).
    /// EXTERNALIZE returns its audit hash — but quorum math treats the
    /// sender as the singleton `{sender, 1}` and never fetches it (§5.4).
    pub fn qsetHash(self: *const OwnedStatement) [32]u8 {
        return switch (self.pledges) {
            .nominate => |n| n.qset_hash,
            .prepare => |p| p.qset_hash,
            .confirm => |c| c.qset_hash,
            .externalize => |e| e.commit_qset_hash,
        };
    }

    pub fn isNomination(self: *const OwnedStatement) bool {
        return self.pledges == .nominate;
    }
};

fn copyHash32(bytes: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    @memcpy(&out, bytes);
    return out;
}

fn copyBallot(gpa: std.mem.Allocator, r: gen_slcp.Ballot.Reader) !OwnedBallot {
    return .{ .counter = try r.getCounter(), .value = try gpa.dupe(u8, try r.getValue()) };
}

fn copyValueList(gpa: std.mem.Allocator, list: anytype) ![][]u8 {
    var out = try gpa.alloc([]u8, list.len());
    var built: usize = 0;
    errdefer {
        for (out[0..built]) |v| gpa.free(v);
        gpa.free(out);
    }
    for (0..list.len()) |i| {
        out[i] = try gpa.dupe(u8, try list.get(@intCast(i)));
        built += 1;
    }
    return out;
}

/// Decode a Statement reader into owned data. PRECONDITION: the statement
/// passed `checkStatementSane` (lengths, sortedness, counters all verified);
/// decode failures here are engine bugs, surfaced as errors.
pub fn fromReader(gpa: std.mem.Allocator, reader: gen_slcp.Statement.Reader) !OwnedStatement {
    const node_id = copyHash32(try reader.getNodeId());
    const slot = try reader.getSlotIndex();
    const pledges_reader = reader.getPledges();
    const pledges: OwnedPledges = switch (try pledges_reader.which()) {
        .unset => return error.UnsetPledges,
        .nominate => blk: {
            const n = try pledges_reader.getNominate();
            const votes = try copyValueList(gpa, try n.getVotes());
            errdefer freeValues(gpa, votes);
            const accepted = try copyValueList(gpa, try n.getAccepted());
            break :blk .{ .nominate = .{
                .qset_hash = copyHash32(try n.getQuorumSetHash()),
                .votes = votes,
                .accepted = accepted,
            } };
        },
        .prepare => blk: {
            const p = try pledges_reader.getPrepare();
            var ballot = try copyBallot(gpa, try p.getBallot());
            errdefer ballot.deinit(gpa);
            // absent pointer == unset (§4.1): pointer slots 2 / 3
            var prepared: ?OwnedBallot = if (p._reader.isPointerNull(2)) null else try copyBallot(gpa, try p.getPrepared());
            errdefer if (prepared) |*b| b.deinit(gpa);
            const prepared_prime: ?OwnedBallot = if (p._reader.isPointerNull(3)) null else try copyBallot(gpa, try p.getPreparedPrime());
            break :blk .{ .prepare = .{
                .qset_hash = copyHash32(try p.getQuorumSetHash()),
                .ballot = ballot,
                .prepared = prepared,
                .prepared_prime = prepared_prime,
                .n_c = try p.getNC(),
                .n_h = try p.getNH(),
            } };
        },
        .confirm => blk: {
            const c = try pledges_reader.getConfirm();
            break :blk .{ .confirm = .{
                .qset_hash = copyHash32(try c.getQuorumSetHash()),
                .ballot = try copyBallot(gpa, try c.getBallot()),
                .n_prepared = try c.getNPrepared(),
                .n_commit = try c.getNCommit(),
                .n_h = try c.getNH(),
            } };
        },
        .externalize => blk: {
            const e = try pledges_reader.getExternalize();
            break :blk .{ .externalize = .{
                .commit = try copyBallot(gpa, try e.getCommit()),
                .n_h = try e.getNH(),
                .commit_qset_hash = copyHash32(try e.getCommitQuorumSetHash()),
            } };
        },
    };
    return .{ .node_id = node_id, .slot = slot, .pledges = pledges };
}

/// A processed statement kept per (node, protocol): the decoded data plus
/// the original wire Envelope frame bytes for relay / persistence / catch-up.
pub const StoredEnvelope = struct {
    envelope_framed: []u8,
    statement: OwnedStatement,

    pub fn deinit(self: *StoredEnvelope, gpa: std.mem.Allocator) void {
        gpa.free(self.envelope_framed);
        self.statement.deinit(gpa);
        self.* = undefined;
    }

    pub fn byteSize(self: *const StoredEnvelope) usize {
        return self.envelope_framed.len;
    }
};
