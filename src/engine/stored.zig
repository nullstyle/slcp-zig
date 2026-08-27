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

// ---------------------------------------------------------------------------
// Freshness over OWNED statements (design §5.4 slot.zig bullet) — the
// pipeline's hot-path comparator. Same partial orders as
// statement.isNewerStatement (which walks capnp readers); the differential
// test at the bottom locks the two together across a generated statement
// matrix, so they cannot drift apart silently.
// ---------------------------------------------------------------------------

fn viewOpt(b: ?OwnedBallot) ?statement_mod.BallotView {
    return if (b) |bb| bb.view() else null;
}

/// p ⊆ v over strictly-ascending sorted value lists; `not_equal` reports
/// strict growth when the subset holds. Oracle:
/// NominationProtocol::isSubsetHelper (NominationProtocol.cpp:49-71),
/// std::includes specialized to sorted-unique inputs.
fn isSubsetSorted(p: []const []u8, v: []const []u8, not_equal: *bool) bool {
    if (p.len > v.len) {
        not_equal.* = true;
        return false;
    }
    var pi: usize = 0;
    var vi: usize = 0;
    while (pi < p.len and vi < v.len) {
        switch (std.mem.order(u8, p[pi], v[vi])) {
            .eq => {
                pi += 1;
                vi += 1;
            },
            .gt => vi += 1,
            .lt => {
                // p's element cannot appear later in ascending v
                not_equal.* = true;
                return false;
            },
        }
    }
    if (pi == p.len) {
        not_equal.* = p.len != v.len;
        return true;
    }
    not_equal.* = true;
    return false;
}

fn ballotRank(p: *const OwnedPledges) u8 {
    return switch (p.*) {
        .nominate => 0, // never compared against ballot arms (protocols never mix)
        .prepare => 1,
        .confirm => 2,
        .externalize => 3,
    };
}

/// True iff `new` strictly supersedes `old` in its protocol's partial order.
/// Callers guarantee same node + same slot. Nomination and ballot statements
/// never compare newer against each other; two EXTERNALIZE never compare
/// newer. Oracle: Slot::isNewerNominationOrBallotSt (Slot.cpp:109-141),
/// NominationProtocol::isNewerStatement (NominationProtocol.cpp:87-104),
/// BallotProtocol::isNewerStatement (BallotProtocol.cpp:55-134).
pub fn isNewerOwned(old: *const OwnedStatement, new: *const OwnedStatement) bool {
    const old_nom = old.isNomination();
    const new_nom = new.isNomination();
    if (old_nom != new_nom) return false; // Slot.cpp:117-120: protocols never mix

    if (old_nom) {
        // NominationProtocol.cpp:87-104: BOTH sets must be superset-or-equal,
        // and at least one must strictly grow.
        const o = &old.pledges.nominate;
        const n = &new.pledges.nominate;
        var votes_grew = false;
        if (!isSubsetSorted(o.votes, n.votes, &votes_grew)) return false;
        var accepted_grew = false;
        if (!isSubsetSorted(o.accepted, n.accepted, &accepted_grew)) return false;
        return votes_grew or accepted_grew; // true only if one of the sets grew
    }

    // Statement type order PREPARE < CONFIRM < EXTERNALIZE
    // (BallotProtocol.cpp:60-67).
    const old_rank = ballotRank(&old.pledges);
    const new_rank = ballotRank(&new.pledges);
    if (old_rank != new_rank) return old_rank < new_rank;

    switch (new.pledges) {
        .nominate => unreachable, // handled above
        // can't have duplicate EXTERNALIZE statements (BallotProtocol.cpp:70-74)
        .externalize => return false,
        .confirm => |*n| {
            // sorted by (b, nPrepared, nH) (BallotProtocol.cpp:75-96)
            const o = &old.pledges.confirm;
            const comp = statement_mod.compareBallots(o.ballot.view(), n.ballot.view());
            if (comp != .eq) return comp == .lt;
            if (o.n_prepared != n.n_prepared) return o.n_prepared < n.n_prepared;
            return o.n_h < n.n_h;
        },
        .prepare => |*n| {
            // lexicographic (b, p, p', nH), absent < present
            // (BallotProtocol.cpp:97-131)
            const o = &old.pledges.prepare;
            var comp = statement_mod.compareBallots(o.ballot.view(), n.ballot.view());
            if (comp != .eq) return comp == .lt;
            comp = statement_mod.compareOptBallots(viewOpt(o.prepared), viewOpt(n.prepared));
            if (comp != .eq) return comp == .lt;
            comp = statement_mod.compareOptBallots(viewOpt(o.prepared_prime), viewOpt(n.prepared_prime));
            if (comp != .eq) return comp == .lt;
            return o.n_h < n.n_h;
        },
    }
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const capnpc = @import("capnpc-zig");
const testing = std.testing;

/// A statement built two ways at once: the framed capnp message (for
/// statement.isNewerStatement over readers) and the OwnedStatement decoded
/// from it via fromReader (for isNewerOwned).
const DiffStmt = struct {
    framed: []const u8,
    msg: capnpc.message.Message,
    owned: OwnedStatement,

    fn reader(self: *const DiffStmt) !gen_slcp.Statement.Reader {
        return gen_slcp.Statement.Reader.init(&self.msg);
    }

    fn deinit(self: *DiffStmt, gpa: std.mem.Allocator) void {
        self.owned.deinit(gpa);
        self.msg.deinit();
        gpa.free(self.framed);
        self.* = undefined;
    }
};

fn finishDiff(gpa: std.mem.Allocator, mb: *capnpc.message.MessageBuilder) !DiffStmt {
    const framed = try mb.toBytes();
    errdefer gpa.free(framed);
    var msg = try capnpc.message.Message.init(gpa, framed, .{});
    errdefer msg.deinit();
    const rdr = try gen_slcp.Statement.Reader.init(&msg);
    const owned = try fromReader(gpa, rdr);
    return .{ .framed = framed, .msg = msg, .owned = owned };
}

const DiffB = struct { counter: u32, value: []const u8 };

fn setDiffBallot(bb: *gen_slcp.Ballot.Builder, b: DiffB) !void {
    try bb.setCounter(b.counter);
    try bb.setValue(b.value);
}

fn startDiffStmt(mb: *capnpc.message.MessageBuilder) !gen_slcp.Statement.Builder {
    var st = try gen_slcp.Statement.Builder.init(mb);
    const node_id: [32]u8 = @splat(0x0d);
    try st.setNodeId(&node_id);
    try st.setSlotIndex(1);
    return st;
}

fn buildDiffNominate(gpa: std.mem.Allocator, votes: []const []const u8, accepted: []const []const u8) !DiffStmt {
    var mb = capnpc.message.MessageBuilder.init(gpa);
    defer mb.deinit();
    var st = try startDiffStmt(&mb);
    var pledges = st.getPledges();
    var nom = try pledges.initNominate();
    const qsh: [32]u8 = @splat(0xaa);
    try nom.setQuorumSetHash(&qsh);
    if (votes.len > 0) {
        const vl = try nom.initVotes(@intCast(votes.len));
        for (votes, 0..) |v, i| try vl.set(@intCast(i), v);
    }
    if (accepted.len > 0) {
        const al = try nom.initAccepted(@intCast(accepted.len));
        for (accepted, 0..) |v, i| try al.set(@intCast(i), v);
    }
    return finishDiff(gpa, &mb);
}

const DiffPrepareSpec = struct {
    ballot: DiffB,
    prepared: ?DiffB = null,
    prepared_prime: ?DiffB = null,
    n_c: u32 = 0,
    n_h: u32 = 0,
};

fn buildDiffPrepare(gpa: std.mem.Allocator, spec: DiffPrepareSpec) !DiffStmt {
    var mb = capnpc.message.MessageBuilder.init(gpa);
    defer mb.deinit();
    var st = try startDiffStmt(&mb);
    var pledges = st.getPledges();
    var prep = try pledges.initPrepare();
    const qsh: [32]u8 = @splat(0xaa);
    try prep.setQuorumSetHash(&qsh);
    var ballot = try prep.initBallot();
    try setDiffBallot(&ballot, spec.ballot);
    if (spec.prepared) |b| {
        var pb = try prep.initPrepared();
        try setDiffBallot(&pb, b);
    }
    if (spec.prepared_prime) |b| {
        var pb = try prep.initPreparedPrime();
        try setDiffBallot(&pb, b);
    }
    try prep.setNC(spec.n_c);
    try prep.setNH(spec.n_h);
    return finishDiff(gpa, &mb);
}

const DiffConfirmSpec = struct {
    ballot: DiffB,
    n_prepared: u32 = 1,
    n_commit: u32 = 1,
    n_h: u32 = 1,
};

fn buildDiffConfirm(gpa: std.mem.Allocator, spec: DiffConfirmSpec) !DiffStmt {
    var mb = capnpc.message.MessageBuilder.init(gpa);
    defer mb.deinit();
    var st = try startDiffStmt(&mb);
    var pledges = st.getPledges();
    var conf = try pledges.initConfirm();
    const qsh: [32]u8 = @splat(0xaa);
    try conf.setQuorumSetHash(&qsh);
    var ballot = try conf.initBallot();
    try setDiffBallot(&ballot, spec.ballot);
    try conf.setNPrepared(spec.n_prepared);
    try conf.setNCommit(spec.n_commit);
    try conf.setNH(spec.n_h);
    return finishDiff(gpa, &mb);
}

fn buildDiffExternalize(gpa: std.mem.Allocator, commit: DiffB, n_h: u32) !DiffStmt {
    var mb = capnpc.message.MessageBuilder.init(gpa);
    defer mb.deinit();
    var st = try startDiffStmt(&mb);
    var pledges = st.getPledges();
    var ext = try pledges.initExternalize();
    var cb = try ext.initCommit();
    try setDiffBallot(&cb, commit);
    try ext.setNH(n_h);
    const qsh: [32]u8 = @splat(0xaa);
    try ext.setCommitQuorumSetHash(&qsh);
    return finishDiff(gpa, &mb);
}

test "differential: isNewerOwned agrees with statement.isNewerStatement over a statement matrix" {
    const gpa = testing.allocator;
    const statement = statement_mod;

    var stmts: std.ArrayList(DiffStmt) = .empty;
    defer {
        for (stmts.items) |*s| s.deinit(gpa);
        stmts.deinit(gpa);
    }

    // Nominations: growth, shrink, sideways, accepted-only growth,
    // both-grow, accepted-shrinks-while-votes-grow.
    const NomSpec = struct { votes: []const []const u8, accepted: []const []const u8 };
    const nom_specs = [_]NomSpec{
        .{ .votes = &.{"a"}, .accepted = &.{} },
        .{ .votes = &.{ "a", "b" }, .accepted = &.{} },
        .{ .votes = &.{ "a", "b", "c" }, .accepted = &.{} },
        .{ .votes = &.{ "a", "d" }, .accepted = &.{} },
        .{ .votes = &.{ "a", "b" }, .accepted = &.{"a"} },
        .{ .votes = &.{ "a", "b" }, .accepted = &.{ "a", "b" } },
        .{ .votes = &.{ "a", "b", "c" }, .accepted = &.{"b"} },
        .{ .votes = &.{"a"}, .accepted = &.{"a"} },
    };
    for (nom_specs) |sp| try stmts.append(gpa, try buildDiffNominate(gpa, sp.votes, sp.accepted));

    // Prepares: every lexicographic axis of (b, p, p', nH), including
    // absent-vs-present optionals and value tie-breaks.
    const prep_specs = [_]DiffPrepareSpec{
        .{ .ballot = .{ .counter = 1, .value = "v" } },
        .{ .ballot = .{ .counter = 2, .value = "v" } },
        .{ .ballot = .{ .counter = 2, .value = "w" } },
        .{ .ballot = .{ .counter = 2, .value = "v" }, .prepared = .{ .counter = 1, .value = "v" } },
        .{ .ballot = .{ .counter = 2, .value = "v" }, .prepared = .{ .counter = 2, .value = "v" } },
        .{ .ballot = .{ .counter = 2, .value = "v" }, .prepared = .{ .counter = 2, .value = "v" }, .prepared_prime = .{ .counter = 1, .value = "u" } },
        .{ .ballot = .{ .counter = 2, .value = "v" }, .prepared = .{ .counter = 2, .value = "v" }, .prepared_prime = .{ .counter = 1, .value = "u" }, .n_h = 2 },
        .{ .ballot = .{ .counter = 2, .value = "v" }, .prepared = .{ .counter = 2, .value = "v" }, .n_h = 1 },
    };
    for (prep_specs) |sp| try stmts.append(gpa, try buildDiffPrepare(gpa, sp));

    // Confirms: (b, nPrepared, nH) axes.
    const conf_specs = [_]DiffConfirmSpec{
        .{ .ballot = .{ .counter = 2, .value = "v" }, .n_prepared = 1, .n_commit = 1, .n_h = 2 },
        .{ .ballot = .{ .counter = 3, .value = "v" }, .n_prepared = 1, .n_commit = 1, .n_h = 3 },
        .{ .ballot = .{ .counter = 2, .value = "w" }, .n_prepared = 1, .n_commit = 1, .n_h = 2 },
        .{ .ballot = .{ .counter = 2, .value = "v" }, .n_prepared = 2, .n_commit = 1, .n_h = 2 },
        .{ .ballot = .{ .counter = 2, .value = "v" }, .n_prepared = 1, .n_commit = 1, .n_h = 1 },
    };
    for (conf_specs) |sp| try stmts.append(gpa, try buildDiffConfirm(gpa, sp));

    // Externalize: two distinct — never newer than each other.
    try stmts.append(gpa, try buildDiffExternalize(gpa, .{ .counter = 1, .value = "v" }, 1));
    try stmts.append(gpa, try buildDiffExternalize(gpa, .{ .counter = 9, .value = "z" }, 9));

    // Every ordered pair (including self-pairs and cross-protocol pairs):
    // the two implementations must agree exactly.
    var newer_pairs: usize = 0;
    var pair_count: usize = 0;
    for (stmts.items) |*old| {
        for (stmts.items) |*new| {
            const via_reader = try statement.isNewerStatement(try old.reader(), try new.reader());
            const via_owned = isNewerOwned(&old.owned, &new.owned);
            try testing.expectEqual(via_reader, via_owned);
            if (via_owned) newer_pairs += 1;
            pair_count += 1;
        }
    }
    // The matrix must actually exercise both verdicts.
    try testing.expect(newer_pairs > 0);
    try testing.expect(newer_pairs < pair_count);
    try testing.expectEqual(@as(usize, 23 * 23), pair_count);
}
