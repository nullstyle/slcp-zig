//! Statement sanity (`checkStatementSane`) and freshness (`isNewerStatement`)
//! for received SLCP statements (design §4.1 schema comments + "Deliberate
//! sanity divergences", §4.5 frozen limits, §5.4 slot.zig freshness orders).
//!
//! Oracle: stellar-core `BallotProtocol::isStatementSane` /
//! `BallotProtocol::isNewerStatement` / `compareBallots` /
//! `areBallotsCompatible` (BallotProtocol.cpp),
//! `NominationProtocol::isSane` / `isNewerStatement` / `isSubsetHelper`
//! (NominationProtocol.cpp), `Slot::isNewerNominationOrBallotSt` (Slot.cpp).
//! SLCP is deliberately STRICTER in three named places (§4.1): nomination
//! `votes` must be nonempty, `preparedPrime` requires `prepared`, and CONFIRM
//! requires `nPrepared >= 1` and `nCommit >= 1`. Unlike the oracle, qset
//! resolution is NOT part of sanity here — unknown qset hashes park (§5.4),
//! they are not insane.

const std = @import("std");
const gen_slcp = @import("../gen/slcp.zig");
const limits = @import("limits.zig");

// ---------------------------------------------------------------------------
// Sanity
// ---------------------------------------------------------------------------

/// Every rejection class of `checkStatementSane`. The vector files pin these
/// names (`@tagName`), so renaming an arm is a vector-regeneration event.
pub const InsaneReason = enum {
    /// capnp traversal failed mid-walk (callers normally run the validating
    /// decode first, so this is a defense-in-depth arm, not a wire case).
    decode_error,
    /// nodeId is not exactly 32 bytes (§4.1 Statement).
    bad_node_id_length,
    /// pledges union discriminant 0 — an all-zero message decodes here (§4.1).
    unset_pledges,
    /// pledges union discriminant above any known arm.
    unknown_pledges_tag,
    /// quorumSetHash / commitQuorumSetHash is not exactly 32 bytes (§4.1).
    bad_quorum_set_hash_length,
    /// a value (ballot value or nomination value) has length outside
    /// [1, limits.max_value_bytes] (§4.1, §4.5).
    bad_value_length,
    /// a present ballot has counter 0 — the engine-internal bottom
    /// placeholder is never transmitted (§4.1 Ballot).
    zero_ballot_counter,
    /// nomination votes empty — STRICTER than stellar-core, which requires
    /// only votes+accepted jointly nonempty (§4.1 divergences).
    empty_votes,
    /// nomination votes not strictly ascending byte order (§4.1).
    unsorted_votes,
    /// nomination votes exceed limits.max_nomination_values (§4.5).
    too_many_votes,
    /// nomination accepted not strictly ascending byte order (§4.1).
    unsorted_accepted,
    /// nomination accepted exceeds limits.max_nomination_values (§4.5).
    too_many_accepted,
    /// preparedPrime present without prepared — STRICTER than stellar-core,
    /// which tolerates its absence (§4.1 divergences).
    prepared_prime_without_prepared,
    /// !(preparedPrime ⋦ prepared): must be <= AND value-incompatible
    /// (oracle: areBallotsLessAndIncompatible, BallotProtocol.cpp).
    prepared_prime_not_less_and_incompatible,
    /// nH != 0 without prepared set, or nH > prepared.counter (§4.1 Prepare).
    bad_prepare_nh,
    /// nC != 0 without (nH != 0 and nC <= nH <= ballot.counter) (§4.1).
    bad_prepare_nc,
    /// CONFIRM nPrepared == 0 — STRICTER than stellar-core (§4.1 divergences).
    zero_confirm_n_prepared,
    /// CONFIRM nCommit == 0 — STRICTER than stellar-core (§4.1 divergences).
    zero_confirm_n_commit,
    /// CONFIRM !(nCommit <= nH <= ballot.counter) (§4.1).
    bad_confirm_counters,
    /// EXTERNALIZE nH < commit.counter (§4.1).
    bad_externalize_nh,
};

/// Sanity-check a decoded Statement against §4.1 + §4.5. Returns null when
/// sane, otherwise the first failing rule in a fixed check order (the vectors
/// pin that order). Oracle: BallotProtocol::isStatementSane (self = false —
/// network statements never get the counter-0 exemption) +
/// NominationProtocol::isSane, plus the SLCP-stricter rules.
pub fn checkStatementSane(reader: gen_slcp.Statement.Reader, l: limits.Limits) ?InsaneReason {
    return checkInner(reader, l) catch .decode_error;
}

fn checkInner(reader: gen_slcp.Statement.Reader, l: limits.Limits) !?InsaneReason {
    const node_id = try reader.getNodeId();
    if (node_id.len != 32) return .bad_node_id_length;

    const pledges = reader.getPledges();
    const tag = pledges.which() catch return .unknown_pledges_tag;
    switch (tag) {
        .unset => return .unset_pledges,
        .nominate => {
            const nom = try pledges.getNominate();
            if ((try nom.getQuorumSetHash()).len != 32) return .bad_quorum_set_hash_length;
            const votes = try nom.getVotes();
            if (votes.len() == 0) return .empty_votes; // STRICTER than oracle
            if (votes.len() > l.max_nomination_values) return .too_many_votes;
            if (try checkValueList(votes, l, .unsorted_votes)) |r| return r;
            const accepted = try nom.getAccepted();
            if (accepted.len() > l.max_nomination_values) return .too_many_accepted;
            if (try checkValueList(accepted, l, .unsorted_accepted)) |r| return r;
            // Receivers require only sortedness: accepted ⊆ votes is an
            // emitter property, NOT checked here (§4.1 Nomination).
            return null;
        },
        .prepare => {
            const p = try pledges.getPrepare();
            if ((try p.getQuorumSetHash()).len != 32) return .bad_quorum_set_hash_length;
            const ballot = try ballotView(try p.getBallot());
            if (checkBallot(ballot, l)) |r| return r;
            const prepared = try preparedOf(p);
            const prepared_prime = try preparedPrimeOf(p);
            if (prepared) |b| if (checkBallot(b, l)) |r| return r;
            if (prepared_prime) |b| if (checkBallot(b, l)) |r| return r;
            if (prepared_prime != null and prepared == null)
                return .prepared_prime_without_prepared; // STRICTER than oracle
            if (prepared_prime) |pp| {
                if (!areBallotsLessAndIncompatible(pp, prepared.?))
                    return .prepared_prime_not_less_and_incompatible;
            }
            const n_c = try p.getNC();
            const n_h = try p.getNH();
            // h != 0 -> prepared set and h <= prepared.counter
            if (n_h != 0 and (prepared == null or n_h > prepared.?.counter))
                return .bad_prepare_nh;
            // c != 0 -> c <= h <= b (oracle: BallotProtocol.cpp "c != 0 -> c <= h <= b")
            if (n_c != 0 and (n_h == 0 or n_c > n_h or n_h > ballot.counter))
                return .bad_prepare_nc;
            return null;
        },
        .confirm => {
            const c = try pledges.getConfirm();
            if ((try c.getQuorumSetHash()).len != 32) return .bad_quorum_set_hash_length;
            const ballot = try ballotView(try c.getBallot());
            if (checkBallot(ballot, l)) |r| return r;
            if ((try c.getNPrepared()) == 0) return .zero_confirm_n_prepared; // STRICTER
            const n_commit = try c.getNCommit();
            const n_h = try c.getNH();
            if (n_commit == 0) return .zero_confirm_n_commit; // STRICTER
            if (n_commit > n_h or n_h > ballot.counter) return .bad_confirm_counters;
            return null;
        },
        .externalize => {
            const e = try pledges.getExternalize();
            if ((try e.getCommitQuorumSetHash()).len != 32) return .bad_quorum_set_hash_length;
            const commit = try ballotView(try e.getCommit());
            if (checkBallot(commit, l)) |r| return r;
            if ((try e.getNH()) < commit.counter) return .bad_externalize_nh;
            return null;
        },
    }
}

/// Values strictly ascending (implies dedup) and each in
/// [1, max_value_bytes]. `unsorted_reason` distinguishes votes from accepted.
fn checkValueList(list: anytype, l: limits.Limits, unsorted_reason: InsaneReason) !?InsaneReason {
    var prev: ?[]const u8 = null;
    var i: u32 = 0;
    while (i < list.len()) : (i += 1) {
        const v = try list.get(i);
        if (v.len < 1 or v.len > l.max_value_bytes) return .bad_value_length;
        if (prev) |p| {
            if (std.mem.order(u8, p, v) != .lt) return unsorted_reason;
        }
        prev = v;
    }
    return null;
}

fn checkBallot(b: BallotView, l: limits.Limits) ?InsaneReason {
    if (b.counter == 0) return .zero_ballot_counter;
    if (b.value.len < 1 or b.value.len > l.max_value_bytes) return .bad_value_length;
    return null;
}

// ---------------------------------------------------------------------------
// Ballot ordering (oracle: BallotProtocol.cpp compareBallots /
// areBallotsCompatible / areBallotsLessAndIncompatible)
// ---------------------------------------------------------------------------

/// Borrowed view of a wire Ballot; `value` aliases the decode buffer.
pub const BallotView = struct {
    counter: u32,
    value: []const u8,
};

pub fn ballotView(r: gen_slcp.Ballot.Reader) !BallotView {
    return .{ .counter = try r.getCounter(), .value = try r.getValue() };
}

/// Total order: counter first, then lexicographic value bytes
/// (oracle: BallotProtocol::compareBallots(SCPBallot, SCPBallot)).
pub fn compareBallots(a: BallotView, b: BallotView) std.math.Order {
    if (a.counter != b.counter) return std.math.order(a.counter, b.counter);
    return std.mem.order(u8, a.value, b.value);
}

/// Same value bytes (oracle: BallotProtocol::areBallotsCompatible).
pub fn areBallotsCompatible(a: BallotView, b: BallotView) bool {
    return std.mem.eql(u8, a.value, b.value);
}

/// a ⋦ b: a <= b AND value-incompatible
/// (oracle: BallotProtocol::areBallotsLessAndIncompatible).
pub fn areBallotsLessAndIncompatible(a: BallotView, b: BallotView) bool {
    return compareBallots(a, b) != .gt and !areBallotsCompatible(a, b);
}

/// Optional-ballot order: absent < any present (oracle: the unique_ptr
/// overload of BallotProtocol::compareBallots).
pub fn compareOptBallots(a: ?BallotView, b: ?BallotView) std.math.Order {
    if (a != null and b != null) return compareBallots(a.?, b.?);
    if (a != null) return .gt;
    if (b != null) return .lt;
    return .eq;
}

fn preparedOf(p: gen_slcp.Prepare.Reader) !?BallotView {
    if (p._reader.isPointerNull(2)) return null; // absent pointer == unset (§4.1)
    return try ballotView(try p.getPrepared());
}

fn preparedPrimeOf(p: gen_slcp.Prepare.Reader) !?BallotView {
    if (p._reader.isPointerNull(3)) return null;
    return try ballotView(try p.getPreparedPrime());
}

// ---------------------------------------------------------------------------
// Freshness (§5.4 slot.zig bullet; oracle: Slot::isNewerNominationOrBallotSt,
// NominationProtocol::isNewerStatement, BallotProtocol::isNewerStatement)
// ---------------------------------------------------------------------------

/// True iff `new` strictly supersedes `old` in its protocol's partial order.
/// Callers guarantee same node + same slot. Nomination and ballot statements
/// never compare newer against each other (Slot.cpp: protocols never mix);
/// two EXTERNALIZE never compare newer.
pub fn isNewerStatement(old: gen_slcp.Statement.Reader, new: gen_slcp.Statement.Reader) !bool {
    // Callers should run checkStatementSane first; malformed pledges (unset
    // arm or unknown discriminant) are treated as never-newer, not as errors.
    const old_tag = old.getPledges().which() catch return false;
    const new_tag = new.getPledges().which() catch return false;
    if (old_tag == .unset or new_tag == .unset) return false; // insane input, never newer
    const old_nom = old_tag == .nominate;
    const new_nom = new_tag == .nominate;
    if (old_nom != new_nom) return false; // Slot::isNewerNominationOrBallotSt

    if (old_nom) {
        return isNewerNomination(
            try old.getPledges().getNominate(),
            try new.getPledges().getNominate(),
        );
    }

    // Ballot protocol: statement type PREPARE < CONFIRM < EXTERNALIZE
    // (WhichTag ints preserve this order).
    if (old_tag != new_tag) return @intFromEnum(old_tag) < @intFromEnum(new_tag);
    switch (new_tag) {
        // can't have duplicate EXTERNALIZE statements
        .externalize => return false,
        .confirm => {
            // sorted by (b, nPrepared, nH)
            const oldc = try old.getPledges().getConfirm();
            const newc = try new.getPledges().getConfirm();
            const comp = compareBallots(
                try ballotView(try oldc.getBallot()),
                try ballotView(try newc.getBallot()),
            );
            if (comp != .eq) return comp == .lt;
            const old_np = try oldc.getNPrepared();
            const new_np = try newc.getNPrepared();
            if (old_np != new_np) return old_np < new_np;
            return (try oldc.getNH()) < (try newc.getNH());
        },
        .prepare => {
            // lexicographic (b, p, p', nH), absent < present
            const oldp = try old.getPledges().getPrepare();
            const newp = try new.getPledges().getPrepare();
            var comp = compareBallots(
                try ballotView(try oldp.getBallot()),
                try ballotView(try newp.getBallot()),
            );
            if (comp != .eq) return comp == .lt;
            comp = compareOptBallots(try preparedOf(oldp), try preparedOf(newp));
            if (comp != .eq) return comp == .lt;
            comp = compareOptBallots(try preparedPrimeOf(oldp), try preparedPrimeOf(newp));
            if (comp != .eq) return comp == .lt;
            return (try oldp.getNH()) < (try newp.getNH());
        },
        else => unreachable,
    }
}

fn isNewerNomination(oldn: gen_slcp.Nomination.Reader, newn: gen_slcp.Nomination.Reader) !bool {
    // Oracle: NominationProtocol::isNewerStatement — BOTH sets must be
    // superset-or-equal, and at least one must strictly grow.
    var votes_grew = false;
    if (!try isSubsetHelper(try oldn.getVotes(), try newn.getVotes(), &votes_grew)) return false;
    var accepted_grew = false;
    if (!try isSubsetHelper(try oldn.getAccepted(), try newn.getAccepted(), &accepted_grew)) return false;
    return votes_grew or accepted_grew;
}

/// p ⊆ v over strictly-ascending sorted lists; `not_equal` reports strict
/// growth when the subset holds (oracle: NominationProtocol::isSubsetHelper,
/// std::includes specialized to sorted-unique inputs).
fn isSubsetHelper(p: anytype, v: anytype, not_equal: *bool) !bool {
    if (p.len() > v.len()) {
        not_equal.* = true;
        return false;
    }
    var pi: u32 = 0;
    var vi: u32 = 0;
    while (pi < p.len() and vi < v.len()) {
        switch (std.mem.order(u8, try p.get(pi), try v.get(vi))) {
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
    if (pi == p.len()) {
        not_equal.* = p.len() != v.len();
        return true;
    }
    not_equal.* = true;
    return false;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const capnpc = @import("capnpc-zig");
const canonical = @import("../canonical.zig");
const crypto = @import("../crypto.zig");

const TestStmt = struct {
    framed: []const u8,
    msg: capnpc.message.Message,

    fn reader(self: *const TestStmt) !gen_slcp.Statement.Reader {
        return gen_slcp.Statement.Reader.init(&self.msg);
    }

    fn deinit(self: *TestStmt, gpa: std.mem.Allocator) void {
        self.msg.deinit();
        gpa.free(self.framed);
        self.* = undefined;
    }
};

const B = struct { counter: u32, value: []const u8 };

const NominateSpec = struct {
    node_id_len: usize = 32,
    qsh_len: usize = 32,
    votes: []const []const u8 = &.{},
    accepted: []const []const u8 = &.{},
};

const PrepareSpec = struct {
    qsh_len: usize = 32,
    ballot: B = .{ .counter = 1, .value = "v" },
    prepared: ?B = null,
    prepared_prime: ?B = null,
    n_c: u32 = 0,
    n_h: u32 = 0,
};

const ConfirmSpec = struct {
    qsh_len: usize = 32,
    ballot: B = .{ .counter = 2, .value = "v" },
    n_prepared: u32 = 1,
    n_commit: u32 = 1,
    n_h: u32 = 2,
};

const ExternalizeSpec = struct {
    qsh_len: usize = 32,
    commit: B = .{ .counter = 1, .value = "v" },
    n_h: u32 = 1,
};

fn hashBytes(gpa: std.mem.Allocator, n: usize, fill: u8) ![]u8 {
    const out = try gpa.alloc(u8, n);
    @memset(out, fill);
    return out;
}

fn finishStmt(gpa: std.mem.Allocator, mb: *capnpc.message.MessageBuilder) !TestStmt {
    const framed = try mb.toBytes();
    errdefer gpa.free(framed);
    const msg = try capnpc.message.Message.init(gpa, framed, .{});
    return .{ .framed = framed, .msg = msg };
}

fn setBallot(bb: *gen_slcp.Ballot.Builder, b: B) !void {
    try bb.setCounter(b.counter);
    try bb.setValue(b.value);
}

fn makeNominate(gpa: std.mem.Allocator, spec: NominateSpec) !TestStmt {
    var mb = capnpc.message.MessageBuilder.init(gpa);
    defer mb.deinit();
    var st = try gen_slcp.Statement.Builder.init(&mb);
    const node_id = try hashBytes(gpa, spec.node_id_len, 0x0d);
    defer gpa.free(node_id);
    try st.setNodeId(node_id);
    try st.setSlotIndex(1);
    var pledges = st.getPledges();
    var nom = try pledges.initNominate();
    const qsh = try hashBytes(gpa, spec.qsh_len, 0xaa);
    defer gpa.free(qsh);
    try nom.setQuorumSetHash(qsh);
    if (spec.votes.len > 0) {
        const vl = try nom.initVotes(@intCast(spec.votes.len));
        for (spec.votes, 0..) |v, i| try vl.set(@intCast(i), v);
    }
    if (spec.accepted.len > 0) {
        const al = try nom.initAccepted(@intCast(spec.accepted.len));
        for (spec.accepted, 0..) |v, i| try al.set(@intCast(i), v);
    }
    return finishStmt(gpa, &mb);
}

fn makePrepare(gpa: std.mem.Allocator, spec: PrepareSpec) !TestStmt {
    var mb = capnpc.message.MessageBuilder.init(gpa);
    defer mb.deinit();
    var st = try gen_slcp.Statement.Builder.init(&mb);
    const node_id = try hashBytes(gpa, 32, 0x01);
    defer gpa.free(node_id);
    try st.setNodeId(node_id);
    try st.setSlotIndex(1);
    var pledges = st.getPledges();
    var prep = try pledges.initPrepare();
    const qsh = try hashBytes(gpa, spec.qsh_len, 0xaa);
    defer gpa.free(qsh);
    try prep.setQuorumSetHash(qsh);
    var ballot = try prep.initBallot();
    try setBallot(&ballot, spec.ballot);
    if (spec.prepared) |b| {
        var pb = try prep.initPrepared();
        try setBallot(&pb, b);
    }
    if (spec.prepared_prime) |b| {
        var pb = try prep.initPreparedPrime();
        try setBallot(&pb, b);
    }
    try prep.setNC(spec.n_c);
    try prep.setNH(spec.n_h);
    return finishStmt(gpa, &mb);
}

fn makeConfirm(gpa: std.mem.Allocator, spec: ConfirmSpec) !TestStmt {
    var mb = capnpc.message.MessageBuilder.init(gpa);
    defer mb.deinit();
    var st = try gen_slcp.Statement.Builder.init(&mb);
    const node_id = try hashBytes(gpa, 32, 0x01);
    defer gpa.free(node_id);
    try st.setNodeId(node_id);
    try st.setSlotIndex(1);
    var pledges = st.getPledges();
    var conf = try pledges.initConfirm();
    const qsh = try hashBytes(gpa, spec.qsh_len, 0xaa);
    defer gpa.free(qsh);
    try conf.setQuorumSetHash(qsh);
    var ballot = try conf.initBallot();
    try setBallot(&ballot, spec.ballot);
    try conf.setNPrepared(spec.n_prepared);
    try conf.setNCommit(spec.n_commit);
    try conf.setNH(spec.n_h);
    return finishStmt(gpa, &mb);
}

fn makeExternalize(gpa: std.mem.Allocator, spec: ExternalizeSpec) !TestStmt {
    var mb = capnpc.message.MessageBuilder.init(gpa);
    defer mb.deinit();
    var st = try gen_slcp.Statement.Builder.init(&mb);
    const node_id = try hashBytes(gpa, 32, 0x01);
    defer gpa.free(node_id);
    try st.setNodeId(node_id);
    try st.setSlotIndex(1);
    var pledges = st.getPledges();
    var ext = try pledges.initExternalize();
    var commit = try ext.initCommit();
    try setBallot(&commit, spec.commit);
    try ext.setNH(spec.n_h);
    const qsh = try hashBytes(gpa, spec.qsh_len, 0xaa);
    defer gpa.free(qsh);
    try ext.setCommitQuorumSetHash(qsh);
    return finishStmt(gpa, &mb);
}

fn makeUnset(gpa: std.mem.Allocator) !TestStmt {
    var mb = capnpc.message.MessageBuilder.init(gpa);
    defer mb.deinit();
    var st = try gen_slcp.Statement.Builder.init(&mb);
    const node_id = try hashBytes(gpa, 32, 0x01);
    defer gpa.free(node_id);
    try st.setNodeId(node_id);
    try st.setSlotIndex(1);
    return finishStmt(gpa, &mb);
}

fn expectReason(stmt: *const TestStmt, expected: ?InsaneReason) !void {
    try std.testing.expectEqual(expected, checkStatementSane(try stmt.reader(), .{}));
}

test "sanity: nomination arms" {
    const gpa = std.testing.allocator;

    var sane = try makeNominate(gpa, .{ .votes = &.{ "a", "b" }, .accepted = &.{"a"} });
    defer sane.deinit(gpa);
    try expectReason(&sane, null);

    // accepted ⊄ votes is fine for receivers (§4.1)
    var not_subset = try makeNominate(gpa, .{ .votes = &.{"a"}, .accepted = &.{"z"} });
    defer not_subset.deinit(gpa);
    try expectReason(&not_subset, null);

    var bad_node = try makeNominate(gpa, .{ .node_id_len = 31, .votes = &.{"a"} });
    defer bad_node.deinit(gpa);
    try expectReason(&bad_node, .bad_node_id_length);

    var bad_qsh = try makeNominate(gpa, .{ .qsh_len = 16, .votes = &.{"a"} });
    defer bad_qsh.deinit(gpa);
    try expectReason(&bad_qsh, .bad_quorum_set_hash_length);

    var empty = try makeNominate(gpa, .{});
    defer empty.deinit(gpa);
    try expectReason(&empty, .empty_votes);

    var unsorted = try makeNominate(gpa, .{ .votes = &.{ "b", "a" } });
    defer unsorted.deinit(gpa);
    try expectReason(&unsorted, .unsorted_votes);

    // equal adjacent = not strictly ascending
    var dup = try makeNominate(gpa, .{ .votes = &.{ "a", "a" } });
    defer dup.deinit(gpa);
    try expectReason(&dup, .unsorted_votes);

    var unsorted_acc = try makeNominate(gpa, .{ .votes = &.{"a"}, .accepted = &.{ "b", "a" } });
    defer unsorted_acc.deinit(gpa);
    try expectReason(&unsorted_acc, .unsorted_accepted);

    // 65 one-byte values breach max_nomination_values = 64
    var many: [65][]const u8 = undefined;
    var storage: [65][1]u8 = undefined;
    for (0..65) |i| {
        storage[i][0] = @intCast(i);
        many[i] = &storage[i];
    }
    var too_many = try makeNominate(gpa, .{ .votes = &many });
    defer too_many.deinit(gpa);
    try expectReason(&too_many, .too_many_votes);

    var too_many_acc = try makeNominate(gpa, .{ .votes = &.{"a"}, .accepted = &many });
    defer too_many_acc.deinit(gpa);
    try expectReason(&too_many_acc, .too_many_accepted);

    // oversized nomination value (> default 4096)
    const big = try gpa.alloc(u8, 4097);
    defer gpa.free(big);
    @memset(big, 0x77);
    var oversized = try makeNominate(gpa, .{ .votes = &.{big} });
    defer oversized.deinit(gpa);
    try expectReason(&oversized, .bad_value_length);

    // exactly max_value_bytes is sane
    var at_cap = try makeNominate(gpa, .{ .votes = &.{big[0..4096]} });
    defer at_cap.deinit(gpa);
    try expectReason(&at_cap, null);
}

test "sanity: unset pledges" {
    const gpa = std.testing.allocator;
    var unset = try makeUnset(gpa);
    defer unset.deinit(gpa);
    try expectReason(&unset, .unset_pledges);
}

test "sanity: unknown pledges tag" {
    const gpa = std.testing.allocator;
    var mb = capnpc.message.MessageBuilder.init(gpa);
    defer mb.deinit();
    var st = try gen_slcp.Statement.Builder.init(&mb);
    const node_id = try hashBytes(gpa, 32, 0x01);
    defer gpa.free(node_id);
    try st.setNodeId(node_id);
    try st.setSlotIndex(1);
    // discriminant 5: above every known union arm
    st._builder.writeU16(8, 5);
    var stmt = try finishStmt(gpa, &mb);
    defer stmt.deinit(gpa);
    try expectReason(&stmt, .unknown_pledges_tag);
}

test "sanity: prepare arms" {
    const gpa = std.testing.allocator;

    var sane = try makePrepare(gpa, .{});
    defer sane.deinit(gpa);
    try expectReason(&sane, null);

    var full = try makePrepare(gpa, .{
        .ballot = .{ .counter = 3, .value = "y" },
        .prepared = .{ .counter = 3, .value = "y" },
        .prepared_prime = .{ .counter = 2, .value = "x" },
        .n_c = 1,
        .n_h = 3,
    });
    defer full.deinit(gpa);
    try expectReason(&full, null);

    var zero = try makePrepare(gpa, .{ .ballot = .{ .counter = 0, .value = "v" } });
    defer zero.deinit(gpa);
    try expectReason(&zero, .zero_ballot_counter);

    var empty_val = try makePrepare(gpa, .{ .ballot = .{ .counter = 1, .value = "" } });
    defer empty_val.deinit(gpa);
    try expectReason(&empty_val, .bad_value_length);

    var zero_prepared = try makePrepare(gpa, .{ .prepared = .{ .counter = 0, .value = "v" } });
    defer zero_prepared.deinit(gpa);
    try expectReason(&zero_prepared, .zero_ballot_counter);

    var pp_alone = try makePrepare(gpa, .{ .prepared_prime = .{ .counter = 1, .value = "u" } });
    defer pp_alone.deinit(gpa);
    try expectReason(&pp_alone, .prepared_prime_without_prepared);

    // compatible (same value) => not ⋦
    var pp_compat = try makePrepare(gpa, .{
        .ballot = .{ .counter = 3, .value = "v" },
        .prepared = .{ .counter = 2, .value = "v" },
        .prepared_prime = .{ .counter = 1, .value = "v" },
    });
    defer pp_compat.deinit(gpa);
    try expectReason(&pp_compat, .prepared_prime_not_less_and_incompatible);

    // greater => not ⋦
    var pp_greater = try makePrepare(gpa, .{
        .ballot = .{ .counter = 3, .value = "v" },
        .prepared = .{ .counter = 1, .value = "a" },
        .prepared_prime = .{ .counter = 2, .value = "b" },
    });
    defer pp_greater.deinit(gpa);
    try expectReason(&pp_greater, .prepared_prime_not_less_and_incompatible);

    // equal counter, incompatible value, pp < p lexicographically: sane ⋦
    var pp_eq_counter = try makePrepare(gpa, .{
        .ballot = .{ .counter = 3, .value = "v" },
        .prepared = .{ .counter = 2, .value = "b" },
        .prepared_prime = .{ .counter = 2, .value = "a" },
    });
    defer pp_eq_counter.deinit(gpa);
    try expectReason(&pp_eq_counter, null);

    var nh_no_prepared = try makePrepare(gpa, .{ .n_h = 1 });
    defer nh_no_prepared.deinit(gpa);
    try expectReason(&nh_no_prepared, .bad_prepare_nh);

    var nh_above_prepared = try makePrepare(gpa, .{
        .ballot = .{ .counter = 5, .value = "v" },
        .prepared = .{ .counter = 2, .value = "v" },
        .n_h = 3,
    });
    defer nh_above_prepared.deinit(gpa);
    try expectReason(&nh_above_prepared, .bad_prepare_nh);

    var nc_no_nh = try makePrepare(gpa, .{ .n_c = 1 });
    defer nc_no_nh.deinit(gpa);
    try expectReason(&nc_no_nh, .bad_prepare_nc);

    var nc_above_nh = try makePrepare(gpa, .{
        .ballot = .{ .counter = 5, .value = "v" },
        .prepared = .{ .counter = 5, .value = "v" },
        .n_c = 3,
        .n_h = 2,
    });
    defer nc_above_nh.deinit(gpa);
    try expectReason(&nc_above_nh, .bad_prepare_nc);

    var nh_above_ballot = try makePrepare(gpa, .{
        .ballot = .{ .counter = 2, .value = "v" },
        .prepared = .{ .counter = 5, .value = "v" },
        .n_c = 1,
        .n_h = 4,
    });
    defer nh_above_ballot.deinit(gpa);
    try expectReason(&nh_above_ballot, .bad_prepare_nc);
}

test "sanity: confirm arms" {
    const gpa = std.testing.allocator;

    var sane = try makeConfirm(gpa, .{});
    defer sane.deinit(gpa);
    try expectReason(&sane, null);

    var zero_ballot = try makeConfirm(gpa, .{ .ballot = .{ .counter = 0, .value = "v" } });
    defer zero_ballot.deinit(gpa);
    try expectReason(&zero_ballot, .zero_ballot_counter);

    var zero_np = try makeConfirm(gpa, .{ .n_prepared = 0 });
    defer zero_np.deinit(gpa);
    try expectReason(&zero_np, .zero_confirm_n_prepared);

    var zero_nc = try makeConfirm(gpa, .{ .n_commit = 0 });
    defer zero_nc.deinit(gpa);
    try expectReason(&zero_nc, .zero_confirm_n_commit);

    var nc_above_nh = try makeConfirm(gpa, .{ .ballot = .{ .counter = 5, .value = "v" }, .n_commit = 3, .n_h = 2 });
    defer nc_above_nh.deinit(gpa);
    try expectReason(&nc_above_nh, .bad_confirm_counters);

    var nh_above_b = try makeConfirm(gpa, .{ .ballot = .{ .counter = 2, .value = "v" }, .n_commit = 1, .n_h = 3 });
    defer nh_above_b.deinit(gpa);
    try expectReason(&nh_above_b, .bad_confirm_counters);

    var bad_qsh = try makeConfirm(gpa, .{ .qsh_len = 0 });
    defer bad_qsh.deinit(gpa);
    try expectReason(&bad_qsh, .bad_quorum_set_hash_length);
}

test "sanity: externalize arms" {
    const gpa = std.testing.allocator;

    var sane = try makeExternalize(gpa, .{ .commit = .{ .counter = 2, .value = "v" }, .n_h = 5 });
    defer sane.deinit(gpa);
    try expectReason(&sane, null);

    var zero = try makeExternalize(gpa, .{ .commit = .{ .counter = 0, .value = "v" }, .n_h = 1 });
    defer zero.deinit(gpa);
    try expectReason(&zero, .zero_ballot_counter);

    var low_nh = try makeExternalize(gpa, .{ .commit = .{ .counter = 3, .value = "v" }, .n_h = 2 });
    defer low_nh.deinit(gpa);
    try expectReason(&low_nh, .bad_externalize_nh);

    var bad_qsh = try makeExternalize(gpa, .{ .qsh_len = 31 });
    defer bad_qsh.deinit(gpa);
    try expectReason(&bad_qsh, .bad_quorum_set_hash_length);
}

test "ballot compare and compatibility" {
    const a1: BallotView = .{ .counter = 1, .value = "aaa" };
    const a2: BallotView = .{ .counter = 2, .value = "aaa" };
    const b1: BallotView = .{ .counter = 1, .value = "bbb" };

    try std.testing.expectEqual(std.math.Order.lt, compareBallots(a1, a2)); // counter first
    try std.testing.expectEqual(std.math.Order.gt, compareBallots(a2, b1)); // counter beats value
    try std.testing.expectEqual(std.math.Order.lt, compareBallots(a1, b1)); // value tie-break
    try std.testing.expectEqual(std.math.Order.eq, compareBallots(a1, a1));

    try std.testing.expect(areBallotsCompatible(a1, a2));
    try std.testing.expect(!areBallotsCompatible(a1, b1));

    try std.testing.expect(areBallotsLessAndIncompatible(a1, b1)); // eq counter, lt value, incompatible
    try std.testing.expect(!areBallotsLessAndIncompatible(a1, a2)); // compatible
    try std.testing.expect(!areBallotsLessAndIncompatible(b1, a1)); // greater

    // absent < any present
    try std.testing.expectEqual(std.math.Order.lt, compareOptBallots(null, a1));
    try std.testing.expectEqual(std.math.Order.gt, compareOptBallots(a1, null));
    try std.testing.expectEqual(std.math.Order.eq, compareOptBallots(null, null));
}

test "freshness: nomination superset growth" {
    const gpa = std.testing.allocator;

    var ab = try makeNominate(gpa, .{ .votes = &.{ "a", "b" } });
    defer ab.deinit(gpa);
    var abc = try makeNominate(gpa, .{ .votes = &.{ "a", "b", "c" } });
    defer abc.deinit(gpa);
    var abc_acc = try makeNominate(gpa, .{ .votes = &.{ "a", "b", "c" }, .accepted = &.{"a"} });
    defer abc_acc.deinit(gpa);
    var ad = try makeNominate(gpa, .{ .votes = &.{ "a", "d" } });
    defer ad.deinit(gpa);

    // votes grew
    try std.testing.expect(try isNewerStatement(try ab.reader(), try abc.reader()));
    // shrink direction: not newer
    try std.testing.expect(!try isNewerStatement(try abc.reader(), try ab.reader()));
    // equal sets: not newer
    try std.testing.expect(!try isNewerStatement(try ab.reader(), try ab.reader()));
    // accepted grew while votes stayed equal
    try std.testing.expect(try isNewerStatement(try abc.reader(), try abc_acc.reader()));
    // sideways (not a superset): not newer either way
    try std.testing.expect(!try isNewerStatement(try ab.reader(), try ad.reader()));
    try std.testing.expect(!try isNewerStatement(try ad.reader(), try ab.reader()));
}

test "freshness: nomination requires BOTH sets superset-or-equal" {
    const gpa = std.testing.allocator;
    // votes grow but accepted shrinks: NOT newer (oracle requires both subsets)
    var old = try makeNominate(gpa, .{ .votes = &.{"a"}, .accepted = &.{ "a", "b" } });
    defer old.deinit(gpa);
    var new = try makeNominate(gpa, .{ .votes = &.{ "a", "b" }, .accepted = &.{"a"} });
    defer new.deinit(gpa);
    try std.testing.expect(!try isNewerStatement(try old.reader(), try new.reader()));
    try std.testing.expect(!try isNewerStatement(try new.reader(), try old.reader()));
}

test "freshness: statement type order and protocol separation" {
    const gpa = std.testing.allocator;

    var nom = try makeNominate(gpa, .{ .votes = &.{"a"} });
    defer nom.deinit(gpa);
    var prep = try makePrepare(gpa, .{});
    defer prep.deinit(gpa);
    var conf = try makeConfirm(gpa, .{});
    defer conf.deinit(gpa);
    var ext = try makeExternalize(gpa, .{});
    defer ext.deinit(gpa);
    var ext2 = try makeExternalize(gpa, .{ .commit = .{ .counter = 9, .value = "z" }, .n_h = 9 });
    defer ext2.deinit(gpa);

    // PREPARE < CONFIRM < EXTERNALIZE
    try std.testing.expect(try isNewerStatement(try prep.reader(), try conf.reader()));
    try std.testing.expect(try isNewerStatement(try conf.reader(), try ext.reader()));
    try std.testing.expect(try isNewerStatement(try prep.reader(), try ext.reader()));
    try std.testing.expect(!try isNewerStatement(try conf.reader(), try prep.reader()));
    try std.testing.expect(!try isNewerStatement(try ext.reader(), try conf.reader()));

    // two EXTERNALIZE never compare newer
    try std.testing.expect(!try isNewerStatement(try ext.reader(), try ext2.reader()));
    try std.testing.expect(!try isNewerStatement(try ext2.reader(), try ext.reader()));

    // nomination and ballot statements never mix (Slot.cpp)
    try std.testing.expect(!try isNewerStatement(try nom.reader(), try prep.reader()));
    try std.testing.expect(!try isNewerStatement(try prep.reader(), try nom.reader()));
}

test "freshness: prepare lexicographic (b, p, p', nH)" {
    const gpa = std.testing.allocator;

    var base = try makePrepare(gpa, .{ .ballot = .{ .counter = 2, .value = "v" } });
    defer base.deinit(gpa);
    var higher_b = try makePrepare(gpa, .{ .ballot = .{ .counter = 3, .value = "v" } });
    defer higher_b.deinit(gpa);
    var with_p = try makePrepare(gpa, .{
        .ballot = .{ .counter = 2, .value = "v" },
        .prepared = .{ .counter = 1, .value = "v" },
    });
    defer with_p.deinit(gpa);
    var with_higher_p = try makePrepare(gpa, .{
        .ballot = .{ .counter = 2, .value = "v" },
        .prepared = .{ .counter = 2, .value = "v" },
    });
    defer with_higher_p.deinit(gpa);
    var with_pp = try makePrepare(gpa, .{
        .ballot = .{ .counter = 2, .value = "v" },
        .prepared = .{ .counter = 2, .value = "v" },
        .prepared_prime = .{ .counter = 1, .value = "u" },
    });
    defer with_pp.deinit(gpa);
    var with_nh = try makePrepare(gpa, .{
        .ballot = .{ .counter = 2, .value = "v" },
        .prepared = .{ .counter = 2, .value = "v" },
        .prepared_prime = .{ .counter = 1, .value = "u" },
        .n_h = 2,
    });
    defer with_nh.deinit(gpa);

    // b advances
    try std.testing.expect(try isNewerStatement(try base.reader(), try higher_b.reader()));
    try std.testing.expect(!try isNewerStatement(try higher_b.reader(), try base.reader()));
    // p appears (absent < present)
    try std.testing.expect(try isNewerStatement(try base.reader(), try with_p.reader()));
    try std.testing.expect(!try isNewerStatement(try with_p.reader(), try base.reader()));
    // p advances
    try std.testing.expect(try isNewerStatement(try with_p.reader(), try with_higher_p.reader()));
    // p' appears
    try std.testing.expect(try isNewerStatement(try with_higher_p.reader(), try with_pp.reader()));
    // nH advances
    try std.testing.expect(try isNewerStatement(try with_pp.reader(), try with_nh.reader()));
    try std.testing.expect(!try isNewerStatement(try with_nh.reader(), try with_pp.reader()));
    // equal statements: not newer
    try std.testing.expect(!try isNewerStatement(try with_nh.reader(), try with_nh.reader()));
}

test "freshness: confirm lexicographic (b, nPrepared, nH)" {
    const gpa = std.testing.allocator;

    var base = try makeConfirm(gpa, .{ .ballot = .{ .counter = 2, .value = "v" } });
    defer base.deinit(gpa);
    var higher_b = try makeConfirm(gpa, .{ .ballot = .{ .counter = 3, .value = "v" } });
    defer higher_b.deinit(gpa);
    var higher_np = try makeConfirm(gpa, .{ .ballot = .{ .counter = 2, .value = "v" }, .n_prepared = 2 });
    defer higher_np.deinit(gpa);
    var low_nh = try makeConfirm(gpa, .{ .ballot = .{ .counter = 2, .value = "v" }, .n_h = 1 });
    defer low_nh.deinit(gpa);

    try std.testing.expect(try isNewerStatement(try base.reader(), try higher_b.reader()));
    try std.testing.expect(!try isNewerStatement(try higher_b.reader(), try base.reader()));
    try std.testing.expect(try isNewerStatement(try base.reader(), try higher_np.reader()));
    try std.testing.expect(!try isNewerStatement(try higher_np.reader(), try base.reader()));
    try std.testing.expect(try isNewerStatement(try low_nh.reader(), try base.reader()));
    try std.testing.expect(!try isNewerStatement(try base.reader(), try low_nh.reader()));
    try std.testing.expect(!try isNewerStatement(try base.reader(), try base.reader()));
}

test "M1 input_status trio: insane, stale, invalid_signature" {
    const gpa = std.testing.allocator;

    // insane: empty votes fails checkStatementSane
    var insane = try makeNominate(gpa, .{});
    defer insane.deinit(gpa);
    try std.testing.expectEqual(@as(?InsaneReason, .empty_votes), checkStatementSane(try insane.reader(), .{}));

    // stale: a statement that is not newer than the recorded latest
    var latest = try makeNominate(gpa, .{ .votes = &.{ "a", "b" } });
    defer latest.deinit(gpa);
    var stale = try makeNominate(gpa, .{ .votes = &.{"a"} });
    defer stale.deinit(gpa);
    try std.testing.expect(!try isNewerStatement(try latest.reader(), try stale.reader()));

    // invalid_signature: sign the canonical statementBytes, tamper, verify fails
    var sane = try makeNominate(gpa, .{ .votes = &.{ "a", "b" } });
    defer sane.deinit(gpa);
    const flat = try canonical.canonicalFlatFromFramed(gpa, sane.framed);
    defer gpa.free(flat);
    const network_id = crypto.networkIdFromPassphrase("statement.zig trio test");
    const seed: [32]u8 = @splat(0x42);
    const digest = crypto.statementDigest(network_id, flat);
    const sig = try crypto.sign(seed, digest);
    const pk = try crypto.publicKeyFromSeed(seed);
    try std.testing.expect(crypto.verify(pk, digest, sig));

    const tampered = try gpa.dupe(u8, flat);
    defer gpa.free(tampered);
    tampered[tampered.len - 1] ^= 0x01;
    const tampered_digest = crypto.statementDigest(network_id, tampered);
    try std.testing.expect(!crypto.verify(pk, tampered_digest, sig));
}
