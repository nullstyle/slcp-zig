//! Ballot protocol (design §5.4 ballot.zig bullet) — M2.
//!
//! Line-level transcription of stellar-core BallotProtocol
//! (stellar-core/src/scp/BallotProtocol.cpp; each transcribed function cites
//! its oracle lines). The advanceSlot pipeline attemptAcceptPrepared →
//! attemptConfirmPrepared → attemptAcceptCommit → attemptConfirmCommit runs
//! on every hint; the attemptBump loop and checkHeardFromQuorum run at
//! recursion depth 1 only, and actual emission is deferred to depth 0
//! (sendLatestEnvelope), gated on !watcher and fully_validated (§5.4: this
//! one flag is how watcher and lagging nodes run passively).
//!
//! Deliberate SLCP divergences (design text normative, §5.4):
//! - The 4-level validation enum's CAP-0083 `structurally-valid` level is
//!   collapsed away: peer CONFIRM/EXTERNALIZE statements whose values the
//!   driver calls `invalid` are processed at `maybe_valid` semantics (never
//!   treated as invalid, or lagging nodes could not catch up); the oracle's
//!   peer-CONFIRM/EXTERNALIZE rejection existed only at its
//!   structurally-valid level and has no SLCP counterpart
//!   (BallotProtocol.cpp:206-240).
//! - Self statements are recorded into the slot's latest_ballot map as
//!   zero-frame placeholders at build time (self visibility for federated
//!   voting, mirroring recordEnvelope of the self-signed envelope); the wire
//!   envelope is built/signed once at depth 0 for the newest statement only
//!   (the oracle signs every intermediate statement but also sends only the
//!   newest — mLastEnvelope vs mLastEnvelopeEmit, BallotProtocol.cpp:2152-2165).
//! - The empty-tx-set machinery (maybeReplaceValueWithEmptyTxSet,
//!   BallotProtocol.cpp:376-427,470) is CAP-0083 structurally-valid plumbing
//!   and is collapsed away with it.

const std = @import("std");
const stored = @import("stored.zig");

pub const Phase = enum(u2) { prepare, confirm, externalize };

const engine_mod = @import("engine.zig");
const slot_mod = @import("slot.zig");
const statement_mod = @import("statement.zig");
const local_node = @import("local_node.zig");
const qset = @import("qset.zig");
const driver_mod = @import("../driver.zig");
const emit_mod = @import("emit.zig");
const nomination_mod = @import("nomination.zig");

const BV = statement_mod.BallotView;

pub const State = struct {
    phase: Phase = .prepare,
    /// b / p / p' / h / c (§5.4). counter-0 internal placeholder never emitted.
    current: ?stored.OwnedBallot = null,
    prepared: ?stored.OwnedBallot = null,
    prepared_prime: ?stored.OwnedBallot = null,
    high: ?stored.OwnedBallot = null,
    commit: ?stored.OwnedBallot = null,
    heard_from_quorum: bool = false,
    /// advanceSlot recursion depth (guard: max_advance_recursion = 50).
    message_level: u32 = 0,
    /// z — mValueOverride (BallotProtocol.h:85): sticky value once we
    /// confirmed prepared / voted to commit; owned copy.
    value_override: ?[]u8 = null,
    /// Boxed singleton qsets {threshold 1, [node]} for nodes whose latest
    /// ballot statement is EXTERNALIZE (oracle: LocalNode::getSingletonQSet,
    /// LocalNode.cpp:66, via Slot::getQuorumSetFromStatement,
    /// Slot.cpp:316-348). Pointer-stable (heap-boxed) so the QSetLookup
    /// borrow contract holds; freed in deinit.
    singletons: std.AutoHashMapUnmanaged([32]u8, *qset.QuorumSetOwned) = .empty,
    /// mLastEnvelope analog (BallotProtocol.h:93): the newest own statement
    /// built during processing; what sendLatestEnvelope emits at depth 0.
    last_built: ?stored.OwnedStatement = null,
    /// mLastEnvelope != mLastEnvelopeEmit analog: a newer own statement was
    /// built (with a real ballot) and has not been emitted yet.
    emit_dirty: bool = false,

    pub fn deinit(self: *State, gpa: std.mem.Allocator) void {
        inline for (.{ &self.current, &self.prepared, &self.prepared_prime, &self.high, &self.commit }) |slot_ptr| {
            if (slot_ptr.*) |*b| b.deinit(gpa);
        }
        if (self.value_override) |v| gpa.free(v);
        var it = self.singletons.valueIterator();
        while (it.next()) |boxed| {
            boxed.*.deinit(gpa);
            gpa.destroy(boxed.*);
        }
        self.singletons.deinit(gpa);
        if (self.last_built) |*st| st.deinit(gpa);
        self.* = undefined;
    }
};

/// MAX_ADVANCE_SLOT_RECURSION (BallotProtocol.cpp:27).
pub const max_advance_recursion: u32 = 50;

/// Exceeding the recursion guard is an engine error (§5.4); InvalidValue is
/// the oracle's EnvelopeState::INVALID for a driver-invalid PREPARE value or
/// an EXTERNALIZE-phase statement on a different value; the pipeline maps it
/// to an input_status.
pub const Error = error{ InvalidValue, AlreadyStarted, WrongProtocol } || engine_mod.EngineError;

// ---------------------------------------------------------------------------
// Small ballot helpers over stored.OwnedBallot / statement_mod.BallotView
// ---------------------------------------------------------------------------

fn bv(b: *const stored.OwnedBallot) BV {
    return .{ .counter = b.counter, .value = b.value };
}

fn optBv(b: *const ?stored.OwnedBallot) ?BV {
    return if (b.*) |*x| bv(x) else null;
}

/// Replace `dst` with an owned copy of `b`. Copies BEFORE freeing the old
/// value: `b` may borrow the very bytes being replaced (e.g. abandonBallot
/// bumping onto the current ballot's own value).
fn setOwnedBallot(gpa: std.mem.Allocator, dst: *?stored.OwnedBallot, b: BV) !void {
    const copy = try gpa.dupe(u8, b.value);
    if (dst.*) |*old| old.deinit(gpa);
    dst.* = .{ .counter = b.counter, .value = copy };
}

fn clearOwnedBallot(gpa: std.mem.Allocator, dst: *?stored.OwnedBallot) void {
    if (dst.*) |*old| old.deinit(gpa);
    dst.* = null;
}

fn cmp(a: BV, b: BV) std.math.Order {
    return statement_mod.compareBallots(a, b);
}

fn compatible(a: BV, b: BV) bool {
    return statement_mod.areBallotsCompatible(a, b);
}

/// b1 <= b2 && b1 !~ b2 (oracle: areBallotsLessAndIncompatible,
/// BallotProtocol.cpp:1880-1885).
fn lessAndIncompatible(a: BV, b: BV) bool {
    return statement_mod.areBallotsLessAndIncompatible(a, b);
}

/// b1 <= b2 && b1 ~ b2 (oracle: areBallotsLessAndCompatible,
/// BallotProtocol.cpp:1887-1892).
fn lessAndCompatible(a: BV, b: BV) bool {
    return cmp(a, b) != .gt and compatible(a, b);
}

fn cloneOwnedBallot(gpa: std.mem.Allocator, b: *const stored.OwnedBallot) !stored.OwnedBallot {
    return b.clone(gpa);
}

fn cloneOptBallot(gpa: std.mem.Allocator, b: *const ?stored.OwnedBallot) !?stored.OwnedBallot {
    return if (b.*) |*x| try x.clone(gpa) else null;
}

/// Deep copy of a BALLOT-protocol OwnedStatement (nominate is out of scope).
fn cloneStatement(gpa: std.mem.Allocator, st: *const stored.OwnedStatement) !stored.OwnedStatement {
    const pledges: stored.OwnedPledges = switch (st.pledges) {
        .nominate => unreachable, // ballot module never clones nominations
        .prepare => |*p| blk: {
            var ballot = try p.ballot.clone(gpa);
            errdefer ballot.deinit(gpa);
            var prepared = if (p.prepared) |*b| try b.clone(gpa) else null;
            errdefer if (prepared) |*b| b.deinit(gpa);
            const prepared_prime = if (p.prepared_prime) |*b| try b.clone(gpa) else null;
            break :blk .{ .prepare = .{
                .qset_hash = p.qset_hash,
                .ballot = ballot,
                .prepared = prepared,
                .prepared_prime = prepared_prime,
                .n_c = p.n_c,
                .n_h = p.n_h,
            } };
        },
        .confirm => |*c| .{ .confirm = .{
            .qset_hash = c.qset_hash,
            .ballot = try c.ballot.clone(gpa),
            .n_prepared = c.n_prepared,
            .n_commit = c.n_commit,
            .n_h = c.n_h,
        } },
        .externalize => |*e| .{ .externalize = .{
            .commit = try e.commit.clone(gpa),
            .n_h = e.n_h,
            .commit_qset_hash = e.commit_qset_hash,
        } },
    };
    return .{ .node_id = st.node_id, .slot = st.slot, .pledges = pledges };
}

fn eqOptBallot(a: ?BV, b: ?BV) bool {
    if ((a == null) != (b == null)) return false;
    if (a == null) return true;
    return cmp(a.?, b.?) == .eq;
}

/// Statement equality for the "same envelope" skip
/// (BallotProtocol.cpp:700-708: statements only keep h.n, so updating h.x in
/// PREPARE can rebuild an identical statement — don't process it again).
fn eqBallotStatements(a: *const stored.OwnedStatement, b: *const stored.OwnedStatement) bool {
    if (std.meta.activeTag(a.pledges) != std.meta.activeTag(b.pledges)) return false;
    return switch (a.pledges) {
        .nominate => false,
        .prepare => |*pa| blk: {
            const pb = &b.pledges.prepare;
            break :blk cmp(bv(&pa.ballot), bv(&pb.ballot)) == .eq and
                eqOptBallot(optBv(&pa.prepared), optBv(&pb.prepared)) and
                eqOptBallot(optBv(&pa.prepared_prime), optBv(&pb.prepared_prime)) and
                pa.n_c == pb.n_c and pa.n_h == pb.n_h;
        },
        .confirm => |*ca| blk: {
            const cb = &b.pledges.confirm;
            break :blk cmp(bv(&ca.ballot), bv(&cb.ballot)) == .eq and
                ca.n_prepared == cb.n_prepared and ca.n_commit == cb.n_commit and
                ca.n_h == cb.n_h;
        },
        .externalize => |*ea| blk: {
            const eb = &b.pledges.externalize;
            break :blk cmp(bv(&ea.commit), bv(&eb.commit)) == .eq and ea.n_h == eb.n_h;
        },
    };
}

// ---------------------------------------------------------------------------
// Statement views (oracle: getWorkingBallot / statementBallotCounter /
// hasPreparedBallot / the commit predicates — the EXTERNALIZE-∞ semantics
// live in these switch arms exactly as in the oracle)
// ---------------------------------------------------------------------------

/// b for PREPARE, (nCommit, value) for CONFIRM, commit for EXTERNALIZE
/// (oracle: getWorkingBallot, BallotProtocol.cpp:1755-1777).
pub fn getWorkingBallot(st: *const stored.OwnedStatement) BV {
    return switch (st.pledges) {
        .nominate => unreachable,
        .prepare => |*p| bv(&p.ballot),
        .confirm => |*c| .{ .counter = c.n_commit, .value = c.ballot.value },
        .externalize => |*e| bv(&e.commit),
    };
}

/// EXTERNALIZE counts as counter infinity (oracle: statementBallotCounter,
/// BallotProtocol.cpp:1515-1530).
fn statementBallotCounter(st: *const stored.OwnedStatement) u32 {
    return switch (st.pledges) {
        .nominate => unreachable,
        .prepare => |*p| p.ballot.counter,
        .confirm => |*c| c.ballot.counter,
        .externalize => std.math.maxInt(u32),
    };
}

/// Is `ballot` prepared by `st`? (oracle: hasPreparedBallot,
/// BallotProtocol.cpp:1696-1732; EXTERNALIZE prepares everything compatible
/// — counter ∞.)
fn hasPreparedBallot(ballot: BV, st: *const stored.OwnedStatement) bool {
    return switch (st.pledges) {
        .nominate => false,
        .prepare => |*p| (p.prepared != null and lessAndCompatible(ballot, bv(&p.prepared.?))) or
            (p.prepared_prime != null and lessAndCompatible(ballot, bv(&p.prepared_prime.?))),
        .confirm => |*c| lessAndCompatible(ballot, .{ .counter = c.n_prepared, .value = c.ballot.value }),
        .externalize => |*e| compatible(ballot, bv(&e.commit)),
    };
}

/// An interval [low, high] of commit counters (oracle Interval,
/// BallotProtocol.h:235). first == 0 means "unset".
const Interval = struct { first: u32 = 0, second: u32 = 0 };

/// Does `st` accept commit of `ballot` over the whole range `check`?
/// (oracle: commitPredicate, BallotProtocol.cpp:1102-1134; EXTERNALIZE
/// commits [commit.counter, ∞).)
fn commitPredicate(ballot: BV, check: Interval, st: *const stored.OwnedStatement) bool {
    return switch (st.pledges) {
        .nominate => false,
        .prepare => false,
        .confirm => |*c| compatible(ballot, bv(&c.ballot)) and
            c.n_commit <= check.first and check.second <= c.n_h,
        .externalize => |*e| compatible(ballot, bv(&e.commit)) and
            e.commit.counter <= check.first,
    };
}

// ---------------------------------------------------------------------------
// Quorum plumbing: node collection + the singleton-qset lookup wrapper
// ---------------------------------------------------------------------------

/// Build a singleton `{threshold 1, [node]}` qset for an EXTERNALIZE sender
/// if not already present (oracle: LocalNode::getSingletonQSet,
/// LocalNode.cpp:66). Boxed for pointer stability.
fn ensureSingleton(gpa: std.mem.Allocator, bs: *State, node: [32]u8) !void {
    if (bs.singletons.contains(node)) return;
    const validators = try gpa.alloc(qset.NodeId, 1);
    errdefer gpa.free(validators);
    validators[0] = node;
    const inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0);
    errdefer gpa.free(inner_sets);
    const boxed = try gpa.create(qset.QuorumSetOwned);
    errdefer gpa.destroy(boxed);
    boxed.* = .{ .threshold = 1, .validators = validators, .inner_sets = inner_sets };
    try bs.singletons.put(gpa, node, boxed);
}

/// QSetLookup used for ALL ballot quorum math, transcribing
/// Slot::getQuorumSetFromStatement (Slot.cpp:316-348):
/// - a node whose latest ballot statement is EXTERNALIZE resolves to the
///   synthetic singleton `{threshold 1, [node]}` (§5.4 SINGLETON QSET rule);
/// - the local node resolves to the configured local qset (its statements
///   advertise local_qset_hash);
/// - anyone else resolves through the engine's advertised-qset store.
/// Read-only: respects the QSetLookup borrow contract.
const BallotLookup = struct {
    ctx: *engine_mod.Ctx,
    s: *slot_mod.Slot,

    fn get(raw: *const anyopaque, node: qset.NodeId) ?*const qset.QuorumSetOwned {
        const self: *const BallotLookup = @ptrCast(@alignCast(raw));
        if (self.s.latest_ballot.get(node)) |env| {
            if (env.statement.pledges == .externalize) {
                return self.s.ballot.singletons.get(node);
            }
        }
        if (std.mem.eql(u8, &node, &self.ctx.cfg.node_id)) {
            return &self.ctx.cfg.quorum_set;
        }
        const inner = self.ctx.qsets.lookup();
        return inner.get(inner.ctx, node);
    }

    fn lookup(self: *const BallotLookup) local_node.QSetLookup {
        return .{ .ctx = self, .get = get };
    }
};

/// Nodes whose latest ballot statement satisfies `pred.matches` (the node
/// sets slot.federatedAccept / federatedRatify are phrased over).
fn collectNodes(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, pred: anytype) ![]qset.NodeId {
    var out: std.ArrayList(qset.NodeId) = .empty;
    errdefer out.deinit(ctx.gpa);
    var it = s.latest_ballot.iterator();
    while (it.next()) |entry| {
        if (pred.matches(&entry.value_ptr.*.statement)) {
            try out.append(ctx.gpa, entry.key_ptr.*);
        }
    }
    return out.toOwnedSlice(ctx.gpa);
}

/// Slot::federatedAccept over the ballot latest_envelopes
/// (BallotProtocol.cpp:2339-2345 → Slot.cpp:408-436).
fn fedAccept(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, voted_pred: anytype, accepted_pred: anytype) !bool {
    const voted = try collectNodes(ctx, s, voted_pred);
    defer ctx.gpa.free(voted);
    const accepted = try collectNodes(ctx, s, accepted_pred);
    defer ctx.gpa.free(accepted);
    const bl = BallotLookup{ .ctx = ctx, .s = s };
    return slot_mod.federatedAccept(ctx.gpa, &ctx.cfg.quorum_set, voted, accepted, bl.lookup());
}

/// Slot::federatedRatify over the ballot latest_envelopes
/// (BallotProtocol.cpp:2347-2352 → Slot.cpp:438-445).
fn fedRatify(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, voted_pred: anytype) !bool {
    const voted = try collectNodes(ctx, s, voted_pred);
    defer ctx.gpa.free(voted);
    const bl = BallotLookup{ .ctx = ctx, .s = s };
    return slot_mod.federatedRatify(ctx.gpa, &ctx.cfg.quorum_set, voted, bl.lookup());
}

// ---------------------------------------------------------------------------
// Validation levels (§5.4 collapse; oracle: getStatementValues /
// statementValidationLevel, BallotProtocol.cpp:2086-2150)
// ---------------------------------------------------------------------------

/// Per-slot cached driver verdict for a ballot value (§5.4 values.zig
/// bullet: each distinct value crosses the driver boundary at most once per
/// slot).
fn cachedValidate(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, value: []const u8) !driver_mod.Validity {
    if (s.validation_cache.get(value)) |v| return v;
    const v = ctx.driverValidate(s.index, value, false);
    try s.validation_cache.put(ctx.gpa, value, v);
    return v;
}

fn minValidity(a: driver_mod.Validity, b: driver_mod.Validity) driver_mod.Validity {
    return @enumFromInt(@min(@intFromEnum(a), @intFromEnum(b)));
}

/// Minimum validation level over all values referenced by `st` (oracle:
/// statementValidationLevel over getStatementValues,
/// BallotProtocol.cpp:2086-2150; the PREPARE b-value is skipped at counter 0
/// exactly as getStatementValues does).
fn statementValidationLevel(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, st: *const stored.OwnedStatement) !driver_mod.Validity {
    var lvl: driver_mod.Validity = .valid;
    switch (st.pledges) {
        .nominate => unreachable,
        .prepare => |*p| {
            if (p.ballot.counter != 0) lvl = minValidity(lvl, try cachedValidate(ctx, s, p.ballot.value));
            if (p.prepared) |*b| {
                if (lvl != .invalid) lvl = minValidity(lvl, try cachedValidate(ctx, s, b.value));
            }
            if (p.prepared_prime) |*b| {
                if (lvl != .invalid) lvl = minValidity(lvl, try cachedValidate(ctx, s, b.value));
            }
        },
        .confirm => |*c| lvl = try cachedValidate(ctx, s, c.ballot.value),
        .externalize => |*e| lvl = try cachedValidate(ctx, s, e.commit.value),
    }
    return lvl;
}

// ---------------------------------------------------------------------------
// Entry point: processEnvelope (oracle: BallotProtocol::processEnvelope,
// BallotProtocol.cpp:153-272 — sanity / freshness / recording already done
// by the pipeline before this is called)
// ---------------------------------------------------------------------------

/// Process a fresh (freshness-checked, stored) peer ballot statement.
pub fn processEnvelope(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, st: *const stored.OwnedStatement) Error!void {
    std.debug.assert(!st.isNomination());
    std.debug.assert(st.slot == s.index); // BallotProtocol.cpp:157
    const bs = &s.ballot;

    // SINGLETON QSET rule: an EXTERNALIZE sender's quorum math uses
    // {threshold 1, [sender]} — materialize it before any lookup (§5.4;
    // Slot.cpp:322-325).
    if (st.pledges == .externalize) try ensureSingleton(ctx.gpa, bs, st.node_id);

    // Validation-level collapse (§5.4): a driver-invalid value drops a
    // PREPARE (BallotProtocol.cpp:193-205) but demotes CONFIRM/EXTERNALIZE
    // to maybe_valid — the oracle's structurally-valid-only rejection of
    // peer CONFIRM/EXTERNALIZE (BallotProtocol.cpp:206-240) has no SLCP
    // counterpart.
    var lvl = try statementValidationLevel(ctx, s, st);
    if (lvl == .invalid) {
        if (st.pledges == .prepare) return error.InvalidValue;
        lvl = .maybe_valid;
    }

    if (bs.phase != .externalize) {
        // BallotProtocol.cpp:242-251.
        if (lvl == .maybe_valid) s.fully_validated = false;
        try advanceSlot(ctx, s, st);
        return;
    }

    // Phase EXTERNALIZE: record-only for statements on the committed value,
    // reject the rest (BallotProtocol.cpp:254-271).
    if (compatible(getWorkingBallot(st), bv(&bs.commit.?))) return;
    return error.InvalidValue;
}

// ---------------------------------------------------------------------------
// advanceSlot (oracle: BallotProtocol::advanceSlot,
// BallotProtocol.cpp:2025-2084)
// ---------------------------------------------------------------------------

fn advanceSlot(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, hint: *const stored.OwnedStatement) Error!void {
    const bs = &s.ballot;
    bs.message_level += 1; // :2029
    const result = advanceSlotBody(ctx, s, hint);
    bs.message_level -= 1; // :2078 (level unwinds on the error path too)
    const did_work = try result;
    if (did_work) try sendLatestEnvelope(ctx, s); // :2080-2083
}

fn advanceSlotBody(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, hint: *const stored.OwnedStatement) Error!bool {
    const bs = &s.ballot;
    // :2033-2037 — the oracle throws; SLCP treats it as an engine error (§5.4).
    if (bs.message_level >= max_advance_recursion) return error.EngineFailed;

    var did_work = false;
    did_work = (try attemptAcceptPrepared(ctx, s, hint)) or did_work; // :2048
    did_work = (try attemptConfirmPrepared(ctx, s, hint)) or did_work; // :2050
    did_work = (try attemptAcceptCommit(ctx, s, hint)) or did_work; // :2052
    did_work = (try attemptConfirmCommit(ctx, s, hint)) or did_work; // :2054

    // only bump after we're done with everything else (:2057-2073)
    if (bs.message_level == 1) {
        while (true) {
            // attemptBump may invoke advanceSlot recursively (:2061)
            if (try attemptBump(ctx, s)) {
                did_work = true;
            } else break;
        }
        try checkHeardFromQuorum(ctx, s);
    }

    return did_work;
}

// ---------------------------------------------------------------------------
// Own-statement building / recording / emission (oracle: createStatement
// :613-673, emitCurrentStateStatement :675-729, sendLatestEnvelope
// :2152-2165)
// ---------------------------------------------------------------------------

/// Build the statement for the current state (oracle: createStatement,
/// BallotProtocol.cpp:613-673). Field mapping, verbatim:
/// - PREPARE: ballot=b (zeroed placeholder when b unset, :628-631),
///   nC=c.counter (:632-635), prepared=p (:636-639), preparedPrime=p'
///   (:640-643), nH=h.counter (:644-647), quorumSetHash=local (:627).
/// - CONFIRM: ballot=b (:654), nPrepared=p.counter (:655),
///   nCommit=c.counter (:656), nH=h.counter (:657), quorumSetHash=local (:653).
/// - EXTERNALIZE: commit=c (:663), nH=h.counter (:664),
///   commitQuorumSetHash=local — the qset in use while confirming (:665).
fn buildOwnStatement(ctx: *engine_mod.Ctx, s: *slot_mod.Slot) !stored.OwnedStatement {
    const gpa = ctx.gpa;
    const bs = &s.ballot;
    checkInvariants(bs); // :619
    const pledges: stored.OwnedPledges = switch (bs.phase) {
        .prepare => blk: {
            // self is allowed b = 0 — the internal placeholder, never
            // emitted (:293, §5.4 counter-0 rule).
            var ballot: stored.OwnedBallot = if (bs.current) |*b|
                try b.clone(gpa)
            else
                .{ .counter = 0, .value = try gpa.dupe(u8, "") };
            errdefer ballot.deinit(gpa);
            var prepared = try cloneOptBallot(gpa, &bs.prepared);
            errdefer if (prepared) |*b| b.deinit(gpa);
            const prepared_prime = try cloneOptBallot(gpa, &bs.prepared_prime);
            break :blk .{ .prepare = .{
                .qset_hash = ctx.local_qset_hash,
                .ballot = ballot,
                .prepared = prepared,
                .prepared_prime = prepared_prime,
                .n_c = if (bs.commit) |*c| c.counter else 0,
                .n_h = if (bs.high) |*h| h.counter else 0,
            } };
        },
        .confirm => .{ .confirm = .{
            .qset_hash = ctx.local_qset_hash,
            .ballot = try bs.current.?.clone(gpa),
            .n_prepared = bs.prepared.?.counter,
            .n_commit = bs.commit.?.counter,
            .n_h = bs.high.?.counter,
        } },
        .externalize => .{ .externalize = .{
            .commit = try bs.commit.?.clone(gpa),
            .n_h = bs.high.?.counter,
            .commit_qset_hash = ctx.local_qset_hash,
        } },
    };
    return .{ .node_id = ctx.cfg.node_id, .slot = s.index, .pledges = pledges };
}

/// Record an own statement into s.latest_ballot as a zero-frame placeholder
/// (self visibility for federated voting — the oracle's recordEnvelope of
/// the self envelope, BallotProtocol.cpp:137-151 via :709-710). The wire
/// frame for the newest statement lands in s.own_ballot at depth 0.
fn recordSelf(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, st: *const stored.OwnedStatement) !void {
    const gpa = ctx.gpa;
    if (st.pledges == .externalize) try ensureSingleton(gpa, &s.ballot, st.node_id);
    var clone = try cloneStatement(gpa, st);
    errdefer clone.deinit(gpa);
    const frame = try gpa.alloc(u8, 0);
    errdefer gpa.free(frame);
    _ = try s.storeLatest(gpa, .{ .envelope_framed = frame, .statement = clone });
}

/// Oracle: emitCurrentStateStatement (BallotProtocol.cpp:675-729). Builds
/// the current-state statement, records it (self visibility), re-enters
/// advanceSlot with it as the hint (the self recursion), and defers the
/// wire emission to sendLatestEnvelope at depth 0.
fn emitCurrentStateStatement(ctx: *engine_mod.Ctx, s: *slot_mod.Slot) Error!void {
    const gpa = ctx.gpa;
    const bs = &s.ballot;

    var st = try buildOwnStatement(ctx, s);
    // if we generate the same envelope, don't process it again (:700-708)
    if (bs.last_built) |*lb| {
        if (eqBallotStatements(lb, &st)) {
            st.deinit(gpa);
            return;
        }
    }
    defer st.deinit(gpa);

    const can_emit = bs.current != null; // :699

    // record + mark for emission (:709-716). The statement is monotonically
    // newer than the previous own statement by protocol construction (the
    // oracle throws on the alternative, :722-727).
    try recordSelf(ctx, s, &st);
    if (bs.last_built) |*lb| {
        lb.deinit(gpa);
        bs.last_built = null;
    }
    bs.last_built = try cloneStatement(gpa, &st);
    if (can_emit) bs.emit_dirty = true;

    // Self recursion (Slot::processEnvelope(self=true) → advanceSlot). In
    // phase EXTERNALIZE the oracle records without advancing (:254-261).
    if (bs.phase != .externalize) try advanceSlot(ctx, s, &st);

    // this will no-op if invoked from advanceSlot (:717-719)
    try sendLatestEnvelope(ctx, s);
}

/// Oracle: sendLatestEnvelope (BallotProtocol.cpp:2152-2165) — emit the
/// newest own statement once at depth 0, gated on fully_validated; SLCP adds
/// the watcher gate (§5.4: watchers track fully, emit nothing) and the
/// sane-to-send gate (counter >= 1 — implied by emit_dirty, which is only
/// set when b exists; b.counter is never 0).
fn sendLatestEnvelope(ctx: *engine_mod.Ctx, s: *slot_mod.Slot) Error!void {
    const gpa = ctx.gpa;
    const bs = &s.ballot;
    if (bs.message_level != 0) return;
    if (!bs.emit_dirty) return;
    if (!s.fully_validated) return;
    if (ctx.isWatcher()) return;
    const lb = if (bs.last_built) |*l| l else return;

    const own: emit_mod.OwnStatement = switch (lb.pledges) {
        .nominate => unreachable,
        .prepare => |*p| blk: {
            std.debug.assert(p.ballot.counter >= 1); // counter-0 never emitted (§5.4)
            break :blk .{ .prepare = .{
                .qset_hash = p.qset_hash,
                .ballot = bv(&p.ballot),
                .prepared = optBv(&p.prepared),
                .prepared_prime = optBv(&p.prepared_prime),
                .n_c = p.n_c,
                .n_h = p.n_h,
            } };
        },
        .confirm => |*c| .{ .confirm = .{
            .qset_hash = c.qset_hash,
            .ballot = bv(&c.ballot),
            .n_prepared = c.n_prepared,
            .n_commit = c.n_commit,
            .n_h = c.n_h,
        } },
        .externalize => |*e| .{ .externalize = .{
            .commit = bv(&e.commit),
            .n_h = e.n_h,
            .commit_qset_hash = e.commit_qset_hash,
        } },
    };

    const env = emit_mod.emit(ctx, s.index, own) catch |err| switch (err) {
        error.WatcherCannotEmit => unreachable, // gated above
        error.OutOfMemory => return error.OutOfMemory,
        error.EffectBudgetExceeded => return error.EffectBudgetExceeded,
        error.EngineFailed => return error.EngineFailed,
        else => return error.EngineFailed, // capnp build errors: engine bug
    };
    if (s.own_ballot) |*old| old.deinit(gpa);
    s.own_ballot = env;
    bs.emit_dirty = false;
}

// ---------------------------------------------------------------------------
// State invariants (oracle: checkInvariants, BallotProtocol.cpp:731-772)
// ---------------------------------------------------------------------------

fn checkInvariants(bs: *const State) void {
    switch (bs.phase) {
        .prepare => {},
        .confirm, .externalize => {
            std.debug.assert(bs.current != null);
            std.debug.assert(bs.prepared != null);
            std.debug.assert(bs.commit != null);
            std.debug.assert(bs.high != null);
        },
    }
    if (bs.current) |*b| std.debug.assert(b.counter != 0);
    if (bs.prepared != null and bs.prepared_prime != null) {
        std.debug.assert(lessAndIncompatible(bv(&bs.prepared_prime.?), bv(&bs.prepared.?)));
    }
    if (bs.high) |*h| {
        std.debug.assert(bs.current != null);
        std.debug.assert(lessAndCompatible(bv(h), bv(&bs.current.?)));
    }
    if (bs.commit) |*c| {
        std.debug.assert(bs.current != null);
        std.debug.assert(lessAndCompatible(bv(c), bv(&bs.high.?)));
        std.debug.assert(lessAndCompatible(bv(&bs.high.?), bv(&bs.current.?)));
    }
}

// ---------------------------------------------------------------------------
// Ballot bumping (oracle: bumpState :429-480, updateCurrentValue :483-535,
// bumpToBallot :537-583, updateCurrentIfNeeded :879-889, abandonBallot
// :347-374, ballotProtocolTimerExpired :606-611)
// ---------------------------------------------------------------------------

/// Nomination hands over a (new) composite candidate value; force bumps
/// even without a current ballot (oracle: bumpState(Value, bool),
/// BallotProtocol.cpp:429-441).
pub fn bumpState(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, value: []const u8, force: bool) Error!bool {
    const bs = &s.ballot;
    if (!force and bs.current != null) return false;
    const n: u32 = if (bs.current) |*b| b.counter + 1 else 1;
    return bumpStateN(ctx, s, value, n);
}

/// Oracle: bumpState(Value, uint32) (BallotProtocol.cpp:443-480). Value
/// choice: mValueOverride wins over the passed value (:456-465) — combined
/// with abandonBallot's composite-then-current fallback this is the §5.4
/// priority override > latest composite > current ballot value.
fn bumpStateN(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, value: []const u8, n: u32) Error!bool {
    const bs = &s.ballot;
    if (bs.phase != .prepare and bs.phase != .confirm) return false; // :447-450

    const newb: BV = .{
        .counter = n,
        .value = if (bs.value_override) |ov| ov else value, // :456-465
    };

    // maybeReplaceValueWithEmptyTxSet (:470) is CAP-0083 plumbing — no SLCP
    // counterpart (§5.4 validation-level collapse).
    const updated = try updateCurrentValue(ctx, s, newb); // :471

    if (updated) {
        try emitCurrentStateStatement(ctx, s); // :475
        try checkHeardFromQuorum(ctx, s); // :476
    }
    return updated;
}

/// Oracle: updateCurrentValue (BallotProtocol.cpp:483-535) — updates the
/// local state to the specified ballot, enforcing invariants.
fn updateCurrentValue(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, ballot: BV) Error!bool {
    const bs = &s.ballot;
    if (bs.phase != .prepare and bs.phase != .confirm) return false; // :488-491

    var updated = false;
    if (bs.current == null) {
        try bumpToBallot(ctx, s, ballot, true); // :494-497
        updated = true;
    } else {
        // once we committed, only compatible bumps are allowed (:503-506)
        if (bs.commit != null and !compatible(bv(&bs.commit.?), ballot)) {
            return false;
        }
        switch (cmp(bv(&bs.current.?), ballot)) {
            .lt => {
                try bumpToBallot(ctx, s, ballot, true); // :509-513
                updated = true;
            },
            // attempt to bump to a smaller value: refuse — we may already
            // have statements at counter+1 (:514-528)
            .gt => return false,
            .eq => {},
        }
    }

    checkInvariants(bs); // :532
    return updated;
}

/// Oracle: bumpToBallot (BallotProtocol.cpp:537-583) — the lowest-level
/// current-ballot update. `check` verifies monotonicity; check=false is the
/// single permitted value switch at accept-commit (§5.4).
fn bumpToBallot(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, ballot: BV, check: bool) Error!void {
    const gpa = ctx.gpa;
    const bs = &s.ballot;
    // `bumpToBallot` should never be called once we committed (:548)
    std.debug.assert(bs.phase != .externalize);
    if (check) {
        // We should move mCurrentBallot monotonically only (:551-555)
        std.debug.assert(bs.current == null or cmp(ballot, bv(&bs.current.?)) != .lt);
    }

    const got_bumped = bs.current == null or bs.current.?.counter != ballot.counter; // :557-558

    if (bs.current == null) {
        // driver.startedBallotProtocol (:560-563)
        try ctx.phaseEvent(s.index, .started_ballot, ballot.counter);
    }

    try setOwnedBallot(gpa, &bs.current, ballot); // :566

    // h/c clear when b bumps to an h-incompatible ballot (§5.4; :569-577):
    // invariant h.value = b.value, and c is set only when h is set.
    if (bs.high != null and !compatible(bv(&bs.current.?), bv(&bs.high.?))) {
        clearOwnedBallot(gpa, &bs.high);
        clearOwnedBallot(gpa, &bs.commit);
    }

    if (got_bumped) bs.heard_from_quorum = false; // :579-582
}

/// Step (8) from the paper (oracle: updateCurrentIfNeeded,
/// BallotProtocol.cpp:879-889).
fn updateCurrentIfNeeded(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, h: BV) Error!bool {
    const bs = &s.ballot;
    if (bs.current == null or cmp(bv(&bs.current.?), h) == .lt) {
        try bumpToBallot(ctx, s, h, true);
        return true;
    }
    return false;
}

/// Abandon the current ballot: move to counter `n`, or increment when
/// n == 0 (oracle: abandonBallot, BallotProtocol.cpp:347-374). Value pick:
/// latest composite, falling back to the current ballot's value (the
/// override, when set, then wins inside bumpState — §5.4 priority).
fn abandonBallot(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, n: u32) Error!bool {
    const bs = &s.ballot;
    var v: ?[]const u8 = s.nom.latest_composite;
    if (v == null or v.?.len == 0) {
        if (bs.current) |*cur| v = cur.value; // :356-361
    }
    if (v != null and v.?.len > 0) {
        if (n == 0) return bumpState(ctx, s, v.?, true); // :364-367
        return bumpStateN(ctx, s, v.?, n); // :368-371
    }
    return false;
}

/// Ballot timer fired: abandon the current ballot — bump the counter
/// (oracle: ballotProtocolTimerExpired, BallotProtocol.cpp:606-611; the
/// oracle's mTimerExpCount feeds reporting only and is not transcribed).
pub fn timerFired(ctx: *engine_mod.Ctx, s: *slot_mod.Slot) Error!void {
    _ = try abandonBallot(ctx, s, 0);
}

// ---------------------------------------------------------------------------
// getPrepareCandidates (oracle: BallotProtocol.cpp:774-877)
// ---------------------------------------------------------------------------

/// Sorted-unique ascending ballot list (std::set<SCPBallot> analog); values
/// are BORROWED from the hint / stored statements — consume before any
/// self-record replaces the self entry.
const BvList = struct {
    items: std.ArrayList(BV) = .empty,

    fn deinit(self: *BvList, gpa: std.mem.Allocator) void {
        self.items.deinit(gpa);
    }

    fn insert(self: *BvList, gpa: std.mem.Allocator, b: BV) !void {
        var lo: usize = 0;
        var hi: usize = self.items.items.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (cmp(self.items.items[mid], b) == .lt) lo = mid + 1 else hi = mid;
        }
        if (lo < self.items.items.len and cmp(self.items.items[lo], b) == .eq) return;
        try self.items.insert(gpa, lo, b);
    }
};

/// Candidate ballots that may have been prepared, seeded from the hint
/// (oracle: getPrepareCandidates, BallotProtocol.cpp:774-877). EXTERNALIZE-∞:
/// CONFIRM contributes (nPrepared, v) and (∞, v); EXTERNALIZE contributes
/// (∞, v) (:796-808).
fn getPrepareCandidates(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, hint: *const stored.OwnedStatement) !BvList {
    const gpa = ctx.gpa;
    const inf = std.math.maxInt(u32);

    var hint_ballots: BvList = .{};
    defer hint_ballots.deinit(gpa);
    switch (hint.pledges) {
        .nominate => unreachable,
        .prepare => |*p| { // :782-795
            try hint_ballots.insert(gpa, bv(&p.ballot));
            if (p.prepared) |*b| try hint_ballots.insert(gpa, bv(b));
            if (p.prepared_prime) |*b| try hint_ballots.insert(gpa, bv(b));
        },
        .confirm => |*c| { // :796-802
            try hint_ballots.insert(gpa, .{ .counter = c.n_prepared, .value = c.ballot.value });
            try hint_ballots.insert(gpa, .{ .counter = inf, .value = c.ballot.value });
        },
        .externalize => |*e| { // :803-808
            try hint_ballots.insert(gpa, .{ .counter = inf, .value = e.commit.value });
        },
    }

    var candidates: BvList = .{};
    errdefer candidates.deinit(gpa);

    // iterate hint ballots from the top (:815-819)
    var hi = hint_ballots.items.items.len;
    while (hi > 0) {
        hi -= 1;
        const top_vote = hint_ballots.items.items[hi];
        const val = top_vote.value;

        // find candidates that may have been prepared (:823-873)
        var it = s.latest_ballot.iterator();
        while (it.next()) |entry| {
            const st = &entry.value_ptr.*.statement;
            switch (st.pledges) {
                .nominate => {},
                .prepare => |*p| { // :829-847
                    if (lessAndCompatible(bv(&p.ballot), top_vote)) {
                        try candidates.insert(gpa, bv(&p.ballot));
                    }
                    if (p.prepared) |*b| {
                        if (lessAndCompatible(bv(b), top_vote)) try candidates.insert(gpa, bv(b));
                    }
                    if (p.prepared_prime) |*b| {
                        if (lessAndCompatible(bv(b), top_vote)) try candidates.insert(gpa, bv(b));
                    }
                },
                .confirm => |*c| { // :848-860
                    if (compatible(top_vote, bv(&c.ballot))) {
                        try candidates.insert(gpa, top_vote);
                        if (c.n_prepared < top_vote.counter) {
                            try candidates.insert(gpa, .{ .counter = c.n_prepared, .value = val });
                        }
                    }
                },
                .externalize => |*e| { // :861-868
                    if (compatible(top_vote, bv(&e.commit))) {
                        try candidates.insert(gpa, top_vote);
                    }
                },
            }
        }
    }

    return candidates;
}

// ---------------------------------------------------------------------------
// Steps 1 and 5: accept prepared (oracle: attemptAcceptPrepared :891-977,
// setAcceptPrepared :979-1013, setPrepared :1779-1822)
// ---------------------------------------------------------------------------

/// The voted predicate of attemptAcceptPrepared's federatedAccept
/// (BallotProtocol.cpp:938-968): who is voting to prepare `ballot`?
/// CONFIRM/EXTERNALIZE vote for every compatible ballot (counter ∞).
const PrepareVoted = struct {
    ballot: BV,
    fn matches(self: @This(), st: *const stored.OwnedStatement) bool {
        return switch (st.pledges) {
            .nominate => false,
            .prepare => |*p| lessAndCompatible(self.ballot, bv(&p.ballot)), // :944-949
            .confirm => |*c| compatible(self.ballot, bv(&c.ballot)), // :950-955
            .externalize => |*e| compatible(self.ballot, bv(&e.commit)), // :956-961
        };
    }
};

const PrepareAccepted = struct {
    ballot: BV,
    fn matches(self: @This(), st: *const stored.OwnedStatement) bool {
        return hasPreparedBallot(self.ballot, st); // :969
    }
};

fn attemptAcceptPrepared(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, hint: *const stored.OwnedStatement) Error!bool {
    const gpa = ctx.gpa;
    const bs = &s.ballot;
    if (bs.phase != .prepare and bs.phase != .confirm) return false; // :895-898

    var candidates = try getPrepareCandidates(ctx, s, hint); // :900
    defer candidates.deinit(gpa);

    // see if we can accept any of the candidates, starting with the highest
    // (:903)
    var i = candidates.items.items.len;
    while (i > 0) {
        i -= 1;
        const ballot = candidates.items.items[i];

        if (bs.phase == .confirm) {
            // only consider the ballot if it may help us increase p
            // (note: at this point, p ~ c) (:907-916)
            if (!lessAndCompatible(bv(&bs.prepared.?), ballot)) continue;
            std.debug.assert(compatible(bv(&bs.commit.?), ballot));
        }

        // if ballot <= p', it is neither a candidate for p nor p' (:920-925)
        if (bs.prepared_prime != null and cmp(ballot, bv(&bs.prepared_prime.?)) != .gt) continue;

        // if ballot is already covered by p, skip (:927-935)
        if (bs.prepared != null and lessAndCompatible(ballot, bv(&bs.prepared.?))) continue;

        const accepted = try fedAccept(
            ctx,
            s,
            PrepareVoted{ .ballot = ballot },
            PrepareAccepted{ .ballot = ballot },
        ); // :937-969
        if (accepted) {
            return setAcceptPrepared(ctx, s, ballot); // :970-973
        }
    }

    return false;
}

/// Oracle: setAcceptPrepared (BallotProtocol.cpp:979-1013).
fn setAcceptPrepared(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, ballot: BV) Error!bool {
    const gpa = ctx.gpa;
    const bs = &s.ballot;
    var did_work = try setPrepared(ctx, s, ballot); // :987

    // c-reset (§5.4): accepting prepared of an incompatible higher ballot
    // (h ⋦ p or h ⋦ p') clears c (:989-1003).
    if (bs.commit != null and bs.high != null) {
        if ((bs.prepared != null and lessAndIncompatible(bv(&bs.high.?), bv(&bs.prepared.?))) or
            (bs.prepared_prime != null and lessAndIncompatible(bv(&bs.high.?), bv(&bs.prepared_prime.?))))
        {
            std.debug.assert(bs.phase == .prepare); // :999
            clearOwnedBallot(gpa, &bs.commit);
            did_work = true;
        }
    }

    if (did_work) {
        // driver.acceptedBallotPrepared (:1007-1008)
        try ctx.phaseEvent(s.index, .accepted_prepared, ballot.counter);
        try emitCurrentStateStatement(ctx, s); // :1009
    }
    return did_work;
}

/// Oracle: setPrepared (BallotProtocol.cpp:1779-1822) — p and p' are the two
/// highest prepared-and-incompatible ballots.
fn setPrepared(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, ballot: BV) Error!bool {
    const gpa = ctx.gpa;
    const bs = &s.ballot;
    var did_work = false;

    if (bs.prepared) |*p| {
        switch (cmp(bv(p), ballot)) {
            .lt => {
                // replacing p: demote it to p' when incompatible (:1788-1796)
                if (!compatible(bv(p), ballot)) {
                    // move p into p' (no copy needed: transfer ownership)
                    clearOwnedBallot(gpa, &bs.prepared_prime);
                    bs.prepared_prime = bs.prepared;
                    bs.prepared = null;
                }
                try setOwnedBallot(gpa, &bs.prepared, ballot);
                did_work = true;
            },
            .gt => {
                // update only p': p' was null, or p' < ballot and ballot is
                // incompatible with p (:1798-1813)
                if (bs.prepared_prime == null or
                    (cmp(bv(&bs.prepared_prime.?), ballot) == .lt and
                        !compatible(bv(&bs.prepared.?), ballot)))
                {
                    try setOwnedBallot(gpa, &bs.prepared_prime, ballot);
                    did_work = true;
                }
            },
            .eq => {},
        }
    } else {
        try setOwnedBallot(gpa, &bs.prepared, ballot); // :1816-1819
        did_work = true;
    }
    return did_work;
}

// ---------------------------------------------------------------------------
// Steps 2+3+8: confirm prepared (oracle: attemptConfirmPrepared :1015-1100,
// setConfirmPrepared :1136-1221)
// ---------------------------------------------------------------------------

fn attemptConfirmPrepared(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, hint: *const stored.OwnedStatement) Error!bool {
    const gpa = ctx.gpa;
    const bs = &s.ballot;
    if (bs.phase != .prepare) return false; // :1019-1022
    if (bs.prepared == null) return false; // :1025-1028

    var candidates = try getPrepareCandidates(ctx, s, hint); // :1030
    defer candidates.deinit(gpa);
    const items = candidates.items.items;

    // find newH, starting with the highest candidate (:1033-1055)
    var new_h: BV = undefined;
    var new_h_found = false;
    var i = items.len;
    while (i > 0) {
        i -= 1;
        const ballot = items[i];
        // only consider it if we can potentially raise h (:1041-1045)
        if (bs.high != null and cmp(bv(&bs.high.?), ballot) != .lt) break;
        if (try fedRatify(ctx, s, PrepareAccepted{ .ballot = ballot })) {
            new_h = ballot;
            new_h_found = true;
            break;
        }
    }

    if (!new_h_found) return false;

    // now, look for newC — step (3) from the paper (:1061-1096). i still
    // indexes newH ("continue where we left off — cur is at newH").
    var new_c: ?BV = null;
    const b: BV = if (bs.current) |*cur| bv(cur) else .{ .counter = 0, .value = "" }; // :1064-1065
    if (bs.commit == null and
        (bs.prepared == null or !lessAndIncompatible(new_h, bv(&bs.prepared.?))) and
        (bs.prepared_prime == null or !lessAndIncompatible(new_h, bv(&bs.prepared_prime.?))))
    { // :1066-1070
        var j = i + 1;
        while (j > 0) {
            j -= 1;
            const ballot = items[j];
            if (cmp(ballot, b) == .lt) break; // :1076-1079
            // c and h must be compatible (:1080-1084)
            if (!lessAndCompatible(ballot, new_h)) continue;
            if (try fedRatify(ctx, s, PrepareAccepted{ .ballot = ballot })) {
                new_c = ballot; // :1085-1090
            } else break; // :1091-1094
        }
    }

    return setConfirmPrepared(ctx, s, new_c, new_h); // :1097
}

/// Oracle: setConfirmPrepared (BallotProtocol.cpp:1136-1221). newC == null
/// is the oracle's counter-0 "no update" sentinel.
fn setConfirmPrepared(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, new_c: ?BV, new_h: BV) Error!bool {
    const gpa = ctx.gpa;
    const bs = &s.ballot;
    var did_work = false;

    // remember newH's value — mValueOverride (:1145-1146)
    {
        const copy = try gpa.dupe(u8, new_h.value);
        if (bs.value_override) |old| gpa.free(old);
        bs.value_override = copy;
    }

    // we don't set c/h if we're not on a compatible ballot (:1148-1150)
    if (bs.current == null or compatible(bv(&bs.current.?), new_h)) {
        if (bs.high == null or cmp(new_h, bv(&bs.high.?)) == .gt) { // :1152-1156
            try setOwnedBallot(gpa, &bs.high, new_h);
            did_work = true;
        }

        if (new_c) |c| {
            std.debug.assert(bs.commit == null); // :1160
            // The oracle re-validates newC.value and refuses to vote-commit
            // a value it cannot validate (:1162-1202; the refused branch is
            // its CAP-0083 structurally-valid case). SLCP collapse: refuse
            // only on driver-invalid; maybe_valid values are committed
            // (:1191-1201 sets mCommit for kMaybeValidNotCurrentValue).
            const lvl = try cachedValidate(ctx, s, c.value);
            if (lvl != .invalid) {
                try setOwnedBallot(gpa, &bs.commit, c);
                did_work = true;
            }
        }

        if (did_work) {
            // driver.confirmedBallotPrepared (:1205-1209)
            try ctx.phaseEvent(s.index, .confirmed_prepared, new_h.counter);
        }
    }

    // always perform step (8) with the computed value of h (:1212-1213)
    did_work = (try updateCurrentIfNeeded(ctx, s, new_h)) or did_work;

    if (did_work) try emitCurrentStateStatement(ctx, s); // :1215-1218
    return did_work;
}

// ---------------------------------------------------------------------------
// Commit interval machinery (oracle: findExtendedInterval :1223-1259,
// getCommitBoundariesFromStatements :1261-1309)
// ---------------------------------------------------------------------------

fn insertBoundary(gpa: std.mem.Allocator, list: *std.ArrayList(u32), v: u32) !void {
    var lo: usize = 0;
    var hi: usize = list.items.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (list.items[mid] < v) lo = mid + 1 else hi = mid;
    }
    if (lo < list.items.len and list.items[lo] == v) return;
    try list.insert(gpa, lo, v);
}

/// The set of counters bounding commit ballots compatible with `ballot`
/// (oracle: getCommitBoundariesFromStatements, BallotProtocol.cpp:1261-1309;
/// EXTERNALIZE contributes ∞). Sorted ascending, unique.
fn getCommitBoundaries(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, ballot: BV, out: *std.ArrayList(u32)) !void {
    const gpa = ctx.gpa;
    var it = s.latest_ballot.iterator();
    while (it.next()) |entry| {
        const st = &entry.value_ptr.*.statement;
        switch (st.pledges) {
            .nominate => {},
            .prepare => |*p| { // :1270-1282
                if (compatible(ballot, bv(&p.ballot)) and p.n_c != 0) {
                    try insertBoundary(gpa, out, p.n_c);
                    try insertBoundary(gpa, out, p.n_h);
                }
            },
            .confirm => |*c| { // :1283-1292
                if (compatible(ballot, bv(&c.ballot))) {
                    try insertBoundary(gpa, out, c.n_commit);
                    try insertBoundary(gpa, out, c.n_h);
                }
            },
            .externalize => |*e| { // :1293-1302
                if (compatible(ballot, bv(&e.commit))) {
                    try insertBoundary(gpa, out, e.commit.counter);
                    try insertBoundary(gpa, out, e.n_h);
                    try insertBoundary(gpa, out, std.math.maxInt(u32));
                }
            },
        }
    }
}

/// Grow `candidate` downward through `boundaries` while `pred` holds
/// (oracle: findExtendedInterval, BallotProtocol.cpp:1223-1259; boundaries
/// iterated from the top).
fn findExtendedInterval(candidate: *Interval, boundaries: []const u32, pred: anytype) Error!void {
    var i = boundaries.len;
    while (i > 0) {
        i -= 1;
        const b = boundaries[i];

        var cur: Interval = undefined;
        if (candidate.first == 0) {
            // first, find the high bound (:1234-1238)
            cur = .{ .first = b, .second = b };
        } else if (b > candidate.second) {
            continue; // invalid (:1239-1242)
        } else {
            cur = .{ .first = b, .second = candidate.second }; // :1243-1247
        }

        if (try pred.call(cur)) {
            candidate.* = cur; // :1249-1252
        } else if (candidate.first != 0) {
            break; // could not extend further (:1253-1257)
        }
    }
}

// ---------------------------------------------------------------------------
// Steps (4 and 6)+8: accept commit (oracle: attemptAcceptCommit :1311-1435,
// setAcceptCommit :1468-1513)
// ---------------------------------------------------------------------------

/// The voted predicate of attemptAcceptCommit's federatedAccept
/// (BallotProtocol.cpp:1363-1405): who votes to commit `ballot` over `cur`?
const CommitVoted = struct {
    ballot: BV,
    cur: Interval,
    fn matches(self: @This(), st: *const stored.OwnedStatement) bool {
        return switch (st.pledges) {
            .nominate => false,
            .prepare => |*p| compatible(self.ballot, bv(&p.ballot)) and p.n_c != 0 and
                p.n_c <= self.cur.first and self.cur.second <= p.n_h, // :1370-1381
            .confirm => |*c| compatible(self.ballot, bv(&c.ballot)) and
                c.n_commit <= self.cur.first, // :1382-1390
            .externalize => |*e| compatible(self.ballot, bv(&e.commit)) and
                e.commit.counter <= self.cur.first, // :1391-1399
        };
    }
};

const CommitAccepted = struct {
    ballot: BV,
    cur: Interval,
    fn matches(self: @This(), st: *const stored.OwnedStatement) bool {
        return commitPredicate(self.ballot, self.cur, st); // :1405
    }
};

fn attemptAcceptCommit(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, hint: *const stored.OwnedStatement) Error!bool {
    const gpa = ctx.gpa;
    const bs = &s.ballot;
    if (bs.phase != .prepare and bs.phase != .confirm) return false; // :1315-1318

    // extract the value to commit from the hint; the counter is only used
    // for logging in the oracle (:1320-1353)
    const ballot: BV = switch (hint.pledges) {
        .nominate => unreachable,
        .prepare => |*p| blk: {
            if (p.n_c == 0) return false; // :1329-1336
            break :blk .{ .counter = p.n_h, .value = p.ballot.value };
        },
        .confirm => |*c| .{ .counter = c.n_h, .value = c.ballot.value }, // :1339-1343
        .externalize => |*e| .{ .counter = e.n_h, .value = e.commit.value }, // :1345-1350
    };

    if (bs.phase == .confirm) {
        if (!compatible(ballot, bv(&bs.high.?))) return false; // :1355-1361
    }

    var boundaries: std.ArrayList(u32) = .empty; // :1409
    defer boundaries.deinit(gpa);
    try getCommitBoundaries(ctx, s, ballot, &boundaries);
    if (boundaries.items.len == 0) return false; // :1411-1414

    // now, look for the high interval (:1416-1419)
    var candidate: Interval = .{};
    const Pred = struct {
        ctx: *engine_mod.Ctx,
        s: *slot_mod.Slot,
        ballot: BV,
        fn call(self: @This(), cur: Interval) Error!bool {
            return fedAccept(
                self.ctx,
                self.s,
                CommitVoted{ .ballot = self.ballot, .cur = cur },
                CommitAccepted{ .ballot = self.ballot, .cur = cur },
            );
        }
    };
    try findExtendedInterval(&candidate, boundaries.items, Pred{ .ctx = ctx, .s = s, .ballot = ballot });

    if (candidate.first != 0) {
        if (bs.phase != .confirm or candidate.second > bs.high.?.counter) { // :1425-1427
            return setAcceptCommit(
                ctx,
                s,
                .{ .counter = candidate.first, .value = ballot.value },
                .{ .counter = candidate.second, .value = ballot.value },
            ); // :1428-1430
        }
    }
    return false;
}

/// Oracle: setAcceptCommit (BallotProtocol.cpp:1468-1513). Contains the
/// single permitted value switch onto an incompatible ballot (§5.4):
/// bumpToBallot(h, check=false), phase → CONFIRM, p' cleared.
fn setAcceptCommit(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, c: BV, h: BV) Error!bool {
    const gpa = ctx.gpa;
    const bs = &s.ballot;
    var did_work = false;

    // remember h's value — mValueOverride (:1478-1479)
    {
        const copy = try gpa.dupe(u8, h.value);
        if (bs.value_override) |old| gpa.free(old);
        bs.value_override = copy;
    }

    if (bs.high == null or bs.commit == null or
        cmp(bv(&bs.high.?), h) != .eq or cmp(bv(&bs.commit.?), c) != .eq)
    { // :1481-1489
        try setOwnedBallot(gpa, &bs.commit, c);
        try setOwnedBallot(gpa, &bs.high, h);
        did_work = true;
    }

    if (bs.phase == .prepare) { // :1491-1502
        bs.phase = .confirm;
        if (bs.current != null and !lessAndCompatible(h, bv(&bs.current.?))) {
            // the single permitted value switch (§5.4): check=false
            try bumpToBallot(ctx, s, h, false); // :1494-1498
        }
        clearOwnedBallot(gpa, &bs.prepared_prime); // :1499
        did_work = true;
    }

    if (did_work) { // :1504-1510
        _ = try updateCurrentIfNeeded(ctx, s, bv(&bs.high.?));
        // driver.acceptedCommit (:1508)
        try ctx.phaseEvent(s.index, .accepted_commit, h.counter);
        try emitCurrentStateStatement(ctx, s);
    }
    return did_work;
}

// ---------------------------------------------------------------------------
// Step 7+8: confirm commit → externalize (oracle: attemptConfirmCommit
// :1604-1667, setConfirmCommit :1669-1694,
// throwIfValueInvalidForConfirmCommit :1437-1466)
// ---------------------------------------------------------------------------

fn attemptConfirmCommit(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, hint: *const stored.OwnedStatement) Error!bool {
    const gpa = ctx.gpa;
    const bs = &s.ballot;
    if (bs.phase != .confirm) return false; // :1608-1611
    if (bs.high == null or bs.commit == null) return false; // :1613-1616

    const ballot: BV = switch (hint.pledges) { // :1620-1642
        .nominate => unreachable,
        .prepare => return false, // :1623-1626
        .confirm => |*c| .{ .counter = c.n_h, .value = c.ballot.value },
        .externalize => |*e| .{ .counter = e.n_h, .value = e.commit.value },
    };

    if (!compatible(ballot, bv(&bs.commit.?))) return false; // :1644-1647

    var boundaries: std.ArrayList(u32) = .empty; // :1649
    defer boundaries.deinit(gpa);
    try getCommitBoundaries(ctx, s, ballot, &boundaries);
    var candidate: Interval = .{};

    const Pred = struct {
        ctx: *engine_mod.Ctx,
        s: *slot_mod.Slot,
        ballot: BV,
        fn call(self: @This(), cur: Interval) Error!bool {
            return fedRatify(self.ctx, self.s, CommitAccepted{ .ballot = self.ballot, .cur = cur }); // :1652-1655
        }
    };
    try findExtendedInterval(&candidate, boundaries.items, Pred{ .ctx = ctx, .s = s, .ballot = ballot });

    if (candidate.first != 0) {
        return setConfirmCommit(
            ctx,
            s,
            .{ .counter = candidate.first, .value = ballot.value },
            .{ .counter = candidate.second, .value = ballot.value },
        ); // :1659-1665
    }
    return false;
}

/// Oracle: setConfirmCommit (BallotProtocol.cpp:1669-1694). SLCP §5.4:
/// the .externalized effect fires exactly once per slot (guarded by
/// s.externalized_value); both timers are canceled; nomination stops
/// permanently. There is no dedicated PhaseKind for confirm-commit — the
/// .externalized effect IS the normative signal (§5.3).
fn setConfirmCommit(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, c: BV, h: BV) Error!bool {
    const gpa = ctx.gpa;
    const bs = &s.ballot;

    // throwIfValueInvalidForConfirmCommit (:1437-1466,1678): the oracle
    // aborts when a federated-ratified value is locally invalid; with the
    // §5.4 collapse a driver-invalid value here means the network committed
    // something we cannot judge — maybe_valid semantics: proceed with own
    // emissions suppressed (never treated as invalid, or laggers could not
    // catch up).
    if ((try cachedValidate(ctx, s, c.value)) != .valid) s.fully_validated = false;

    try setOwnedBallot(gpa, &bs.commit, c); // :1680
    try setOwnedBallot(gpa, &bs.high, h); // :1681
    _ = try updateCurrentIfNeeded(ctx, s, bv(&bs.high.?)); // :1682

    bs.phase = .externalize; // :1684

    try emitCurrentStateStatement(ctx, s); // :1686

    nomination_mod.stopNomination(s); // :1688 (Slot::stopNomination)

    // driver.valueExternalized (:1690-1691) → the .externalized effect,
    // at most once per slot, ever (§5.3).
    if (s.externalized_value == null) {
        const value_copy = try gpa.dupe(u8, bs.commit.?.value);
        errdefer gpa.free(value_copy);
        const effect_copy = try gpa.dupe(u8, bs.commit.?.value);
        ctx.effects.push(.{ .externalized = .{ .slot = s.index, .bytes = effect_copy } }) catch |err| {
            gpa.free(value_copy);
            return err;
        };
        s.externalized_value = value_copy;
        // both timers die with the slot's active phase (§5.4)
        try ctx.cancelTimer(s.index, .nomination);
        try ctx.cancelTimer(s.index, .ballot);
    }

    return true;
}

// ---------------------------------------------------------------------------
// Step 9: attemptBump — the v-blocking counter jump (oracle: attemptBump
// :1559-1602, hasVBlockingSubsetStrictlyAheadOf :1532-1540)
// ---------------------------------------------------------------------------

const CounterAbove = struct {
    n: u32,
    fn matches(self: @This(), st: *const stored.OwnedStatement) bool {
        return statementBallotCounter(st) > self.n; // :1539
    }
};

/// Is there a v-blocking set of nodes with ballot counters strictly above
/// `n`? (oracle: hasVBlockingSubsetStrictlyAheadOf,
/// BallotProtocol.cpp:1532-1540 — pure local-qset structure, no advertised
/// lookups.)
fn hasVBlockingAheadOf(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, n: u32) !bool {
    const nodes = try collectNodes(ctx, s, CounterAbove{ .n = n });
    defer ctx.gpa.free(nodes);
    return local_node.isVBlocking(&ctx.cfg.quorum_set, nodes);
}

/// Step 9 from the paper: when a v-blocking set sits strictly ahead of the
/// local counter, jump immediately (no timer) to the smallest counter where
/// it no longer does (oracle: attemptBump, BallotProtocol.cpp:1559-1602;
/// EXTERNALIZE counts as ∞ and CONFIRM uses its real ballot.counter via
/// statementBallotCounter).
fn attemptBump(ctx: *engine_mod.Ctx, s: *slot_mod.Slot) Error!bool {
    const gpa = ctx.gpa;
    const bs = &s.ballot;
    if (bs.phase != .prepare and bs.phase != .confirm) return false; // :1563

    // if there is no v-blocking set ahead of the local node, return early
    // (:1566-1576)
    const local_counter: u32 = if (bs.current) |*b| b.counter else 0;
    if (!(try hasVBlockingAheadOf(ctx, s, local_counter))) return false;

    // collect all possible counters we might need to advance to (:1578-1585)
    var all_counters: std.ArrayList(u32) = .empty;
    defer all_counters.deinit(gpa);
    var it = s.latest_ballot.valueIterator();
    while (it.next()) |env| {
        const c = statementBallotCounter(&env.*.statement);
        if (c > local_counter) try insertBoundary(gpa, &all_counters, c);
    }

    // find the minimal n at which the v-blocking condition no longer holds,
    // checking in order from the smallest (:1587-1599)
    for (all_counters.items) |n| {
        if (!(try hasVBlockingAheadOf(ctx, s, n))) {
            return abandonBallot(ctx, s, n); // :1597
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Heard-from-quorum + timers (oracle: checkHeardFromQuorum :2354-2406,
// startBallotProtocolTimer :585-595, stopBallotProtocolTimer :597-604)
// ---------------------------------------------------------------------------

/// The counter predicate (§5.4): PREPARE requires ballot.counter >= local
/// b.counter; CONFIRM and EXTERNALIZE pass unconditionally
/// (BallotProtocol.cpp:2369-2380 — every non-PREPARE statement passes).
const HeardPred = struct {
    local_counter: u32,
    fn matches(self: @This(), st: *const stored.OwnedStatement) bool {
        return switch (st.pledges) {
            .nominate => false,
            .prepare => |*p| self.local_counter <= p.ballot.counter,
            .confirm, .externalize => true,
        };
    }
};

/// Oracle: checkHeardFromQuorum (BallotProtocol.cpp:2354-2406). Safe to call
/// on any transition: peers only move to higher counters, so "heard" never
/// flip-flops for a fixed local counter.
fn checkHeardFromQuorum(ctx: *engine_mod.Ctx, s: *slot_mod.Slot) Error!void {
    const gpa = ctx.gpa;
    const bs = &s.ballot;
    const cur = if (bs.current) |*b| b else return; // :2363

    const nodes = try collectNodes(ctx, s, HeardPred{ .local_counter = cur.counter });
    defer gpa.free(nodes);
    const bl = BallotLookup{ .ctx = ctx, .s = s };
    const is_quorum = try local_node.isQuorum(gpa, &ctx.cfg.quorum_set, nodes, bl.lookup()); // :2366-2381

    if (is_quorum) {
        const old_hq = bs.heard_from_quorum; // :2383
        bs.heard_from_quorum = true;
        if (!old_hq) {
            // not heard -> heard: driver.ballotDidHearFromQuorum + start the
            // ballot timer (:2385-2394)
            try ctx.phaseEvent(s.index, .heard_from_quorum, cur.counter);
            if (bs.phase != .externalize) {
                try ctx.armTimer(s.index, .ballot, engine_mod.timeoutMs(ctx.cfg.limits, cur.counter));
            }
        }
        if (bs.phase == .externalize) {
            try ctx.cancelTimer(s.index, .ballot); // :2395-2398
        }
    } else {
        bs.heard_from_quorum = false; // :2400-2404
        try ctx.cancelTimer(s.index, .ballot);
    }
}

// ---------------------------------------------------------------------------
// setStateFromEnvelope (oracle: BallotProtocol.cpp:1894-1962)
// ---------------------------------------------------------------------------

/// restore_own_envelope replay: rebuild phase/b/p/p'/c/h from an own ballot
/// statement (oracle: setStateFromEnvelope, BallotProtocol.cpp:1894-1962).
/// The pipeline records the envelope itself; no emission happens here (the
/// restored statement counts as already emitted — mLastEnvelopeEmit,
/// :1906-1907).
pub fn setStateFromEnvelope(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, st: *const stored.OwnedStatement) Error!void {
    const gpa = ctx.gpa;
    const bs = &s.ballot;
    if (bs.current != null) return error.AlreadyStarted; // :1898-1902
    const inf = std.math.maxInt(u32);

    switch (st.pledges) {
        .nominate => return error.WrongProtocol,
        .prepare => |*p| { // :1913-1936
            try bumpToBallot(ctx, s, bv(&p.ballot), true);
            if (p.prepared) |*b| try setOwnedBallot(gpa, &bs.prepared, bv(b));
            if (p.prepared_prime) |*b| try setOwnedBallot(gpa, &bs.prepared_prime, bv(b));
            if (p.n_h != 0) try setOwnedBallot(gpa, &bs.high, .{ .counter = p.n_h, .value = p.ballot.value });
            if (p.n_c != 0) try setOwnedBallot(gpa, &bs.commit, .{ .counter = p.n_c, .value = p.ballot.value });
            bs.phase = .prepare;
        },
        .confirm => |*c| { // :1937-1947
            const v = c.ballot.value;
            try bumpToBallot(ctx, s, bv(&c.ballot), true);
            try setOwnedBallot(gpa, &bs.prepared, .{ .counter = c.n_prepared, .value = v });
            try setOwnedBallot(gpa, &bs.high, .{ .counter = c.n_h, .value = v });
            try setOwnedBallot(gpa, &bs.commit, .{ .counter = c.n_commit, .value = v });
            bs.phase = .confirm;
        },
        .externalize => |*e| { // :1948-1957
            const v = e.commit.value;
            try ensureSingleton(gpa, bs, st.node_id);
            try bumpToBallot(ctx, s, .{ .counter = inf, .value = v }, true);
            try setOwnedBallot(gpa, &bs.prepared, .{ .counter = inf, .value = v });
            try setOwnedBallot(gpa, &bs.high, .{ .counter = e.n_h, .value = v });
            try setOwnedBallot(gpa, &bs.commit, bv(&e.commit));
            bs.phase = .externalize;
        },
    }

    // mLastEnvelope = mLastEnvelopeEmit = e (:1906-1907): the restored
    // statement is the last built AND emitted — nothing pending.
    if (bs.last_built) |*lb| {
        lb.deinit(gpa);
        bs.last_built = null;
    }
    bs.last_built = try cloneStatement(gpa, st);
    bs.emit_dirty = false;
}

// ---------------------------------------------------------------------------
// Tests — own-module: fabricated stored.OwnedStatement values drive
// processEnvelope/bumpState by hand over a 3-node 2-of-3 qset (self, A, B)
// with a Ctx like emit.zig's test. Peer statements are stored (as the M2
// pipeline would) before processEnvelope is called.
// ---------------------------------------------------------------------------

const testing = std.testing;
const crypto = @import("../crypto.zig");
const qset_store = @import("qset_store.zig");

const test_seed: [32]u8 = @splat(9);
const node_a: [32]u8 = @splat(0xAA);
const node_b: [32]u8 = @splat(0xBB);
const peer_qset_hash: [32]u8 = @splat(0x51);
const test_local_hash: [32]u8 = @splat(0x52);
const test_slot_index: u64 = 1;

fn makeFlatQs(gpa: std.mem.Allocator, threshold: u32, nodes: []const [32]u8) !qset.QuorumSetOwned {
    const vals = try gpa.alloc(qset.NodeId, nodes.len);
    errdefer gpa.free(vals);
    @memcpy(vals, nodes);
    return .{ .threshold = threshold, .validators = vals, .inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0) };
}

const TestEnv = struct {
    gpa: std.mem.Allocator,
    effects: engine_mod.EffectQueue,
    store: qset_store.Store,
    drv: driver_mod.Driver,
    cfg: engine_mod.Config,
    ctx: engine_mod.Ctx,
    slot: slot_mod.Slot,

    /// Must be called on a pinned (stack) TestEnv: ctx borrows &cfg/&effects.
    fn init(self: *TestEnv, drv: driver_mod.Driver, watcher: bool) !void {
        const gpa = testing.allocator;
        const self_id = try crypto.publicKeyFromSeed(test_seed);
        const members = [_][32]u8{ self_id, node_a, node_b };
        self.gpa = gpa;
        self.effects = engine_mod.EffectQueue.init(gpa);
        self.store = qset_store.Store.init(gpa, 16);
        self.drv = drv;
        self.cfg = .{
            .network_id = crypto.networkIdFromPassphrase("ballot-test"),
            .node_id = if (watcher) @splat(0xEE) else self_id,
            .secret_seed = if (watcher) null else test_seed,
            .quorum_set = try makeFlatQs(gpa, 2, &members),
            .limits = .{},
        };
        // both peers advertise the same 2-of-3 (as the pipeline records)
        try self.store.insert(peer_qset_hash, try makeFlatQs(gpa, 2, &members));
        try self.store.setAdvertised(node_a, peer_qset_hash);
        try self.store.setAdvertised(node_b, peer_qset_hash);
        self.ctx = .{
            .gpa = gpa,
            .cfg = &self.cfg,
            .drv = &self.drv,
            .effects = &self.effects,
            .qsets = &self.store,
            .excised = null,
            .local_qset_hash = test_local_hash,
        };
        self.slot = slot_mod.Slot.init(test_slot_index);
    }

    fn deinit(self: *TestEnv) void {
        self.slot.deinit(self.gpa);
        self.effects.deinit();
        self.store.deinit();
        self.cfg.quorum_set.deinit(self.gpa);
        self.* = undefined;
    }
};

const TB = struct { counter: u32, value: []const u8 };

fn tOwned(gpa: std.mem.Allocator, b: TB) !stored.OwnedBallot {
    return .{ .counter = b.counter, .value = try gpa.dupe(u8, b.value) };
}

fn tOptOwned(gpa: std.mem.Allocator, b: ?TB) !?stored.OwnedBallot {
    return if (b) |x| try tOwned(gpa, x) else null;
}

fn mkPrepareSt(gpa: std.mem.Allocator, node: [32]u8, b: TB, p: ?TB, pp: ?TB, n_c: u32, n_h: u32) !stored.OwnedStatement {
    return .{ .node_id = node, .slot = test_slot_index, .pledges = .{ .prepare = .{
        .qset_hash = peer_qset_hash,
        .ballot = try tOwned(gpa, b),
        .prepared = try tOptOwned(gpa, p),
        .prepared_prime = try tOptOwned(gpa, pp),
        .n_c = n_c,
        .n_h = n_h,
    } } };
}

fn mkConfirmSt(gpa: std.mem.Allocator, node: [32]u8, b: TB, n_prepared: u32, n_commit: u32, n_h: u32) !stored.OwnedStatement {
    return .{ .node_id = node, .slot = test_slot_index, .pledges = .{ .confirm = .{
        .qset_hash = peer_qset_hash,
        .ballot = try tOwned(gpa, b),
        .n_prepared = n_prepared,
        .n_commit = n_commit,
        .n_h = n_h,
    } } };
}

fn mkExternalizeSt(gpa: std.mem.Allocator, node: [32]u8, commit: TB, n_h: u32) !stored.OwnedStatement {
    return .{ .node_id = node, .slot = test_slot_index, .pledges = .{ .externalize = .{
        .commit = try tOwned(gpa, commit),
        .n_h = n_h,
        .commit_qset_hash = peer_qset_hash,
    } } };
}

/// Store a fabricated peer statement (as the pipeline would) then run it
/// through processEnvelope.
fn feed(env: *TestEnv, st: stored.OwnedStatement) Error!void {
    const node = st.node_id;
    const frame = env.gpa.alloc(u8, 0) catch |e| {
        var owned = st;
        owned.deinit(env.gpa);
        return e;
    };
    _ = env.slot.storeLatest(env.gpa, .{ .envelope_framed = frame, .statement = st }) catch return error.OutOfMemory;
    const entry = env.slot.latestFor(node, false).?;
    return processEnvelope(&env.ctx, &env.slot, &entry.statement);
}

/// Drain-and-summarize the effect queue.
const Fx = struct {
    persist: usize = 0,
    broadcast: usize = 0,
    arm_ballot: usize = 0,
    arm_delay: u32 = 0,
    cancel_ballot: usize = 0,
    cancel_nomination: usize = 0,
    externalized: usize = 0,
    externalized_value: ?[]u8 = null,
    started_ballot: usize = 0,
    accepted_prepared: usize = 0,
    confirmed_prepared: usize = 0,
    accepted_commit: usize = 0,
    heard_from_quorum: usize = 0,

    /// Frees the captured value only; counters stay readable (tests assert
    /// after releasing, and re-drains reassign the whole struct).
    fn deinit(self: *Fx, gpa: std.mem.Allocator) void {
        if (self.externalized_value) |v| gpa.free(v);
        self.externalized_value = null;
    }
};

fn drain(env: *TestEnv) !Fx {
    var fx = Fx{};
    while (env.effects.peek()) |e| {
        switch (e.*) {
            .persist_own_envelope => fx.persist += 1,
            .broadcast_envelope => fx.broadcast += 1,
            .arm_timer => |a| if (a.timer == .ballot) {
                fx.arm_ballot += 1;
                fx.arm_delay = a.delay_ms;
            },
            .cancel_timer => |c| if (c.timer == .ballot) {
                fx.cancel_ballot += 1;
            } else {
                fx.cancel_nomination += 1;
            },
            .externalized => |x| {
                fx.externalized += 1;
                if (fx.externalized_value == null) {
                    fx.externalized_value = try env.gpa.dupe(u8, x.bytes);
                }
            },
            .phase_event => |p| switch (p.kind) {
                .started_ballot => fx.started_ballot += 1,
                .accepted_prepared => fx.accepted_prepared += 1,
                .confirmed_prepared => fx.confirmed_prepared += 1,
                .accepted_commit => fx.accepted_commit += 1,
                .heard_from_quorum => fx.heard_from_quorum += 1,
                else => {},
            },
            else => {},
        }
        env.effects.commit();
    }
    return fx;
}

fn expectBallot(b: ?stored.OwnedBallot, expected: ?TB) !void {
    if (expected == null) {
        try testing.expect(b == null);
        return;
    }
    try testing.expect(b != null);
    try testing.expectEqual(expected.?.counter, b.?.counter);
    try testing.expectEqualSlices(u8, expected.?.value, b.?.value);
}

/// Directly install ballot state for unit-rule tests (invariant-respecting).
fn setState(env: *TestEnv, phase: Phase, b: ?TB, p: ?TB, pp: ?TB, h: ?TB, c: ?TB) !void {
    const bs = &env.slot.ballot;
    bs.phase = phase;
    bs.current = try tOptOwned(env.gpa, b);
    bs.prepared = try tOptOwned(env.gpa, p);
    bs.prepared_prime = try tOptOwned(env.gpa, pp);
    bs.high = try tOptOwned(env.gpa, h);
    bs.commit = try tOptOwned(env.gpa, c);
}

// --- driver that judges by the value's first byte: 'm' → maybe_valid, ---
// --- 'i' → invalid, anything else valid ---

fn testValidate(dctx: *anyopaque, slot_index: u64, value: []const u8, is_nomination: bool) driver_mod.Validity {
    _ = dctx;
    _ = slot_index;
    _ = is_nomination;
    if (value.len > 0 and value[0] == 'm') return .maybe_valid;
    if (value.len > 0 and value[0] == 'i') return .invalid;
    return .valid;
}

fn testCombine(dctx: *anyopaque, slot_index: u64, candidates: []const []const u8, gpa: std.mem.Allocator, out: *std.ArrayList(u8)) driver_mod.DriverError!void {
    _ = dctx;
    _ = slot_index;
    _ = candidates;
    _ = gpa;
    _ = out;
    return error.DriverFault;
}

var test_driver_ctx: u8 = 0;

fn levelDriver() driver_mod.Driver {
    return .{ .ctx = @ptrCast(&test_driver_ctx), .validate_value = testValidate, .combine_candidates = testCombine };
}

test "happy path: two peers' PREPARE→CONFIRM sequences drive self to externalize" {
    var env: TestEnv = undefined;
    try env.init(driver_mod.Driver.default(), false);
    defer env.deinit();
    const s = &env.slot;
    const gpa = env.gpa;

    // self proposes vv → PREPARE b=(1,vv) emitted
    try testing.expect(try bumpState(&env.ctx, s, "vv", true));
    var fx = try drain(&env);
    try testing.expectEqual(@as(usize, 1), fx.persist);
    try testing.expectEqual(@as(usize, 1), fx.broadcast);
    try testing.expectEqual(@as(usize, 1), fx.started_ballot);
    try testing.expect(s.own_ballot.?.statement.pledges == .prepare);
    {
        const p = &s.own_ballot.?.statement.pledges.prepare;
        try testing.expectEqual(@as(u32, 1), p.ballot.counter);
        try testing.expectEqualSlices(u8, "vv", p.ballot.value);
        try testing.expect(p.prepared == null);
        try testing.expectEqualSlices(u8, &test_local_hash, &p.qset_hash);
    }

    // A votes PREPARE (1,vv): quorum {self, A} votes → accept prepared
    try feed(&env, try mkPrepareSt(gpa, node_a, .{ .counter = 1, .value = "vv" }, null, null, 0, 0));
    fx = try drain(&env);
    try testing.expectEqual(@as(usize, 1), fx.broadcast);
    try testing.expectEqual(@as(usize, 1), fx.accepted_prepared);
    try testing.expectEqual(@as(usize, 1), fx.heard_from_quorum);
    try testing.expectEqual(@as(usize, 1), fx.arm_ballot);
    try testing.expectEqual(engine_mod.timeoutMs(env.cfg.limits, 1), fx.arm_delay);
    try expectBallot(s.ballot.prepared, .{ .counter = 1, .value = "vv" });
    try expectBallot(s.ballot.high, null);

    // B accepts prepared (1,vv): quorum {self, B} accepted → confirm
    // prepared: h=c=(1,vv); own PREPARE(b, p, nC=1, nH=1)
    try feed(&env, try mkPrepareSt(gpa, node_b, .{ .counter = 1, .value = "vv" }, .{ .counter = 1, .value = "vv" }, null, 0, 0));
    fx = try drain(&env);
    try testing.expectEqual(@as(usize, 1), fx.broadcast);
    try testing.expectEqual(@as(usize, 1), fx.confirmed_prepared);
    try expectBallot(s.ballot.high, .{ .counter = 1, .value = "vv" });
    try expectBallot(s.ballot.commit, .{ .counter = 1, .value = "vv" });
    {
        const p = &s.own_ballot.?.statement.pledges.prepare;
        try testing.expectEqual(@as(u32, 1), p.n_c);
        try testing.expectEqual(@as(u32, 1), p.n_h);
    }

    // A votes commit: quorum {self, A} → accept commit → phase CONFIRM.
    // Emitted CONFIRM field mapping (oracle createStatement :650-658):
    // ballot=b, nPrepared=p.counter, nCommit=c.counter, nH=h.counter.
    try feed(&env, try mkPrepareSt(gpa, node_a, .{ .counter = 1, .value = "vv" }, .{ .counter = 1, .value = "vv" }, null, 1, 1));
    fx = try drain(&env);
    try testing.expectEqual(@as(usize, 1), fx.broadcast);
    try testing.expectEqual(@as(usize, 1), fx.accepted_commit);
    try testing.expectEqual(Phase.confirm, s.ballot.phase);
    try testing.expect(s.own_ballot.?.statement.pledges == .confirm);
    {
        const c = &s.own_ballot.?.statement.pledges.confirm;
        try testing.expectEqual(s.ballot.current.?.counter, c.ballot.counter);
        try testing.expectEqualSlices(u8, s.ballot.current.?.value, c.ballot.value);
        try testing.expectEqual(s.ballot.prepared.?.counter, c.n_prepared);
        try testing.expectEqual(s.ballot.commit.?.counter, c.n_commit);
        try testing.expectEqual(s.ballot.high.?.counter, c.n_h);
        try testing.expectEqualSlices(u8, &test_local_hash, &c.qset_hash);
    }

    // B confirms: quorum accepts commit → confirm commit → EXTERNALIZE.
    try feed(&env, try mkConfirmSt(gpa, node_b, .{ .counter = 1, .value = "vv" }, 1, 1, 1));
    fx = try drain(&env);
    defer fx.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), fx.broadcast); // only the newest (EXTERNALIZE) hits the wire
    try testing.expectEqual(@as(usize, 1), fx.externalized);
    try testing.expectEqualSlices(u8, "vv", fx.externalized_value.?);
    try testing.expect(fx.cancel_nomination >= 1);
    try testing.expect(fx.cancel_ballot >= 1);
    try testing.expectEqual(Phase.externalize, s.ballot.phase);
    try testing.expectEqualSlices(u8, "vv", s.externalized_value.?);
    // EXTERNALIZE field mapping (oracle createStatement :660-666):
    // commit=c, nH=h.counter, commitQuorumSetHash=local qset hash (§5.4).
    try testing.expect(s.own_ballot.?.statement.pledges == .externalize);
    {
        const e = &s.own_ballot.?.statement.pledges.externalize;
        try testing.expectEqual(s.ballot.commit.?.counter, e.commit.counter);
        try testing.expectEqualSlices(u8, "vv", e.commit.value);
        try testing.expectEqual(s.ballot.high.?.counter, e.n_h);
        try testing.expectEqualSlices(u8, &test_local_hash, &e.commit_qset_hash);
    }

    // Post-externalize: compatible statements are recorded quietly; the
    // .externalized effect never fires again (at most once per slot, §5.3).
    try feed(&env, try mkExternalizeSt(gpa, node_a, .{ .counter = 1, .value = "vv" }, 1));
    var fx2 = try drain(&env);
    defer fx2.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), fx2.externalized);
    try testing.expectEqual(@as(usize, 0), fx2.broadcast);

    // ...and a statement working on a different value is rejected
    // (BallotProtocol.cpp:254-271).
    try testing.expectError(error.InvalidValue, feed(&env, try mkConfirmSt(gpa, node_b, .{ .counter = 1, .value = "zz" }, 1, 1, 1)));
    var fx3 = try drain(&env);
    defer fx3.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), fx3.externalized);
}

test "c-reset: accepting prepared of an incompatible higher ballot clears c" {
    var env: TestEnv = undefined;
    try env.init(driver_mod.Driver.default(), false);
    defer env.deinit();
    const s = &env.slot;

    // b=p=h=c=(1,v) in PREPARE: vote-to-commit is pending on v.
    try setState(&env, .prepare, .{ .counter = 1, .value = "v" }, .{ .counter = 1, .value = "v" }, null, .{ .counter = 1, .value = "v" }, .{ .counter = 1, .value = "v" });

    // Accepting prepared (2,w) demotes p→p' and yields h ⋦ p → c cleared
    // (setAcceptPrepared, BallotProtocol.cpp:989-1003).
    try testing.expect(try setAcceptPrepared(&env.ctx, s, .{ .counter = 2, .value = "w" }));
    try expectBallot(s.ballot.prepared, .{ .counter = 2, .value = "w" });
    try expectBallot(s.ballot.prepared_prime, .{ .counter = 1, .value = "v" });
    try expectBallot(s.ballot.commit, null); // c reset
    try expectBallot(s.ballot.high, .{ .counter = 1, .value = "v" }); // h survives until b moves
    try testing.expectEqual(Phase.prepare, s.ballot.phase);
    var fx = try drain(&env);
    defer fx.deinit(env.gpa);
    try testing.expectEqual(@as(usize, 1), fx.accepted_prepared);
}

test "h/c clear when b bumps to an h-incompatible ballot" {
    var env: TestEnv = undefined;
    try env.init(driver_mod.Driver.default(), false);
    defer env.deinit();
    const s = &env.slot;

    try setState(&env, .prepare, .{ .counter = 1, .value = "v" }, .{ .counter = 1, .value = "v" }, null, .{ .counter = 1, .value = "v" }, .{ .counter = 1, .value = "v" });
    s.ballot.heard_from_quorum = true;

    // bumpToBallot onto an incompatible ballot: invariant h.value = b.value
    // forces h (and with it c) to clear (BallotProtocol.cpp:569-577); the
    // counter change resets heard_from_quorum (:579-582).
    try bumpToBallot(&env.ctx, s, .{ .counter = 2, .value = "w" }, true);
    try expectBallot(s.ballot.current, .{ .counter = 2, .value = "w" });
    try expectBallot(s.ballot.high, null);
    try expectBallot(s.ballot.commit, null);
    try testing.expect(!s.ballot.heard_from_quorum);
    var fx = try drain(&env);
    defer fx.deinit(env.gpa);
    try testing.expectEqual(@as(usize, 0), fx.started_ballot); // b already existed
}

test "heard-from-quorum counter predicates: PREPARE needs counter >= b.counter; CONFIRM passes unconditionally" {
    var env: TestEnv = undefined;
    try env.init(driver_mod.Driver.default(), false);
    defer env.deinit();
    const s = &env.slot;
    const gpa = env.gpa;

    try testing.expect(try bumpState(&env.ctx, s, "vv", true)); // b=(1,vv)
    var fx0 = try drain(&env);
    fx0.deinit(gpa);

    // A at counter 1 (>= 1): {self, A} is a quorum → heard + timer armed.
    try feed(&env, try mkPrepareSt(gpa, node_a, .{ .counter = 1, .value = "vv" }, null, null, 0, 0));
    var fx = try drain(&env);
    fx.deinit(gpa);
    try testing.expect(s.ballot.heard_from_quorum);
    try testing.expectEqual(@as(usize, 1), fx.heard_from_quorum);
    try testing.expect(fx.arm_ballot >= 1);

    // B at counter 5: still heard (no duplicate event while it stays true).
    try feed(&env, try mkPrepareSt(gpa, node_b, .{ .counter = 5, .value = "vv" }, null, null, 0, 0));
    fx = try drain(&env);
    fx.deinit(gpa);
    try testing.expect(s.ballot.heard_from_quorum);
    try testing.expectEqual(@as(usize, 0), fx.heard_from_quorum);

    // Bump self to counter 6: A(1) and B(5) both fail the PREPARE counter
    // predicate → quorum lost → heard=false + cancel.
    var n: u32 = 0;
    while (n < 5) : (n += 1) {
        try testing.expect(try bumpState(&env.ctx, s, "vv", true));
    }
    fx = try drain(&env);
    fx.deinit(gpa);
    try testing.expectEqual(@as(u32, 6), s.ballot.current.?.counter);
    try testing.expect(!s.ballot.heard_from_quorum);
    try testing.expect(fx.cancel_ballot >= 1);

    // A upgrades to CONFIRM at ballot counter 1 — CONFIRM passes the counter
    // predicate unconditionally (BallotProtocol.cpp:2369-2380) → heard again.
    try feed(&env, try mkConfirmSt(gpa, node_a, .{ .counter = 1, .value = "vv" }, 1, 1, 1));
    fx = try drain(&env);
    fx.deinit(gpa);
    try testing.expect(s.ballot.heard_from_quorum);
    try testing.expectEqual(@as(usize, 1), fx.heard_from_quorum);
}

test "heard-from-quorum: EXTERNALIZE passes unconditionally (and serves its singleton qset)" {
    var env: TestEnv = undefined;
    try env.init(driver_mod.Driver.default(), false);
    defer env.deinit();
    const s = &env.slot;
    const gpa = env.gpa;

    try testing.expect(try bumpState(&env.ctx, s, "vv", true)); // b=(1,vv)
    var fx0 = try drain(&env);
    fx0.deinit(gpa);
    try testing.expect(!s.ballot.heard_from_quorum); // self alone is no quorum

    // A EXTERNALIZE: passes the counter predicate unconditionally and its
    // quorum-math qset is the singleton {A} → {self, A} becomes a quorum.
    try feed(&env, try mkExternalizeSt(gpa, node_a, .{ .counter = 1, .value = "vv" }, 1));
    var fx = try drain(&env);
    fx.deinit(gpa);
    try testing.expect(s.ballot.heard_from_quorum);
    try testing.expect(s.ballot.singletons.contains(node_a));
}

test "v-blocking counter jump: nodes strictly ahead force an immediate jump to the smallest stable counter" {
    var env: TestEnv = undefined;
    try env.init(driver_mod.Driver.default(), false);
    defer env.deinit();
    const s = &env.slot;
    const gpa = env.gpa;

    try testing.expect(try bumpState(&env.ctx, s, "vv", true)); // b=(1,vv)
    var fx = try drain(&env);
    fx.deinit(gpa);

    // A at counter 4: one node is not v-blocking in 2-of-3 → no jump.
    try feed(&env, try mkPrepareSt(gpa, node_a, .{ .counter = 4, .value = "vv" }, null, null, 0, 0));
    fx = try drain(&env);
    fx.deinit(gpa);
    try testing.expectEqual(@as(u32, 1), s.ballot.current.?.counter);

    // B at counter 7: {A(4), B(7)} > 1 is v-blocking → jump immediately (no
    // timer wait) to 4 — the smallest counter where they no longer block
    // (attemptBump, BallotProtocol.cpp:1559-1602).
    try feed(&env, try mkPrepareSt(gpa, node_b, .{ .counter = 7, .value = "vv" }, null, null, 0, 0));
    fx = try drain(&env);
    fx.deinit(gpa);
    try testing.expectEqual(@as(u32, 4), s.ballot.current.?.counter);
    try testing.expectEqualSlices(u8, "vv", s.ballot.current.?.value);
    try testing.expect(s.own_ballot.?.statement.pledges == .prepare);
    try testing.expectEqual(@as(u32, 4), s.own_ballot.?.statement.pledges.prepare.ballot.counter);

    // A moves to 9: {A(9), B(7)} > 4 blocks again → jump to 7.
    try feed(&env, try mkPrepareSt(gpa, node_a, .{ .counter = 9, .value = "vv" }, null, null, 0, 0));
    fx = try drain(&env);
    fx.deinit(gpa);
    try testing.expectEqual(@as(u32, 7), s.ballot.current.?.counter);
}

test "single permitted value switch onto an incompatible ballot at accept-commit" {
    var env: TestEnv = undefined;
    try env.init(driver_mod.Driver.default(), false);
    defer env.deinit();
    const s = &env.slot;

    // Self is on (5,ww); the network accepted commit of vv over [2,3].
    try setState(&env, .prepare, .{ .counter = 5, .value = "ww" }, .{ .counter = 3, .value = "vv" }, .{ .counter = 2, .value = "ww" }, null, null);

    // setAcceptCommit: h=(3,vv) is NOT less-and-compatible with b=(5,ww) →
    // bumpToBallot(h, check=false) — the only place b may move to an
    // incompatible (even smaller) ballot; phase → CONFIRM, p' cleared
    // (BallotProtocol.cpp:1491-1502, §5.4).
    try testing.expect(try setAcceptCommit(&env.ctx, s, .{ .counter = 2, .value = "vv" }, .{ .counter = 3, .value = "vv" }));
    try testing.expectEqual(Phase.confirm, s.ballot.phase);
    try expectBallot(s.ballot.current, .{ .counter = 3, .value = "vv" }); // switched + down-bumped
    try expectBallot(s.ballot.prepared_prime, null); // p' cleared
    try expectBallot(s.ballot.commit, .{ .counter = 2, .value = "vv" });
    try expectBallot(s.ballot.high, .{ .counter = 3, .value = "vv" });
    try testing.expectEqualSlices(u8, "vv", s.ballot.value_override.?);
    var fx = try drain(&env);
    defer fx.deinit(env.gpa);
    try testing.expectEqual(@as(usize, 1), fx.accepted_commit);
    // emitted CONFIRM maps ballot=b (the switched ballot)
    try testing.expect(s.own_ballot.?.statement.pledges == .confirm);
    try testing.expectEqualSlices(u8, "vv", s.own_ballot.?.statement.pledges.confirm.ballot.value);
}

test "value switch end-to-end: peers committing another value pull self off its own" {
    var env: TestEnv = undefined;
    try env.init(driver_mod.Driver.default(), false);
    defer env.deinit();
    const s = &env.slot;
    const gpa = env.gpa;

    var n: u32 = 0;
    while (n < 5) : (n += 1) {
        try testing.expect(try bumpState(&env.ctx, s, "ww", true)); // b=(5,ww)
    }
    var fx = try drain(&env);
    fx.deinit(gpa);
    try testing.expectEqual(@as(u32, 5), s.ballot.current.?.counter);

    try feed(&env, try mkConfirmSt(gpa, node_a, .{ .counter = 3, .value = "vv" }, 3, 2, 3));
    try feed(&env, try mkConfirmSt(gpa, node_b, .{ .counter = 3, .value = "vv" }, 3, 2, 3));
    fx = try drain(&env);
    defer fx.deinit(gpa);

    // A quorum confirmed committing vv: self switches off ww, accepts and
    // confirms the commit, and externalizes vv.
    try testing.expectEqual(Phase.externalize, s.ballot.phase);
    try testing.expectEqualSlices(u8, "vv", s.ballot.current.?.value);
    try testing.expectEqual(@as(usize, 1), fx.externalized);
    try testing.expectEqualSlices(u8, "vv", fx.externalized_value.?);
}

test "mValueOverride stickiness: override > latest composite > current ballot value" {
    // (a) override beats the passed value
    {
        var env: TestEnv = undefined;
        try env.init(driver_mod.Driver.default(), false);
        defer env.deinit();
        env.slot.ballot.value_override = try env.gpa.dupe(u8, "ov");
        try testing.expect(try bumpState(&env.ctx, &env.slot, "xx", true));
        try expectBallot(env.slot.ballot.current, .{ .counter = 1, .value = "ov" });
        var fx = try drain(&env);
        fx.deinit(env.gpa);
    }
    // (b) no override: abandonBallot prefers the latest composite...
    {
        var env: TestEnv = undefined;
        try env.init(driver_mod.Driver.default(), false);
        defer env.deinit();
        try testing.expect(try bumpState(&env.ctx, &env.slot, "bb", true));
        env.slot.nom.latest_composite = try env.gpa.dupe(u8, "cc");
        try timerFired(&env.ctx, &env.slot);
        try expectBallot(env.slot.ballot.current, .{ .counter = 2, .value = "cc" });
        // ...but a set override still wins over the composite
        env.slot.ballot.value_override = try env.gpa.dupe(u8, "ov");
        try timerFired(&env.ctx, &env.slot);
        try expectBallot(env.slot.ballot.current, .{ .counter = 3, .value = "ov" });
        var fx = try drain(&env);
        fx.deinit(env.gpa);
    }
    // (c) neither: fall back to the current ballot's value
    {
        var env: TestEnv = undefined;
        try env.init(driver_mod.Driver.default(), false);
        defer env.deinit();
        try testing.expect(try bumpState(&env.ctx, &env.slot, "bb", true));
        try timerFired(&env.ctx, &env.slot);
        try expectBallot(env.slot.ballot.current, .{ .counter = 2, .value = "bb" });
        var fx = try drain(&env);
        fx.deinit(env.gpa);
    }
}

test "counter-0 internal placeholder never emitted" {
    var env: TestEnv = undefined;
    try env.init(driver_mod.Driver.default(), false);
    defer env.deinit();
    const s = &env.slot;
    const gpa = env.gpa;

    // No own ballot yet. A v-blocking set accepting (1,v) drives
    // accept-prepared while b is unset: the b=0 statement is built and
    // recorded (self-visible) but never emitted (canEmit false,
    // BallotProtocol.cpp:293,699); the cascade then confirms prepared,
    // b jumps to h, and only counter-1 statements reach the wire.
    try feed(&env, try mkPrepareSt(gpa, node_a, .{ .counter = 1, .value = "v" }, .{ .counter = 1, .value = "v" }, null, 0, 0));
    var fx = try drain(&env);
    fx.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), fx.broadcast); // nothing acceptable yet

    try feed(&env, try mkPrepareSt(gpa, node_b, .{ .counter = 1, .value = "v" }, .{ .counter = 1, .value = "v" }, null, 0, 0));
    fx = try drain(&env);
    defer fx.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), fx.accepted_prepared); // fired while b was 0
    try testing.expectEqual(@as(usize, 1), fx.broadcast); // exactly one emission...
    try testing.expectEqual(@as(usize, 1), fx.persist);
    const p = &s.own_ballot.?.statement.pledges.prepare;
    try testing.expectEqual(@as(u32, 1), p.ballot.counter); // ...at counter 1, never 0
    try testing.expectEqual(@as(u32, 1), p.n_c);
    try testing.expectEqual(@as(u32, 1), p.n_h);
}

test "recursion guard: exceeding max_advance_recursion is an engine error" {
    var env: TestEnv = undefined;
    try env.init(driver_mod.Driver.default(), false);
    defer env.deinit();
    const gpa = env.gpa;

    env.slot.ballot.message_level = max_advance_recursion - 1;
    try testing.expectError(error.EngineFailed, feed(&env, try mkPrepareSt(gpa, node_a, .{ .counter = 1, .value = "vv" }, null, null, 0, 0)));
    // the level unwinds on the error path
    try testing.expectEqual(max_advance_recursion - 1, env.slot.ballot.message_level);
}

test "maybe_valid peer values: processed, fully_validated cleared, own emissions suppressed" {
    var env: TestEnv = undefined;
    try env.init(levelDriver(), false);
    defer env.deinit();
    const s = &env.slot;
    const gpa = env.gpa;

    try feed(&env, try mkPrepareSt(gpa, node_a, .{ .counter = 1, .value = "mv" }, .{ .counter = 1, .value = "mv" }, null, 0, 0));
    try feed(&env, try mkPrepareSt(gpa, node_b, .{ .counter = 1, .value = "mv" }, .{ .counter = 1, .value = "mv" }, null, 0, 0));
    var fx = try drain(&env);
    defer fx.deinit(gpa);

    try testing.expect(!s.fully_validated);
    // state advanced all the way to vote-to-commit...
    try expectBallot(s.ballot.prepared, .{ .counter = 1, .value = "mv" });
    try expectBallot(s.ballot.high, .{ .counter = 1, .value = "mv" });
    try expectBallot(s.ballot.commit, .{ .counter = 1, .value = "mv" });
    // ...but nothing was emitted (sendLatestEnvelope fully_validated gate)
    try testing.expectEqual(@as(usize, 0), fx.broadcast);
    try testing.expectEqual(@as(usize, 0), fx.persist);
    try testing.expect(s.own_ballot == null);
}

test "invalid values: PREPARE dropped; CONFIRM/EXTERNALIZE processed at maybe_valid (lagger catch-up)" {
    // invalid PREPARE → InvalidValue, state untouched (BallotProtocol.cpp:193-205)
    {
        var env: TestEnv = undefined;
        try env.init(levelDriver(), false);
        defer env.deinit();
        try testing.expectError(error.InvalidValue, feed(&env, try mkPrepareSt(env.gpa, node_a, .{ .counter = 1, .value = "iv" }, null, null, 0, 0)));
        try testing.expect(env.slot.fully_validated);
        try testing.expect(env.slot.ballot.prepared == null);
        var fx = try drain(&env);
        fx.deinit(env.gpa);
    }
    // invalid CONFIRM values collapse to maybe_valid (§5.4): recorded,
    // processed, fully_validated=false — a v-blocking set can carry the
    // laggard all the way to a (silent) externalize.
    {
        var env: TestEnv = undefined;
        try env.init(levelDriver(), false);
        defer env.deinit();
        const s = &env.slot;
        const gpa = env.gpa;

        try feed(&env, try mkConfirmSt(gpa, node_a, .{ .counter = 1, .value = "iv" }, 1, 1, 1));
        try testing.expect(!s.fully_validated);
        try testing.expect(s.latestFor(node_a, false) != null); // still recorded

        try feed(&env, try mkConfirmSt(gpa, node_b, .{ .counter = 1, .value = "iv" }, 1, 1, 1));
        var fx = try drain(&env);
        defer fx.deinit(gpa);
        try testing.expectEqual(Phase.externalize, s.ballot.phase);
        try testing.expectEqual(@as(usize, 1), fx.externalized);
        try testing.expectEqualSlices(u8, "iv", fx.externalized_value.?);
        try testing.expectEqual(@as(usize, 0), fx.broadcast); // own emissions stay suppressed
    }
}

test "EXTERNALIZE-∞ catch-up: laggard confirms commit from peer EXTERNALIZEs via singleton qsets" {
    var env: TestEnv = undefined;
    try env.init(driver_mod.Driver.default(), false);
    defer env.deinit();
    const s = &env.slot;
    const gpa = env.gpa;

    // One EXTERNALIZE alone is not v-blocking for 2-of-3 → nothing moves.
    try feed(&env, try mkExternalizeSt(gpa, node_a, .{ .counter = 2, .value = "vv" }, 3));
    var fx = try drain(&env);
    fx.deinit(gpa);
    try testing.expectEqual(Phase.prepare, s.ballot.phase);
    try testing.expectEqual(@as(usize, 0), fx.externalized);

    // The second EXTERNALIZE makes {A, B} v-blocking AND a quorum — via the
    // synthetic singleton qsets (Slot.cpp:322-325) — carrying the laggard
    // through accept/confirm commit at counter ∞.
    try feed(&env, try mkExternalizeSt(gpa, node_b, .{ .counter = 2, .value = "vv" }, 3));
    fx = try drain(&env);
    defer fx.deinit(gpa);
    try testing.expect(s.ballot.singletons.contains(node_a));
    try testing.expect(s.ballot.singletons.contains(node_b));
    try testing.expectEqual(Phase.externalize, s.ballot.phase);
    try testing.expectEqual(@as(usize, 1), fx.externalized);
    try testing.expectEqualSlices(u8, "vv", fx.externalized_value.?);
    try testing.expectEqualSlices(u8, "vv", s.externalized_value.?);
}

test "watcher: full tracking, zero emissions" {
    var env: TestEnv = undefined;
    try env.init(driver_mod.Driver.default(), true);
    defer env.deinit();
    const s = &env.slot;
    const gpa = env.gpa;

    try feed(&env, try mkPrepareSt(gpa, node_a, .{ .counter = 1, .value = "vv" }, .{ .counter = 1, .value = "vv" }, null, 0, 0));
    try feed(&env, try mkPrepareSt(gpa, node_b, .{ .counter = 1, .value = "vv" }, .{ .counter = 1, .value = "vv" }, null, 0, 0));
    var fx = try drain(&env);
    defer fx.deinit(gpa);

    // state tracked...
    try expectBallot(s.ballot.prepared, .{ .counter = 1, .value = "vv" });
    try expectBallot(s.ballot.high, .{ .counter = 1, .value = "vv" });
    // ...zero emissions (§5.1 watcher mode)
    try testing.expectEqual(@as(usize, 0), fx.broadcast);
    try testing.expectEqual(@as(usize, 0), fx.persist);
    try testing.expect(s.own_ballot == null);
}

test "setStateFromEnvelope: restore own ballot state per statement type, no emission" {
    const gpa = testing.allocator;
    // PREPARE arm (BallotProtocol.cpp:1913-1936)
    {
        var env: TestEnv = undefined;
        try env.init(driver_mod.Driver.default(), false);
        defer env.deinit();
        var st = try mkPrepareSt(gpa, env.cfg.node_id, .{ .counter = 2, .value = "v" }, .{ .counter = 2, .value = "v" }, .{ .counter = 1, .value = "u" }, 1, 2);
        defer st.deinit(gpa);
        try setStateFromEnvelope(&env.ctx, &env.slot, &st);
        try testing.expectEqual(Phase.prepare, env.slot.ballot.phase);
        try expectBallot(env.slot.ballot.current, .{ .counter = 2, .value = "v" });
        try expectBallot(env.slot.ballot.prepared, .{ .counter = 2, .value = "v" });
        try expectBallot(env.slot.ballot.prepared_prime, .{ .counter = 1, .value = "u" });
        try expectBallot(env.slot.ballot.high, .{ .counter = 2, .value = "v" });
        try expectBallot(env.slot.ballot.commit, .{ .counter = 1, .value = "v" });
        var fx = try drain(&env);
        defer fx.deinit(gpa);
        try testing.expectEqual(@as(usize, 0), fx.broadcast);
        try testing.expectEqual(@as(usize, 0), fx.persist);
        try testing.expectEqual(@as(usize, 1), fx.started_ballot);
        // restoring twice is an error (:1898-1902)
        try testing.expectError(error.AlreadyStarted, setStateFromEnvelope(&env.ctx, &env.slot, &st));
    }
    // CONFIRM arm (:1937-1947)
    {
        var env: TestEnv = undefined;
        try env.init(driver_mod.Driver.default(), false);
        defer env.deinit();
        var st = try mkConfirmSt(gpa, env.cfg.node_id, .{ .counter = 3, .value = "v" }, 2, 1, 2);
        defer st.deinit(gpa);
        try setStateFromEnvelope(&env.ctx, &env.slot, &st);
        try testing.expectEqual(Phase.confirm, env.slot.ballot.phase);
        try expectBallot(env.slot.ballot.current, .{ .counter = 3, .value = "v" });
        try expectBallot(env.slot.ballot.prepared, .{ .counter = 2, .value = "v" });
        try expectBallot(env.slot.ballot.high, .{ .counter = 2, .value = "v" });
        try expectBallot(env.slot.ballot.commit, .{ .counter = 1, .value = "v" });
        var fx = try drain(&env);
        defer fx.deinit(gpa);
        try testing.expectEqual(@as(usize, 0), fx.broadcast);
    }
    // EXTERNALIZE arm (:1948-1957): b and p at counter ∞
    {
        var env: TestEnv = undefined;
        try env.init(driver_mod.Driver.default(), false);
        defer env.deinit();
        var st = try mkExternalizeSt(gpa, env.cfg.node_id, .{ .counter = 2, .value = "v" }, 5);
        defer st.deinit(gpa);
        try setStateFromEnvelope(&env.ctx, &env.slot, &st);
        const inf = std.math.maxInt(u32);
        try testing.expectEqual(Phase.externalize, env.slot.ballot.phase);
        try expectBallot(env.slot.ballot.current, .{ .counter = inf, .value = "v" });
        try expectBallot(env.slot.ballot.prepared, .{ .counter = inf, .value = "v" });
        try expectBallot(env.slot.ballot.high, .{ .counter = 5, .value = "v" });
        try expectBallot(env.slot.ballot.commit, .{ .counter = 2, .value = "v" });
        try testing.expect(env.slot.ballot.singletons.contains(env.cfg.node_id));
        var fx = try drain(&env);
        defer fx.deinit(gpa);
        try testing.expectEqual(@as(usize, 0), fx.broadcast);
    }
}
