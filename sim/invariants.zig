//! Structural invariants for the deterministic simulator (design §13.1),
//! checked after EVERY input on every engine:
//!
//!   - p' ⋦ p (less AND value-incompatible) whenever both are set
//!   - c ≲ h ≲ b (less-and-compatible chain) whenever set
//!   - phase-implied fields present (confirm/externalize ⇒ b, p, c, h set)
//!   - b.counter monotone per (engine, slot)
//!   - phase monotone (prepare → confirm → externalize, never backwards)
//!   - `externalized` effect at most once per slot; the recorded value is
//!     sticky once set
//!   - own emitted statements strictly `isNewerStatement`-ordered per
//!     (slot, protocol), tracked from persist_own_envelope effects — with
//!     the one pair that order cannot rank, own EXTERNALIZE/EXTERNALIZE,
//!     judged by COMMITTED VALUE (same value = the legitimate nH re-emit,
//!     different values = a fork), exactly as the e2e watchdog does
//!   - effect queue bounded (the engine's own budget must never be exceeded)
//!
//! The tracker's memory is scoped like the engine's: `purge_slots` drops all
//! engine state for slots < max_slot (design §10 GC), so the harness must
//! call `Tracker.purgeBelow` when it applies one. A slot re-created after a
//! purge starts from empty state (the oracle's SCP::getSlot(create=true)
//! after purgeSlotsOutsideRange does the same) and its first emission is
//! not ordered against the forgotten one — comparing across the purge was
//! the S9 fuzz-long false positive (tests/fuzz/crash/).
//!
//! All checks return a `?Violation` instead of asserting so the simulator
//! can attach the (seed, n, scenario) one-line repro before failing.

const std = @import("std");
const slcp = @import("slcp-core");

const engine = slcp.engine;
const ballot = slcp.ballot;
const statement = slcp.statement;
const stored = slcp.stored;
const canonical = slcp.canonical;
const capnpc = slcp.capnpc;
const gen_slcp = slcp.gen.slcp;
const limits = slcp.limits;

pub const Violation = struct {
    slot: u64,
    msg: []const u8, // static string
};

// ---------------------------------------------------------------------------
// Per-node tracker (cross-input state the invariants need)
// ---------------------------------------------------------------------------

const SlotTrack = struct {
    max_b_counter: u32 = 0,
    phase: ballot.Phase = .prepare,
    externalized_effects: u32 = 0,
    last_own_nom: ?stored.OwnedStatement = null,
    last_own_ballot: ?stored.OwnedStatement = null,

    fn deinit(self: *SlotTrack, gpa: std.mem.Allocator) void {
        if (self.last_own_nom) |*s| s.deinit(gpa);
        if (self.last_own_ballot) |*s| s.deinit(gpa);
        self.* = undefined;
    }
};

pub const Tracker = struct {
    per_slot: std.AutoHashMapUnmanaged(u64, SlotTrack) = .empty,

    pub fn deinit(self: *Tracker, gpa: std.mem.Allocator) void {
        var it = self.per_slot.valueIterator();
        while (it.next()) |t| t.deinit(gpa);
        self.per_slot.deinit(gpa);
        self.* = undefined;
    }

    fn track(self: *Tracker, gpa: std.mem.Allocator, slot: u64) !*SlotTrack {
        const gop = try self.per_slot.getOrPut(gpa, slot);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        return gop.value_ptr;
    }

    /// Forget every slot < max_slot — the harness-side mirror of an APPLIED
    /// `purge_slots` (the engine drops all state for those slots, §10; the
    /// host's own-latest cache prunes the same way, node.zig
    /// pruneOwnLatest). Anything the engine emits for such a slot afterwards
    /// comes from a freshly created slot and has no previous own statement
    /// to be ordered against. Never call this for a purge the engine did
    /// not apply.
    pub fn purgeBelow(self: *Tracker, gpa: std.mem.Allocator, max_slot: u64) !void {
        var doomed: std.ArrayList(u64) = .empty;
        defer doomed.deinit(gpa);
        var it = self.per_slot.keyIterator();
        while (it.next()) |k| {
            if (k.* < max_slot) try doomed.append(gpa, k.*);
        }
        for (doomed.items) |k| {
            if (self.per_slot.fetchRemove(k)) |kv| {
                var t = kv.value;
                t.deinit(gpa);
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Own-statement decode (persist_own_envelope payload → OwnedStatement)
// ---------------------------------------------------------------------------

fn frameOptions() canonical.ValidationOptions {
    return .{
        .nesting_limit = 32,
        .traversal_limit_words = limits.frozen_max_frame_bytes / 8,
    };
}

fn stmtOptions() canonical.ValidationOptions {
    return .{
        .nesting_limit = 32,
        .traversal_limit_words = limits.frozen_max_statement_bytes / 8,
    };
}

/// Decode an own persisted Envelope frame into an OwnedStatement (caller
/// owns / frees). Own frames are engine-built; decode failure is a bug.
pub fn decodeOwnEnvelope(gpa: std.mem.Allocator, frame: []const u8) !stored.OwnedStatement {
    var env_msg = try capnpc.message.Message.init(gpa, frame, frameOptions());
    defer env_msg.deinit();
    const env_rdr = try gen_slcp.Envelope.Reader.init(&env_msg);
    const stmt_bytes = try env_rdr.getStatementBytes();
    var stmt_msg = try canonical.decodeFlat(gpa, stmt_bytes, stmtOptions());
    defer stmt_msg.deinit();
    const stmt_rdr = try gen_slcp.Statement.Reader.init(&stmt_msg);
    return stored.fromReader(gpa, stmt_rdr);
}

pub const msg_not_newer = "own emitted statement not strictly newer than previous (isNewerStatement order violated)";
pub const msg_externalize_fork = "own EXTERNALIZE committed a different value than this node's previous own EXTERNALIZE for the slot (fork)";

/// The §10 verdict on one own emission against the previous own statement
/// of the same (slot, protocol): true when `new` is allowed to follow `prev`.
///
/// Strictly newer in the protocol's partial order (stored.isNewerOwned) is
/// always allowed. The one pair that order cannot rank is
/// EXTERNALIZE/EXTERNALIZE — `isNewerOwned` answers false for ANY such pair
/// ("can't have duplicate EXTERNALIZE", the right answer for the STORAGE
/// question it exists for) while the engine legitimately re-emits
/// EXTERNALIZE for one slot with a grown nH as it learns more. What matters
/// for §10 is the COMMITTED VALUE: two own EXTERNALIZEs committing
/// different values for one slot is a fork (the most serious violation this
/// checker can find); same value with different bytes is nH growth and is
/// legal. Same rule as the e2e watchdog (tests/e2e/cluster_test.zig).
/// Everything else — a stale or equal PREPARE/CONFIRM, a backward phase, a
/// nomination whose vote/accepted sets did not grow, protocols mixing — stays
/// strict.
pub fn ownEmissionAllowed(prev: *const stored.OwnedStatement, new: *const stored.OwnedStatement) bool {
    if (stored.isNewerOwned(prev, new)) return true;
    if (prev.pledges == .externalize and new.pledges == .externalize) {
        return std.mem.eql(u8, prev.pledges.externalize.commit.value, new.pledges.externalize.commit.value);
    }
    return false;
}

/// Record an own-emitted statement (from a persist_own_envelope effect).
/// Takes ownership of `st`. Returns a violation if the statement does not
/// strictly supersede the previous own statement of the same protocol
/// (`ownEmissionAllowed`); an EXTERNALIZE/EXTERNALIZE fork gets its own
/// message.
pub fn recordOwnStatement(
    tracker: *Tracker,
    gpa: std.mem.Allocator,
    st: stored.OwnedStatement,
) !?Violation {
    var owned = st;
    const t = tracker.track(gpa, owned.slot) catch |err| {
        owned.deinit(gpa);
        return err;
    };
    const slot_ptr = if (owned.isNomination()) &t.last_own_nom else &t.last_own_ballot;
    if (slot_ptr.*) |*prev| {
        if (!ownEmissionAllowed(prev, &owned)) {
            const fork = prev.pledges == .externalize and owned.pledges == .externalize;
            owned.deinit(gpa);
            return .{ .slot = st.slot, .msg = if (fork) msg_externalize_fork else msg_not_newer };
        }
        prev.deinit(gpa);
    }
    slot_ptr.* = owned;
    return null;
}

/// Record an `externalized` effect for a slot. At most one per slot.
pub fn recordExternalizedEffect(tracker: *Tracker, gpa: std.mem.Allocator, slot: u64) !?Violation {
    const t = try tracker.track(gpa, slot);
    t.externalized_effects += 1;
    if (t.externalized_effects > 1) {
        return .{ .slot = slot, .msg = "externalized effect emitted more than once for a slot" };
    }
    return null;
}

// ---------------------------------------------------------------------------
// Engine-state structural check (after every input)
// ---------------------------------------------------------------------------

fn bv(b: *const stored.OwnedBallot) statement.BallotView {
    return .{ .counter = b.counter, .value = b.value };
}

fn lessAndCompatible(a: statement.BallotView, b: statement.BallotView) bool {
    return statement.compareBallots(a, b) != .gt and statement.areBallotsCompatible(a, b);
}

/// Mirror of the oracle's BallotProtocol::checkInvariants
/// (BallotProtocol.cpp:732-772) plus the cross-input monotonicity checks.
pub fn checkEngine(eng: *const engine.Engine, tracker: *Tracker, gpa: std.mem.Allocator) !?Violation {
    // Effect queue bounded (§13.1). The engine errors before exceeding its
    // own budget; a breach here means the budget discipline broke.
    if (eng.effects.len() > engine.EffectQueue.max_effects) {
        return .{ .slot = 0, .msg = "effect queue exceeded max_effects budget" };
    }

    var it = eng.slots.iterator();
    while (it.next()) |entry| {
        const slot_index = entry.key_ptr.*;
        const s = entry.value_ptr.*;
        const bs = &s.ballot;

        // Phase-implied fields (oracle :734-747).
        switch (bs.phase) {
            .prepare => {},
            .confirm, .externalize => {
                if (bs.current == null or bs.prepared == null or bs.commit == null or bs.high == null) {
                    return .{ .slot = slot_index, .msg = "confirm/externalize phase with unset b/p/c/h" };
                }
            },
        }

        // b.counter >= 1 whenever b is set (oracle :749-752; the counter-0
        // placeholder exists only inside emitted PREPARE frames, never in
        // ballot state).
        if (bs.current) |*b| {
            if (b.counter == 0) return .{ .slot = slot_index, .msg = "current ballot with counter 0" };
        }

        // p' ⋦ p when both set (oracle :753-757).
        if (bs.prepared != null and bs.prepared_prime != null) {
            if (!statement.areBallotsLessAndIncompatible(bv(&bs.prepared_prime.?), bv(&bs.prepared.?))) {
                return .{ .slot = slot_index, .msg = "prepared_prime not less-and-incompatible with prepared" };
            }
        }

        // h ≲ b when h set (oracle :758-763).
        if (bs.high) |*h| {
            if (bs.current == null) return .{ .slot = slot_index, .msg = "high set without current ballot" };
            if (!lessAndCompatible(bv(h), bv(&bs.current.?))) {
                return .{ .slot = slot_index, .msg = "high not less-and-compatible with current" };
            }
        }

        // c ≲ h ≲ b when c set (oracle :764-771).
        if (bs.commit) |*c| {
            if (bs.current == null or bs.high == null) {
                return .{ .slot = slot_index, .msg = "commit set without current/high" };
            }
            if (!lessAndCompatible(bv(c), bv(&bs.high.?))) {
                return .{ .slot = slot_index, .msg = "commit not less-and-compatible with high" };
            }
            if (!lessAndCompatible(bv(&bs.high.?), bv(&bs.current.?))) {
                return .{ .slot = slot_index, .msg = "high not less-and-compatible with current (commit chain)" };
            }
        }

        // Cross-input monotonicity.
        const t = try tracker.track(gpa, slot_index);
        if (bs.current) |*b| {
            if (b.counter < t.max_b_counter) {
                return .{ .slot = slot_index, .msg = "b.counter decreased (monotonicity violated)" };
            }
            t.max_b_counter = b.counter;
        }
        if (@backingInt(bs.phase) < @backingInt(t.phase)) {
            return .{ .slot = slot_index, .msg = "phase moved backwards" };
        }
        t.phase = bs.phase;

        // Externalized value sticky + implies externalize phase reached.
        if (t.externalized_effects > 0 and s.externalized_value == null) {
            return .{ .slot = slot_index, .msg = "externalized effect emitted but slot has no externalized_value" };
        }
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tests: the own-emission rule (synthetic statements through the real
// comparator + tracker) and purge-forgetting.
// ---------------------------------------------------------------------------

const testing = std.testing;

const test_node: [32]u8 = @splat(0x0d);
const test_qsh: [32]u8 = @splat(0xaa);

fn testBallot(gpa: std.mem.Allocator, counter: u32, value: []const u8) !stored.OwnedBallot {
    return .{ .counter = counter, .value = try gpa.dupe(u8, value) };
}

fn testValues(gpa: std.mem.Allocator, vals: []const []const u8) ![][]u8 {
    const out = try gpa.alloc([]u8, vals.len);
    var built: usize = 0;
    errdefer {
        for (out[0..built]) |v| gpa.free(v);
        gpa.free(out);
    }
    for (vals, 0..) |v, i| {
        out[i] = try gpa.dupe(u8, v);
        built += 1;
    }
    return out;
}

fn testNominate(gpa: std.mem.Allocator, slot: u64, votes: []const []const u8, accepted: []const []const u8) !stored.OwnedStatement {
    const v = try testValues(gpa, votes);
    errdefer {
        for (v) |x| gpa.free(x);
        gpa.free(v);
    }
    const a = try testValues(gpa, accepted);
    return .{ .node_id = test_node, .slot = slot, .pledges = .{ .nominate = .{ .qset_hash = test_qsh, .votes = v, .accepted = a } } };
}

fn testPrepare(gpa: std.mem.Allocator, slot: u64, counter: u32, value: []const u8, n_h: u32) !stored.OwnedStatement {
    return .{ .node_id = test_node, .slot = slot, .pledges = .{ .prepare = .{
        .qset_hash = test_qsh,
        .ballot = try testBallot(gpa, counter, value),
        .prepared = null,
        .prepared_prime = null,
        .n_c = 0,
        .n_h = n_h,
    } } };
}

fn testConfirm(gpa: std.mem.Allocator, slot: u64, counter: u32, value: []const u8) !stored.OwnedStatement {
    return .{ .node_id = test_node, .slot = slot, .pledges = .{ .confirm = .{
        .qset_hash = test_qsh,
        .ballot = try testBallot(gpa, counter, value),
        .n_prepared = counter,
        .n_commit = counter,
        .n_h = counter,
    } } };
}

fn testExternalize(gpa: std.mem.Allocator, slot: u64, counter: u32, value: []const u8, n_h: u32) !stored.OwnedStatement {
    return .{ .node_id = test_node, .slot = slot, .pledges = .{ .externalize = .{
        .commit = try testBallot(gpa, counter, value),
        .n_h = n_h,
        .commit_qset_hash = test_qsh,
    } } };
}

// Feed `st` to a tracker and return the violation message (null = accepted).
fn record(tracker: *Tracker, gpa: std.mem.Allocator, st: stored.OwnedStatement) !?[]const u8 {
    const v = try recordOwnStatement(tracker, gpa, st);
    return if (v) |vv| vv.msg else null;
}

// Non-vacuity: the committed-value rule for own EXTERNALIZE pairs. Red if
// the rule is dropped (the same-value nH re-emit is flagged again — the
// class the v0.1.0 RELEASING.md run log records and the e2e watchdog exempts) or over-relaxed
// (the fork stops being flagged, or gets the generic message).
test "own EXTERNALIZE pair: same committed value with grown nH is legal; a different value is a fork" {
    const gpa = testing.allocator;
    var tracker: Tracker = .{};
    defer tracker.deinit(gpa);

    // The legitimate re-emit: EXTERNALIZE(1,"x",nH=5) then (1,"x",nH=8) — the
    // storage order ranks no EXTERNALIZE pair, the §10 rule accepts it.
    {
        var e5 = try testExternalize(gpa, 3, 1, "x", 5);
        defer e5.deinit(gpa);
        var e8 = try testExternalize(gpa, 3, 1, "x", 8);
        defer e8.deinit(gpa);
        try testing.expect(!stored.isNewerOwned(&e5, &e8)); // the storage order ranks no EXTERNALIZE pair …
        try testing.expect(ownEmissionAllowed(&e5, &e8)); // … the §10 verdict accepts same-value growth
    }
    try testing.expectEqual(@as(?[]const u8, null), try record(&tracker, gpa, try testExternalize(gpa, 3, 1, "x", 5)));
    try testing.expectEqual(@as(?[]const u8, null), try record(&tracker, gpa, try testExternalize(gpa, 3, 1, "x", 8)));
    // Byte-identical re-emit (the §10 rebroadcast carve-out shape): legal.
    try testing.expectEqual(@as(?[]const u8, null), try record(&tracker, gpa, try testExternalize(gpa, 3, 1, "x", 8)));

    // The fork: a second own EXTERNALIZE committing a DIFFERENT value.
    try testing.expectEqualStrings(msg_externalize_fork, (try record(&tracker, gpa, try testExternalize(gpa, 3, 1, "y", 8))).?);
    // A fork with a higher counter is still a fork (the value decides).
    try testing.expectEqualStrings(msg_externalize_fork, (try record(&tracker, gpa, try testExternalize(gpa, 3, 9, "y", 9))).?);
    // The slot's baseline is unchanged by the rejected ones: "x" still legal.
    try testing.expectEqual(@as(?[]const u8, null), try record(&tracker, gpa, try testExternalize(gpa, 3, 1, "x", 9)));
    // Going back to CONFIRM after EXTERNALIZE is a backward phase: strict.
    try testing.expectEqualStrings(msg_not_newer, (try record(&tracker, gpa, try testConfirm(gpa, 3, 9, "x"))).?);
}

// Non-vacuity: every OTHER pair keeps the strict isNewerStatement order —
// this is what proves the relaxation is scoped to EXTERNALIZE/EXTERNALIZE.
// Red if ownEmissionAllowed starts accepting a stale PREPARE, an equal
// statement, a backward phase, a non-growing nomination, or mixed protocols.
test "strict order kept: stale/equal PREPARE, backward phase, non-growing NOMINATE, mixed protocols are violations" {
    const gpa = testing.allocator;
    var tracker: Tracker = .{};
    defer tracker.deinit(gpa);

    // Ballot protocol on slot 5.
    try testing.expectEqual(@as(?[]const u8, null), try record(&tracker, gpa, try testPrepare(gpa, 5, 3, "v", 0)));
    try testing.expectEqualStrings(msg_not_newer, (try record(&tracker, gpa, try testPrepare(gpa, 5, 2, "v", 0))).?); // stale PREPARE (b went backwards)
    try testing.expectEqualStrings(msg_not_newer, (try record(&tracker, gpa, try testPrepare(gpa, 5, 3, "v", 0))).?); // equal PREPARE
    try testing.expectEqual(@as(?[]const u8, null), try record(&tracker, gpa, try testPrepare(gpa, 5, 3, "v", 2))); // nH grew: newer
    try testing.expectEqual(@as(?[]const u8, null), try record(&tracker, gpa, try testConfirm(gpa, 5, 3, "v"))); // PREPARE → CONFIRM
    try testing.expectEqualStrings(msg_not_newer, (try record(&tracker, gpa, try testPrepare(gpa, 5, 7, "v", 7))).?); // CONFIRM → PREPARE: backward phase
    try testing.expectEqual(@as(?[]const u8, null), try record(&tracker, gpa, try testExternalize(gpa, 5, 3, "v", 3))); // CONFIRM → EXTERNALIZE
    try testing.expectEqualStrings(msg_not_newer, (try record(&tracker, gpa, try testConfirm(gpa, 5, 9, "v"))).?); // EXTERNALIZE → CONFIRM

    // Nomination protocol on slot 5 (independent of the ballot track).
    try testing.expectEqual(@as(?[]const u8, null), try record(&tracker, gpa, try testNominate(gpa, 5, &.{ "a", "b" }, &.{})));
    try testing.expectEqualStrings(msg_not_newer, (try record(&tracker, gpa, try testNominate(gpa, 5, &.{"a"}, &.{}))).?); // shrink
    try testing.expectEqualStrings(msg_not_newer, (try record(&tracker, gpa, try testNominate(gpa, 5, &.{ "a", "b" }, &.{}))).?); // equal
    try testing.expectEqualStrings(msg_not_newer, (try record(&tracker, gpa, try testNominate(gpa, 5, &.{ "a", "c" }, &.{}))).?); // not a superset
    try testing.expectEqual(@as(?[]const u8, null), try record(&tracker, gpa, try testNominate(gpa, 5, &.{ "a", "b" }, &.{"a"}))); // accepted grew

    // Protocols never mix, in both directions, on a fresh slot.
    try testing.expectEqual(@as(?[]const u8, null), try record(&tracker, gpa, try testNominate(gpa, 6, &.{"a"}, &.{})));
    try testing.expectEqual(@as(?[]const u8, null), try record(&tracker, gpa, try testPrepare(gpa, 6, 1, "a", 0))); // separate track, first ballot statement
    try testing.expect(!ownEmissionAllowed(&(tracker.per_slot.get(6).?.last_own_nom.?), &(tracker.per_slot.get(6).?.last_own_ballot.?)));
    try testing.expect(!ownEmissionAllowed(&(tracker.per_slot.get(6).?.last_own_ballot.?), &(tracker.per_slot.get(6).?.last_own_nom.?)));
}

// Non-vacuity: the S9 fuzz-long class. A NOMINATE whose votes are disjoint
// from the previous own NOMINATE is a violation on a LIVE slot and is NOT
// one after the slot was purged (the engine re-created it from empty
// state). Red if purgeBelow stops forgetting, forgets slots >= max_slot, or
// the live-slot shrink stops being flagged.
test "purgeBelow forgets slots below max_slot: a fresh NOMINATE after the purge is legal; on a live slot it is still a violation" {
    const gpa = testing.allocator;
    var tracker: Tracker = .{};
    defer tracker.deinit(gpa);

    try testing.expectEqual(@as(?[]const u8, null), try record(&tracker, gpa, try testNominate(gpa, 7, &.{"a"}, &.{})));
    try testing.expectEqual(@as(?[]const u8, null), try record(&tracker, gpa, try testNominate(gpa, 8, &.{"a"}, &.{})));
    try testing.expectEqual(@as(?[]const u8, null), try record(&tracker, gpa, try testExternalize(gpa, 7, 1, "x", 1)));
    try testing.expectEqual(@as(u32, 0), tracker.per_slot.get(7).?.externalized_effects);

    // Control (no purge): the disjoint NOMINATE {b} is flagged.
    try testing.expectEqualStrings(msg_not_newer, (try record(&tracker, gpa, try testNominate(gpa, 7, &.{"b"}, &.{}))).?);

    // purge_slots max_slot=8 applied: slot 7 is forgotten, slot 8 is not.
    try tracker.purgeBelow(gpa, 8);
    try testing.expect(tracker.per_slot.get(7) == null);
    try testing.expect(tracker.per_slot.get(8) != null);
    try testing.expectEqual(@as(?[]const u8, null), try record(&tracker, gpa, try testNominate(gpa, 7, &.{"b"}, &.{}))); // fresh slot: legal
    try testing.expectEqualStrings(msg_not_newer, (try record(&tracker, gpa, try testNominate(gpa, 8, &.{"b"}, &.{}))).?); // slot 8 still live: flagged
    // Ballot track of the re-created slot 7 is fresh too (no phase memory).
    try testing.expectEqual(@as(?[]const u8, null), try record(&tracker, gpa, try testPrepare(gpa, 7, 1, "y", 0)));
    // A purge below every tracked slot is a no-op.
    try tracker.purgeBelow(gpa, 0);
    try testing.expectEqual(@as(usize, 2), tracker.per_slot.count());
}
