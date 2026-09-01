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
//!     (slot, protocol), tracked from persist_own_envelope effects
//!   - effect queue bounded (the engine's own budget must never be exceeded)
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

/// Record an own-emitted statement (from a persist_own_envelope effect).
/// Takes ownership of `st`. Returns a violation if the statement does not
/// strictly supersede the previous own statement of the same protocol.
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
        if (!stored.isNewerOwned(prev, &owned)) {
            owned.deinit(gpa);
            return .{ .slot = st.slot, .msg = "own emitted statement not strictly newer than previous (isNewerStatement order violated)" };
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
