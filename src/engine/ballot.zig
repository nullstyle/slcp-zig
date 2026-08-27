//! Ballot protocol (design §5.4 ballot.zig bullet) — M2.
//! State skeleton pinned in phase 0; the advanceSlot pipeline
//! (attemptAcceptPrepared → attemptConfirmPrepared → attemptAcceptCommit →
//! attemptConfirmCommit, attemptBump, checkHeardFromQuorum) is transcribed
//! from stellar-core BallotProtocol.cpp by the M2 ballot agent.

const std = @import("std");
const stored = @import("stored.zig");

pub const Phase = enum(u2) { prepare, confirm, externalize };

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
    value_override: ?[]u8 = null,

    pub fn deinit(self: *State, gpa: std.mem.Allocator) void {
        inline for (.{ &self.current, &self.prepared, &self.prepared_prime, &self.high, &self.commit }) |slot_ptr| {
            if (slot_ptr.*) |*b| b.deinit(gpa);
        }
        if (self.value_override) |v| gpa.free(v);
        self.* = undefined;
    }
};

pub const max_advance_recursion: u32 = 50;

// --- M2 protocol entry points (implemented by the ballot agent; ---
// --- signatures are the pinned contract for pipeline.zig / nomination.zig) ---

const engine_mod = @import("engine.zig");
const slot_mod = @import("slot.zig");

/// Process a fresh (freshness-checked, stored) peer ballot statement.
pub fn processEnvelope(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, st: *const stored.OwnedStatement) !void {
    _ = ctx;
    _ = s;
    _ = st;
    return error.NotImplemented;
}

/// Nomination hands over a (new) composite candidate value; force bumps
/// even without a current ballot (stellar-core bumpState semantics).
pub fn bumpState(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, value: []const u8, force: bool) !bool {
    _ = ctx;
    _ = s;
    _ = value;
    _ = force;
    return error.NotImplemented;
}

/// Ballot timer fired: abandon the current ballot (bump counter).
pub fn timerFired(ctx: *engine_mod.Ctx, s: *slot_mod.Slot) !void {
    _ = ctx;
    _ = s;
    return error.NotImplemented;
}

/// restore_own_envelope replay (stellar-core setStateFromEnvelope semantics).
pub fn setStateFromEnvelope(ctx: *engine_mod.Ctx, s: *slot_mod.Slot, st: *const stored.OwnedStatement) !void {
    _ = ctx;
    _ = s;
    _ = st;
    return error.NotImplemented;
}
