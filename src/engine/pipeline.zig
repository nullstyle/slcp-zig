//! The envelope/input pipeline (design §5 intro, §5.2/§5.3, M2): decode →
//! sanity → signature verify → strictCanonical → relevance filter → slot
//! admission → freshness → qset resolution/parking → stored-bytes budget →
//! protocol precheck → qset-reference capacity → store/dispatch/forward —
//! and exactly ONE input_status per input, ALWAYS
//! pushed as the final effect of its drain (§5.3).
//!
//! Receive-path order for envelope_received (§4.2 with the one mechanical
//! reordering the design permits: the statement must be decoded before the
//! signature can be checked, because the verifying key IS statement.nodeId):
//!   1. frame cap (§4.5) → insane
//!   2. validating decode of the Envelope frame (§4.5 ValidationOptions,
//!      nesting 32, traversal scaled to the frame cap) → insane
//!   3. statementBytes cap / signature length → insane
//!   4. validating flat decode of statementBytes (Message.initFlat) → insane
//!   5. checkStatementSane → insane
//!   6. Ed25519 verify over the RECEIVED statementBytes (§4.2; wrong-network
//!      envelopes implicitly fail — their digests differ) → invalid_signature
//!   7. strictCanonical structural walk on the SAME parse (§4.2) → insane
//!   8. relevance: sender outside the published transitive quorum graph (§5.4) →
//!      ignored; for an unknown-qset envelope during a conservative generation,
//!      advance the generation and recheck before slot admission (an exact
//!      checkpoint can change the result to ignored)
//!   9. slot admission (max_live_slots; existing slots always accept) →
//!      over_limit
//!  10. freshness vs the per-(node, protocol) latest via stored.isNewerOwned
//!      (§5.4 partial orders) → stale
//!  11. qset resolution: unknown non-EXTERNALIZE qset hash parks (§5.4;
//!      EXTERNALIZE never parks — singleton qset) → parked_awaiting_qset /
//!      over_limit (per-node cap); evictions of PAST inputs emit
//!      phase_event(parked_evicted), never a second input_status
//!  12. stored-bytes budget (§5.1 max_stored_statement_bytes) → over_limit
//!  13. ballot protocol/value rejection before replacement → insane
//!  14. exact live-statement qset-reference capacity → over_limit
//!  15. storeLatest + replace its exact live-statement qset reference +
//!      protocol dispatch + forward_envelope (freshness advanced ⇒ relay,
//!      §5.3) → applied
//!
//! Failure discipline (§7.2): any EffectQueue budget breach, OOM, or
//! non-protocol error marks the engine failed (sticky); pushInput then
//! always returns error.EngineFailed.

const std = @import("std");
const capnpc = @import("capnpc-zig");
const canonical = @import("../canonical.zig");
const crypto = @import("../crypto.zig");
const gen_slcp = @import("../gen/slcp.zig");
const ballot_mod = @import("ballot.zig");
const engine = @import("engine.zig");
const limits_mod = @import("limits.zig");
const nomination_mod = @import("nomination.zig");
const qset = @import("qset.zig");
const slot_mod = @import("slot.zig");
const statement_mod = @import("statement.zig");
const stored = @import("stored.zig");

// (The M2-integration protocol_stubs marker is gone: nomination.zig and
// ballot.zig are real; any error.NotImplemented is now an engine fault.)

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// §5.1 pushInput: exactly one InputStatus per input, pushed LAST.
pub fn pushInput(eng: *engine.Engine, input: engine.Input) engine.PushError!void {
    if (eng.failed) return error.EngineFailed;
    fixupCtx(eng);
    const status = run(eng, input) catch |err| {
        eng.failed = true; // sticky (§7.2)
        return err;
    };
    eng.effects.push(.{ .input_status = .{ .code = status } }) catch |err| {
        eng.failed = true;
        return err;
    };
}

/// Engine.init returns the Engine by value, so the self-referential pointers
/// in ctx (cfg/drv/effects/qsets/excised) can dangle after the move. The
/// pipeline re-anchors them against the Engine's current address before
/// every input; local_qset_hash is a plain value and survives the move.
fn fixupCtx(eng: *engine.Engine) void {
    eng.ctx.gpa = eng.gpa;
    eng.ctx.cfg = &eng.cfg;
    eng.ctx.drv = &eng.drv;
    eng.ctx.effects = &eng.effects;
    eng.ctx.qsets = &eng.qsets;
    eng.ctx.excised = if (eng.excised) |*e| e else null;
    eng.ctx.stored_bytes = &eng.stored_statement_bytes;
}

fn run(eng: *engine.Engine, input: engine.Input) engine.EngineError!engine.InputStatus {
    return switch (input) {
        .envelope_received => |a| handleEnvelope(eng, a.bytes),
        .timer_fired => |a| handleTimer(eng, a.slot, a.timer),
        .nominate => |a| handleNominate(eng, a.slot, a.value, a.prev_value),
        .qset_received => |a| handleQset(eng, a.bytes),
        .restore_own_envelope => |a| handleRestore(eng, a.bytes),
        .purge_slots => |a| handlePurge(eng, a.max_slot),
    };
}

// ---------------------------------------------------------------------------
// Protocol-dispatch error mapping (§7.2 + the protocol_stubs carve-out)
// ---------------------------------------------------------------------------

fn protoResult(r: anyerror!void) engine.EngineError!void {
    r catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.EffectBudgetExceeded => return error.EffectBudgetExceeded,
        else => return error.EngineFailed,
    };
}

fn protoBool(r: anyerror!bool, stub_default: bool) engine.EngineError!bool {
    _ = stub_default;
    return r catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.EffectBudgetExceeded => return error.EffectBudgetExceeded,
        else => return error.EngineFailed,
    };
}

// ---------------------------------------------------------------------------
// Shared decode (envelope_received + restore_own_envelope, §4.2/§4.5)
// ---------------------------------------------------------------------------

/// §4.5: every network decode is validating — nesting limit 32, traversal
/// limit scaled to the 1 MiB frame cap. Never initUnvalidated.
fn frameOptions() canonical.ValidationOptions {
    return .{
        .nesting_limit = 32,
        .traversal_limit_words = limits_mod.frozen_max_frame_bytes / 8,
    };
}

/// Same policy for the flat statementBytes parse, scaled to the 256 KiB
/// statement cap.
fn stmtOptions() canonical.ValidationOptions {
    return .{
        .nesting_limit = 32,
        .traversal_limit_words = limits_mod.frozen_max_statement_bytes / 8,
    };
}

const DecodeError = error{ Insane, OutOfMemory };

/// A decoded envelope: both Messages BORROW the caller's input frame bytes
/// (zero-copy), so the frame must outlive this struct. `stmt_bytes` aliases
/// the frame; readers are re-created on demand so the struct can be moved.
const DecodedEnvelope = struct {
    env_msg: capnpc.message.Message,
    stmt_msg: capnpc.message.Message,
    stmt_bytes: []const u8,
    signature: [64]u8,

    fn statement(self: *const DecodedEnvelope) !gen_slcp.Statement.Reader {
        return gen_slcp.Statement.Reader.init(&self.stmt_msg);
    }

    fn deinit(self: *DecodedEnvelope) void {
        self.stmt_msg.deinit();
        self.env_msg.deinit();
        self.* = undefined;
    }
};

fn mapDecode(err: anyerror) DecodeError {
    return if (err == error.OutOfMemory) error.OutOfMemory else error.Insane;
}

/// Steps 1–5 of the receive path: frame cap, validating envelope decode,
/// statementBytes/signature extraction + caps, validating flat statement
/// decode, checkStatementSane. Everything that maps to `insane`.
fn decodeEnvelope(gpa: std.mem.Allocator, bytes: []const u8, l: limits_mod.Limits) DecodeError!DecodedEnvelope {
    if (bytes.len > limits_mod.frozen_max_frame_bytes) return error.Insane;

    var env_msg = capnpc.message.Message.init(gpa, bytes, frameOptions()) catch |err| return mapDecode(err);
    errdefer env_msg.deinit();
    const env_rdr = gen_slcp.Envelope.Reader.init(&env_msg) catch return error.Insane;

    const stmt_bytes = env_rdr.getStatementBytes() catch return error.Insane;
    if (stmt_bytes.len == 0 or stmt_bytes.len > limits_mod.frozen_max_statement_bytes) return error.Insane;
    const sig_bytes = env_rdr.getSignature() catch return error.Insane;
    if (sig_bytes.len != 64) return error.Insane;
    var sig: [64]u8 = undefined;
    @memcpy(&sig, sig_bytes);

    var stmt_msg = canonical.decodeFlat(gpa, stmt_bytes, stmtOptions()) catch |err| return mapDecode(err);
    errdefer stmt_msg.deinit();
    const stmt_rdr = gen_slcp.Statement.Reader.init(&stmt_msg) catch return error.Insane;
    if (statement_mod.checkStatementSane(stmt_rdr, l) != null) return error.Insane;

    return .{ .env_msg = env_msg, .stmt_msg = stmt_msg, .stmt_bytes = stmt_bytes, .signature = sig };
}

// ---------------------------------------------------------------------------
// Slot admission
// ---------------------------------------------------------------------------

/// Get or create the slot. Returns null when creation would breach
/// max_live_slots (→ over_limit). Existing slots — including already
/// externalized ones — always accept (they keep answering laggards).
fn getOrCreateSlot(eng: *engine.Engine, index: u64) !?*slot_mod.Slot {
    if (eng.slots.get(index)) |p| return p;
    if (eng.slots.count() >= eng.cfg.limits.max_live_slots) return null;
    const p = try eng.gpa.create(slot_mod.Slot);
    errdefer eng.gpa.destroy(p);
    p.* = slot_mod.Slot.init(index);
    try eng.slots.put(eng.gpa, index, p);
    return p;
}

// ---------------------------------------------------------------------------
// Post-resolution half: budget → retain qset → store → dispatch → forward.
// Shared by the live envelope path and the qset_received unpark replay.
// ---------------------------------------------------------------------------

/// All statement-local rejection must happen in the pre-store gate below so
/// replacing a sender's previous statement is transactional. InvalidValue at
/// this point means that gate and the protocol have drifted apart; fail the
/// engine closed instead of trying to reconstruct the overwritten state.
fn dispatchProtocol(eng: *engine.Engine, s: *slot_mod.Slot, st: *const stored.OwnedStatement) engine.EngineError!void {
    const r = if (st.isNomination())
        nomination_mod.processEnvelope(&eng.ctx, s, st)
    else
        ballot_mod.processEnvelope(&eng.ctx, s, st);
    r catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.EffectBudgetExceeded => return error.EffectBudgetExceeded,
        error.InvalidValue => return error.EngineFailed,
        else => return error.EngineFailed,
    };
}

/// Steps 12–15. Takes ownership of `env` unconditionally. Reports a budget,
/// qset-capacity, or value rejection without replacing the prior statement.
const Admit = enum { admitted, over_budget, over_qset_capacity, value_invalid };

/// The cache reference owned by one stored statement. Local statements use
/// the configured qset directly, and EXTERNALIZE uses a synthetic singleton,
/// so neither contributes a remote cache reference.
fn statementQsetReference(eng: *const engine.Engine, st: *const stored.OwnedStatement) ?[32]u8 {
    if (std.mem.eql(u8, &st.node_id, &eng.cfg.node_id)) return null;
    if (st.pledges == .externalize) return null;
    return st.qsetHash();
}

fn admitResolved(eng: *engine.Engine, s: *slot_mod.Slot, env: stored.StoredEnvelope) engine.EngineError!Admit {
    var owned = env;
    const gpa = eng.gpa;
    const node = owned.statement.node_id;
    const is_nom = owned.statement.isNomination();
    const old_ref = if (s.latestFor(node, is_nom)) |old|
        statementQsetReference(eng, &old.statement)
    else
        null;
    const new_ref = statementQsetReference(eng, &owned.statement);

    // §5.1 engine-wide latest-envelope budget: projected size after the
    // replace must fit, else over_limit (drop, do not store).
    const new_size: isize = @intCast(owned.byteSize());
    const old_size: isize = if (s.latestFor(node, is_nom)) |old| @intCast(old.byteSize()) else 0;
    const projected = @as(isize, @intCast(eng.stored_statement_bytes)) + new_size - old_size;
    if (projected > @as(isize, @intCast(eng.cfg.limits.max_stored_statement_bytes))) {
        owned.deinit(gpa);
        return .over_budget;
    }

    // ORACLE ORDER (BallotProtocol.cpp:189-249): driver validation precedes
    // recording — a driver-invalid PREPARE is rejected WITHOUT storing, so
    // the sender's previous statement stays in the voting universe.
    if (!is_nom) {
        const rejects = ballot_mod.statementRejectsPreStore(&eng.ctx, s, &owned.statement) catch |err| {
            owned.deinit(gpa);
            // exhaustive: a new error in the gate's set must be mapped here
            return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
            };
        };
        if (rejects) {
            owned.deinit(gpa);
            return .value_invalid;
        }
    }

    if (!eng.qsets.canReplaceStatementReference(old_ref, new_ref)) {
        owned.deinit(gpa);
        return .over_qset_capacity;
    }

    const delta = try s.storeLatest(gpa, owned);
    eng.stored_statement_bytes = @intCast(@as(isize, @intCast(eng.stored_statement_bytes)) + delta);
    try eng.qsets.replaceStatementReference(node, old_ref, new_ref);
    const kept = s.latestFor(node, is_nom).?;

    // Process BEFORE relaying (stellar-core broadcasts only VALID
    // envelopes). Current protocol-invalid paths are exhausted by the gate
    // above. A residual InvalidValue is therefore an invariant failure and
    // dispatchProtocol makes the engine sticky-failed rather than losing the
    // previous statement through a partial rollback.
    try dispatchProtocol(eng, s, &kept.statement);

    // Freshness advanced + processed ⇒ relay (§5.3): engine freshness IS
    // the dedup.
    const fwd = try gpa.dupe(u8, kept.envelope_framed);
    try eng.effects.push(.{ .forward_envelope = .{ .slot = s.index, .bytes = fwd } });
    return .admitted;
}

// ---------------------------------------------------------------------------
// envelope_received (§4.2 / §5.4)
// ---------------------------------------------------------------------------

fn handleEnvelope(eng: *engine.Engine, bytes: []const u8) engine.EngineError!engine.InputStatus {
    const gpa = eng.gpa;

    // Steps 1–5: decode + sanity.
    var dec = decodeEnvelope(gpa, bytes, eng.cfg.limits) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Insane => return .insane,
    };
    defer dec.deinit();
    const rdr = dec.statement() catch return .insane;
    const nid = rdr.getNodeId() catch return .insane;
    if (nid.len != 32) return .insane; // guaranteed by sanity; defense in depth
    var node: [32]u8 = undefined;
    @memcpy(&node, nid);

    // Step 6: signature over the RECEIVED statementBytes (§4.2). A
    // wrong-network envelope fails here — its digest differs.
    const digest = crypto.statementDigest(eng.cfg.network_id, dec.stmt_bytes);
    if (!crypto.verify(node, digest, dec.signature)) return .invalid_signature;

    // Step 7: §4.2 receive-side canonicality — a cheap structural walk on
    // the SAME parse, no re-canonicalization.
    if (eng.cfg.strict_canonical and !capnpc.canonical.isCanonical(&dec.stmt_msg)) return .insane;

    // Step 8: §5.4 relevance filter — outside the published graph. The graph
    // can temporarily be a conservative superset, never a subset.
    if (!eng.qsets.inGraph(node)) return .ignored;

    var owned = stored.fromReader(gpa, rdr) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .insane, // sane statements decode; defense in depth
    };

    const qset_hash = owned.qsetHash();
    const is_ext = owned.pledges == .externalize;
    if (!is_ext and eng.qsets.get(qset_hash) == null) {
        const still_relevant = eng.qsets.recheckBeforeParking(node) catch |err| {
            owned.deinit(gpa);
            return err;
        };
        if (!still_relevant) {
            owned.deinit(gpa);
            return .ignored;
        }
    }

    // Step 9: slot admission.
    const s = (getOrCreateSlot(eng, owned.slot) catch |err| {
        owned.deinit(gpa);
        return err;
    }) orelse {
        owned.deinit(gpa);
        return .over_limit;
    };

    // Step 10: freshness (stored.isNewerOwned — §5.4 partial orders).
    const is_nom = owned.isNomination();
    if (s.latestFor(node, is_nom)) |old| {
        if (!stored.isNewerOwned(&old.statement, &owned)) {
            owned.deinit(gpa);
            return .stale;
        }
    }

    // Step 11: qset resolution. EXTERNALIZE never parks (§5.4).
    if (!is_ext and eng.qsets.get(qset_hash) == null) {
        const frame_copy = gpa.dupe(u8, bytes) catch |err| {
            owned.deinit(gpa);
            return err;
        };
        const env = stored.StoredEnvelope{ .envelope_framed = frame_copy, .statement = owned };
        var evicted: std.ArrayList(u64) = .empty;
        defer evicted.deinit(gpa);
        // park() takes ownership of env even on rejection.
        const parked = try eng.pending.park(qset_hash, env, &evicted);
        // Evicting a PAST input must not consume this input's 1:1
        // input_status — evictions are phase events (§5.4).
        for (evicted.items) |victim_slot| {
            try eng.ctx.phaseEvent(victim_slot, .parked_evicted, 0);
        }
        if (!parked) return .over_limit; // per-node parking cap
        try eng.effects.push(.{ .request_qset = .{ .hash = qset_hash } });
        return .parked_awaiting_qset;
    }

    // Steps 12–13.
    const frame_copy = gpa.dupe(u8, bytes) catch |err| {
        owned.deinit(gpa);
        return err;
    };
    const env = stored.StoredEnvelope{ .envelope_framed = frame_copy, .statement = owned };
    return switch (try admitResolved(eng, s, env)) {
        .admitted => .applied,
        .over_budget => .over_limit,
        .over_qset_capacity => .over_limit,
        // Driver/protocol-invalid value: rejected before replacement; the
        // sender's prior statement and exact qset reference remain live. The
        // closest §5.2 status is insane (unusable as received).
        .value_invalid => .insane,
    };
}

// ---------------------------------------------------------------------------
// qset_received (§5.4 parking + unpark)
// ---------------------------------------------------------------------------

fn handleQset(eng: *engine.Engine, bytes: []const u8) engine.EngineError!engine.InputStatus {
    const gpa = eng.gpa;

    if (bytes.len > limits_mod.frozen_max_frame_bytes) return .insane;
    var msg = capnpc.message.Message.init(gpa, bytes, frameOptions()) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .insane,
    };
    defer msg.deinit();
    const rdr = gen_slcp.QuorumSet.Reader.init(&msg) catch return .insane;

    var qs = qset.fromReader(gpa, rdr) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .insane,
    };
    qset.validateAndNormalize(gpa, &qs) catch |err| {
        qs.deinit(gpa);
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => .insane, // rejected, not repaired (§4.3)
        };
    };

    // The store never trusts a claimed hash: the engine recomputes (§4.3);
    // the requester knows what it asked for by this recomputed key.
    const h = qset.hashNormalized(gpa, &qs) catch |err| {
        qs.deinit(gpa);
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => .insane,
        };
    };
    eng.qsets.retain(h) catch |err| {
        qs.deinit(gpa);
        return err;
    };
    defer eng.qsets.release(h);
    try eng.qsets.insert(h, qs); // takes ownership; dedups

    // Unpark: re-drive every envelope waiting on this hash through the
    // post-resolution half. Parked envelopes were FULLY verified (decode,
    // sanity, signature, canonicality, relevance) before parking — no
    // re-verification. Replays carry NO input_status of their own (§5.3 1:1
    // rule); a replay that now fails admission is dropped silently.
    const taken = try eng.pending.take(h);
    defer gpa.free(taken);
    var remaining = taken.len;
    defer for (taken[0..remaining]) |*env| env.deinit(gpa);

    // A qset response may unlock the entire pending-envelope cap. All replay
    // happens inside this input, and protocol quorum lookup uses each exact
    // statement qset rather than the relevance graph, so publish one exact
    // post-replay graph instead of rebuilding after every replacement.
    eng.qsets.beginReferenceBatch();

    // Usually this is a FIFO pass. At a full cache an earlier waiter may be
    // blocked until a later statement rotates an old live qset to this hash.
    // Ordered in-place removal preserves FIFO among currently eligible items
    // while permitting that bounded one-entry transition to complete.
    while (remaining > 0) {
        var progressed = false;
        var i: usize = 0;
        while (i < remaining) {
            if (!canReplayQsetReference(eng, &taken[i])) {
                i += 1;
                continue;
            }
            const env = taken[i];
            var shift = i;
            while (shift + 1 < remaining) : (shift += 1) {
                taken[shift] = taken[shift + 1];
            }
            remaining -= 1;
            progressed = true;
            try replayParked(eng, env);
            break; // restart at the oldest waiter after every state change
        }
        if (!progressed) break;
    }
    try eng.qsets.finishReferenceBatch();

    // The sans-I/O Engine has no request ledger: direct hosts may pre-warm it
    // with any valid qset. Native Node correlates network responses with an
    // outstanding request before it constructs this input.
    return .applied;
}

/// Slot admission, freshness, and the post-resolution half for one replayed
/// envelope. Takes ownership; drops silently on any admission failure.
fn replayParked(eng: *engine.Engine, env: stored.StoredEnvelope) engine.EngineError!void {
    var owned_env = env;
    const gpa = eng.gpa;
    const s = (getOrCreateSlot(eng, owned_env.statement.slot) catch |err| {
        owned_env.deinit(gpa);
        return err;
    }) orelse {
        owned_env.deinit(gpa);
        return; // live-slot cap: drop
    };
    const node = owned_env.statement.node_id;
    const is_nom = owned_env.statement.isNomination();
    if (s.latestFor(node, is_nom)) |old| {
        if (!stored.isNewerOwned(&old.statement, &owned_env.statement)) {
            owned_env.deinit(gpa);
            return; // superseded while parked: drop
        }
    }
    _ = try admitResolved(eng, s, owned_env); // budget rejection: drop
}

fn canReplayQsetReference(eng: *engine.Engine, env: *const stored.StoredEnvelope) bool {
    const new_ref = statementQsetReference(eng, &env.statement) orelse return true;
    const s = eng.slots.get(env.statement.slot) orelse {
        return eng.qsets.canReplaceStatementReference(null, new_ref);
    };
    const is_nom = env.statement.isNomination();
    const old = s.latestFor(env.statement.node_id, is_nom) orelse {
        return eng.qsets.canReplaceStatementReference(null, new_ref);
    };
    if (!stored.isNewerOwned(&old.statement, &env.statement)) return true;
    return eng.qsets.canReplaceStatementReference(
        statementQsetReference(eng, &old.statement),
        new_ref,
    );
}

// ---------------------------------------------------------------------------
// nominate / timer_fired
// ---------------------------------------------------------------------------

fn handleNominate(eng: *engine.Engine, slot_index: u64, value: []const u8, prev_value: []const u8) engine.EngineError!engine.InputStatus {
    // Watcher mode: full tracking, zero emissions (§5.1) — proposing is not
    // legal, not fatal.
    if (eng.ctx.isWatcher()) return .ignored;
    const s = (try getOrCreateSlot(eng, slot_index)) orelse return .over_limit;
    const advanced = try protoBool(nomination_mod.nominate(&eng.ctx, s, value, prev_value), true);
    return if (advanced) .applied else .ignored;
}

fn handleTimer(eng: *engine.Engine, slot_index: u64, timer: engine.TimerId) engine.EngineError!engine.InputStatus {
    // A timer for a purged (or never-created) slot is stale — ignored.
    const s = eng.slots.get(slot_index) orelse return .ignored;
    switch (timer) {
        .nomination => try protoResult(nomination_mod.timerFired(&eng.ctx, s)),
        .ballot => try protoResult(ballot_mod.timerFired(&eng.ctx, s)),
    }
    return .applied;
}

// ---------------------------------------------------------------------------
// restore_own_envelope (§10)
// ---------------------------------------------------------------------------

fn handleRestore(eng: *engine.Engine, bytes: []const u8) engine.EngineError!engine.InputStatus {
    const gpa = eng.gpa;

    // Decode exactly like envelope_received through sanity.
    var dec = decodeEnvelope(gpa, bytes, eng.cfg.limits) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Insane => return .insane,
    };
    defer dec.deinit();
    const rdr = dec.statement() catch return .insane;
    const nid = rdr.getNodeId() catch return .insane;
    if (nid.len != 32) return .insane;
    var node: [32]u8 = undefined;
    @memcpy(&node, nid);

    // §10: only OWN statements restore.
    if (!std.mem.eql(u8, &node, &eng.cfg.node_id)) return .ignored;

    // The own log needs no re-verification in principle (we wrote it), but
    // the check is cheap and catches corruption the host's CRC missed —
    // verify anyway. strictCanonical is skipped: own emissions are canonical
    // by construction and §10 replays them byte-identically.
    const digest = crypto.statementDigest(eng.cfg.network_id, dec.stmt_bytes);
    if (!crypto.verify(node, digest, dec.signature)) return .invalid_signature;

    var owned = stored.fromReader(gpa, rdr) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .insane,
    };
    const slot_index = owned.slot;
    const is_nom = owned.isNomination();

    const s = (getOrCreateSlot(eng, slot_index) catch |err| {
        owned.deinit(gpa);
        return err;
    }) orelse {
        owned.deinit(gpa);
        return .over_limit;
    };

    // Protocol state replay (stellar-core setStateFromEnvelope semantics).
    {
        errdefer owned.deinit(gpa);
        if (is_nom) {
            try protoResult(nomination_mod.setStateFromEnvelope(&eng.ctx, s, &owned));
        } else {
            try protoResult(ballot_mod.setStateFromEnvelope(&eng.ctx, s, &owned));
        }
    }

    // Store as the slot's own_* AND as our per-node latest (peers see our
    // rebroadcast as the latest too). Own restores bypass the stored-bytes
    // over_limit gate — the own log is bounded by the answering window — but
    // still count toward the budget accounting.
    var own_stmt = stored.fromReader(gpa, rdr) catch |err| switch (err) {
        error.OutOfMemory => {
            owned.deinit(gpa);
            return error.OutOfMemory;
        },
        else => {
            owned.deinit(gpa);
            return .insane;
        },
    };
    const frame_latest = gpa.dupe(u8, bytes) catch |err| {
        owned.deinit(gpa);
        own_stmt.deinit(gpa);
        return err;
    };
    const frame_own = gpa.dupe(u8, bytes) catch |err| {
        owned.deinit(gpa);
        own_stmt.deinit(gpa);
        gpa.free(frame_latest);
        return err;
    };

    const latest_env = stored.StoredEnvelope{ .envelope_framed = frame_latest, .statement = owned };
    // storeLatest owns latest_env on every path (it frees it on failure),
    // but frame_own / own_stmt are only handed to the slot below: free them
    // here and ONLY here (after the hand-off the slot owns them, and
    // effects.push owns `bcast` even on failure).
    const delta = s.storeLatest(gpa, latest_env) catch |err| {
        gpa.free(frame_own);
        own_stmt.deinit(gpa);
        return err;
    };
    eng.stored_statement_bytes = @intCast(@as(isize, @intCast(eng.stored_statement_bytes)) + delta);

    const own_env = stored.StoredEnvelope{ .envelope_framed = frame_own, .statement = own_stmt };
    if (is_nom) {
        if (s.own_nom) |*o| o.deinit(gpa);
        s.own_nom = own_env;
    } else {
        if (s.own_ballot) |*o| o.deinit(gpa);
        s.own_ballot = own_env;
    }

    // §10 carve-out: byte-identical rebroadcast of the restored latest
    // envelope — broadcast ONLY, no persist (it is already durable; peers
    // treat the duplicate as stale and drop it).
    const bcast = try gpa.dupe(u8, bytes);
    try eng.effects.push(.{ .broadcast_envelope = .{ .slot = slot_index, .bytes = bcast } });

    return .applied;
}

// ---------------------------------------------------------------------------
// purge_slots (§10 GC / answering window)
// ---------------------------------------------------------------------------

fn handlePurge(eng: *engine.Engine, max_slot: u64) engine.EngineError!engine.InputStatus {
    const gpa = eng.gpa;
    var victims: std.ArrayList(u64) = .empty;
    defer victims.deinit(gpa);
    var qset_refs: std.ArrayList(qset_store.StatementReference) = .empty;
    defer qset_refs.deinit(gpa);
    var it = eng.slots.iterator();
    while (it.next()) |entry| {
        if (entry.key_ptr.* < max_slot) try victims.append(gpa, entry.key_ptr.*);
    }

    // Gather before mutating anything so allocation failure in this phase
    // leaves both ownership domains unchanged. The following batch mutates
    // references before staging its rebuilt graph; an OOM there is terminal
    // (Engine becomes sticky-failed), but retains every qset and remains safe
    // to deinit. Retire the window with only one graph rebuild.
    for (victims.items) |k| {
        const p = eng.slots.get(k).?;
        inline for (.{ &p.latest_nom, &p.latest_ballot }) |latest| {
            var statements = latest.valueIterator();
            while (statements.next()) |boxed| {
                if (statementQsetReference(eng, &boxed.*.statement)) |hash| {
                    try qset_refs.append(gpa, .{ .node = boxed.*.statement.node_id, .hash = hash });
                }
            }
        }
    }
    try eng.qsets.removeStatementReferences(qset_refs.items);

    for (victims.items) |k| {
        if (eng.slots.fetchSwapRemove(k)) |kv| {
            const p = kv.value;
            // Saturating: the counter is maintained incrementally by the
            // pipeline AND by protocol self-stores (Ctx.addStoredBytes); a
            // future accounting slip must degrade, never underflow.
            eng.stored_statement_bytes -|= p.storedBytes();
            p.deinit(gpa);
            gpa.destroy(p);
        }
    }
    eng.pending.purgeBelow(max_slot);
    return .applied;
}

// ---------------------------------------------------------------------------
// Tests — every InputStatus code reached, input_status ALWAYS last.
// Peer envelopes are fabricated through emit.emit with peer seeds.
// ---------------------------------------------------------------------------

const testing = std.testing;
const emit = @import("emit.zig");
const qset_store = @import("qset_store.zig");
const driver_mod = @import("../driver.zig");

const engine_seed: [32]u8 = @splat(1);
const peer_seed: [32]u8 = @splat(2);
const peer2_seed: [32]u8 = @splat(3);
const peer3_seed: [32]u8 = @splat(4);
const outsider_seed: [32]u8 = @splat(9);

fn testNet() [32]u8 {
    return crypto.networkIdFromPassphrase("pipeline-test-net");
}

fn ownedQsetOf(gpa: std.mem.Allocator, threshold: u32, members: []const [32]u8) !qset.QuorumSetOwned {
    const vals = try gpa.alloc(qset.NodeId, members.len);
    errdefer gpa.free(vals);
    @memcpy(vals, members);
    var qs = qset.QuorumSetOwned{
        .threshold = threshold,
        .validators = vals,
        .inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0),
    };
    try qset.validateAndNormalize(gpa, &qs);
    return qs;
}

fn qsetHashOf(gpa: std.mem.Allocator, threshold: u32, members: []const [32]u8) ![32]u8 {
    var qs = try ownedQsetOf(gpa, threshold, members);
    defer qs.deinit(gpa);
    return qset.hashNormalized(gpa, &qs);
}

/// Framed wire QuorumSet bytes for a qset_received input.
fn framedQset(gpa: std.mem.Allocator, threshold: u32, members: []const [32]u8) ![]const u8 {
    var mb = capnpc.message.MessageBuilder.init(gpa);
    defer mb.deinit();
    var b = try gen_slcp.QuorumSet.Builder.init(&mb);
    try b.setThreshold(threshold);
    const vl = try b.initValidators(@intCast(members.len));
    for (members, 0..) |m, i| {
        const mm = m;
        try vl.set(@intCast(i), &mm);
    }
    return mb.toBytes();
}

const EngineOpts = struct {
    watcher: bool = false,
    strict: bool = true,
    quorum_threshold: u32 = 1,
    limits: limits_mod.Limits = .{},
};

/// Engine whose local qset is {1, [self, peer, peer2, peer3]} — all test
/// peers are in the published transitive quorum graph.
fn makeEngine(gpa: std.mem.Allocator, opts: EngineOpts) !engine.Engine {
    const node_id = try crypto.publicKeyFromSeed(engine_seed);
    const members = [_][32]u8{
        node_id,
        try crypto.publicKeyFromSeed(peer_seed),
        try crypto.publicKeyFromSeed(peer2_seed),
        try crypto.publicKeyFromSeed(peer3_seed),
    };
    const qs = try ownedQsetOf(gpa, opts.quorum_threshold, &members);
    return engine.Engine.init(gpa, .{
        .network_id = testNet(),
        .node_id = node_id,
        .secret_seed = if (opts.watcher) null else engine_seed,
        .quorum_set = qs,
        .strict_canonical = opts.strict,
        .limits = opts.limits,
    }, driver_mod.Driver.default());
}

/// Build a signed Envelope frame from `seed`'s keypair via emit (a stand-in
/// peer Ctx). Caller frees.
fn peerEnvelope(gpa: std.mem.Allocator, seed: [32]u8, slot: u64, own: emit.OwnStatement) ![]u8 {
    var effects = engine.EffectQueue.init(gpa);
    defer effects.deinit();
    var store = qset_store.Store.init(gpa, 4);
    defer store.deinit();
    const cfg = engine.Config{
        .network_id = testNet(),
        .node_id = try crypto.publicKeyFromSeed(seed),
        .secret_seed = seed,
        .quorum_set = undefined, // emit never touches it
        .limits = .{},
    };
    const drv = driver_mod.Driver.default();
    var stored_bytes: usize = 0;
    var ctx = engine.Ctx{
        .gpa = gpa,
        .cfg = &cfg,
        .drv = &drv,
        .effects = &effects,
        .qsets = &store,
        .excised = null,
        .local_qset_hash = @splat(0),
        .stored_bytes = &stored_bytes,
    };
    var env = try emit.emit(&ctx, slot, own);
    defer env.deinit(gpa);
    return gpa.dupe(u8, env.envelope_framed);
}

const EnvelopeParts = struct { stmt: []u8, sig: [64]u8 };

fn extractParts(gpa: std.mem.Allocator, env_bytes: []const u8) !EnvelopeParts {
    var msg = try capnpc.message.Message.init(gpa, env_bytes, .{});
    defer msg.deinit();
    const r = try gen_slcp.Envelope.Reader.init(&msg);
    const stmt = try gpa.dupe(u8, try r.getStatementBytes());
    errdefer gpa.free(stmt);
    const sig_bytes = try r.getSignature();
    var sig: [64]u8 = undefined;
    @memcpy(&sig, sig_bytes);
    return .{ .stmt = stmt, .sig = sig };
}

fn rebuildEnvelope(gpa: std.mem.Allocator, stmt_bytes: []const u8, sig: [64]u8) ![]const u8 {
    var emb = capnpc.message.MessageBuilder.init(gpa);
    defer emb.deinit();
    var env = try gen_slcp.Envelope.Builder.init(&emb);
    try env.setStatementBytes(stmt_bytes);
    try env.setSignature(&sig);
    return emb.toBytes();
}

/// Drain ALL effects of the last input. Asserts exactly one input_status and
/// that it is the FINAL effect (the §5.3 1:1 rule, checked in every test).
const Drained = struct {
    status: engine.InputStatus = undefined,
    forwards: usize = 0,
    broadcasts: usize = 0,
    persists: usize = 0,
    requests: usize = 0,
    evicted_events: usize = 0,
    last_request_hash: [32]u8 = @splat(0),
    last_broadcast: ?[]u8 = null,

    fn deinit(self: *Drained, gpa: std.mem.Allocator) void {
        if (self.last_broadcast) |b| gpa.free(b);
        self.* = undefined;
    }
};

fn drain(gpa: std.mem.Allocator, eng: *engine.Engine) !Drained {
    var out = Drained{};
    errdefer out.deinit(gpa);
    var got_status = false;
    while (eng.popEffect()) |e| {
        try testing.expect(!got_status); // input_status is ALWAYS the last effect
        switch (e.*) {
            .input_status => |st| {
                out.status = st.code;
                got_status = true;
            },
            .forward_envelope => out.forwards += 1,
            .broadcast_envelope => |sb| {
                out.broadcasts += 1;
                if (out.last_broadcast) |b| gpa.free(b);
                out.last_broadcast = try gpa.dupe(u8, sb.bytes);
            },
            .persist_own_envelope => out.persists += 1,
            .request_qset => |r| {
                out.requests += 1;
                out.last_request_hash = r.hash;
            },
            .phase_event => |p| {
                if (p.kind == .parked_evicted) out.evicted_events += 1;
            },
            else => {},
        }
        eng.commitEffect();
    }
    try testing.expect(got_status); // exactly one per input
    return out;
}

fn pushAndDrain(gpa: std.mem.Allocator, eng: *engine.Engine, input: engine.Input) !Drained {
    try eng.pushInput(input);
    return drain(gpa, eng);
}

fn expectStatus(gpa: std.mem.Allocator, eng: *engine.Engine, input: engine.Input, expected: engine.InputStatus) !void {
    var d = try pushAndDrain(gpa, eng, input);
    defer d.deinit(gpa);
    try testing.expectEqual(expected, d.status);
}

// (protocol_stubs marker test removed at integration: protocols are real.)

test "applied: qset_received then fresh envelope stores, forwards, dispatches" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{});
    defer eng.deinit();

    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const qh = try qsetHashOf(gpa, 1, &.{peer_pk});
    const qbytes = try framedQset(gpa, 1, &.{peer_pk});
    defer gpa.free(qbytes);
    try expectStatus(gpa, &eng, .{ .qset_received = .{ .bytes = qbytes } }, .applied);

    const env = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{
        .qset_hash = qh,
        .votes = &.{"v1"},
        .accepted = &.{},
    } });
    defer gpa.free(env);
    var d = try pushAndDrain(gpa, &eng, .{ .envelope_received = .{ .bytes = env } });
    defer d.deinit(gpa);
    try testing.expectEqual(engine.InputStatus.applied, d.status);
    try testing.expectEqual(@as(usize, 1), d.forwards); // freshness advanced => relay
    const st = eng.stats();
    try testing.expectEqual(@as(usize, 1), st.live_slots);
    try testing.expect(st.stored_statement_bytes > 0);

    // A strictly fresher statement (superset growth) applies again.
    const env2 = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{
        .qset_hash = qh,
        .votes = &.{ "v1", "v2" },
        .accepted = &.{},
    } });
    defer gpa.free(env2);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = env2 } }, .applied);
}

// Oracle order requires every value/protocol rejection to happen before
// recordEnvelope replaces the sender's latest statement. In particular, once
// this node has externalized, a fresher but incompatible EXTERNALIZE must not
// erase an older valid CONFIRM or release its exact qset reference.
test "externalized slot rejects an incompatible newer ballot without replacing the previous peer statement" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{ .watcher = true, .quorum_threshold = 4 });
    defer eng.deinit();

    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const qh = try qsetHashOf(gpa, 1, &.{peer_pk});
    const qbytes = try framedQset(gpa, 1, &.{peer_pk});
    defer gpa.free(qbytes);
    try expectStatus(gpa, &eng, .{ .qset_received = .{ .bytes = qbytes } }, .applied);

    const prior = try peerEnvelope(gpa, peer_seed, 7, .{ .confirm = .{
        .qset_hash = qh,
        .ballot = .{ .counter = 2, .value = "committed" },
        .n_prepared = 2,
        .n_commit = 1,
        .n_h = 2,
    } });
    defer gpa.free(prior);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = prior } }, .applied);

    const s = eng.slots.get(7).?;
    try testing.expectEqual(@as(u32, 1), eng.qsets.statement_refs.get(qh).?);
    const bytes_before = eng.stored_statement_bytes;
    if (s.ballot.commit) |*old| old.deinit(gpa);
    s.ballot.commit = .{ .counter = 2, .value = try gpa.dupe(u8, "committed") };
    s.ballot.phase = .externalize;

    const incompatible = try peerEnvelope(gpa, peer_seed, 7, .{ .externalize = .{
        .commit = .{ .counter = 2, .value = "other" },
        .n_h = 2,
        .commit_qset_hash = qh,
    } });
    defer gpa.free(incompatible);
    var rejected = try pushAndDrain(gpa, &eng, .{ .envelope_received = .{ .bytes = incompatible } });
    defer rejected.deinit(gpa);
    try testing.expectEqual(engine.InputStatus.insane, rejected.status);
    try testing.expectEqual(@as(usize, 0), rejected.forwards);

    const kept = s.latestFor(peer_pk, false) orelse return error.PreviousStatementWasLost;
    switch (kept.statement.pledges) {
        .confirm => |*c| try testing.expectEqualSlices(u8, "committed", c.ballot.value),
        else => return error.PreviousStatementWasReplaced,
    }
    try testing.expectEqual(bytes_before, eng.stored_statement_bytes);
    try testing.expectEqual(@as(u32, 1), eng.qsets.statement_refs.get(qh).?);
}

test "zero-sized foreign cache preserves the engine's mandatory local qset" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{ .limits = .{ .max_cached_qsets = 0 } });
    defer eng.deinit();
    const local_hash = eng.ctx.local_qset_hash;

    const foreign_node: [32]u8 = @splat(0xA5);
    const foreign_qset = try framedQset(gpa, 1, &.{foreign_node});
    defer gpa.free(foreign_qset);
    try expectStatus(gpa, &eng, .{ .qset_received = .{ .bytes = foreign_qset } }, .applied);

    try testing.expect(eng.qsets.get(local_hash) != null);
    try testing.expectEqual(@as(usize, 1), eng.stats().cached_qsets);
}

test "zero-sized foreign cache cannot be bypassed by rotating a live reference" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{ .limits = .{ .max_cached_qsets = 0 } });
    defer eng.deinit();

    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const using_local = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{
        .qset_hash = eng.ctx.local_qset_hash,
        .votes = &.{"a"},
        .accepted = &.{},
    } });
    defer gpa.free(using_local);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = using_local } }, .applied);

    const foreign_hash = try qsetHashOf(gpa, 1, &.{peer_pk});
    const rotating = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{
        .qset_hash = foreign_hash,
        .votes = &.{ "a", "b" },
        .accepted = &.{},
    } });
    defer gpa.free(rotating);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = rotating } }, .parked_awaiting_qset);

    const foreign_qset = try framedQset(gpa, 1, &.{peer_pk});
    defer gpa.free(foreign_qset);
    var answered = try pushAndDrain(gpa, &eng, .{ .qset_received = .{ .bytes = foreign_qset } });
    defer answered.deinit(gpa);
    try testing.expectEqual(engine.InputStatus.applied, answered.status);
    try testing.expectEqual(@as(usize, 0), answered.forwards);
    try testing.expectEqual(@as(usize, 1), eng.stats().cached_qsets);
}

test "stale: the same envelope twice" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{});
    defer eng.deinit();

    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const qh = try qsetHashOf(gpa, 1, &.{peer_pk});
    const qbytes = try framedQset(gpa, 1, &.{peer_pk});
    defer gpa.free(qbytes);
    try expectStatus(gpa, &eng, .{ .qset_received = .{ .bytes = qbytes } }, .applied);

    const env = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{
        .qset_hash = qh,
        .votes = &.{"v1"},
        .accepted = &.{},
    } });
    defer gpa.free(env);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = env } }, .applied);

    var d = try pushAndDrain(gpa, &eng, .{ .envelope_received = .{ .bytes = env } });
    defer d.deinit(gpa);
    try testing.expectEqual(engine.InputStatus.stale, d.status);
    try testing.expectEqual(@as(usize, 0), d.forwards); // no relay for stale
}

test "invalid_signature: tampered statementBytes inside the frame" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{});
    defer eng.deinit();

    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const qh = try qsetHashOf(gpa, 1, &.{peer_pk});
    const env = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{
        .qset_hash = qh,
        .votes = &.{"v1"},
        .accepted = &.{},
    } });
    defer gpa.free(env);

    // Tamper a byte of the signed statement bytes and rebuild the envelope
    // around them: the old signature no longer verifies.
    var parts = try extractParts(gpa, env);
    defer gpa.free(parts.stmt);
    parts.stmt[parts.stmt.len - 1] ^= 0x01;
    const tampered = try rebuildEnvelope(gpa, parts.stmt, parts.sig);
    defer gpa.free(tampered);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = tampered } }, .invalid_signature);

    // Flipping a signature bit fails the same way.
    var parts2 = try extractParts(gpa, env);
    defer gpa.free(parts2.stmt);
    parts2.sig[0] ^= 0x01;
    const bad_sig = try rebuildEnvelope(gpa, parts2.stmt, parts2.sig);
    defer gpa.free(bad_sig);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = bad_sig } }, .invalid_signature);
}

test "insane: truncated frame and oversized frame" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{});
    defer eng.deinit();

    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const qh = try qsetHashOf(gpa, 1, &.{peer_pk});
    const env = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{
        .qset_hash = qh,
        .votes = &.{"v1"},
        .accepted = &.{},
    } });
    defer gpa.free(env);

    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = env[0..12] } }, .insane);

    const big = try gpa.alloc(u8, limits_mod.frozen_max_frame_bytes + 8);
    defer gpa.free(big);
    @memset(big, 0);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = big } }, .insane);
}

test "insane: non-canonical statementBytes under strict_canonical; applied without it" {
    const gpa = testing.allocator;

    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const qh = try qsetHashOf(gpa, 1, &.{peer_pk});
    const env = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{
        .qset_hash = qh,
        .votes = &.{"v1"},
        .accepted = &.{},
    } });
    defer gpa.free(env);

    // Append one zero word to the canonical flat statement bytes: still a
    // valid flat parse, no longer canonical (a trailing zero word must be
    // truncated). Sign the padded bytes so the signature check passes and
    // the canonicality walk is provably the rejecting step.
    const parts = try extractParts(gpa, env);
    defer gpa.free(parts.stmt);
    const padded = try gpa.alloc(u8, parts.stmt.len + 8);
    defer gpa.free(padded);
    @memcpy(padded[0..parts.stmt.len], parts.stmt);
    @memset(padded[parts.stmt.len..], 0);
    const digest = crypto.statementDigest(testNet(), padded);
    const sig = try crypto.sign(peer_seed, digest);
    const noncanonical = try rebuildEnvelope(gpa, padded, sig);
    defer gpa.free(noncanonical);

    var strict = try makeEngine(gpa, .{ .strict = true });
    defer strict.deinit();
    try expectStatus(gpa, &strict, .{ .envelope_received = .{ .bytes = noncanonical } }, .insane);

    // strict_canonical=false is the legal interop-debugging opt-out (§4.2).
    var lax = try makeEngine(gpa, .{ .strict = false });
    defer lax.deinit();
    const qbytes = try framedQset(gpa, 1, &.{peer_pk});
    defer gpa.free(qbytes);
    try expectStatus(gpa, &lax, .{ .qset_received = .{ .bytes = qbytes } }, .applied);
    try expectStatus(gpa, &lax, .{ .envelope_received = .{ .bytes = noncanonical } }, .applied);
}

test "insane: malformed qset_received frame and invalid qset" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{});
    defer eng.deinit();

    // Truncated garbage frame.
    try expectStatus(gpa, &eng, .{ .qset_received = .{ .bytes = &.{ 1, 2, 3 } } }, .insane);

    // Structurally valid frame, invalid qset (threshold 0): rejected, not
    // repaired (§4.3).
    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const bad = try framedQset(gpa, 0, &.{peer_pk});
    defer gpa.free(bad);
    try expectStatus(gpa, &eng, .{ .qset_received = .{ .bytes = bad } }, .insane);
}

test "parked_awaiting_qset then unpark on qset_received" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{});
    defer eng.deinit();

    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const peer2_pk = try crypto.publicKeyFromSeed(peer2_seed);
    const members = [_][32]u8{ peer_pk, peer2_pk };
    const qh = try qsetHashOf(gpa, 2, &members);

    const env = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{
        .qset_hash = qh,
        .votes = &.{"v1"},
        .accepted = &.{},
    } });
    defer gpa.free(env);

    var d = try pushAndDrain(gpa, &eng, .{ .envelope_received = .{ .bytes = env } });
    defer d.deinit(gpa);
    try testing.expectEqual(engine.InputStatus.parked_awaiting_qset, d.status);
    try testing.expectEqual(@as(usize, 1), d.requests);
    try testing.expectEqualSlices(u8, &qh, &d.last_request_hash);
    try testing.expectEqual(@as(usize, 0), d.forwards);
    try testing.expectEqual(@as(usize, 1), eng.stats().parked);

    // The host answers: the parked envelope replays through the
    // post-resolution half (store + forward + dispatch), no extra status.
    const qbytes = try framedQset(gpa, 2, &members);
    defer gpa.free(qbytes);
    var d2 = try pushAndDrain(gpa, &eng, .{ .qset_received = .{ .bytes = qbytes } });
    defer d2.deinit(gpa);
    try testing.expectEqual(engine.InputStatus.applied, d2.status);
    try testing.expectEqual(@as(usize, 1), d2.forwards); // the unparked envelope relayed
    try testing.expectEqual(@as(usize, 0), eng.stats().parked);
    try testing.expect(eng.stats().stored_statement_bytes > 0);
}

test "qset_received replaces a peer's advertised qset at cache capacity" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{ .limits = .{ .max_cached_qsets = 2 } });
    defer eng.deinit();

    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const peer2_pk = try crypto.publicKeyFromSeed(peer2_seed);
    const first_hash = try qsetHashOf(gpa, 1, &.{peer_pk});
    const first_env = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{
        .qset_hash = first_hash,
        .votes = &.{"v1"},
        .accepted = &.{},
    } });
    defer gpa.free(first_env);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = first_env } }, .parked_awaiting_qset);
    const first_qset = try framedQset(gpa, 1, &.{peer_pk});
    defer gpa.free(first_qset);
    try expectStatus(gpa, &eng, .{ .qset_received = .{ .bytes = first_qset } }, .applied);

    const replacement_members = [_][32]u8{ peer_pk, peer2_pk };
    const replacement_hash = try qsetHashOf(gpa, 2, &replacement_members);
    const replacement_env = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{
        .qset_hash = replacement_hash,
        .votes = &.{ "v1", "v2" },
        .accepted = &.{},
    } });
    defer gpa.free(replacement_env);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = replacement_env } }, .parked_awaiting_qset);
    const replacement_qset = try framedQset(gpa, 2, &replacement_members);
    defer gpa.free(replacement_qset);
    try expectStatus(gpa, &eng, .{ .qset_received = .{ .bytes = replacement_qset } }, .applied);

    const replacement_cached = eng.qsets.get(replacement_hash).?;
    try testing.expectEqual(@as(u32, 2), replacement_cached.threshold);
    try testing.expectEqual(@as(usize, 2), replacement_cached.validators.len);
    try testing.expect(eng.qsets.get(first_hash) == null);
    try testing.expectEqual(@as(usize, 2), eng.stats().cached_qsets);
}

test "qset replay admits capacity-freeing replacements before other waiters" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{ .limits = .{ .max_cached_qsets = 2 } });
    defer eng.deinit();

    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const peer2_pk = try crypto.publicKeyFromSeed(peer2_seed);

    // Local + this live reference fills the cache.
    const old_hash = try qsetHashOf(gpa, 1, &.{peer_pk});
    const old_env = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{
        .qset_hash = old_hash,
        .votes = &.{"old"},
        .accepted = &.{},
    } });
    defer gpa.free(old_env);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = old_env } }, .parked_awaiting_qset);
    const old_qset = try framedQset(gpa, 1, &.{peer_pk});
    defer gpa.free(old_qset);
    try expectStatus(gpa, &eng, .{ .qset_received = .{ .bytes = old_qset } }, .applied);

    const replacement_members = [_][32]u8{ peer_pk, peer2_pk };
    const replacement_hash = try qsetHashOf(gpa, 1, &replacement_members);

    // This no-old-reference waiter arrives first and cannot initially grow
    // the full cache. It must be retried after the next waiter trades away
    // the cache's last old_hash reference.
    const first_waiter = try peerEnvelope(gpa, peer2_seed, 2, .{ .nominate = .{
        .qset_hash = replacement_hash,
        .votes = &.{"new"},
        .accepted = &.{},
    } });
    defer gpa.free(first_waiter);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = first_waiter } }, .parked_awaiting_qset);

    const freeing_waiter = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{
        .qset_hash = replacement_hash,
        .votes = &.{ "new", "old" },
        .accepted = &.{},
    } });
    defer gpa.free(freeing_waiter);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = freeing_waiter } }, .parked_awaiting_qset);

    const replacement_qset = try framedQset(gpa, 1, &replacement_members);
    defer gpa.free(replacement_qset);
    var replayed = try pushAndDrain(gpa, &eng, .{ .qset_received = .{ .bytes = replacement_qset } });
    defer replayed.deinit(gpa);
    try testing.expectEqual(engine.InputStatus.applied, replayed.status);
    try testing.expectEqual(@as(usize, 2), replayed.forwards);
}

test "qset replay rotates every live reference to the same replacement at cache pressure" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{ .limits = .{ .max_cached_qsets = 2 } });
    defer eng.deinit();

    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const peer2_pk = try crypto.publicKeyFromSeed(peer2_seed);
    const old_hash = try qsetHashOf(gpa, 1, &.{peer_pk});

    var old_frames: [2][]u8 = undefined;
    var old_made: usize = 0;
    defer for (old_frames[0..old_made]) |frame| gpa.free(frame);
    for (&old_frames, 0..) |*frame, i| {
        frame.* = try peerEnvelope(gpa, peer_seed, i + 1, .{ .nominate = .{
            .qset_hash = old_hash,
            .votes = &.{"a"},
            .accepted = &.{},
        } });
        old_made += 1;
        try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = frame.* } }, .parked_awaiting_qset);
    }
    const old_qset = try framedQset(gpa, 1, &.{peer_pk});
    defer gpa.free(old_qset);
    var old_replay = try pushAndDrain(gpa, &eng, .{ .qset_received = .{ .bytes = old_qset } });
    defer old_replay.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), old_replay.forwards);

    const replacement_members = [_][32]u8{ peer_pk, peer2_pk };
    const replacement_hash = try qsetHashOf(gpa, 1, &replacement_members);
    var replacements: [2][]u8 = undefined;
    var replacements_made: usize = 0;
    defer for (replacements[0..replacements_made]) |frame| gpa.free(frame);
    for (&replacements, 0..) |*frame, i| {
        frame.* = try peerEnvelope(gpa, peer_seed, i + 1, .{ .nominate = .{
            .qset_hash = replacement_hash,
            .votes = &.{ "a", "b" },
            .accepted = &.{},
        } });
        replacements_made += 1;
        try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = frame.* } }, .parked_awaiting_qset);
    }

    const replacement_qset = try framedQset(gpa, 1, &replacement_members);
    defer gpa.free(replacement_qset);
    var replayed = try pushAndDrain(gpa, &eng, .{ .qset_received = .{ .bytes = replacement_qset } });
    defer replayed.deinit(gpa);
    try testing.expectEqual(engine.InputStatus.applied, replayed.status);
    try testing.expectEqual(@as(usize, 2), replayed.forwards);
}

test "qset replay preserves FIFO among eligible statements" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{});
    defer eng.deinit();

    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const qh = try qsetHashOf(gpa, 1, &.{peer_pk});
    const vote_sets = [_][]const []const u8{
        &.{"a"},
        &.{ "a", "b" },
        &.{ "a", "b", "c" },
    };
    var frames: [vote_sets.len][]u8 = undefined;
    var made: usize = 0;
    defer for (frames[0..made]) |frame| gpa.free(frame);
    for (vote_sets, 0..) |votes, i| {
        frames[i] = try peerEnvelope(gpa, peer_seed, 7, .{ .nominate = .{
            .qset_hash = qh,
            .votes = votes,
            .accepted = &.{},
        } });
        made += 1;
        try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = frames[i] } }, .parked_awaiting_qset);
    }

    const qbytes = try framedQset(gpa, 1, &.{peer_pk});
    defer gpa.free(qbytes);
    var replayed = try pushAndDrain(gpa, &eng, .{ .qset_received = .{ .bytes = qbytes } });
    defer replayed.deinit(gpa);
    try testing.expectEqual(engine.InputStatus.applied, replayed.status);
    try testing.expectEqual(@as(usize, 3), replayed.forwards);
}

test "live statements keep their slot-specific qsets after the signer changes qsets elsewhere" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{
        .quorum_threshold = 2,
        .limits = .{ .max_cached_qsets = 3 },
    });
    defer eng.deinit();

    try expectStatus(gpa, &eng, .{ .nominate = .{ .slot = 1, .value = "own", .prev_value = "" } }, .applied);

    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const first_hash = try qsetHashOf(gpa, 1, &.{peer_pk});
    const first_env = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{
        .qset_hash = first_hash,
        .votes = &.{"v1"},
        .accepted = &.{},
    } });
    defer gpa.free(first_env);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = first_env } }, .parked_awaiting_qset);
    const first_qset = try framedQset(gpa, 1, &.{peer_pk});
    defer gpa.free(first_qset);
    try expectStatus(gpa, &eng, .{ .qset_received = .{ .bytes = first_qset } }, .applied);

    // The same signer uses a different qset in another slot. That changes
    // graph reachability, but must not change how its slot-1 statement is
    // interpreted or make the slot-1 qset evictable.
    const outsider: [32]u8 = @splat(0xA1);
    const second_hash = try qsetHashOf(gpa, 1, &.{outsider});
    const second_env = try peerEnvelope(gpa, peer_seed, 2, .{ .nominate = .{
        .qset_hash = second_hash,
        .votes = &.{"other-slot"},
        .accepted = &.{},
    } });
    defer gpa.free(second_env);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = second_env } }, .parked_awaiting_qset);
    const second_qset = try framedQset(gpa, 1, &.{outsider});
    defer gpa.free(second_qset);
    try expectStatus(gpa, &eng, .{ .qset_received = .{ .bytes = second_qset } }, .applied);

    // Force real cache pressure. The disposable qset, not a qset referenced
    // by either live statement, is the only valid eviction victim.
    const disposable_node: [32]u8 = @splat(0xD1);
    const disposable_qset = try framedQset(gpa, 1, &.{disposable_node});
    defer gpa.free(disposable_qset);
    try expectStatus(gpa, &eng, .{ .qset_received = .{ .bytes = disposable_qset } }, .applied);

    const peer2_pk = try crypto.publicKeyFromSeed(peer2_seed);
    const deciding_env = try peerEnvelope(gpa, peer2_seed, 1, .{ .nominate = .{
        .qset_hash = eng.ctx.local_qset_hash,
        .votes = &.{"v1"},
        .accepted = &.{},
    } });
    defer gpa.free(deciding_env);
    var decided = try pushAndDrain(gpa, &eng, .{ .envelope_received = .{ .bytes = deciding_env } });
    defer decided.deinit(gpa);
    try testing.expectEqual(engine.InputStatus.applied, decided.status);
    try testing.expectEqual(@as(usize, 1), decided.broadcasts);
    _ = peer2_pk;
}

test "all live statements from one signer contribute to graph reachability until purge" {
    const gpa = testing.allocator;
    const self_pk = try crypto.publicKeyFromSeed(engine_seed);
    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const peer2_pk = try crypto.publicKeyFromSeed(peer2_seed);
    const local_members = [_][32]u8{ self_pk, peer_pk };
    var eng = try engine.Engine.init(gpa, .{
        .network_id = testNet(),
        .node_id = self_pk,
        .secret_seed = null, // watcher: exercise tracking without emissions
        .quorum_set = try ownedQsetOf(gpa, 1, &local_members),
        .limits = .{ .max_cached_qsets = 3 },
    }, driver_mod.Driver.default());
    defer eng.deinit();

    // Slot 1 makes peer2 transitively relevant through peer's first qset.
    const reaches_peer2_hash = try qsetHashOf(gpa, 1, &.{peer2_pk});
    const slot1 = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{
        .qset_hash = reaches_peer2_hash,
        .votes = &.{"slot-1"},
        .accepted = &.{},
    } });
    defer gpa.free(slot1);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = slot1 } }, .parked_awaiting_qset);
    const reaches_peer2 = try framedQset(gpa, 1, &.{peer2_pk});
    defer gpa.free(reaches_peer2);
    try expectStatus(gpa, &eng, .{ .qset_received = .{ .bytes = reaches_peer2 } }, .applied);

    // A newer advertisement in another slot excludes peer2. The still-live
    // slot-1 statement keeps its own edge in the union.
    const self_only_hash = try qsetHashOf(gpa, 1, &.{peer_pk});
    const slot2 = try peerEnvelope(gpa, peer_seed, 2, .{ .nominate = .{
        .qset_hash = self_only_hash,
        .votes = &.{"slot-2"},
        .accepted = &.{},
    } });
    defer gpa.free(slot2);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = slot2 } }, .parked_awaiting_qset);
    const self_only = try framedQset(gpa, 1, &.{peer_pk});
    defer gpa.free(self_only);
    try expectStatus(gpa, &eng, .{ .qset_received = .{ .bytes = self_only } }, .applied);

    const peer2_live = try peerEnvelope(gpa, peer2_seed, 1, .{ .nominate = .{
        .qset_hash = eng.ctx.local_qset_hash,
        .votes = &.{"reachable"},
        .accepted = &.{},
    } });
    defer gpa.free(peer2_live);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = peer2_live } }, .applied);

    // Once every contributing slot is purged, the stale transitive edge is
    // rebuilt away and the same non-root signer is filtered again.
    try expectStatus(gpa, &eng, .{ .purge_slots = .{ .max_slot = 3 } }, .applied);
    const peer2_after_purge = try peerEnvelope(gpa, peer2_seed, 3, .{ .nominate = .{
        .qset_hash = eng.ctx.local_qset_hash,
        .votes = &.{"no-longer-reachable"},
        .accepted = &.{},
    } });
    defer gpa.free(peer2_after_purge);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = peer2_after_purge } }, .ignored);
}

test "conservative relevance temporarily admits a disconnected signer until purge" {
    const gpa = testing.allocator;
    const self_pk = try crypto.publicKeyFromSeed(engine_seed);
    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const disconnected_pk = try crypto.publicKeyFromSeed(peer2_seed);
    const local_members = [_][32]u8{ self_pk, peer_pk };
    var eng = try engine.Engine.init(gpa, .{
        .network_id = testNet(),
        .node_id = self_pk,
        .secret_seed = null,
        .quorum_set = try ownedQsetOf(gpa, 1, &local_members),
        .limits = .{ .max_cached_qsets = 3 },
    }, driver_mod.Driver.default());
    defer eng.deinit();

    const reaches_disconnected_hash = try qsetHashOf(gpa, 1, &.{disconnected_pk});
    const reaches_disconnected = try framedQset(gpa, 1, &.{disconnected_pk});
    defer gpa.free(reaches_disconnected);
    try expectStatus(gpa, &eng, .{ .qset_received = .{ .bytes = reaches_disconnected } }, .applied);

    const peer_only_hash = try qsetHashOf(gpa, 1, &.{peer_pk});
    const peer_only = try framedQset(gpa, 1, &.{peer_pk});
    defer gpa.free(peer_only);
    try expectStatus(gpa, &eng, .{ .qset_received = .{ .bytes = peer_only } }, .applied);

    const first = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{
        .qset_hash = reaches_disconnected_hash,
        .votes = &.{"a"},
        .accepted = &.{},
    } });
    defer gpa.free(first);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = first } }, .applied);

    const replacement = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{
        .qset_hash = peer_only_hash,
        .votes = &.{ "a", "b" },
        .accepted = &.{},
    } });
    defer gpa.free(replacement);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = replacement } }, .applied);
    try testing.expect(eng.qsets.inGraph(disconnected_pk));

    // This signer is absent from exact current reachability, but the bounded
    // conservative generation admits and relays it as a resource-policy
    // false positive. Quorum math still uses exact statement qsets.
    const during_grace = try peerEnvelope(gpa, peer2_seed, 2, .{ .nominate = .{
        .qset_hash = eng.ctx.local_qset_hash,
        .votes = &.{"grace"},
        .accepted = &.{},
    } });
    defer gpa.free(during_grace);
    var admitted = try pushAndDrain(gpa, &eng, .{ .envelope_received = .{ .bytes = during_grace } });
    defer admitted.deinit(gpa);
    try testing.expectEqual(engine.InputStatus.applied, admitted.status);
    try testing.expectEqual(@as(usize, 1), admitted.forwards);

    try expectStatus(gpa, &eng, .{ .purge_slots = .{ .max_slot = 2 } }, .applied);
    try testing.expect(!eng.qsets.inGraph(disconnected_pk));

    const after_checkpoint = try peerEnvelope(gpa, peer2_seed, 2, .{ .nominate = .{
        .qset_hash = eng.ctx.local_qset_hash,
        .votes = &.{ "grace", "later" },
        .accepted = &.{},
    } });
    defer gpa.free(after_checkpoint);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = after_checkpoint } }, .ignored);
}

test "unknown-qset churn checkpoints stale relevance before slot admission" {
    const gpa = testing.allocator;
    const self_pk = try crypto.publicKeyFromSeed(engine_seed);
    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const disconnected_pk = try crypto.publicKeyFromSeed(peer2_seed);
    const local_members = [_][32]u8{ self_pk, peer_pk };
    var eng = try engine.Engine.init(gpa, .{
        .network_id = testNet(),
        .node_id = self_pk,
        .secret_seed = null,
        .quorum_set = try ownedQsetOf(gpa, 1, &local_members),
        .limits = .{ .max_cached_qsets = 3 },
    }, driver_mod.Driver.default());
    defer eng.deinit();

    const old_hash = try qsetHashOf(gpa, 1, &.{disconnected_pk});
    const old_qset = try framedQset(gpa, 1, &.{disconnected_pk});
    defer gpa.free(old_qset);
    try expectStatus(gpa, &eng, .{ .qset_received = .{ .bytes = old_qset } }, .applied);

    const replacement_hash = try qsetHashOf(gpa, 1, &.{peer_pk});
    const replacement_qset = try framedQset(gpa, 1, &.{peer_pk});
    defer gpa.free(replacement_qset);
    try expectStatus(gpa, &eng, .{ .qset_received = .{ .bytes = replacement_qset } }, .applied);

    const old = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{
        .qset_hash = old_hash,
        .votes = &.{"a"},
        .accepted = &.{},
    } });
    defer gpa.free(old);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = old } }, .applied);

    const replacement = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{
        .qset_hash = replacement_hash,
        .votes = &.{ "a", "b" },
        .accepted = &.{},
    } });
    defer gpa.free(replacement);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = replacement } }, .applied);
    try testing.expect(eng.qsets.inGraph(disconnected_pk));

    const missing_hash: [32]u8 = @splat(0xcc);
    const churn = try peerEnvelope(gpa, peer2_seed, 2, .{ .nominate = .{
        .qset_hash = missing_hash,
        .votes = &.{"unknown"},
        .accepted = &.{},
    } });
    defer gpa.free(churn);

    // The first four consume the per-node pending allowance. Rejected repeats
    // still advance the already-open generation; pending memory stays bounded,
    // but it must not let unknown-qset churn preserve stale relevance forever.
    for (0..62) |i| {
        var d = try pushAndDrain(gpa, &eng, .{ .envelope_received = .{ .bytes = churn } });
        defer d.deinit(gpa);
        try testing.expectEqual(
            if (i < 4) engine.InputStatus.parked_awaiting_qset else engine.InputStatus.over_limit,
            d.status,
        );
    }
    try testing.expectEqual(@as(usize, 4), eng.pending.count());

    // This is the 64th generation update (the replacement was the first).
    // Its exact checkpoint removes the signer before getOrCreateSlot, so a
    // never-before-seen slot cannot be left behind empty.
    const triggering = try peerEnvelope(gpa, peer2_seed, 99, .{ .nominate = .{
        .qset_hash = missing_hash,
        .votes = &.{"trigger"},
        .accepted = &.{},
    } });
    defer gpa.free(triggering);
    var final = try pushAndDrain(gpa, &eng, .{ .envelope_received = .{ .bytes = triggering } });
    defer final.deinit(gpa);
    try testing.expectEqual(engine.InputStatus.ignored, final.status);
    try testing.expectEqual(@as(usize, 0), final.requests);
    try testing.expect(eng.slots.get(99) == null);
    try testing.expect(!eng.qsets.inGraph(disconnected_pk));
}

test "over_limit: live-slot cap" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{ .limits = .{ .max_live_slots = 1 } });
    defer eng.deinit();

    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const qh = try qsetHashOf(gpa, 1, &.{peer_pk});
    const qbytes = try framedQset(gpa, 1, &.{peer_pk});
    defer gpa.free(qbytes);
    try expectStatus(gpa, &eng, .{ .qset_received = .{ .bytes = qbytes } }, .applied);

    const env1 = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{ .qset_hash = qh, .votes = &.{"v1"}, .accepted = &.{} } });
    defer gpa.free(env1);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = env1 } }, .applied);

    const env2 = try peerEnvelope(gpa, peer_seed, 2, .{ .nominate = .{ .qset_hash = qh, .votes = &.{"v1"}, .accepted = &.{} } });
    defer gpa.free(env2);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = env2 } }, .over_limit);
    try testing.expectEqual(@as(usize, 1), eng.stats().live_slots);
}

test "over_limit: per-node parking cap (4 per node)" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{});
    defer eng.deinit();

    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const peer2_pk = try crypto.publicKeyFromSeed(peer2_seed);
    const unknown_qh = try qsetHashOf(gpa, 2, &.{ peer_pk, peer2_pk });

    // Four distinct slots so each envelope is fresh; all park on the same
    // unknown hash. The 5th from the same node breaches the per-node cap.
    var envs: [5][]u8 = undefined;
    for (0..5) |i| {
        envs[i] = try peerEnvelope(gpa, peer_seed, @intCast(i + 1), .{ .nominate = .{
            .qset_hash = unknown_qh,
            .votes = &.{"v1"},
            .accepted = &.{},
        } });
    }
    defer for (envs) |e| gpa.free(e);

    for (0..4) |i| {
        try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = envs[i] } }, .parked_awaiting_qset);
    }
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = envs[4] } }, .over_limit);
    try testing.expectEqual(@as(usize, 4), eng.stats().parked);
}

test "over_limit: engine-wide stored-bytes budget drops without storing" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{ .limits = .{ .max_stored_statement_bytes = 8 } });
    defer eng.deinit();

    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const qh = try qsetHashOf(gpa, 1, &.{peer_pk});
    const qbytes = try framedQset(gpa, 1, &.{peer_pk});
    defer gpa.free(qbytes);
    try expectStatus(gpa, &eng, .{ .qset_received = .{ .bytes = qbytes } }, .applied);

    const env = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{ .qset_hash = qh, .votes = &.{"v1"}, .accepted = &.{} } });
    defer gpa.free(env);
    var d = try pushAndDrain(gpa, &eng, .{ .envelope_received = .{ .bytes = env } });
    defer d.deinit(gpa);
    try testing.expectEqual(engine.InputStatus.over_limit, d.status);
    try testing.expectEqual(@as(usize, 0), d.forwards); // dropped, not stored/relayed
    try testing.expectEqual(@as(usize, 0), eng.stats().stored_statement_bytes);
}

test "parking eviction of a PAST input emits phase_event, not a second status" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{ .limits = .{ .max_pending_envelopes = 2 } });
    defer eng.deinit();

    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const peer2_pk = try crypto.publicKeyFromSeed(peer2_seed);
    const unknown_qh = try qsetHashOf(gpa, 2, &.{ peer_pk, peer2_pk });

    const seeds = [_][32]u8{ peer_seed, peer2_seed, peer3_seed };
    var envs: [3][]u8 = undefined;
    for (seeds, 0..) |sd, i| {
        envs[i] = try peerEnvelope(gpa, sd, @intCast(i + 1), .{ .nominate = .{
            .qset_hash = unknown_qh,
            .votes = &.{"v1"},
            .accepted = &.{},
        } });
    }
    defer for (envs) |e| gpa.free(e);

    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = envs[0] } }, .parked_awaiting_qset);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = envs[1] } }, .parked_awaiting_qset);
    var d = try pushAndDrain(gpa, &eng, .{ .envelope_received = .{ .bytes = envs[2] } });
    defer d.deinit(gpa);
    try testing.expectEqual(engine.InputStatus.parked_awaiting_qset, d.status);
    try testing.expectEqual(@as(usize, 1), d.evicted_events); // FIFO victim signaled
    try testing.expectEqual(@as(usize, 2), eng.stats().parked);
}

test "ignored: out-of-graph sender, watcher nominate, stale timer" {
    const gpa = testing.allocator;

    var eng = try makeEngine(gpa, .{});
    defer eng.deinit();

    // Sender outside the transitive quorum graph (§5.4) — dropped before
    // qset resolution could even park it.
    const outsider_pk = try crypto.publicKeyFromSeed(outsider_seed);
    const qh = try qsetHashOf(gpa, 1, &.{outsider_pk});
    const env = try peerEnvelope(gpa, outsider_seed, 1, .{ .nominate = .{ .qset_hash = qh, .votes = &.{"v1"}, .accepted = &.{} } });
    defer gpa.free(env);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = env } }, .ignored);
    try testing.expectEqual(@as(usize, 0), eng.stats().parked);
    try testing.expectEqual(@as(usize, 0), eng.stats().live_slots);

    // Watcher mode: nominate is not legal (§5.1).
    var watcher = try makeEngine(gpa, .{ .watcher = true });
    defer watcher.deinit();
    try expectStatus(gpa, &watcher, .{ .nominate = .{ .slot = 1, .value = "v", .prev_value = "" } }, .ignored);

    // Stale timer after purge / for a never-created slot.
    try expectStatus(gpa, &eng, .{ .timer_fired = .{ .slot = 42, .timer = .nomination } }, .ignored);
    try expectStatus(gpa, &eng, .{ .timer_fired = .{ .slot = 42, .timer = .ballot } }, .ignored);
}

test "applied via protocol stubs: nominate and live-slot timers" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{});
    defer eng.deinit();

    // nominate creates the slot and reaches nomination.nominate (stubbed).
    try expectStatus(gpa, &eng, .{ .nominate = .{ .slot = 1, .value = "v", .prev_value = "" } }, .applied);
    try testing.expectEqual(@as(usize, 1), eng.stats().live_slots);

    // Timers for the live slot reach the (stubbed) protocol handlers.
    try expectStatus(gpa, &eng, .{ .timer_fired = .{ .slot = 1, .timer = .nomination } }, .applied);
    try expectStatus(gpa, &eng, .{ .timer_fired = .{ .slot = 1, .timer = .ballot } }, .applied);
}

test "over_limit: nominate beyond the live-slot cap" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{ .limits = .{ .max_live_slots = 1 } });
    defer eng.deinit();
    try expectStatus(gpa, &eng, .{ .nominate = .{ .slot = 1, .value = "v", .prev_value = "" } }, .applied);
    try expectStatus(gpa, &eng, .{ .nominate = .{ .slot = 2, .value = "v", .prev_value = "" } }, .over_limit);
}

test "restore_own_envelope: broadcast only, byte-identical, no persist" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{});
    defer eng.deinit();

    // The own log entry: an envelope signed with the ENGINE's own seed.
    const own = try peerEnvelope(gpa, engine_seed, 3, .{ .nominate = .{
        .qset_hash = eng.ctx.local_qset_hash,
        .votes = &.{"mine"},
        .accepted = &.{},
    } });
    defer gpa.free(own);

    var d = try pushAndDrain(gpa, &eng, .{ .restore_own_envelope = .{ .bytes = own } });
    defer d.deinit(gpa);
    try testing.expectEqual(engine.InputStatus.applied, d.status);
    try testing.expectEqual(@as(usize, 1), d.broadcasts);
    try testing.expectEqual(@as(usize, 0), d.persists); // §10 carve-out: NO persist
    try testing.expectEqual(@as(usize, 0), d.forwards);
    try testing.expectEqualSlices(u8, own, d.last_broadcast.?); // byte-identical

    // Restored as own latest for the slot.
    const s = eng.slots.get(3).?;
    try testing.expect(s.own_nom != null);
    try testing.expect(s.latestFor(eng.cfg.node_id, true) != null);

    // A peer's envelope in the own log is not ours: ignored.
    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const foreign = try peerEnvelope(gpa, peer_seed, 3, .{ .nominate = .{
        .qset_hash = try qsetHashOf(gpa, 1, &.{peer_pk}),
        .votes = &.{"v"},
        .accepted = &.{},
    } });
    defer gpa.free(foreign);
    try expectStatus(gpa, &eng, .{ .restore_own_envelope = .{ .bytes = foreign } }, .ignored);
}

test "purge_slots: drops slots below max_slot, parked envelopes, and byte accounting" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{});
    defer eng.deinit();

    const peer_pk = try crypto.publicKeyFromSeed(peer_seed);
    const peer2_pk = try crypto.publicKeyFromSeed(peer2_seed);
    const qh = try qsetHashOf(gpa, 1, &.{peer_pk});
    const qbytes = try framedQset(gpa, 1, &.{peer_pk});
    defer gpa.free(qbytes);
    try expectStatus(gpa, &eng, .{ .qset_received = .{ .bytes = qbytes } }, .applied);

    // Slot 1: applied (stored). Slot 2: parked on an unknown hash.
    const env1 = try peerEnvelope(gpa, peer_seed, 1, .{ .nominate = .{ .qset_hash = qh, .votes = &.{"v1"}, .accepted = &.{} } });
    defer gpa.free(env1);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = env1 } }, .applied);
    const unknown_qh = try qsetHashOf(gpa, 2, &.{ peer_pk, peer2_pk });
    const env2 = try peerEnvelope(gpa, peer_seed, 2, .{ .nominate = .{ .qset_hash = unknown_qh, .votes = &.{"v1"}, .accepted = &.{} } });
    defer gpa.free(env2);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = env2 } }, .parked_awaiting_qset);

    try testing.expectEqual(@as(usize, 2), eng.stats().live_slots);
    try testing.expectEqual(@as(usize, 1), eng.stats().parked);
    try testing.expect(eng.stats().stored_statement_bytes > 0);

    try expectStatus(gpa, &eng, .{ .purge_slots = .{ .max_slot = 10 } }, .applied);
    const st = eng.stats();
    try testing.expectEqual(@as(usize, 0), st.live_slots);
    try testing.expectEqual(@as(usize, 0), st.parked);
    try testing.expectEqual(@as(usize, 0), st.stored_statement_bytes);

    // Purge below the live slots keeps them.
    const env3 = try peerEnvelope(gpa, peer_seed, 7, .{ .nominate = .{ .qset_hash = qh, .votes = &.{"v1"}, .accepted = &.{} } });
    defer gpa.free(env3);
    try expectStatus(gpa, &eng, .{ .envelope_received = .{ .bytes = env3 } }, .applied);
    try expectStatus(gpa, &eng, .{ .purge_slots = .{ .max_slot = 7 } }, .applied);
    try testing.expectEqual(@as(usize, 1), eng.stats().live_slots);
}

test "sticky failure: after an engine error every pushInput fails" {
    const gpa = testing.allocator;
    var eng = try makeEngine(gpa, .{});
    defer eng.deinit();
    eng.failed = true; // simulate a prior §7.2 breach
    try testing.expectError(error.EngineFailed, eng.pushInput(.{ .purge_slots = .{ .max_slot = 1 } }));
    try testing.expectError(error.EngineFailed, eng.pushInput(.{ .timer_fired = .{ .slot = 1, .timer = .ballot } }));
}

// ---------------------------------------------------------------------------
// OOM injection over restore_own_envelope (design §12: never leak on any
// input; S8 review dimension D5).
// ---------------------------------------------------------------------------

fn restoreOnce(gpa: std.mem.Allocator, own: []const u8) !void {
    var eng = try makeEngine(gpa, .{});
    defer eng.deinit();
    var d = try pushAndDrain(gpa, &eng, .{ .restore_own_envelope = .{ .bytes = own } });
    defer d.deinit(gpa);
    try testing.expectEqual(engine.InputStatus.applied, d.status);
}

/// Sweep every allocation made by pushInput(restore_own_envelope) + drain:
/// each induced failure must surface as error.OutOfMemory with every byte
/// the failing allocator handed out freed again. Allocation order is
/// deterministic, so the sweep starts right after Engine.init's own
/// allocations (init's unwind is not what this test pins).
fn expectRestoreLeaksNothing(own: []const u8) !void {
    const gpa = testing.allocator;
    const init_allocs = blk: {
        var counting = std.testing.FailingAllocator.init(gpa, .{});
        var eng = try makeEngine(counting.allocator(), .{});
        defer eng.deinit();
        break :blk counting.alloc_index;
    };
    var idx = init_allocs;
    var swept: usize = 0;
    while (true) : (idx += 1) {
        var fa = std.testing.FailingAllocator.init(gpa, .{ .fail_index = idx });
        const r = restoreOnce(fa.allocator(), own);
        if (!fa.has_induced_failure) {
            // Past the last allocation: the un-failed run is the plain
            // restore and must succeed.
            try r;
            break;
        }
        swept += 1;
        try testing.expectError(error.OutOfMemory, r);
        if (fa.allocated_bytes != fa.freed_bytes) {
            std.debug.print(
                "restore_own_envelope leaked {d} B when allocation #{d} (the {d}th after Engine.init) failed\n",
                .{ fa.allocated_bytes - fa.freed_bytes, idx, idx - init_allocs + 1 },
            );
            return error.MemoryLeakDetected;
        }
    }
    try testing.expect(swept >= 8); // non-vacuity: the restore path really allocates
}

const PreparkOomAttempt = struct {
    induced: bool,
    checkpoint_failure: bool,
};

fn runPreparkOomAttempt(fa: *std.testing.FailingAllocator, fail_offset: usize) !PreparkOomAttempt {
    const gpa = fa.allocator();
    var eng = try makeEngine(gpa, .{});
    defer eng.deinit();

    const unknown_hash: [32]u8 = @splat(0xdd);
    const env = try peerEnvelope(gpa, peer2_seed, 99, .{ .nominate = .{
        .qset_hash = unknown_hash,
        .votes = &.{"unknown"},
        .accepted = &.{},
    } });
    defer gpa.free(env);

    // The next qualifying unknown-qset envelope must attempt exact graph
    // publication. Configure failure only after all test setup is owned.
    eng.qsets.deferred_reference_updates = 63;
    fa.fail_index = fa.alloc_index + fail_offset;
    const result = handleEnvelope(&eng, env);
    const induced = fa.has_induced_failure;
    const checkpoint_failure = induced and eng.qsets.deferred_reference_updates == 64;
    if (result) |status| {
        try testing.expect(!induced);
        try testing.expectEqual(engine.InputStatus.parked_awaiting_qset, status);
    } else |err| {
        try testing.expect(induced);
        try testing.expectEqual(@as(anyerror, error.OutOfMemory), @as(anyerror, err));
    }
    return .{ .induced = induced, .checkpoint_failure = checkpoint_failure };
}

test "unknown-qset pre-parking checkpoint leaks nothing on allocation failure" {
    const gpa = testing.allocator;
    var fail_offset: usize = 0;
    var swept: usize = 0;
    var saw_checkpoint_failure = false;
    while (true) : (fail_offset += 1) {
        var fa = std.testing.FailingAllocator.init(gpa, .{});
        const attempt = try runPreparkOomAttempt(&fa, fail_offset);
        if (fa.allocated_bytes != fa.freed_bytes) return error.MemoryLeakDetected;
        if (!attempt.induced) break;
        swept += 1;
        saw_checkpoint_failure = saw_checkpoint_failure or attempt.checkpoint_failure;
    }
    try testing.expect(swept >= 8);
    try testing.expect(saw_checkpoint_failure);
}

// Non-vacuity: handleRestore stores `latest_env` via s.storeLatest (which
// owns and frees it on failure) while `frame_own` and `own_stmt` are still
// live locals; reverting the scoped `catch` around that call to a bare
// `try` leaks both (the framed envelope copy + the decoded statement) at
// the two allocation points inside storeLatest (map getOrPut, the
// StoredEnvelope box), and this test reports MemoryLeakDetected.
test "restore_own_envelope: no leak at any allocation point (nominate + externalize)" {
    const gpa = testing.allocator;

    // The own log entries: envelopes signed with the ENGINE's own seed —
    // a NOMINATE (slot 3) and an EXTERNALIZE (slot 8, what own.log holds
    // after a crash), so both storeLatest maps and both own_* arms run.
    var eng = try makeEngine(gpa, .{});
    const local_qset_hash = eng.ctx.local_qset_hash;
    eng.deinit();
    const own_nom = try peerEnvelope(gpa, engine_seed, 3, .{ .nominate = .{
        .qset_hash = local_qset_hash,
        .votes = &.{"mine"},
        .accepted = &.{},
    } });
    defer gpa.free(own_nom);
    const own_ext = try peerEnvelope(gpa, engine_seed, 8, .{ .externalize = .{
        .commit = .{ .counter = 1, .value = "mine" },
        .n_h = 1,
        .commit_qset_hash = local_qset_hash,
    } });
    defer gpa.free(own_ext);

    try expectRestoreLeaksNothing(own_nom);
    try expectRestoreLeaksNothing(own_ext);
}
