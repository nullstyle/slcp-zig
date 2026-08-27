//! The envelope/input pipeline (design §5 intro, §5.2/§5.3, M2): decode →
//! sanity → signature verify → strictCanonical → relevance filter → slot
//! admission → freshness → qset resolution/parking → stored-bytes budget →
//! store/forward/dispatch — and exactly ONE input_status per input, ALWAYS
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
//!   8. relevance: sender outside the transitive quorum graph (§5.4) → ignored
//!   9. slot admission (max_live_slots; existing slots always accept) →
//!      over_limit
//!  10. freshness vs the per-(node, protocol) latest via stored.isNewerOwned
//!      (§5.4 partial orders) → stale
//!  11. qset resolution: unknown non-EXTERNALIZE qset hash parks (§5.4;
//!      EXTERNALIZE never parks — singleton qset) → parked_awaiting_qset /
//!      over_limit (per-node cap); evictions of PAST inputs emit
//!      phase_event(parked_evicted), never a second input_status
//!  12. stored-bytes budget (§5.1 max_stored_statement_bytes) → over_limit
//!  13. setAdvertised + storeLatest + forward_envelope (freshness advanced ⇒
//!      relay, §5.3) + protocol dispatch → applied
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
// Post-resolution half: budget → advertise → store → forward → dispatch.
// Shared by the live envelope path and the qset_received unpark replay.
// ---------------------------------------------------------------------------

/// Returns false when the protocol rejected the statement's VALUE via the
/// driver (ballot error.InvalidValue — stellar-core's EnvelopeState::INVALID):
/// the statement stays stored (freshness dedup holds, reprocessing-spam
/// protection — a deliberate SLCP divergence, documented) but is NOT relayed.
fn dispatchProtocol(eng: *engine.Engine, s: *slot_mod.Slot, st: *const stored.OwnedStatement) engine.EngineError!bool {
    const r = if (st.isNomination())
        nomination_mod.processEnvelope(&eng.ctx, s, st)
    else
        ballot_mod.processEnvelope(&eng.ctx, s, st);
    r catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.EffectBudgetExceeded => return error.EffectBudgetExceeded,
        error.InvalidValue => return false,
        else => return error.EngineFailed,
    };
    return true;
}

/// Steps 12–13. Takes ownership of `env` unconditionally. Returns false when
/// the engine-wide stored-bytes budget rejected it (dropped, not stored).
const Admit = enum { admitted, over_budget, value_invalid };

fn admitResolved(eng: *engine.Engine, s: *slot_mod.Slot, env: stored.StoredEnvelope) engine.EngineError!Admit {
    var owned = env;
    const gpa = eng.gpa;
    const node = owned.statement.node_id;
    const is_nom = owned.statement.isNomination();
    const is_ext = owned.statement.pledges == .externalize;
    const qh = owned.statement.qsetHash();

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

    const delta = try s.storeLatest(gpa, owned);
    eng.stored_statement_bytes = @intCast(@as(isize, @intCast(eng.stored_statement_bytes)) + delta);
    // Advertised AFTER the store (ownership review: an advertise failure
    // must not leak the in-flight envelope). EXTERNALIZE's audit hash is
    // never advertised (§5.4: the sender counts as the singleton {sender,1}).
    if (!is_ext) try eng.qsets.setAdvertised(node, qh);
    const kept = s.latestFor(node, is_nom).?;

    // Process BEFORE relaying (stellar-core broadcasts only VALID
    // envelopes). A residual protocol rejection (the EXTERNALIZE-phase
    // value-mismatch arm) purges the stored statement — it must count in no
    // federated predicate (oracle: never recorded).
    if (!try dispatchProtocol(eng, s, &kept.statement)) {
        const freed = s.removeLatest(gpa, node, is_nom);
        eng.stored_statement_bytes -= freed;
        return .value_invalid;
    }

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

    // Step 8: §5.4 relevance filter — outside the transitive quorum graph.
    if (!eng.qsets.inGraph(node)) return .ignored;

    var owned = stored.fromReader(gpa, rdr) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .insane, // sane statements decode; defense in depth
    };

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
    const qset_hash = owned.qsetHash();
    const is_ext = owned.pledges == .externalize;
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
        // Driver-invalid value: stored (dedup) but rejected — the closest
        // §5.2 status is insane (the statement is unusable as received).
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
    try eng.qsets.insert(h, qs); // takes ownership; dedups

    // Unpark: re-drive every envelope waiting on this hash through the
    // post-resolution half. Parked envelopes were FULLY verified (decode,
    // sanity, signature, canonicality, relevance) before parking — no
    // re-verification. Replays carry NO input_status of their own (§5.3 1:1
    // rule); a replay that now fails admission is dropped silently.
    const taken = try eng.pending.take(h);
    defer gpa.free(taken);
    var replay_err: ?engine.EngineError = null;
    for (taken) |env| {
        var e = env;
        if (replay_err != null) {
            e.deinit(gpa);
            continue;
        }
        replayParked(eng, e) catch |err| {
            replay_err = err;
        };
    }
    if (replay_err) |e| return e;

    // Unsolicited qsets are still useful (cache warm-up) — applied either way.
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
    const delta = try s.storeLatest(gpa, latest_env);
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
    var it = eng.slots.iterator();
    while (it.next()) |entry| {
        if (entry.key_ptr.* < max_slot) try victims.append(gpa, entry.key_ptr.*);
    }
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
    limits: limits_mod.Limits = .{},
};

/// Engine whose local qset is {1, [self, peer, peer2, peer3]} — all test
/// peers are in the transitive quorum graph.
fn makeEngine(gpa: std.mem.Allocator, opts: EngineOpts) !engine.Engine {
    const node_id = try crypto.publicKeyFromSeed(engine_seed);
    const members = [_][32]u8{
        node_id,
        try crypto.publicKeyFromSeed(peer_seed),
        try crypto.publicKeyFromSeed(peer2_seed),
        try crypto.publicKeyFromSeed(peer3_seed),
    };
    const qs = try ownedQsetOf(gpa, 1, &members);
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
    var ctx = engine.Ctx{
        .gpa = gpa,
        .cfg = &cfg,
        .drv = &drv,
        .effects = &effects,
        .qsets = &store,
        .excised = null,
        .local_qset_hash = @splat(0),
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
