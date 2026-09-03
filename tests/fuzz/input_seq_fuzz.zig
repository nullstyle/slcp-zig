//! Input-sequence fuzz target (design §13.5): random VALID-TYPED input
//! interleavings against ONE honest engine, checking the §13.1 structural
//! invariants after EVERY input. Where decode_fuzz hammers the decode surface
//! with arbitrary bytes, this target drives the STATE MACHINE: nominations,
//! timer fires, real key-holder envelopes (crafted via the phase-0 Forger),
//! qset answers, purges, and own-envelope restore — in an arbitrary order
//! derived from the fuzz bytes.
//!
//! Invariants asserted after every input (reusing sim/invariants.zig):
//!   - exactly ONE input_status per input, always the final effect (§5.3);
//!   - the effect queue stays within its bounds (§13.1 / EffectQueue budget);
//!   - own emitted statements are strictly newer than the previous own
//!     statement of the same protocol — phase/counter monotonic per slot
//!     (invariants.recordOwnStatement; own EXTERNALIZE pairs are judged by
//!     committed value, invariants.ownEmissionAllowed) — with the tracker's
//!     memory scoped like the engine's: an APPLIED purge_slots forgets the
//!     purged slots (invariants.Tracker.purgeBelow), because the target draws
//!     `nominate` slots independently of its purges and the engine restarts a
//!     purged slot from empty state (the S9 fuzz-long class, tests/fuzz/crash/);
//!   - `externalized` is emitted at most once per slot
//!     (invariants.recordExternalizedEffect);
//!   - the per-slot ballot invariants (invariants.checkEngine, the oracle's
//!     BallotProtocol::checkInvariants mirror);
//!   - the engine never panics/UB, and either stays healthy or goes cleanly
//!     sticky-failed (a legitimate typed outcome, §7.2).
//!
//! Adversary channel: honest engines only ever act on crafted
//! envelope_received frames from real key-holders, so the fuzzed peer
//! statements are minted by a `Forger` (sim/adversary.zig) seeded with a
//! validator of the shared qset (relevance filter, §5.4).
//!
//! Fuzz API (zig 0.17): std.testing.fuzz(context, testOne, .{ .corpus }),
//! testOne: fn (context, *std.testing.Smith). The deterministic `fuzz-smoke`
//! runs 5000 fixed-seed multi-input sequences, giving every input a valid
//! Smith{ .in = bytes } replay stream.

const std = @import("std");
const slcp = @import("slcp-core");
const adversary = @import("adversary");
const invariants = @import("invariants");

const engine = slcp.engine;
const crypto = slcp.crypto;
const qset = slcp.qset;
const canonical = slcp.canonical;
const driver = slcp.driver;

const sim_passphrase = "slcp-sim v1";
fn nodeSeed(i: u8) [32]u8 {
    var s: [32]u8 = @splat(0);
    s[0] = i +% 1;
    return s;
}

const n_members: u8 = 4;
const max_inputs = 48; // per-iteration cap on the derived sequence
const max_value_bytes = 40;

/// What the deterministic smoke actually derived at the `stepOnce` seam.
/// This deliberately observes consumed Smith values rather than the byte
/// producer, so a malformed replay stream cannot satisfy the diversity gate.
const SmokeDiversity = struct {
    const max_distinct_values = 64;
    const Value = struct {
        len: u8 = 0,
        bytes: [max_value_bytes]u8 = @splat(0),
    };

    operations: [7]bool = @splat(false),
    slots: [8]bool = @splat(false),
    forged_statements: [4]bool = @splat(false),
    statuses: std.enums.EnumSet(engine.InputStatus) = .empty,
    checked_inputs: usize = 0,
    values: [max_distinct_values]Value = @splat(.{}),
    value_count: usize = 0,

    fn record(self: *SmokeDiversity, operation: u8, slot: ?u64, value: ?[]const u8) void {
        self.operations[operation] = true;
        if (slot) |s| self.slots[s - 1] = true;

        // Values only reach the engine on nominate and forged-envelope
        // inputs. Callers pass null for operations without an input value so
        // the common decoder's unused candidate cannot inflate this count.
        const input_value = value orelse return;
        for (self.values[0..self.value_count]) |known| {
            if (known.len == input_value.len and std.mem.eql(u8, known.bytes[0..known.len], input_value)) return;
        }
        if (self.value_count == self.values.len) return;
        var sample: Value = .{ .len = @intCast(input_value.len) };
        @memcpy(sample.bytes[0..input_value.len], input_value);
        self.values[self.value_count] = sample;
        self.value_count += 1;
    }

    fn operationCount(self: *const SmokeDiversity) usize {
        var count: usize = 0;
        for (self.operations) |seen| count += @intFromBool(seen);
        return count;
    }

    fn slotCount(self: *const SmokeDiversity) usize {
        var count: usize = 0;
        for (self.slots) |seen| count += @intFromBool(seen);
        return count;
    }

    fn recordForged(self: *SmokeDiversity, statement: adversary.RawStatement) void {
        const subtype: usize = switch (statement) {
            .nominate => 0,
            .prepare => 1,
            .confirm => 2,
            .externalize => 3,
        };
        self.forged_statements[subtype] = true;
    }

    fn forgedStatementCount(self: *const SmokeDiversity) usize {
        var count: usize = 0;
        for (self.forged_statements) |seen| count += @intFromBool(seen);
        return count;
    }

    fn recordCheckedStatus(self: *SmokeDiversity, status: engine.InputStatus) void {
        self.statuses.insert(status);
        self.checked_inputs += 1;
    }

    fn sawStatus(self: *const SmokeDiversity, status: engine.InputStatus) bool {
        return self.statuses.contains(status);
    }

    fn statusCount(self: *const SmokeDiversity) usize {
        return self.statuses.count();
    }
};

/// A fully-wired honest node plus the shared-qset framing the fuzzer needs to
/// answer request_qset and to make peer statements resolve (not park).
const Fixture = struct {
    eng: engine.Engine,
    forger: adversary.Forger,
    shared_framed: []u8,
    shared_hash: [32]u8,
    tracker: invariants.Tracker = .{},
    last_own: ?[]u8 = null,
    smoke_diversity: ?*SmokeDiversity = null,
    // Replay instrumentation (null in fuzz / smoke runs): an optional trace
    // sink plus the bookkeeping a violation report needs — the previous own
    // statement per (slot, protocol) and the last APPLIED restore per slot.
    trace: ?*Trace = null,
    step: usize = 0,
    last_status: ?engine.InputStatus = null,
    prev_own: std.AutoHashMapUnmanaged(u64, [2]?OwnSummary) = .empty,
    restore_steps: std.AutoHashMapUnmanaged(u64, usize) = .empty,

    fn init(gpa: std.mem.Allocator) !Fixture {
        var pks: [n_members][32]u8 = undefined;
        for (0..n_members) |i| pks[i] = try crypto.publicKeyFromSeed(nodeSeed(@intCast(i)));

        var shared = qset.QuorumSetOwned{
            .threshold = (2 * @as(u32, n_members) + 2) / 3,
            .validators = try gpa.dupe([32]u8, pks[0..]),
            .inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0),
        };
        defer shared.deinit(gpa);
        try qset.validateAndNormalize(gpa, &shared);
        const shared_flat = try qset.canonicalBytes(gpa, &shared);
        defer gpa.free(shared_flat);
        const shared_hash = crypto.qsetHash(shared_flat);
        const shared_framed = try canonical.frameFlat(gpa, shared_flat);
        errdefer gpa.free(shared_framed);

        const net = crypto.networkIdFromPassphrase(sim_passphrase);
        var eng = try engine.Engine.init(gpa, .{
            .network_id = net,
            .node_id = pks[0],
            .secret_seed = nodeSeed(0),
            .quorum_set = try qset.clone(gpa, &shared),
        }, driver.Driver.default());
        errdefer eng.deinit();

        // Forger keyed as node 1 — a validator of the shared qset, so its
        // frames pass the relevance filter.
        const forger = try adversary.Forger.init(gpa, nodeSeed(1), net);

        return .{ .eng = eng, .forger = forger, .shared_framed = shared_framed, .shared_hash = shared_hash };
    }

    fn deinit(self: *Fixture, gpa: std.mem.Allocator) void {
        self.eng.deinit();
        self.tracker.deinit(gpa);
        gpa.free(self.shared_framed);
        if (self.last_own) |b| gpa.free(b);
        self.prev_own.deinit(gpa);
        self.restore_steps.deinit(gpa);
        self.* = undefined;
    }
};

/// Drain every effect of the last input, wiring the §13.1 structural
/// invariants. Returns a violation string on a real breach (fails the iter);
/// returns normally when the contract holds.
fn drainAndCheck(gpa: std.mem.Allocator, fx: *Fixture) !void {
    const eng = &fx.eng;
    var status_count: usize = 0;
    var last_was_status = false;
    while (eng.popEffect()) |eff| {
        last_was_status = false;
        switch (eff.*) {
            .persist_own_envelope => |sb| {
                const st = invariants.decodeOwnEnvelope(gpa, sb.bytes) catch return error.OwnEnvelopeUndecodable;
                const summary = summarizeOwn(&st, fx.step);
                if (try invariants.recordOwnStatement(&fx.tracker, gpa, st)) |_| {
                    try noteViolation(fx, summary);
                    return error.OwnStatementNotMonotonic;
                }
                try noteOwn(gpa, fx, summary);
                // Keep the latest own frame for restore_own_envelope replay.
                if (fx.last_own) |b| gpa.free(b);
                fx.last_own = try gpa.dupe(u8, sb.bytes);
            },
            .externalized => |sb| {
                if (fx.trace) |t| if (t.w) |w| {
                    const tag = hashTag(sb.bytes);
                    try w.print("      effect externalized slot={d} value={s}/{d}B\n", .{ sb.slot, &tag, sb.bytes.len });
                };
                if (try invariants.recordExternalizedEffect(&fx.tracker, gpa, sb.slot)) |_| return error.ExternalizedTwice;
            },
            .input_status => |st| {
                status_count += 1;
                last_was_status = true;
                fx.last_status = st.code;
            },
            else => {},
        }
        eng.commitEffect();
    }
    if (fx.trace) |t| if (t.w) |w| {
        if (fx.last_status) |code| try w.print("      -> {t}\n", .{code});
    };
    // §5.3: exactly one input_status per input, always last.
    if (status_count != 1 or !last_was_status) return error.InputStatusContract;
    // Per-slot ballot invariants + effect-queue bound (§13.1).
    if (try invariants.checkEngine(eng, &fx.tracker, gpa)) |_| return error.EngineInvariant;
    if (fx.smoke_diversity) |diversity| {
        diversity.recordCheckedStatus(fx.last_status orelse unreachable);
        executed_steps += 1;
    }
}

/// Push one input; on a clean sticky failure (a legitimate §7.2 outcome)
/// drain leftover effects and report `.failed` so the caller stops the run.
const PushOutcome = enum { ok, failed };
fn pushOne(gpa: std.mem.Allocator, fx: *Fixture, input: engine.Input) !PushOutcome {
    fx.eng.pushInput(input) catch |err| {
        if (fx.trace) |t| if (t.w) |w| try w.print("      -> engine sticky-failed: {t}\n", .{err});
        while (fx.eng.popEffect()) |_| fx.eng.commitEffect();
        return .failed;
    };
    try drainAndCheck(gpa, fx);
    return .ok;
}

/// Push a purge_slots input and, once the engine APPLIED it, scope the
/// harness memory the same way: the invariants tracker forgets the purged
/// slots (§10 — the engine dropped all state for them; a later input for
/// such a slot re-creates it from empty state) and so does the replay
/// bookkeeping.
fn purgeSlots(gpa: std.mem.Allocator, fx: *Fixture, max_slot: u64) !PushOutcome {
    const outcome = try pushOne(gpa, fx, .{ .purge_slots = .{ .max_slot = max_slot } });
    if (outcome == .ok and fx.last_status == .applied) try forgetPurged(gpa, fx, max_slot);
    return outcome;
}

fn forgetPurged(gpa: std.mem.Allocator, fx: *Fixture, max_slot: u64) !void {
    try fx.tracker.purgeBelow(gpa, max_slot);
    var doomed: std.ArrayList(u64) = .empty;
    defer doomed.deinit(gpa);
    var it = fx.prev_own.keyIterator();
    while (it.next()) |k| if (k.* < max_slot) try doomed.append(gpa, k.*);
    for (doomed.items) |k| _ = fx.prev_own.remove(k);
    doomed.clearRetainingCapacity();
    var rit = fx.restore_steps.keyIterator();
    while (rit.next()) |k| if (k.* < max_slot) try doomed.append(gpa, k.*);
    for (doomed.items) |k| _ = fx.restore_steps.remove(k);
}

/// Trace one derived input (replay only; a no-op without a trace sink).
fn traceInput(fx: *Fixture, comptime fmt: []const u8, args: anytype) !void {
    const t = fx.trace orelse return;
    const w = t.w orelse return;
    try w.print("[{d:>3}] " ++ fmt ++ "\n", .{fx.step} ++ args);
}

fn pickBallot(smith: *std.testing.Smith, value: []const u8) adversary.BV {
    return .{ .counter = smith.valueRangeAtMost(u32, 0, 6), .value = value };
}

/// Derive and execute one arbitrary VALID-TYPED input from the Smith, against
/// `fx`. Returns .failed once the engine sticky-fails.
fn stepOnce(gpa: std.mem.Allocator, fx: *Fixture, smith: *std.testing.Smith) !PushOutcome {
    fx.step += 1;
    const slot = smith.valueRangeAtMost(u64, 1, 8);
    var vbuf: [max_value_bytes]u8 = undefined;
    const vlen = smith.slice(&vbuf);
    const value = vbuf[0..vlen];
    const vtag = hashTag(value);

    // Mostly a random hash to exercise the park path; occasionally the shared
    // hash so statements resolve immediately.
    const shared_qh = smith.boolWeighted(7, 1);
    const qh: [32]u8 = if (shared_qh) fx.shared_hash else smith.value([32]u8);

    const operation = smith.valueRangeAtMost(u8, 0, 6);
    switch (operation) {
        0 => {
            try traceInput(fx, "nominate slot={d} value={s}/{d}B", .{ slot, &vtag, value.len });
            if (fx.smoke_diversity) |diversity| diversity.record(operation, slot, value);
            return pushOne(gpa, fx, .{ .nominate = .{ .slot = slot, .value = value, .prev_value = &.{} } });
        },
        1 => {
            const timer: engine.TimerId = if (smith.value(bool)) .ballot else .nomination;
            try traceInput(fx, "timer_fired slot={d} timer={t}", .{ slot, timer });
            if (fx.smoke_diversity) |diversity| diversity.record(operation, slot, null);
            return pushOne(gpa, fx, .{ .timer_fired = .{ .slot = slot, .timer = timer } });
        },
        2 => {
            // A real key-holder envelope with fuzz-chosen content.
            const forged_subtype = smith.valueRangeAtMost(u8, 0, 3);
            const raw: adversary.RawStatement = switch (forged_subtype) {
                0 => .{ .nominate = .{ .qset_hash = qh, .votes = &.{value}, .accepted = &.{} } },
                1 => .{ .prepare = .{ .qset_hash = qh, .ballot = pickBallot(smith, value) } },
                2 => .{ .confirm = .{
                    .qset_hash = qh,
                    .ballot = pickBallot(smith, value),
                    .n_prepared = smith.valueRangeAtMost(u32, 0, 6),
                    .n_commit = smith.valueRangeAtMost(u32, 0, 6),
                    .n_h = smith.valueRangeAtMost(u32, 0, 6),
                } },
                else => .{ .externalize = .{
                    .commit = pickBallot(smith, value),
                    .n_h = smith.valueRangeAtMost(u32, 0, 6),
                    .commit_qset_hash = qh,
                } },
            };
            switch (raw) {
                .nominate => try traceInput(fx, "envelope(peer1) NOMINATE slot={d} votes=[{s}/{d}B] qset={s}", .{ slot, &vtag, value.len, if (shared_qh) "shared" else "random" }),
                .prepare => |p| try traceInput(fx, "envelope(peer1) PREPARE slot={d} b=({d},{s}/{d}B) qset={s}", .{ slot, p.ballot.counter, &vtag, value.len, if (shared_qh) "shared" else "random" }),
                .confirm => |c| try traceInput(fx, "envelope(peer1) CONFIRM slot={d} b=({d},{s}/{d}B) nPrepared={d} nCommit={d} nH={d} qset={s}", .{ slot, c.ballot.counter, &vtag, value.len, c.n_prepared, c.n_commit, c.n_h, if (shared_qh) "shared" else "random" }),
                .externalize => |e| try traceInput(fx, "envelope(peer1) EXTERNALIZE slot={d} commit=({d},{s}/{d}B) nH={d} qset={s}", .{ slot, e.commit.counter, &vtag, value.len, e.n_h, if (shared_qh) "shared" else "random" }),
            }
            const env = fx.forger.sign(slot, raw) catch return .ok; // build failure ⇒ skip
            defer gpa.free(env);
            if (fx.smoke_diversity) |diversity| {
                diversity.record(operation, slot, value);
                diversity.recordForged(raw);
            }
            return pushOne(gpa, fx, .{ .envelope_received = .{ .bytes = env } });
        },
        3 => {
            try traceInput(fx, "qset_received (shared qset)", .{});
            if (fx.smoke_diversity) |diversity| diversity.record(operation, null, null);
            return pushOne(gpa, fx, .{ .qset_received = .{ .bytes = fx.shared_framed } });
        },
        4 => {
            const max_slot = smith.valueRangeAtMost(u64, 0, 8);
            try traceInput(fx, "purge_slots max_slot={d}", .{max_slot});
            if (fx.smoke_diversity) |diversity| diversity.record(operation, null, null);
            return purgeSlots(gpa, fx, max_slot);
        },
        5 => {
            // Replay a captured own frame (startup-only in practice; a
            // mid-stream replay must still yield a typed status, never UB).
            if (fx.last_own) |frame| {
                const dup = try gpa.dupe(u8, frame); // engine may free/replace fx.last_own during the push
                defer gpa.free(dup);
                var restored = invariants.decodeOwnEnvelope(gpa, dup) catch return error.OwnEnvelopeUndecodable;
                const rs = summarizeOwn(&restored, fx.step);
                restored.deinit(gpa);
                if (fx.trace) |t| if (t.w) |w| {
                    try w.print("[{d:>3}] restore_own_envelope (latest own frame) ", .{fx.step});
                    try writeSummary(w, rs);
                    try w.writeAll("\n");
                };
                if (fx.smoke_diversity) |diversity| diversity.record(operation, rs.slot, null);
                const outcome = try pushOne(gpa, fx, .{ .restore_own_envelope = .{ .bytes = dup } });
                if (outcome == .ok and fx.last_status == .applied) try fx.restore_steps.put(gpa, rs.slot, fx.step);
                return outcome;
            }
            try traceInput(fx, "restore_own_envelope skipped (no own frame yet)", .{});
            return .ok;
        },
        else => {
            // A typed envelope carrying arbitrary garbage bytes.
            var gbuf: [64]u8 = undefined;
            const glen = smith.slice(&gbuf);
            try traceInput(fx, "envelope(garbage {d}B)", .{glen});
            if (fx.smoke_diversity) |diversity| diversity.record(operation, null, null);
            return pushOne(gpa, fx, .{ .envelope_received = .{ .bytes = gbuf[0..glen] } });
        },
    }
}

/// One fuzz iteration: build a fresh engine, derive an arbitrary-length input
/// sequence from the Smith, and check invariants after every input. Runs on a
/// leak-checked DebugAllocator so leaks fail the iteration.
fn fuzzInputSeqOne(_: void, smith: *std.testing.Smith) anyerror!void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    const result = run(da.allocator(), smith, null); // coverage-guided: eos picks the length
    const leak = da.deinit();
    try result;
    if (leak == .leak) return error.MemoryLeak;
}

fn appendSmokeU64(out: []u8, used: *usize, value: u64) void {
    std.debug.assert(used.* + @sizeOf(u64) <= out.len);
    std.mem.writeInt(u64, out[used.*..][0..@sizeOf(u64)], value, .little);
    used.* += @sizeOf(u64);
}

fn appendSmokeSlice(rand: std.Random, out: []u8, used: *usize, max_len: u32) void {
    const len = rand.uintLessThan(u32, max_len + 1);
    const len_usize: usize = @intCast(len);
    std.debug.assert(used.* + @sizeOf(u32) + len_usize <= out.len);
    std.mem.writeInt(u32, out[used.*..][0..@sizeOf(u32)], len, .little);
    used.* += @sizeOf(u32);
    rand.bytes(out[used.* .. used.* + len_usize]);
    used.* += len_usize;
}

fn appendSmokeBytes(rand: std.Random, out: []u8, used: *usize, len: usize) void {
    std.debug.assert(used.* + len <= out.len);
    rand.bytes(out[used.* .. used.* + len]);
    used.* += len;
}

/// Produce one valid Smith replay stream for `stepOnce`. In replay mode every
/// constrained scalar occupies a little-endian u64 and every slice is a u32
/// length followed by that many bytes. Uniform random bytes do not have that
/// shape: nearly every scalar falls outside its allowed range and the first
/// random slice length consumes the rest of the stream.
fn smokeStepBytes(rand: std.Random, out: []u8) []const u8 {
    var used: usize = 0;

    appendSmokeU64(out, &used, rand.intRangeAtMost(u64, 1, 8)); // slot
    appendSmokeSlice(rand, out, &used, max_value_bytes); // value

    // Mirror boolWeighted(7, 1): false seven-eighths of the time, true once.
    const shared_qset = rand.uintLessThan(u8, 8) == 0;
    appendSmokeU64(out, &used, @intFromBool(shared_qset));
    if (!shared_qset) appendSmokeBytes(rand, out, &used, 32); // random qset hash

    const operation = rand.uintLessThan(u8, 7);
    appendSmokeU64(out, &used, operation);
    switch (operation) {
        0, 3, 5 => {},
        1 => appendSmokeU64(out, &used, @intFromBool(rand.boolean())),
        2 => {
            const statement = rand.uintLessThan(u8, 4);
            appendSmokeU64(out, &used, statement);
            switch (statement) {
                0 => {},
                1 => appendSmokeU64(out, &used, rand.intRangeAtMost(u64, 0, 6)),
                2 => {
                    appendSmokeU64(out, &used, rand.intRangeAtMost(u64, 0, 6)); // ballot counter
                    appendSmokeU64(out, &used, rand.intRangeAtMost(u64, 0, 6)); // n_prepared
                    appendSmokeU64(out, &used, rand.intRangeAtMost(u64, 0, 6)); // n_commit
                    appendSmokeU64(out, &used, rand.intRangeAtMost(u64, 0, 6)); // n_h
                },
                else => {
                    appendSmokeU64(out, &used, rand.intRangeAtMost(u64, 0, 6)); // commit counter
                    appendSmokeU64(out, &used, rand.intRangeAtMost(u64, 0, 6)); // n_h
                },
            }
        },
        4 => appendSmokeU64(out, &used, rand.intRangeAtMost(u64, 0, 8)),
        else => appendSmokeSlice(rand, out, &used, 64), // arbitrary garbage envelope
    }
    return out[0..used];
}

/// One deterministic smoke iteration over a fixed `budget` of inputs. Each
/// input receives its own well-formed Smith stream, so branch-specific bytes
/// left unread by one step cannot misalign the next. The engine fixture stays
/// alive for the full multi-input sequence. Leak-checked.
fn smokeOne(rand: std.Random, budget: usize, diversity: *SmokeDiversity) anyerror!void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    const result = smokeSequence(da.allocator(), rand, budget, diversity);
    const leak = da.deinit();
    try result;
    if (leak == .leak) return error.MemoryLeak;
}

fn smokeSequence(gpa: std.mem.Allocator, rand: std.Random, budget: usize, diversity: *SmokeDiversity) !void {
    var fx = try Fixture.init(gpa);
    defer fx.deinit(gpa);
    fx.smoke_diversity = diversity;

    var scratch: [192]u8 = undefined;
    const guard_len = 16;
    var steps: usize = 0;
    while (steps < budget) : (steps += 1) {
        const encoded = smokeStepBytes(rand, &scratch);
        @memset(scratch[encoded.len..][0..guard_len], 0xa5);
        var smith: std.testing.Smith = .{ .in = scratch[0 .. encoded.len + guard_len] };
        const outcome = try stepOnce(gpa, &fx, &smith);
        // The producer mirrors Smith's replay ABI exactly. Keeping a guard
        // beyond the intended stream catches both under-production (Smith
        // consumes guard bytes instead of defaulting at EOF) and over-
        // production (encoded bytes remain before the intact guard).
        const remaining = smith.in.?;
        if (remaining.len != guard_len or !std.mem.allEqual(u8, remaining, 0xa5)) {
            return error.SmokeSmithStreamMismatch;
        }
        if (outcome == .failed) break;
    }
}

/// Coverage-guided path: the fuzzer drives sequence length through eos and
/// supplies Smith's typed values directly.
fn run(gpa: std.mem.Allocator, smith: *std.testing.Smith, trace: ?*Trace) !void {
    var fx = try Fixture.init(gpa);
    defer fx.deinit(gpa);
    fx.trace = trace;
    defer if (trace) |t| {
        t.steps = fx.step;
    };

    var steps: usize = 0;
    while (steps < max_inputs and !smith.eos()) : (steps += 1) {
        if (try stepOnce(gpa, &fx, smith) == .failed) break;
    }
}

// ---------------------------------------------------------------------------
// Replay of saved fuzz inputs (S9 finding 2). The coverage-guided fuzzer
// logs every value it hands the Smith into `.zig-cache/f/in<N>` in exactly
// the `Smith{ .in = bytes }` encoding — ints as u64 LE, eos as one byte,
// bytes raw, slices as u32 LE length + bytes (lib/fuzzer.zig nextInt /
// nextEos / nextBytes / nextSlice) — and on a failure the build runner
// copies the header-stripped stream to `.zig-cache/f/crash`. Feeding those
// bytes back through `Smith{ .in = bytes }` and the SAME eos-gated `run`
// path replays the failing iteration deterministically.
// ---------------------------------------------------------------------------

pub const OwnKind = enum { nominate, prepare, confirm, externalize };

/// A decoded own statement flattened for reporting (no allocations).
pub const OwnSummary = struct {
    /// The 1-based input index whose drain carried the persist effect.
    step: usize,
    slot: u64,
    kind: OwnKind,
    /// ballot.counter (PREPARE / CONFIRM) or commit.counter (EXTERNALIZE).
    counter: u32 = 0,
    n_c: u32 = 0,
    n_h: u32 = 0,
    n_prepared: u32 = 0,
    prepared: ?u32 = null,
    prepared_prime: ?u32 = null,
    /// sha256 of the ballot / commit value (NOMINATE: of the joined votes).
    value_hash: [32]u8 = @splat(0),
    value_len: usize = 0,
    votes: usize = 0,
    accepted: usize = 0,
};

/// The pair the §13.1 own-monotonicity invariant rejected.
pub const Finding = struct {
    prev: OwnSummary,
    new: OwnSummary,
    /// A restore_own_envelope for this slot was APPLIED strictly between
    /// the two emissions.
    restore_between: bool,
    /// Set only when both are EXTERNALIZE: byte-equal commit values (the
    /// v0.1.0 RELEASING.md run-log re-emit class) or not (a fork).
    same_committed_value: ?bool,
};

pub const Trace = struct {
    /// Optional human-readable trace sink (one line per input / own effect).
    w: ?*std.Io.Writer = null,
    /// Filled when the own-monotonicity invariant fires.
    finding: ?Finding = null,
    /// Inputs derived (including ones the engine rejected) before the run
    /// ended.
    steps: usize = 0,
    /// Unconsumed input bytes when the run ended (replayBytes only). Zero
    /// means the stream was exhausted — `eos()` on an empty stream is true,
    /// so a saved input that is a truncated prefix ends there quietly.
    bytes_left: usize = 0,
};

/// Replay a saved fuzz byte stream (the `.zig-cache/f/crash` bytes) through
/// the coverage-guided path: `Smith{ .in = bytes }`, eos-gated length.
pub fn replayBytes(gpa: std.mem.Allocator, bytes: []const u8, trace: ?*Trace) !void {
    var smith: std.testing.Smith = .{ .in = bytes };
    defer if (trace) |t| {
        t.bytes_left = if (smith.in) |rest| rest.len else 0;
    };
    return run(gpa, &smith, trace);
}

/// 16 hex chars of sha256(bytes) — a short stable tag for values / frames.
pub fn hashTag(bytes: []const u8) [16]u8 {
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &d, .{});
    return std.fmt.bytesToHex(d[0..8].*, .lower);
}

fn summarizeOwn(st: *const slcp.stored.OwnedStatement, step: usize) OwnSummary {
    var s: OwnSummary = .{ .step = step, .slot = st.slot, .kind = .nominate };
    switch (st.pledges) {
        .nominate => |*n| {
            s.kind = .nominate;
            s.votes = n.votes.len;
            s.accepted = n.accepted.len;
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            for (n.votes) |v| {
                h.update(v);
                h.update(&.{0});
            }
            h.final(&s.value_hash);
        },
        .prepare => |*p| {
            s.kind = .prepare;
            s.counter = p.ballot.counter;
            s.n_c = p.n_c;
            s.n_h = p.n_h;
            s.prepared = if (p.prepared) |*b| b.counter else null;
            s.prepared_prime = if (p.prepared_prime) |*b| b.counter else null;
            std.crypto.hash.sha2.Sha256.hash(p.ballot.value, &s.value_hash, .{});
            s.value_len = p.ballot.value.len;
        },
        .confirm => |*c| {
            s.kind = .confirm;
            s.counter = c.ballot.counter;
            s.n_prepared = c.n_prepared;
            s.n_c = c.n_commit;
            s.n_h = c.n_h;
            std.crypto.hash.sha2.Sha256.hash(c.ballot.value, &s.value_hash, .{});
            s.value_len = c.ballot.value.len;
        },
        .externalize => |*e| {
            s.kind = .externalize;
            s.counter = e.commit.counter;
            s.n_h = e.n_h;
            std.crypto.hash.sha2.Sha256.hash(e.commit.value, &s.value_hash, .{});
            s.value_len = e.commit.value.len;
        },
    }
    return s;
}

pub fn writeSummary(w: *std.Io.Writer, s: OwnSummary) !void {
    const tag = std.fmt.bytesToHex(s.value_hash[0..8].*, .lower);
    switch (s.kind) {
        .nominate => try w.print("slot={d} NOMINATE votes={d} accepted={d} votes_hash={s} (step {d})", .{ s.slot, s.votes, s.accepted, &tag, s.step }),
        .prepare => try w.print("slot={d} PREPARE b=({d},{s}/{d}B) p={?d} p'={?d} nC={d} nH={d} (step {d})", .{ s.slot, s.counter, &tag, s.value_len, s.prepared, s.prepared_prime, s.n_c, s.n_h, s.step }),
        .confirm => try w.print("slot={d} CONFIRM b=({d},{s}/{d}B) nPrepared={d} nCommit={d} nH={d} (step {d})", .{ s.slot, s.counter, &tag, s.value_len, s.n_prepared, s.n_c, s.n_h, s.step }),
        .externalize => try w.print("slot={d} EXTERNALIZE commit=({d},{s}/{d}B) nH={d} (step {d})", .{ s.slot, s.counter, &tag, s.value_len, s.n_h, s.step }),
    }
}

fn protoIndex(kind: OwnKind) usize {
    return if (kind == .nominate) 0 else 1;
}

fn noteOwn(gpa: std.mem.Allocator, fx: *Fixture, s: OwnSummary) !void {
    const gop = try fx.prev_own.getOrPut(gpa, s.slot);
    if (!gop.found_existing) gop.value_ptr.* = .{ null, null };
    gop.value_ptr.*[protoIndex(s.kind)] = s;
    if (fx.trace) |t| if (t.w) |w| {
        try w.writeAll("      own ");
        try writeSummary(w, s);
        try w.writeAll("\n");
    };
}

fn noteViolation(fx: *Fixture, s: OwnSummary) !void {
    const t = fx.trace orelse return;
    const prev = ((fx.prev_own.get(s.slot) orelse return)[protoIndex(s.kind)]) orelse return;
    const restore_between = if (fx.restore_steps.get(s.slot)) |r| r > prev.step else false;
    const same: ?bool = if (prev.kind == .externalize and s.kind == .externalize)
        std.mem.eql(u8, &prev.value_hash, &s.value_hash)
    else
        null;
    t.finding = .{ .prev = prev, .new = s, .restore_between = restore_between, .same_committed_value = same };
    if (t.w) |w| {
        try w.writeAll("      VIOLATION own statement rejected (invariants.ownEmissionAllowed == false)\n        prev: ");
        try writeSummary(w, prev);
        try w.writeAll("\n        new:  ");
        try writeSummary(w, s);
        try w.print("\n        restore applied in between: {}", .{restore_between});
        if (same) |eq| try w.print("; both EXTERNALIZE, committed values {s}", .{if (eq) "EQUAL" else "DIFFER"});
        try w.writeAll("\n");
    }
}

/// The three inputs `just fuzz-long` saved during the S9 release preflight
/// (sha256 86afba4c…, 2d05cef1…, 2307f4ae…), byte-identical copies.
pub const crash_inputs = [_]struct { name: []const u8, bytes: []const u8 }{
    .{ .name = "tests/fuzz/crash/input-seq-1.bin", .bytes = @embedFile("crash/input-seq-1.bin") },
    .{ .name = "tests/fuzz/crash/input-seq-2.bin", .bytes = @embedFile("crash/input-seq-2.bin") },
    .{ .name = "tests/fuzz/crash/input-seq-3.bin", .bytes = @embedFile("crash/input-seq-3.bin") },
};

// Regression corpus (S9 finding 2): the three inputs `just fuzz-long` saved
// during the v0.1.0 preflight, replayed through the coverage-guided path.
// How they were found: `zig build fuzz --fuzz` (200K, then 50K, then a
// re-run) failed the input-seq target with error.OwnStatementNotMonotonic
// three times on distinct inputs; the runner copied each failing Smith byte
// stream to .zig-cache/f/crash. What they are: inputs 1 and 3 carry an own
// NOMINATE for slot 7, an APPLIED `purge_slots max_slot=8` (the engine drops
// slot 7, design §10 GC), then `nominate slot=7` with a fresh value — the
// engine re-creates the slot and starts nomination from empty state (the
// oracle's SCP::getSlot(create=true) after purgeSlotsOutsideRange does the
// same), so its vote set {b} is not a superset of the forgotten {a}. The
// harness tracker used to compare across the purge; it now forgets purged
// slots with the engine. Neither input involves an EXTERNALIZE pair or a
// restore_own_envelope between the pair (input 3's restore at input 10 is
// for slot 5). Input 2's saved bytes are a 512-byte prefix (the runner's
// crash writer truncated it): the stream is exhausted after 8 inputs.
// Red if: the tracker stops forgetting on purge (the pair is flagged again
// at input 14 / 13), the engine stops emitting after a purge + re-nominate,
// or the corpus bytes change (sha256s pinned in RELEASING.md).
test "regression corpus: the S9 fuzz-long crash inputs replay clean (own NOMINATE after an applied purge_slots is a fresh slot, not stale-vs-self)" {
    const gpa = testing.allocator;

    // Input 1 (sha256 86afba4c…): used to fail on the 14th input.
    {
        var trace: Trace = .{};
        try replayBytes(gpa, crash_inputs[0].bytes, &trace);
        try testing.expect(trace.finding == null);
        try testing.expect(trace.steps >= 14);
    }
    // Input 2 (sha256 2d05cef1…): truncated — exhausted after 8 inputs.
    {
        var trace: Trace = .{};
        try replayBytes(gpa, crash_inputs[1].bytes, &trace);
        try testing.expect(trace.finding == null);
        try testing.expectEqual(@as(usize, 8), trace.steps);
        try testing.expectEqual(@as(usize, 0), trace.bytes_left);
    }
    // Input 3 (sha256 2307f4ae…): used to fail on the 13th input.
    {
        var trace: Trace = .{};
        try replayBytes(gpa, crash_inputs[2].bytes, &trace);
        try testing.expect(trace.finding == null);
        try testing.expect(trace.steps >= 13);
    }
}

// Non-vacuity: the minimal three-input form of what inputs 1 and 3 hit,
// against the same Fixture + invariants, plus the two controls that keep it
// honest. (1) nominate 7 "a" → purge_slots 8 → nominate 7 "b": the engine
// emits a fresh own NOMINATE whose single vote differs from "a" (proves the
// engine restarted the slot from empty state — the class is real) and the
// tracker, having forgotten slot 7, accepts it. (2) The SAME pair fed to a
// tracker that was not told about the purge is still a violation (the rule
// is live; forgetting is what changed). (3) No purge: two nominates on a
// live slot never violate (own votes only grow). Red if the purge stops
// dropping the slot, the second nominate stops emitting, the tracker keeps
// purged slots, or a live-slot shrink stops being flagged.
test "minimal: nominate, purge_slots, nominate the purged slot → fresh own NOMINATE accepted; the same pair on an unpurged tracker is a violation" {
    const gpa = testing.allocator;

    {
        var fx = try Fixture.init(gpa);
        defer fx.deinit(gpa);
        var trace: Trace = .{};
        fx.trace = &trace;
        fx.step = 1;
        try testing.expectEqual(PushOutcome.ok, try pushOne(gpa, &fx, .{ .nominate = .{ .slot = 7, .value = "a", .prev_value = &.{} } }));
        try testing.expectEqual(engine.InputStatus.applied, fx.last_status.?);
        const first = fx.prev_own.get(7).?[0].?; // own NOMINATE {a} recorded
        try testing.expectEqual(@as(usize, 1), first.votes);

        // A second tracker that never hears about the purge: the control.
        var unpurged: invariants.Tracker = .{};
        defer unpurged.deinit(gpa);
        try testing.expect((try invariants.recordOwnStatement(&unpurged, gpa, try invariants.decodeOwnEnvelope(gpa, fx.last_own.?))) == null);

        fx.step = 2;
        try testing.expectEqual(PushOutcome.ok, try purgeSlots(gpa, &fx, 8));
        try testing.expectEqual(engine.InputStatus.applied, fx.last_status.?);
        try testing.expect(fx.eng.slots.get(7) == null); // §10: slot 7 dropped by the engine …
        try testing.expect(fx.tracker.per_slot.get(7) == null); // … and forgotten by the tracker
        try testing.expect(fx.prev_own.get(7) == null);

        fx.step = 3;
        try testing.expectEqual(PushOutcome.ok, try pushOne(gpa, &fx, .{ .nominate = .{ .slot = 7, .value = "b", .prev_value = &.{} } }));
        try testing.expectEqual(engine.InputStatus.applied, fx.last_status.?);
        try testing.expect(trace.finding == null);
        const second = fx.prev_own.get(7).?[0].?;
        try testing.expectEqual(@as(usize, 3), second.step);
        try testing.expectEqual(@as(usize, 1), second.votes);
        try testing.expect(!std.mem.eql(u8, &first.value_hash, &second.value_hash)); // {b}, not {a,b}: a fresh slot

        // Control: the unpurged tracker still rejects {a} → {b}.
        const v = try invariants.recordOwnStatement(&unpurged, gpa, try invariants.decodeOwnEnvelope(gpa, fx.last_own.?));
        try testing.expectEqualStrings(invariants.msg_not_newer, v.?.msg);
    }
    // Control: same two nominations, no purge — own votes grow (or the
    // second nominate is a no-op); either way the order holds.
    {
        var fx = try Fixture.init(gpa);
        defer fx.deinit(gpa);
        var trace: Trace = .{};
        fx.trace = &trace;
        fx.step = 1;
        try testing.expectEqual(PushOutcome.ok, try pushOne(gpa, &fx, .{ .nominate = .{ .slot = 7, .value = "a", .prev_value = &.{} } }));
        fx.step = 2;
        try testing.expectEqual(PushOutcome.ok, try pushOne(gpa, &fx, .{ .nominate = .{ .slot = 7, .value = "b", .prev_value = &.{} } }));
        try testing.expect(trace.finding == null);
        const last = fx.prev_own.get(7).?[0].?;
        try testing.expect(last.votes >= 1);
    }
}

const testing = std.testing;

// ---------------------------------------------------------------------------
// zig build fuzz — corpus-driven std.testing.fuzz target
// ---------------------------------------------------------------------------

// Seed corpus. The three S9 crash inputs are in the fuzzer's own Smith
// encoding, so they seed coverage-guided runs with the purge → re-nominate
// shape and are replayed by every non-fuzz run of this test (the test
// runner feeds each corpus entry through testOne when not built with --fuzz).
const seq_corpus = [_][]const u8{
    &.{},
    &.{ 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // one qset_received-ish
    &.{ 0x02, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xaa, 0xbb }, // envelope path
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
    crash_inputs[0].bytes,
    crash_inputs[1].bytes,
    crash_inputs[2].bytes,
};

test "fuzz: random valid-typed input interleavings preserve §13.1 invariants" {
    try std.testing.fuzz({}, fuzzInputSeqOne, .{ .corpus = &seq_corpus });
}

// ---------------------------------------------------------------------------
// fuzz-smoke — deterministic bounded run (part of `zig build test`)
// ---------------------------------------------------------------------------

pub const smoke_iterations: usize = 5000;
pub const smoke_seed: u64 = 0x1257_5e9f_a220_1b0d;

/// Actual single inputs successfully fed through the engine and checked at
/// the invariant seam. Skipped restore operations and pre-feed construction
/// failures do not inflate it. Asserted large at the end of runSmoke so a
/// regression to the vacuous eos-terminated behavior (M3 review finding #1:
/// 15 steps across 5000 iterations) fails loudly.
pub var executed_steps: usize = 0;
var smoke_diversity: SmokeDiversity = .{};

pub fn runSmoke() !void {
    executed_steps = 0;
    smoke_diversity = .{};
    var prng = std.Random.DefaultPrng.init(smoke_seed);
    const rand = prng.random();

    var i: usize = 0;
    while (i < smoke_iterations) : (i += 1) {
        // A real per-iteration budget in [8, max_inputs] — never eos-gated.
        const budget = 8 + rand.uintLessThan(usize, max_inputs - 7);
        try smokeOne(rand, budget, &smoke_diversity);
    }
}

test "fuzz-smoke: input-seq target, 5000 deterministic iterations, leak-free" {
    try runSmoke();
    // Non-vacuity gate (finding #1): the smoke must drive a real sequence,
    // not eos-terminate after ~1 input. At budgets in [8, max_inputs] over
    // 5000 iterations this is tens of thousands of engine inputs, each
    // invariant-checked.
    try std.testing.expect(executed_steps > 40_000);
    try std.testing.expectEqual(smoke_diversity.checked_inputs, executed_steps);
    // Behavioral non-vacuity: derived inputs must span every operation and
    // slot, every forged wire-statement subtype, and many byte-distinct
    // nominate/envelope values. Statuses are recorded only after the Engine
    // feed and invariant check, so they prove several semantic paths ran too.
    try std.testing.expectEqual(@as(usize, 7), smoke_diversity.operationCount());
    try std.testing.expectEqual(@as(usize, 8), smoke_diversity.slotCount());
    try std.testing.expectEqual(@as(usize, SmokeDiversity.max_distinct_values), smoke_diversity.value_count);
    try std.testing.expectEqual(@as(usize, 4), smoke_diversity.forgedStatementCount());
    try std.testing.expect(smoke_diversity.sawStatus(.applied));
    try std.testing.expect(smoke_diversity.sawStatus(.insane));
    try std.testing.expect(smoke_diversity.sawStatus(.parked_awaiting_qset));
    try std.testing.expect(smoke_diversity.sawStatus(.ignored));
    try std.testing.expect(smoke_diversity.statusCount() >= 4);
}
