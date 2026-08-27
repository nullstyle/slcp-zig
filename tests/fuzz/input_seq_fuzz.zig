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
//!     (invariants.recordOwnStatement);
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
//! run replays 5000 fixed-seed iterations through Smith{ .in = bytes }.

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

/// A fully-wired honest node plus the shared-qset framing the fuzzer needs to
/// answer request_qset and to make peer statements resolve (not park).
const Fixture = struct {
    eng: engine.Engine,
    forger: adversary.Forger,
    shared_framed: []u8,
    shared_hash: [32]u8,
    tracker: invariants.Tracker = .{},
    last_own: ?[]u8 = null,

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
                if (try invariants.recordOwnStatement(&fx.tracker, gpa, st)) |_| return error.OwnStatementNotMonotonic;
                // Keep the latest own frame for restore_own_envelope replay.
                if (fx.last_own) |b| gpa.free(b);
                fx.last_own = try gpa.dupe(u8, sb.bytes);
            },
            .externalized => |sb| {
                if (try invariants.recordExternalizedEffect(&fx.tracker, gpa, sb.slot)) |_| return error.ExternalizedTwice;
            },
            .input_status => {
                status_count += 1;
                last_was_status = true;
            },
            else => {},
        }
        eng.commitEffect();
    }
    // §5.3: exactly one input_status per input, always last.
    if (status_count != 1 or !last_was_status) return error.InputStatusContract;
    // Per-slot ballot invariants + effect-queue bound (§13.1).
    if (try invariants.checkEngine(eng, &fx.tracker, gpa)) |_| return error.EngineInvariant;
}

/// Push one input; on a clean sticky failure (a legitimate §7.2 outcome)
/// drain leftover effects and report `.failed` so the caller stops the run.
const PushOutcome = enum { ok, failed };
fn pushOne(gpa: std.mem.Allocator, fx: *Fixture, input: engine.Input) !PushOutcome {
    fx.eng.pushInput(input) catch {
        while (fx.eng.popEffect()) |_| fx.eng.commitEffect();
        return .failed;
    };
    try drainAndCheck(gpa, fx);
    return .ok;
}

fn pickBallot(smith: *std.testing.Smith, value: []const u8) adversary.BV {
    return .{ .counter = smith.valueRangeAtMost(u32, 0, 6), .value = value };
}

/// Derive and execute one arbitrary VALID-TYPED input from the Smith, against
/// `fx`. Returns .failed once the engine sticky-fails.
fn stepOnce(gpa: std.mem.Allocator, fx: *Fixture, smith: *std.testing.Smith) !PushOutcome {
    const slot = smith.valueRangeAtMost(u64, 1, 8);
    var vbuf: [max_value_bytes]u8 = undefined;
    const vlen = smith.slice(&vbuf);
    const value = vbuf[0..vlen];

    // Mostly the shared hash (statements resolve); occasionally a random hash
    // to exercise the park path.
    const qh: [32]u8 = if (smith.boolWeighted(7, 1)) fx.shared_hash else smith.value([32]u8);

    switch (smith.valueRangeAtMost(u8, 0, 6)) {
        0 => return pushOne(gpa, fx, .{ .nominate = .{ .slot = slot, .value = value, .prev_value = &.{} } }),
        1 => {
            const timer: engine.TimerId = if (smith.value(bool)) .ballot else .nomination;
            return pushOne(gpa, fx, .{ .timer_fired = .{ .slot = slot, .timer = timer } });
        },
        2 => {
            // A real key-holder envelope with fuzz-chosen content.
            const raw: adversary.RawStatement = switch (smith.valueRangeAtMost(u8, 0, 3)) {
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
            const env = fx.forger.sign(slot, raw) catch return .ok; // build failure ⇒ skip
            defer gpa.free(env);
            return pushOne(gpa, fx, .{ .envelope_received = .{ .bytes = env } });
        },
        3 => return pushOne(gpa, fx, .{ .qset_received = .{ .bytes = fx.shared_framed } }),
        4 => return pushOne(gpa, fx, .{ .purge_slots = .{ .max_slot = smith.valueRangeAtMost(u64, 0, 8) } }),
        5 => {
            // Replay a captured own frame (startup-only in practice; a
            // mid-stream replay must still yield a typed status, never UB).
            if (fx.last_own) |frame| {
                const dup = try gpa.dupe(u8, frame); // engine may free/replace fx.last_own during the push
                defer gpa.free(dup);
                return pushOne(gpa, fx, .{ .restore_own_envelope = .{ .bytes = dup } });
            }
            return .ok;
        },
        else => {
            // A typed envelope carrying arbitrary garbage bytes.
            var gbuf: [64]u8 = undefined;
            const glen = smith.slice(&gbuf);
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

/// One deterministic smoke iteration over a fixed `budget` of inputs (finding
/// #1 fix): guarantees a real multi-input sequence with an invariant check
/// after each. Leak-checked.
fn smokeOne(smith: *std.testing.Smith, budget: usize) anyerror!void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    const result = run(da.allocator(), smith, budget);
    const leak = da.deinit();
    try result;
    if (leak == .leak) return error.MemoryLeak;
}

/// `budget == null`: the coverage-guided path — the loop length is chosen by
/// `smith.eos()` (correct under `zig build fuzz --fuzz`, where the fuzzer
/// drives eos from coverage). `budget != null`: the deterministic smoke — run
/// exactly that many steps ignoring eos, because in `Smith{ .in = bytes }`
/// mode eos() consumes a byte and returns true on any nonzero value, which
/// would terminate the loop after ~1 step on random input (M3 review finding
/// #1). A fixed budget is what makes the smoke actually exercise multi-input
/// sequences and the after-every-input invariant checks.
fn run(gpa: std.mem.Allocator, smith: *std.testing.Smith, budget: ?usize) !void {
    var fx = try Fixture.init(gpa);
    defer fx.deinit(gpa);

    var steps: usize = 0;
    if (budget) |b| {
        while (steps < b) : (steps += 1) {
            executed_steps += 1;
            if (try stepOnce(gpa, &fx, smith) == .failed) break; // cleanly sticky-failed
        }
    } else {
        while (steps < max_inputs and !smith.eos()) : (steps += 1) {
            if (try stepOnce(gpa, &fx, smith) == .failed) break;
        }
    }
}

// ---------------------------------------------------------------------------
// zig build fuzz — corpus-driven std.testing.fuzz target
// ---------------------------------------------------------------------------

const seq_corpus = [_][]const u8{
    &.{},
    &.{ 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, // one qset_received-ish
    &.{ 0x02, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0xaa, 0xbb }, // envelope path
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
};

test "fuzz: random valid-typed input interleavings preserve §13.1 invariants" {
    try std.testing.fuzz({}, fuzzInputSeqOne, .{ .corpus = &seq_corpus });
}

// ---------------------------------------------------------------------------
// fuzz-smoke — deterministic bounded run (part of `zig build test`)
// ---------------------------------------------------------------------------

pub const smoke_iterations: usize = 5000;
pub const smoke_seed: u64 = 0x1257_5e9f_a220_1b0d;

/// Actual single inputs executed through the engine (incremented per
/// stepOnce). Asserted large at the end of runSmoke so a regression to the
/// vacuous eos-terminated behavior (M3 review finding #1: 15 steps across
/// 5000 iterations) fails loudly.
pub var executed_steps: usize = 0;

pub fn runSmoke() !void {
    executed_steps = 0;
    var prng = std.Random.DefaultPrng.init(smoke_seed);
    const rand = prng.random();
    // Big enough that a full budget of steps rarely exhausts the byte stream
    // (each stepOnce consumes ~10-40 bytes); when it does, Smith yields zeros
    // — still valid typed inputs.
    var scratch: [4096]u8 = undefined;

    var i: usize = 0;
    while (i < smoke_iterations) : (i += 1) {
        rand.bytes(&scratch);
        // A real per-iteration budget in [8, max_inputs] — never eos-gated.
        const budget = 8 + rand.uintLessThan(usize, max_inputs - 7);
        var smith: std.testing.Smith = .{ .in = &scratch };
        try smokeOne(&smith, budget);
    }
}

test "fuzz-smoke: input-seq target, 5000 deterministic iterations, leak-free" {
    try runSmoke();
    // Non-vacuity gate (finding #1): the smoke must drive a real sequence,
    // not eos-terminate after ~1 input. At budgets in [8, max_inputs] over
    // 5000 iterations this is tens of thousands of engine inputs, each
    // invariant-checked.
    try std.testing.expect(executed_steps > 40_000);
}
