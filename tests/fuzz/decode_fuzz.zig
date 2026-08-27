//! Decode-path fuzz target (design §13.5): arbitrary attacker bytes into the
//! three untrusted decode entry points, with the invariant that the engine
//! NEVER panics, hits UB, or leaks — every input yields a TYPED REJECTION (an
//! `InputStatus` or a caught decode error) and a well-formed effect drain.
//!
//! Entry points (all fed the SAME arbitrary buffer per iteration):
//!   (a) engine.pushInput(.{ .envelope_received = .{ .bytes = fuzz } })
//!       — the full receive pipeline (frame cap → validating decode →
//!         signature → strictCanonical → relevance → admission → …, §5.2/§5.3).
//!       Property: returns normally with exactly ONE input_status as the last
//!       effect, OR the engine goes cleanly sticky-failed; never UB.
//!   (b) engine.pushInput(.{ .qset_received = .{ .bytes = fuzz } })
//!       — the qset-answer decode path; same property.
//!   (c) canonical.decodeFlat(fuzz) and capnpc Message.init(fuzz) directly
//!       — capnp-zig's validating flat/framed decode under our
//!         ValidationOptions (nesting 32, traversal scaled to the frame cap).
//!       Property: a validated Message (deinit'd) or a typed error; never UB.
//!       (decoder findings feed §15.)
//!
//! The whole body runs under a leak-checked `std.heap.DebugAllocator`, so a
//! leak on ANY path fails the iteration. `fuzz-smoke` additionally runs the
//! raw decoders under `std.testing.checkAllAllocationFailures` over a fixed
//! corpus of VALID frames (OOM injection — capnp-zig's idea), proving the
//! decoder frees everything on every allocation-failure point.
//!
//! Fuzz API (zig 0.17, /Users/nullstyle/.zvm/master/lib/std/testing.zig):
//!   std.testing.fuzz(context, testOne, .{ .corpus = &.{...} })
//!   testOne: fn (context, smith: *std.testing.Smith) anyerror!void
//! The `Smith` yields structured values from the fuzzer (or, when built
//! without `--fuzz`, replays the provided corpus + the empty string). For the
//! deterministic `fuzz-smoke` run we drive the same `*One` function through a
//! PRNG-seeded `Smith{ .in = bytes }` loop (5000 iterations, fixed seed) so CI
//! exercises the targets reproducibly and leak-free.

const std = @import("std");
const slcp = @import("slcp-core");

const engine = slcp.engine;
const crypto = slcp.crypto;
const qset = slcp.qset;
const canonical = slcp.canonical;
const driver = slcp.driver;
const limits = slcp.limits;
const capnpc = slcp.capnpc;

// Match the sim's network + node scheme so the built engine is a real,
// fully-configured honest node (sim/sim.zig sim_passphrase / nodeSeed).
const sim_passphrase = "slcp-sim v1";
fn nodeSeed(i: u8) [32]u8 {
    var s: [32]u8 = @splat(0);
    s[0] = i +% 1;
    return s;
}

const n_members: u8 = 4;
const max_fuzz_bytes = 8192;

/// Validating decode options mirroring the engine's frame/statement caps
/// (pipeline.zig frameOptions/stmtOptions; §4.5 ValidationOptions).
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

/// Build a real honest engine (node 0 of a shared ceil(2n/3)-of-n qset) on
/// `gpa`. Mirrors sim/sim.zig init; caller deinits.
fn makeEngine(gpa: std.mem.Allocator) !engine.Engine {
    var pks: [n_members][32]u8 = undefined;
    for (0..n_members) |i| pks[i] = try crypto.publicKeyFromSeed(nodeSeed(@intCast(i)));

    var shared = qset.QuorumSetOwned{
        .threshold = (2 * @as(u32, n_members) + 2) / 3,
        .validators = try gpa.dupe([32]u8, pks[0..]),
        .inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0),
    };
    defer shared.deinit(gpa);
    try qset.validateAndNormalize(gpa, &shared);

    return engine.Engine.init(gpa, .{
        .network_id = crypto.networkIdFromPassphrase(sim_passphrase),
        .node_id = pks[0],
        .secret_seed = nodeSeed(0),
        .quorum_set = try qset.clone(gpa, &shared),
    }, driver.Driver.default());
}

/// Drain every queued effect, freeing owned payloads, and assert the §5.3
/// contract: exactly ONE input_status, always the final effect. Returns an
/// error only on a genuine contract violation (a real bug).
fn drainAndCheck(eng: *engine.Engine) !void {
    var status_count: usize = 0;
    var last_was_status = false;
    while (eng.popEffect()) |eff| {
        last_was_status = false;
        switch (eff.*) {
            .input_status => {
                status_count += 1;
                last_was_status = true;
            },
            else => {},
        }
        eng.commitEffect(); // frees any owned SlotBytes payload
    }
    if (status_count != 1 or !last_was_status) return error.InputStatusContract;
}

/// Feed `bytes` to one engine input; a garbage buffer must produce a typed
/// status (drained here) OR cleanly sticky-fail. A sticky failure leaves
/// partial effects queued — drain and discard them so nothing leaks.
fn pushOne(eng: *engine.Engine, input: engine.Input) !void {
    eng.pushInput(input) catch {
        // Cleanly sticky-failed (EngineFailed / EffectBudgetExceeded / OOM):
        // an acceptable typed rejection. Clear the queue and stop.
        while (eng.popEffect()) |_| eng.commitEffect();
        return;
    };
    try drainAndCheck(eng);
}

/// The three decode entry points over one arbitrary buffer. Expected decode
/// failures are caught (they ARE the typed rejection); only genuine contract
/// violations propagate. Runs entirely on `gpa` (a leak-checked allocator).
fn decodeEntryPoints(gpa: std.mem.Allocator, fuzz: []const u8) !void {
    // (a) + (b): full engine receive paths on a real honest node.
    var eng = try makeEngine(gpa);
    defer eng.deinit();
    try pushOne(&eng, .{ .envelope_received = .{ .bytes = fuzz } });
    if (!eng.failed) try pushOne(&eng, .{ .qset_received = .{ .bytes = fuzz } });

    // (c) raw capnp validating decode — flat (borrows fuzz) and framed.
    if (canonical.decodeFlat(gpa, fuzz, stmtOptions())) |*m| {
        var msg = m.*;
        msg.deinit();
    } else |_| {}

    if (capnpc.message.Message.init(gpa, fuzz, frameOptions())) |*m| {
        var msg = m.*;
        msg.deinit();
    } else |_| {}
}

/// One fuzz iteration: pull an arbitrary buffer from the Smith and run all
/// three entry points under a leak-checked DebugAllocator. A leak on ANY path
/// (including error paths inside decodeEntryPoints, which clean up via defer)
/// fails the iteration.
fn fuzzDecodeOne(_: void, smith: *std.testing.Smith) anyerror!void {
    var buf: [max_fuzz_bytes]u8 = undefined;
    const len = smith.slice(&buf);
    const fuzz = buf[0..len];

    var da: std.heap.DebugAllocator(.{}) = .init;
    const result = decodeEntryPoints(da.allocator(), fuzz);
    const leak = da.deinit();
    try result;
    if (leak == .leak) return error.MemoryLeak;
}

// ---------------------------------------------------------------------------
// zig build fuzz — corpus-driven std.testing.fuzz target
// ---------------------------------------------------------------------------

/// A small seed corpus of interesting shapes (empty, truncated frames, an
/// oversized length prefix). Under `--fuzz` these seed the coverage-guided
/// fuzzer; without it, std.testing.fuzz replays them + the empty string.
const decode_corpus = [_][]const u8{
    &.{},
    &.{ 0x00, 0x00, 0x00, 0x00 }, // seg count 0, size 0
    &.{ 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff }, // huge seg size
    &.{ 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 }, // 2 segs, no data
    "\xde\xad\xbe\xef\xde\xad\xbe\xef",
};

test "fuzz: decode entry points (envelope/qset/raw capnp) reject typed, never UB" {
    try std.testing.fuzz({}, fuzzDecodeOne, .{ .corpus = &decode_corpus });
}

// ---------------------------------------------------------------------------
// fuzz-smoke — deterministic bounded run (part of `zig build test`)
// ---------------------------------------------------------------------------

pub const smoke_iterations: usize = 5000;
pub const smoke_seed: u64 = 0x51c9_de60_de50_c0de;

/// Deterministic PRNG-driven replay of `fuzzDecodeOne`: each iteration builds
/// a fresh arbitrary buffer and feeds it through the Smith's byte-replay path
/// (`Smith{ .in = bytes }`). Fixed seed ⇒ reproducible; leak-checked per iter.
pub fn runSmoke() !void {
    var prng = std.Random.DefaultPrng.init(smoke_seed);
    const rand = prng.random();
    var scratch: [max_fuzz_bytes]u8 = undefined;

    var i: usize = 0;
    while (i < smoke_iterations) : (i += 1) {
        // A length-prefixed Smith input: first 4 bytes are the slice length
        // (Smith.sliceWeightedWithHash reads a little-endian u32), then the
        // payload the decoders actually see.
        const payload_len = rand.uintLessThan(u32, max_fuzz_bytes - 4);
        std.mem.writeInt(u32, scratch[0..4], payload_len, .little);
        rand.bytes(scratch[4..][0..payload_len]);
        var smith: std.testing.Smith = .{ .in = scratch[0 .. 4 + payload_len] };
        try fuzzDecodeOne({}, &smith);
    }
}

// -- OOM injection (checkAllAllocationFailures) over a fixed VALID corpus ----

/// Decode one VALID envelope frame both framed (Message.init) and flat
/// (decodeFlat on the inner statementBytes). Fully frees on success, and
/// returns error.OutOfMemory on an injected failure — the shape
/// checkAllAllocationFailures requires. Proves no leak at ANY alloc point.
fn decodeValidFrame(gpa: std.mem.Allocator, frame: []const u8) !void {
    var env_msg = try capnpc.message.Message.init(gpa, frame, frameOptions());
    defer env_msg.deinit();
    const env = try slcp.gen.slcp.Envelope.Reader.init(&env_msg);
    const stmt_bytes = try env.getStatementBytes();
    var stmt_msg = try canonical.decodeFlat(gpa, stmt_bytes, stmtOptions());
    stmt_msg.deinit();
}

/// Build a handful of VALID envelope frames (deterministic forger seeds) and
/// run the decoders over each under full OOM injection.
fn runOomInjection(gpa: std.mem.Allocator) !void {
    const adversary = @import("adversary");
    const net = crypto.networkIdFromPassphrase(sim_passphrase);
    var forger = try adversary.Forger.init(gpa, nodeSeed(1), net);

    const frames = [_][]const u8{
        try forger.sign(1, .{ .nominate = .{ .qset_hash = @splat(7), .votes = &.{"v0"}, .accepted = &.{} } }),
        try forger.sign(2, .{ .prepare = .{ .qset_hash = @splat(3), .ballot = .{ .counter = 1, .value = "vv" } } }),
        try forger.sign(3, .{ .confirm = .{ .qset_hash = @splat(5), .ballot = .{ .counter = 2, .value = "cc" }, .n_prepared = 2, .n_commit = 1, .n_h = 2 } }),
        try forger.sign(4, .{ .externalize = .{ .commit = .{ .counter = 1, .value = "xx" }, .n_h = 1, .commit_qset_hash = @splat(9) } }),
    };
    defer for (frames) |f| gpa.free(f);

    for (frames) |frame| {
        try std.testing.checkAllAllocationFailures(gpa, decodeValidFrame, .{frame});
    }
}

test "fuzz-smoke: decode targets, 5000 deterministic iterations, leak-free" {
    try runSmoke();
    try runOomInjection(std.testing.allocator);
}
