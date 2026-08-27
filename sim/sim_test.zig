//! M2 acceptance core (design §13.1), budget-scaled for CI:
//!  - SMOKE matrix (part of `zig build test`): seeds 1..25 × n {3,4,5,7} ×
//!    {healthy, lossy-20%, partition-heal}; every cell green with
//!    agreement + validity (+ liveness where guaranteed) and structural
//!    invariants after every input.
//!  - Named single-seed scenarios: partition halt-then-recover,
//!    duplication storm, heavy reordering.
//!  - Determinism proof: same (seed, config) twice → identical event log.
//! The full 1000-seed matrix runs behind `zig build sim-matrix`.
//! Prints nothing on success; failures print the one-line seed repro.

const std = @import("std");
const sim = @import("sim.zig");
const scenario = @import("scenario.zig");

test "oracle scenarios (§13.3)" { _ = @import("oracle_scenarios.zig"); } // pulls the stellar-core oracle-port tests into this bundle

const smoke_seeds_max: u64 = 25;
const smoke_ns = [_]u8{ 3, 4, 5, 7 };
const smoke_scenarios = [_]scenario.Name{ .healthy, .lossy20, .partition_heal };

/// ENGINE BUG #1 (found by this simulator; MUST NOT be fixed from sim/ —
/// engine files are owned elsewhere): pipeline.zig admitResolved keeps
/// `kept` (a pointer into the slot's latest_nom/latest_ballot hash map,
/// pipeline.zig:257) alive across dispatchProtocol; when processing a peer
/// envelope makes the engine emit its own FIRST statement for that
/// protocol, emitNomination's self-store inserts a new key into the same
/// map, which can rehash and leave `kept` dangling — the forward-envelope
/// dupe at pipeline.zig:265 then reads garbage (OutOfMemory in ReleaseSafe;
/// UB in ReleaseFast). n >= 6 trips the initial-capacity growth reliably
/// (e.g. `zig build sim -- --seed=3 --nodes=6 --scenario=healthy`,
/// `--seed=1 --nodes=7 --scenario=healthy`); n <= 5 never exceeds the
/// map's initial capacity and is safe. Once the engine fix lands, raise
/// this ceiling back to sim.max_nodes and every gated cell goes live.
const engine_bug1_max_n: u8 = 7; // engine bug #1 FIXED (boxed latest maps); full matrix live

test "smoke matrix: seeds 1..25 x n {3,4,5,7} x {healthy, lossy20, partition_heal}" {
    const gpa = std.testing.allocator;
    for (smoke_scenarios) |name| {
        for (smoke_ns) |n| {
            if (n > engine_bug1_max_n) continue; // ENGINE BUG #1 gate — see above
            var seed: u64 = 1;
            while (seed <= smoke_seeds_max) : (seed += 1) {
                try scenario.runCell(gpa, name, seed, n);
            }
        }
    }
}

test "partition heals: majority-less sides halt, then all recover (n=5, 3|2 split)" {
    const gpa = std.testing.allocator;
    // n=5 threshold 4; split 2|3 leaves NO side with a quorum: halting
    // during the cut IS correct FBA behavior.
    var s = try sim.Sim.init(gpa, scenario.config(.partition_heal, 42, 5));
    defer s.deinit();

    const before = try s.run(scenario.heal_ms - 1);
    try s.checkNoneExternalized(0); // nobody may externalize while cut
    try std.testing.expect(before.stalled);

    const after = try s.run(scenario.bound_ms);
    try s.checkAgreement();
    try s.checkValidity();
    try s.checkLiveness(0); // everyone externalizes after the heal
    try std.testing.expect(!after.stalled);
}

test "partition heal (n=3): isolated node halts; all three recover after heal" {
    const gpa = std.testing.allocator;
    // n=3 threshold 2; node 0 isolated. The {1,2} side keeps a 2-of-3
    // quorum and externalizes DURING the cut (the engine self-advertises
    // its qset at init — engine bug #2, found by this simulator, is fixed);
    // node 0 halting alone IS correct FBA behavior.
    var s = try sim.Sim.init(gpa, scenario.config(.partition_heal, 5, 3));
    defer s.deinit();

    _ = try s.run(scenario.heal_ms - 1);
    try s.checkLiveness(0b110); // the quorum side progresses mid-cut
    try s.checkNoneExternalized(0b001); // the isolated node halts

    _ = try s.run(scenario.bound_ms);
    try s.checkAgreement();
    try s.checkValidity();
    try s.checkLiveness(0); // everyone externalizes once votes cross post-heal
}

test "duplication storm: 90% of messages duplicated, agreement + liveness hold" {
    const gpa = std.testing.allocator;
    try scenario.runCell(gpa, .dup_storm, 7, 4);
}

test "heavy reordering: latency 1..2000ms, agreement + liveness hold" {
    const gpa = std.testing.allocator;
    try scenario.runCell(gpa, .reorder_heavy, 9, 5);
}

test "determinism: same (seed, config) twice gives a byte-identical event log" {
    const gpa = std.testing.allocator;

    var a = try sim.Sim.init(gpa, scenario.config(.lossy20, 1234, 4));
    defer a.deinit();
    var b = try sim.Sim.init(gpa, scenario.config(.lossy20, 1234, 4));
    defer b.deinit();

    const ra = try a.run(scenario.bound_ms);
    const rb = try b.run(scenario.bound_ms);

    try std.testing.expectEqual(ra.events_processed, rb.events_processed);
    try std.testing.expectEqual(ra.counts, rb.counts);
    try std.testing.expectEqual(a.log.items.len, b.log.items.len);
    for (a.log.items, b.log.items) |ea, eb| {
        try std.testing.expectEqual(ea, eb);
    }
    // ...and identical outcomes.
    for (0..4) |i| {
        const va = a.externalizedValue(@intCast(i), 1);
        const vb = b.externalizedValue(@intCast(i), 1);
        try std.testing.expectEqual(va == null, vb == null);
        if (va != null) try std.testing.expectEqualSlices(u8, va.?, vb.?);
    }
}

test "threshold: ceil(2n/3) table + scenario partition splits" {
    try std.testing.expectEqual(@as(u32, 2), sim.thresholdFor(3));
    try std.testing.expectEqual(@as(u32, 3), sim.thresholdFor(4));
    try std.testing.expectEqual(@as(u32, 4), sim.thresholdFor(5));
    try std.testing.expectEqual(@as(u32, 4), sim.thresholdFor(6));
    try std.testing.expectEqual(@as(u32, 5), sim.thresholdFor(7));

    // n=3 is the only n whose scenario split leaves a quorum-capable side.
    try std.testing.expectEqual(@as(u8, 0b110), scenario.quorumSideMask(3));
    try std.testing.expectEqual(@as(u8, 0), scenario.quorumSideMask(4));
    try std.testing.expectEqual(@as(u8, 0), scenario.quorumSideMask(5));
    try std.testing.expectEqual(@as(u8, 0), scenario.quorumSideMask(6));
    try std.testing.expectEqual(@as(u8, 0), scenario.quorumSideMask(7));
}
