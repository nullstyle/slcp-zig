//! The FULL §13.1 CI matrix (behind `zig build sim-matrix`, NOT part of
//! `zig build test`): 1000 seeds × n ∈ {3..7} × {healthy, lossy-20%,
//! partition-heal}. Prints one progress line per (scenario, n) block; any
//! failing cell prints its one-line repro and aborts.
//! Tip: build with -Doptimize=ReleaseSafe for a fast run.

const std = @import("std");
const sim = @import("sim.zig");
const scenario = @import("scenario.zig");

const matrix_seeds: u64 = 1000;
const matrix_ns = [_]u8{ 3, 4, 5, 6, 7 };
const matrix_scenarios = [_]scenario.Name{ .healthy, .lossy20, .partition_heal };

/// ENGINE BUG #1 gate (see sim/sim_test.zig for the full description):
/// pipeline.zig admitResolved's `kept` pointer dangles across a
/// latest-envelope map rehash mid-dispatch; n >= 6 trips it reliably.
/// Raise to sim.max_nodes once the engine fix lands.
const engine_bug1_max_n: u8 = 7; // engine bug #1 FIXED (boxed latest maps); full matrix live

pub fn main(init: std.process.Init) !void {
    var seeds: u64 = matrix_seeds;
    var it = std.process.Args.Iterator.init(init.minimal.args);
    _ = it.next();
    while (it.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--seeds=")) {
            seeds = std.fmt.parseInt(u64, arg["--seeds=".len..], 0) catch 1000;
        }
    }

    const gpa = init.gpa;
    const io = init.io;
    const t0 = std.Io.Clock.now(.boot, io);
    var t_block = t0;
    var cells: u64 = 0;

    for (matrix_scenarios) |name| {
        for (matrix_ns) |n| {
            if (n > engine_bug1_max_n) {
                std.debug.print("SKIP: {s} n={d} (engine bug #1: dangling latest-envelope pointer, see sim/sim_test.zig)\n", .{ @tagName(name), n });
                continue;
            }
            var seed: u64 = 1;
            while (seed <= seeds) : (seed += 1) {
                scenario.runCell(gpa, name, seed, n) catch |err| {
                    std.debug.print("MATRIX FAILURE at scenario={s} n={d} seed={d}: {t}\n", .{ @tagName(name), n, seed, err });
                    std.process.exit(1);
                };
                cells += 1;
            }
            const t_now = std.Io.Clock.now(.boot, io);
            const block_ms = @divTrunc(t_block.durationTo(t_now).nanoseconds, std.time.ns_per_ms);
            t_block = t_now;
            std.debug.print("ok: {s} n={d} seeds=1..{d} ({d} ms)\n", .{ @tagName(name), n, seeds, block_ms });
        }
    }

    const total_ms = @divTrunc(t0.durationTo(std.Io.Clock.now(.boot, io)).nanoseconds, std.time.ns_per_ms);
    std.debug.print("sim-matrix: {d} cells green in {d} ms\n", .{ cells, total_ms });
}
