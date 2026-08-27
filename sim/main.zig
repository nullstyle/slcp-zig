//! One-line repro runner for the deterministic simulator (design §13.1):
//!   zig build sim -- --seed=N --nodes=N --scenario=name [--max-ms=N]
//! Runs a single (seed, n, scenario) cell with full invariant checking and
//! prints the outcome; exits non-zero on any violation.

const std = @import("std");
const sim = @import("sim.zig");
const scenario = @import("scenario.zig");

fn usage() noreturn {
    std.debug.print(
        "usage: zig build sim -- --seed=N --nodes=N --scenario=NAME [--max-ms=N] [--trace]\n" ++
            "  scenarios: healthy lossy20 partition_heal dup_storm reorder_heavy\n",
        .{},
    );
    std.process.exit(2);
}

pub fn main(init: std.process.Init) !void {
    var seed: u64 = 1;
    var nodes: u8 = 3;
    var name: scenario.Name = .healthy;
    var max_ms: u64 = scenario.bound_ms;
    var trace = false;

    var it = std.process.Args.Iterator.init(init.minimal.args);
    _ = it.next(); // argv[0]
    while (it.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--seed=")) {
            seed = std.fmt.parseInt(u64, arg["--seed=".len..], 0) catch usage();
        } else if (std.mem.startsWith(u8, arg, "--nodes=")) {
            nodes = std.fmt.parseInt(u8, arg["--nodes=".len..], 0) catch usage();
        } else if (std.mem.startsWith(u8, arg, "--scenario=")) {
            name = scenario.Name.fromString(arg["--scenario=".len..]) orelse usage();
        } else if (std.mem.startsWith(u8, arg, "--max-ms=")) {
            max_ms = std.fmt.parseInt(u64, arg["--max-ms=".len..], 0) catch usage();
        } else if (std.mem.eql(u8, arg, "--trace")) {
            trace = true;
        } else usage();
    }
    if (nodes < 3 or nodes > sim.max_nodes) usage();

    const gpa = init.gpa;

    var s = try sim.Sim.init(gpa, scenario.config(name, seed, nodes));
    defer s.deinit();
    s.trace = trace;

    const result = s.run(max_ms) catch |err| {
        std.debug.print("FAILED: {t}\n", .{err});
        std.process.exit(1);
    };

    var failed = false;
    s.checkAgreement() catch {
        failed = true;
    };
    s.checkValidity() catch {
        failed = true;
    };

    std.debug.print(
        "scenario={s} seed={d} n={d}: {s} after {d} events (virtual t={d}ms)\n" ++
            "  inputs={d} effects={d} sent={d} delivered={d} dropped(rand)={d} dropped(part)={d} dup={d} timers={d}\n",
        .{
            @tagName(name),                 seed,                        nodes,
            if (result.stalled) "STALLED" else "all externalized",      result.events_processed,
            result.virtual_now_ms,          result.counts.inputs,        result.counts.effects,
            result.counts.sent,             result.counts.delivered,     result.counts.dropped_random,
            result.counts.dropped_partition, result.counts.duplicated,   result.counts.timer_fires,
        },
    );
    for (0..nodes) |i| {
        if (s.externalizedValue(@intCast(i), 1)) |v| {
            std.debug.print("  node {d}: slot 1 -> \"{s}\"\n", .{ i, v });
        } else {
            std.debug.print("  node {d}: slot 1 -> (not externalized)\n", .{i});
        }
    }
    if (failed) std.process.exit(1);
}
