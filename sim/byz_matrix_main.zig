//! Full Byzantine seed matrix (design §14-M3 accept: "Byzantine matrix green
//! across 1000 seeds"). `zig build byz-matrix` — the CI `zig build test`
//! runs the bounded 50-seed matrix; this is the heavy manual gate.

const std = @import("std");
const byzantine = @import("byzantine.zig");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;

    const seeds: u64 = 1000;
    byzantine.runMatrix(gpa, seeds) catch |err| {
        std.debug.print("byz-matrix FAILED: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    std.debug.print("byz-matrix: {d} seeds x 2 actors green\n", .{seeds});
}
