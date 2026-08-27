//! Deterministic conformance-vector generator (design §13.4).
//! Writes vectors/*.json. M0 scope: sets 1 (crypto), 2 (qset), 5 (lint),
//! 4-partial (sanity). Placeholder: filled in during M0.

const std = @import("std");
const slcp = @import("slcp-core");

pub fn main() !void {
    std.debug.print("gen-vectors: not yet implemented (M0 in progress)\n", .{});
}
