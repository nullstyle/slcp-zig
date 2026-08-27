//! Named simulation scenarios (design §13.1). Every scenario is a pure
//! function of (name, seed, n) → SimConfig, so a failing cell is always a
//! one-line repro: `zig build sim -- --seed=N --nodes=N --scenario=name`.

const std = @import("std");
const sim = @import("sim.zig");

pub const Name = enum {
    healthy,
    lossy20,
    partition_heal,
    dup_storm,
    reorder_heavy,

    pub fn fromString(s: []const u8) ?Name {
        if (std.meta.stringToEnum(Name, s)) |n| return n;
        // Accept dashes too (CLI convenience).
        if (std.mem.eql(u8, s, "partition-heal")) return .partition_heal;
        if (std.mem.eql(u8, s, "lossy-20")) return .lossy20;
        if (std.mem.eql(u8, s, "dup-storm")) return .dup_storm;
        if (std.mem.eql(u8, s, "reorder-heavy")) return .reorder_heavy;
        return null;
    }
};

/// Virtual-time bound for every scenario run (generous: timeouts cap at
/// 60s; healthy convergence is typically < 5s virtual).
pub const bound_ms: u64 = 240_000;

/// Partition heals at this virtual time in partition_heal.
pub const heal_ms: u64 = 30_000;

/// Deterministic conflicting per-node proposal values (nomination race:
/// every node proposes its own value for slot 1 at t=0).
pub const proposal_values = [sim.max_nodes][]const u8{
    "proposal-alpha",
    "proposal-bravo",
    "proposal-charlie",
    "proposal-delta",
    "proposal-echo",
    "proposal-foxtrot",
    "proposal-golf",
};

const all_proposals = blk: {
    var out: [sim.max_nodes]sim.Proposal = undefined;
    for (0..sim.max_nodes) |i| {
        out[i] = .{ .node = i, .slot = 1, .at_ms = 0, .value = proposal_values[i] };
    }
    break :blk out;
};

pub fn proposalsFor(n: u8) []const sim.Proposal {
    return all_proposals[0..n];
}

// Partition splits (side_a bitmask). Chosen so that for n >= 4 NO side
// holds a quorum (threshold ceil(2n/3)) — both sides must halt until heal.
// n=3 (threshold 2) has no quorum-less split: node 0 is isolated and the
// {1,2} side keeps quorum, so it is expected to progress during the cut.
const part3 = [1]sim.Partition{.{ .side_a = 0b0000001, .heal_ms = heal_ms }}; // 1 | 2, quorum side = {1,2}
const part4 = [1]sim.Partition{.{ .side_a = 0b0000011, .heal_ms = heal_ms }}; // 2 | 2, threshold 3
const part5 = [1]sim.Partition{.{ .side_a = 0b0000011, .heal_ms = heal_ms }}; // 2 | 3, threshold 4
const part6 = [1]sim.Partition{.{ .side_a = 0b0000111, .heal_ms = heal_ms }}; // 3 | 3, threshold 4... see note
const part7 = [1]sim.Partition{.{ .side_a = 0b0000111, .heal_ms = heal_ms }}; // 3 | 4, threshold 5

pub fn partitionsFor(n: u8) []const sim.Partition {
    return switch (n) {
        3 => &part3,
        4 => &part4,
        5 => &part5,
        6 => &part6,
        7 => &part7,
        else => unreachable,
    };
}

/// Bitmask of nodes on a side of the scenario partition that holds a
/// quorum on its own (>= threshold members); 0 when neither side does.
pub fn quorumSideMask(n: u8) u8 {
    const parts = partitionsFor(n);
    const side_a = parts[0].side_a;
    const all: u8 = @intCast((@as(u16, 1) << @intCast(n)) - 1);
    const side_b = all & ~side_a;
    const t = sim.thresholdFor(n);
    if (@popCount(side_a) >= t) return side_a;
    if (@popCount(side_b) >= t) return side_b;
    return 0;
}

pub fn config(name: Name, seed: u64, n: u8) sim.SimConfig {
    var cfg = sim.SimConfig{
        .seed = seed,
        .n = n,
        .name = @tagName(name),
        .proposals = proposalsFor(n),
    };
    switch (name) {
        .healthy => {
            cfg.latency = .{ .min_ms = 10, .max_ms = 100 };
        },
        .lossy20 => {
            cfg.latency = .{ .min_ms = 10, .max_ms = 200 };
            cfg.drop_rate = 0.20;
        },
        .partition_heal => {
            cfg.latency = .{ .min_ms = 10, .max_ms = 100 };
            cfg.partitions = partitionsFor(n);
        },
        .dup_storm => {
            cfg.latency = .{ .min_ms = 10, .max_ms = 100 };
            cfg.dup_rate = 0.90;
        },
        .reorder_heavy => {
            cfg.latency = .{ .min_ms = 1, .max_ms = 2000 };
        },
    }
    return cfg;
}

/// Run one (scenario, seed, n) cell and apply its per-cell assertions:
/// agreement + validity always; liveness where the scenario guarantees it.
pub fn runCell(gpa: std.mem.Allocator, name: Name, seed: u64, n: u8) !void {
    var s = try sim.Sim.init(gpa, config(name, seed, n));
    defer s.deinit();
    _ = try s.run(bound_ms);
    try s.checkAgreement();
    try s.checkValidity();
    switch (name) {
        // Healthy-network guarantees: everyone externalizes within the bound.
        .healthy, .dup_storm, .reorder_heavy => try s.checkLiveness(0),
        // Post-heal (with reconnect state-resync) everyone externalizes:
        // quorum sides finish during the cut, halted sides after the heal,
        // laggards via the EXTERNALIZE catch-up path.
        .partition_heal => try s.checkLiveness(0),
        // Lossy has no liveness bound (drops can starve nomination);
        // agreement + validity + structural invariants are the assertions.
        .lossy20 => {},
    }
}
