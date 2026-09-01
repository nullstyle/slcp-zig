const std = @import("std");
const slcp = @import("slcp");

// Deployment facts — edit these five lines per machine.
// Each pk_* is the `public key:` line of `slcp key show slcp.key` on that machine.
const pk_a = slcp.nodeId("0101010101010101010101010101010101010101010101010101010101010101");
const pk_b = slcp.nodeId("0202020202020202020202020202020202020202020202020202020202020202");
const pk_c = slcp.nodeId("0303030303030303030303030303030303030303030303030303030303030303");

const Counter = struct {
    pub const State = struct { count: u64 = 0 };
    pub const Command = struct { next: u64 };

    pub fn validate(state: State, cmd: Command) slcp.Validity {
        if (cmd.next == state.count + 1) return .valid;
        if (cmd.next > state.count + 1) return .maybe_valid; // this node may be behind
        return .invalid;
    }
    pub fn apply(state: State, cmd: Command) State {
        _ = state;
        return .{ .count = cmd.next };
    }
};

pub fn main(init: std.process.Init) !void {
    const node = try slcp.AppNode(Counter).create(init.gpa, init.io, .{
        .network = "my-counter-app v1", // passphrase → 32-byte networkId; never transmitted
        .key_file = "slcp.key", // ed25519 seed; created on first run (0600)
        .listen_port = 7311,
        .peers = &.{ "b.example.com:7311", "c.example.com:7311" },
        .quorum = slcp.Quorum.twoThirdsOf(&.{ pk_a, pk_b, pk_c }), // self auto-included
        .data_dir = "slcp-data", // created on first run
    });
    defer node.deinit();

    try node.propose(.{ .next = 1 });
    while (try node.waitApplied(.{ .timeout_ms = null })) |ext| {
        std.debug.print("slot {d}: count = {d}\n", .{ ext.slot, ext.state.count });
        try node.propose(.{ .next = ext.state.count + 1 });
    }
}
