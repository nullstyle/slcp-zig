//! The bytes-level quickstart (README "Quickstart: a bytes-level Node"):
//! the replicated counter of examples/counter again, but over `slcp.Node`
//! with the default driver and a hand-rolled 8-byte big-endian encoding
//! instead of the typed `AppNode` + auto-codec.
//!
//! Compile-only: `zig build docs-smoke` (part of `zig build test`) builds
//! this file against the in-tree `slcp` module so the README block cannot
//! rot; it is never run here (it would dial example.com).

const std = @import("std");
const slcp = @import("slcp");

// Deployment facts — edit per machine, exactly as in examples/counter.
const pk_a = slcp.nodeId("0101010101010101010101010101010101010101010101010101010101010101");
const pk_b = slcp.nodeId("0202020202020202020202020202020202020202020202020202020202020202");
const pk_c = slcp.nodeId("0303030303030303030303030303030303030303030303030303030303030303");

// The value the network agrees on is "the count becomes N": 8 bytes,
// big-endian, so byte order equals numeric order and the default driver's
// highest-candidate-wins combine picks the largest proposed count.
fn encode(count: u64) [8]u8 {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, count, .big);
    return buf;
}

fn decode(value: []const u8) ?u64 {
    if (value.len != 8) return null;
    return std.mem.readInt(u64, value[0..8], .big);
}

pub fn main(init: std.process.Init) !void {
    const node = try slcp.Node.create(init.gpa, init.io, .{
        .network = "my-bytes-app v1", // passphrase → 32-byte networkId; never transmitted
        .key_file = "slcp.key", // ed25519 seed; created on first run (0600)
        .listen_port = 7311,
        .peers = &.{ "b.example.com:7311", "c.example.com:7311" },
        .quorum = slcp.Quorum.of(2, &.{ pk_a, pk_b, pk_c }), // explicit 2-of-3; self auto-included
        .data_dir = "slcp-data", // created on first run
        // .driver = null → the default: any non-empty value is valid, the
        // lexicographically greatest candidate wins (docs/driver-upgrade.md).
    });
    defer node.deinit();

    var count: u64 = 0;
    try node.propose(&encode(count + 1));
    while (node.waitExternalized(.{ .timeout_ms = null })) |ext| {
        defer node.allocator().free(ext.value); // the value is owned by the caller
        // Bytes the network already agreed on must decode: a mismatch is a
        // codec/version bug, not a value to skip.
        count = decode(ext.value) orelse return error.UndecodableExternalizedValue;
        std.debug.print("slot {d}: count = {d}\n", .{ ext.slot, count });
        try node.propose(&encode(count + 1));
    }
}
