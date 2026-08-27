//! Engine-level end-to-end: THREE real engines, a deterministic in-memory
//! message bus, and a virtual clock — the first full SLCP consensus run.
//! All three nodes nominate different values for slot 1; the protocol must
//! externalize the SAME value on every node (agreement + validity), driven
//! purely through the public Input/Effect surface (§5.1). This is the
//! integration seed of the M2 simulator (sim/ generalizes it with seeded
//! network conditions).

const std = @import("std");
const slcp = @import("slcp-core");

const engine = slcp.engine;
const crypto = slcp.crypto;
const qset = slcp.qset;
const canonical = slcp.canonical;
const driver = slcp.driver;

const Frame = struct { to: usize, bytes: []u8 };

const Timer = struct { slot: u64, timer: engine.TimerId, deadline: u64 };

const Node = struct {
    eng: engine.Engine,
    inbox: std.ArrayList([]u8) = .empty,
    timers: std.ArrayList(Timer) = .empty,
    externalized: ?[]u8 = null,
    persist_count: usize = 0,

    fn deinit(self: *Node, gpa: std.mem.Allocator) void {
        self.eng.deinit();
        for (self.inbox.items) |b| gpa.free(b);
        self.inbox.deinit(gpa);
        self.timers.deinit(gpa);
        if (self.externalized) |v| gpa.free(v);
    }
};

fn setTimer(gpa: std.mem.Allocator, node: *Node, slot: u64, id: engine.TimerId, deadline: u64) !void {
    for (node.timers.items) |*t| {
        if (t.slot == slot and t.timer == id) {
            t.deadline = deadline;
            return;
        }
    }
    try node.timers.append(gpa, .{ .slot = slot, .timer = id, .deadline = deadline });
}

fn cancelTimer(node: *Node, slot: u64, id: engine.TimerId) void {
    var i: usize = 0;
    while (i < node.timers.items.len) {
        const t = node.timers.items[i];
        if (t.slot == slot and t.timer == id) {
            _ = node.timers.swapRemove(i);
        } else i += 1;
    }
}

/// Drain one engine's effect queue into the bus/timers. Returns true if any
/// effect was seen.
fn drainEffects(gpa: std.mem.Allocator, nodes: []Node, idx: usize, now: u64, qset_framed: []const u8, qset_hash: [32]u8) !bool {
    var node = &nodes[idx];
    var any = false;
    while (node.eng.popEffect()) |eff| {
        any = true;
        switch (eff.*) {
            .persist_own_envelope => node.persist_count += 1,
            .broadcast_envelope, .forward_envelope => |sb| {
                for (nodes, 0..) |*peer, j| {
                    if (j == idx) continue;
                    _ = peer;
                    const copy = try gpa.dupe(u8, sb.bytes);
                    try nodes[j].inbox.append(gpa, copy);
                }
            },
            .arm_timer => |t| try setTimer(gpa, node, t.slot, t.timer, now + t.delay_ms),
            .cancel_timer => |t| cancelTimer(node, t.slot, t.timer),
            .request_qset => |r| {
                // the shared qset is the only one in this network
                std.debug.assert(std.mem.eql(u8, &r.hash, &qset_hash));
                try node.eng.pushInput(.{ .qset_received = .{ .bytes = qset_framed } });
            },
            .externalized => |sb| {
                std.debug.assert(node.externalized == null); // at most once
                node.externalized = try gpa.dupe(u8, sb.bytes);
            },
            .input_status, .phase_event => {},
        }
        node.eng.commitEffect();
    }
    return any;
}

test "three engines externalize the same value through the public surface" {
    const gpa = std.testing.allocator;

    const seeds = [3][32]u8{ @splat(0x11), @splat(0x22), @splat(0x33) };
    var pks: [3][32]u8 = undefined;
    for (seeds, 0..) |s, i| pks[i] = try crypto.publicKeyFromSeed(s);

    // shared 2-of-3 qset; canonical bytes + framed form for qset_received
    var shared = blk: {
        const vals = try gpa.dupe([32]u8, &pks);
        break :blk qset.QuorumSetOwned{ .threshold = 2, .validators = vals, .inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0) };
    };
    defer shared.deinit(gpa);
    try qset.validateAndNormalize(gpa, &shared);
    const shared_flat = try qset.canonicalBytes(gpa, &shared);
    defer gpa.free(shared_flat);
    const shared_hash = crypto.qsetHash(shared_flat);
    const shared_framed = try canonical.frameFlat(gpa, shared_flat);
    defer gpa.free(shared_framed);

    const network_id = crypto.networkIdFromPassphrase("e2e-net v1");

    var nodes: [3]Node = undefined;
    var made: usize = 0;
    defer for (nodes[0..made]) |*n| n.deinit(gpa);
    for (seeds, 0..) |s, i| {
        nodes[i] = .{ .eng = try engine.Engine.init(gpa, .{
            .network_id = network_id,
            .node_id = pks[i],
            .secret_seed = s,
            .quorum_set = try qset.clone(gpa, &shared),
        }, driver.Driver.default()) };
        made += 1;
    }

    // every node proposes its own value for slot 1
    const proposals = [3][]const u8{ "value-from-A", "value-from-B", "value-from-C" };
    for (&nodes, 0..) |*n, i| {
        try n.eng.pushInput(.{ .nominate = .{ .slot = 1, .value = proposals[i], .prev_value = "genesis" } });
    }

    // deterministic pump: drain effects, deliver inboxes; when quiescent,
    // advance the virtual clock to the earliest timer and fire it.
    var now: u64 = 0;
    var iterations: usize = 0;
    while (iterations < 2000) : (iterations += 1) {
        var progressed = false;
        for (0..3) |i| {
            if (try drainEffects(gpa, &nodes, i, now, shared_framed, shared_hash)) progressed = true;
        }
        for (0..3) |i| {
            if (nodes[i].inbox.items.len == 0) continue;
            progressed = true;
            const frame = nodes[i].inbox.orderedRemove(0);
            defer gpa.free(frame);
            try nodes[i].eng.pushInput(.{ .envelope_received = .{ .bytes = frame } });
        }
        if (progressed) continue;

        if (nodes[0].externalized != null and nodes[1].externalized != null and nodes[2].externalized != null) break;

        // quiescent: fire the earliest timer (ties: lowest node, then slot,
        // then timer id — deterministic)
        var best: ?struct { node: usize, t: Timer } = null;
        for (&nodes, 0..) |*n, i| {
            for (n.timers.items) |t| {
                if (best == null or t.deadline < best.?.t.deadline) best = .{ .node = i, .t = t };
            }
        }
        const b = best orelse break; // no timers, no progress: stalled
        now = @max(now, b.t.deadline);
        cancelTimer(&nodes[b.node], b.t.slot, b.t.timer);
        try nodes[b.node].eng.pushInput(.{ .timer_fired = .{ .slot = b.t.slot, .timer = b.t.timer } });
    }

    // AGREEMENT: all three externalized the same value.
    try std.testing.expect(nodes[0].externalized != null);
    try std.testing.expect(nodes[1].externalized != null);
    try std.testing.expect(nodes[2].externalized != null);
    try std.testing.expectEqualSlices(u8, nodes[0].externalized.?, nodes[1].externalized.?);
    try std.testing.expectEqualSlices(u8, nodes[0].externalized.?, nodes[2].externalized.?);

    // VALIDITY: the agreed value is one of the proposals.
    var found = false;
    for (proposals) |p| {
        if (std.mem.eql(u8, p, nodes[0].externalized.?)) found = true;
    }
    try std.testing.expect(found);

    // Every node persisted its own statements before broadcasting (§10):
    // at minimum each emitted something on the way.
    for (&nodes) |*n| try std.testing.expect(n.persist_count > 0);
}
