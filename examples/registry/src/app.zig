//! app.zig — the `slcp.AppNode` adapter for the registry
//! (docs/examples-roadmap.md "E1 — Registry").
//!
//! The pure state machine lives in `registry.zig`; this file is the glue the
//! typed layer needs: the `App` contract (`State`, `Command`, `validate`,
//! `apply`, `combine`, the custom codec, `initialState` / `initialSlot`) and
//! the process-wide `boot` snapshot the two initial* functions read.
//!
//! `boot` is a global because `initialState()` is `fn () State` — it can
//! take no `io` and no argument (the roadmap's first "Gaps recorded by E1"
//! item). `main.zig` sets it
//! from the snapshot file (or genesis) BEFORE `Node.create`.

const std = @import("std");
const slcp = @import("slcp");
pub const registry = @import("registry.zig");

/// What `initialState()` / `initialSlot()` return. Set once before `create`.
pub var boot: struct { state: registry.State, slot: u64 } = .{ .state = .{}, .slot = 0 };

/// The §8.5 App. `validate` and `apply` run on the engine thread; both are
/// pure over `State` and the set.
pub const Registry = struct {
    pub const State = registry.State;
    pub const Command = registry.TxSet;

    pub fn validate(state: State, cmd: Command) slcp.Validity {
        return switch (registry.validate(&state, &cmd)) {
            .invalid => .invalid,
            .maybe_valid => .maybe_valid,
            .valid => .valid,
        };
    }

    /// The large-state shape: the ~20 KB State is updated in place.
    pub fn apply(state: *State, cmd: Command) void {
        registry.apply(state, &cmd);
    }

    pub fn combine(state: State, cmds: []const Command) Command {
        return registry.combine(&state, cmds);
    }

    pub fn initialState() State {
        return boot.state;
    }

    pub fn initialSlot() u64 {
        return boot.slot;
    }

    // The custom codec (variable-length sets; the auto-codec cannot).
    pub fn encode(cmd: Command, buf: []u8) []u8 {
        return cmd.encode(buf);
    }

    pub fn decode(bytes: []const u8) ?Command {
        return registry.TxSet.decode(bytes);
    }
};

pub const Node = slcp.AppNode(Registry);

comptime {
    // The custom codec's largest encoding must fit the node option the
    // program passes (roadmap §3.1); the contract check happens at create.
    std.debug.assert(registry.max_set_bytes <= registry.max_value_bytes);
    std.debug.assert(Node.codec.is_custom);
    std.debug.assert(Node.apply_in_place);
}

// ---------------------------------------------------------------------------
// Tests: the pure module's suite, the RPC's, and one live 2-of-2 node pair
// ---------------------------------------------------------------------------

test {
    _ = registry;
    _ = @import("rpc.zig");
}

const testing = std.testing;

const Track = struct {
    /// head hash by slot (slots 1..max_slots), null until applied.
    hashes: [max_slots + 1]?[32]u8 = @splat(null),
    last_slot: u64 = 0,
    /// The state copy of the last applied item.
    last_state: ?registry.State = null,
    const max_slots = 8;

    fn note(self: *Track, item: Node.Applied) !void {
        // Roadmap §3.8: the header's slot must be the delivered slot.
        try testing.expectEqual(item.slot, item.state.head.slot);
        if (item.slot <= max_slots) self.hashes[item.slot] = item.state.head.hash;
        self.last_slot = item.slot;
        self.last_state = item.state;
    }
};

/// What a node proposes after an applied slot, given its new state — the
/// node loop's rule in miniature: pending transactions until they apply,
/// then the empty set.
const Proposer = *const fn (*const registry.State) registry.TxSet;

var test_claim_set: registry.TxSet = .{ .count = 0 };

fn proposeClaimUntilApplied(state: *const registry.State) registry.TxSet {
    return if (state.findName("alice") == null) test_claim_set else registry.TxSet.empty;
}

fn proposeEmpty(state: *const registry.State) registry.TxSet {
    _ = state;
    return registry.TxSet.empty;
}

/// Drive both nodes until each has applied `target`: after every applied
/// slot below `target` a node proposes again (2-of-2 needs both proposers).
/// `ta` / `tb` record the head hashes and the last state.
fn pump(a: *Node, b: *Node, pa: Proposer, pb: Proposer, ta: *Track, tb: *Track, target: u64, deadline_ms: u64) !void {
    var waited: u64 = 0;
    while (ta.last_slot < target or tb.last_slot < target) {
        if (waited > deadline_ms) return error.PumpTimeout;
        if (try a.waitApplied(.{ .timeout_ms = 20 })) |x| {
            try ta.note(x);
            if (x.slot < target) try a.propose(pa(&x.state));
        }
        if (try b.waitApplied(.{ .timeout_ms = 20 })) |x| {
            try tb.note(x);
            if (x.slot < target) try b.propose(pb(&x.state));
        }
        waited += 40;
    }
}

// Non-vacuity: without `initialSlot()` reading `boot.slot` the restarted
// node re-applies slots 1..3 on top of the slot-3 snapshot and its first
// applied item is slot 1 with a header at slot 4 (the §3.8 check fails);
// without the custom codec the set does not round-trip and the claim is
// never applied; a different `network_id` in `boot` makes validate reject
// the claim (bad signature) and the pump times out.
test "registry over AppNode (2-of-2 loopback): a claim applies on both nodes with equal heads; a restart from the snapshot skips the replayed tail" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buf[0..try tmp.dir.realPath(io, &root_buf)];
    var dir_a_buf: [std.fs.max_path_bytes]u8 = undefined;
    var dir_b_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_a = try std.fmt.bufPrint(&dir_a_buf, "{s}/a", .{root});
    const dir_b = try std.fmt.bufPrint(&dir_b_buf, "{s}/b", .{root});

    const network = "registry app test v1";
    const seed_a: [32]u8 = @splat(0x81);
    const seed_b: [32]u8 = @splat(0x82);
    const ids = [2][32]u8{ try registry.publicKeyOf(seed_a), try registry.publicKeyOf(seed_b) };
    const nid = registry.networkId(network);
    var diag: slcp.node.Diagnostic = .{};
    var spec_buf: [32]u8 = undefined;

    // A client transaction: alice claims "alice".
    const client_seed: [32]u8 = @splat(0x91);
    const client_pk = try registry.publicKeyOf(client_seed);
    var claim = registry.Tx.init(client_pk, 1, .claim, "alice", "", registry.zero_key).?;
    try claim.sign(client_seed, nid);
    test_claim_set = .{ .count = 1 };
    test_claim_set.txs[0] = claim;

    boot = .{ .state = .{ .network_id = nid }, .slot = 0 };
    var ta: Track = .{};
    var tb: Track = .{};

    const b = blk: {
        const a = try Node.create(gpa, io, .{
            .network = network,
            .secret_seed = seed_a,
            .quorum = slcp.Quorum.of(2, &ids),
            .listen_port = 0,
            .data_dir = dir_a,
            .max_value_bytes = registry.max_value_bytes,
            .diagnostic = &diag,
        });
        defer a.deinit();
        const b = try Node.create(gpa, io, .{
            .network = network,
            .secret_seed = seed_b,
            .quorum = slcp.Quorum.of(2, &ids),
            .listen_port = 0,
            .peers = &.{try std.fmt.bufPrint(&spec_buf, "127.0.0.1:{d}", .{a.raw().boundPort()})},
            .data_dir = dir_b,
            .max_value_bytes = registry.max_value_bytes,
            .diagnostic = &diag,
        });
        errdefer b.deinit();

        try a.propose(test_claim_set);
        try b.propose(registry.TxSet.empty);
        try pump(a, b, proposeClaimUntilApplied, proposeEmpty, &ta, &tb, 3, 60_000);

        // The claim landed (a re-proposes it until it does — the node
        // loop's rule; which slot carries it depends on who led each
        // round) and both nodes agree on every head.
        for (1..4) |s| {
            try testing.expect(ta.hashes[s] != null and tb.hashes[s] != null);
            try testing.expectEqualSlices(u8, &ta.hashes[s].?, &tb.hashes[s].?);
        }
        break :blk b;
    };
    defer b.deinit();

    // Phase 2 needs a's slot-3 STATE (the value copy `waitApplied` handed
    // out), not just its hash. Which slot carried the claim depends on
    // who led the first round; the entry is there either way.
    const s3 = ta.last_state.?;
    try testing.expectEqual(@as(u64, 3), s3.head.slot);
    try testing.expectEqualSlices(u8, &ta.hashes[3].?, &s3.head.hash);
    try testing.expectEqualSlices(u8, &client_pk, &s3.findName("alice").?.owner);
    try testing.expectEqual(@as(u64, 1), s3.accountSeq(client_pk));

    // Snapshot round-trip through the file format, then restart a from it.
    var snap_buf: [registry.snapshot_max_bytes]u8 = undefined;
    const snap = registry.writeSnapshot(&s3, &snap_buf);
    boot = .{ .state = registry.readSnapshot(snap).?, .slot = 3 };
    const a2 = try Node.create(gpa, io, .{
        .network = network,
        .secret_seed = seed_a,
        .quorum = slcp.Quorum.of(2, &ids),
        .listen_port = 0,
        .peers = &.{try std.fmt.bufPrint(&spec_buf, "127.0.0.1:{d}", .{b.raw().boundPort()})},
        .data_dir = dir_a,
        .max_value_bytes = registry.max_value_bytes,
        .diagnostic = &diag,
    });
    defer a2.deinit();
    var ta2: Track = .{};
    try a2.propose(registry.TxSet.empty);
    try b.propose(registry.TxSet.empty);
    try pump(a2, b, proposeClaimUntilApplied, proposeEmpty, &ta2, &tb, 4, 90_000);
    // First applied item after the restart is slot 4 (1..3 skipped), and it
    // matches b's slot 4.
    try testing.expect(ta2.hashes[1] == null and ta2.hashes[2] == null and ta2.hashes[3] == null);
    try testing.expect(ta2.hashes[4] != null and tb.hashes[4] != null);
    try testing.expectEqualSlices(u8, &ta2.hashes[4].?, &tb.hashes[4].?);
}
