//! app.zig — the `slcp.OwnedAppNode` adapter for the registry
//! (docs/examples-roadmap.md E1–E2d).
//!
//! The pure state machine lives in `registry.zig`; this file is the glue the
//! owned typed layer needs: the App contract (`State`, `Command`, contextual
//! `validate`, allocating `apply`, `combine`, the custom codec, and the
//! observation) plus the startup `Context` that carries the selected boot
//! state into `initState`. What used to be the process-wide `boot` global is
//! now an argument: `main.zig` hands the exact snapshot (or genesis) it
//! selected to `OwnedAppNode.create`, and `initState` receives it before any
//! engine, thread, or listener exists.
//!
//! Restart continuity binds to what `initState` loaded: `initialSlot` is the
//! state's own head slot and `initialCommand` its last consensus value, so
//! the dedup floor, the exact-predecessor nomination seed, and the
//! contiguous-journal rules all describe the same state the adapter owns.
//!
//! The state is heap-backed (the capacity epoch): `initState` clones the
//! context's state, `apply` allocates through its `gpa` (an OutOfMemory halts
//! the node, never the agreed value), and the observation is an OWNED clone
//! of the whole state — `deinitObs` frees it and every `Applied` returns
//! through `release` (ADR 0003). The cadence loop moves each observation into
//! the RPC shared state and the history outbox borrows it first.

const std = @import("std");
const slcp = @import("slcp");
pub const registry = @import("registry.zig");

/// The owned-contract App. `validate`, `apply`, `combine`, and `observe` run
/// on the engine thread, pure over `State`, the candidate value, and the
/// driver's slot context.
pub const Registry = struct {
    pub const State = registry.State;
    pub const Command = registry.LedgerValue;

    /// The whole state, as an OWNED clone: the cadence loop persists the
    /// snapshot from it, offers history publication, then moves it into the
    /// RPC shared state. Every Applied returns through `release`.
    pub const Obs = registry.State;

    /// The boot state `main.zig` selected (genesis, local snapshot, or
    /// recovered history frontier). Borrowed for the `initState` call only.
    pub const Context = registry.State;

    pub const InitError = error{OutOfMemory};

    pub fn initState(context: Context, gpa: std.mem.Allocator) InitError!State {
        return context.clone(gpa);
    }

    pub fn deinitState(state: *State, gpa: std.mem.Allocator) void {
        state.deinit(gpa);
    }

    pub fn initialSlot(state: *const State) u64 {
        return state.head.slot;
    }

    pub fn initialCommand(state: *const State) ?Command {
        return state.last_value;
    }

    pub fn validate(state: *const State, cmd: Command, context: slcp.ValueContext) slcp.Validity {
        return switch (registry.validate(state, &cmd, context.slot)) {
            .invalid => .invalid,
            .maybe_valid => .maybe_valid,
            .valid => .valid,
        };
    }

    pub fn apply(state: *State, cmd: Command, gpa: std.mem.Allocator) std.mem.Allocator.Error!void {
        try registry.apply(state, &cmd, gpa);
    }

    pub fn observe(state: *const State, gpa: std.mem.Allocator) std.mem.Allocator.Error!Obs {
        return state.clone(gpa);
    }

    pub fn deinitObs(obs: *Obs, gpa: std.mem.Allocator) void {
        obs.deinit(gpa);
    }

    pub fn combine(state: *const State, cmds: []const Command) Command {
        return registry.combine(state, cmds);
    }

    // The custom codec (variable-length sets; the auto-codec cannot).
    pub fn encode(cmd: Command, buf: []u8) []u8 {
        return cmd.encode(buf);
    }
    pub fn decode(bytes: []const u8) ?Command {
        return registry.LedgerValue.decode(bytes);
    }
};

pub const Node = slcp.OwnedAppNode(Registry);

comptime {
    // The custom codec's largest encoding must fit the node option the
    // program passes (roadmap §3.1); the contract check happens at create.
    std.debug.assert(registry.max_ledger_value_bytes <= registry.max_value_bytes);
    std.debug.assert(Node.codec.is_custom);
    // The observation owns a heap clone of the state; every Applied must be
    // released.
    std.debug.assert(Node.obs_owns_memory);
}

// ---------------------------------------------------------------------------
// Tests: the pure module's suite, the RPC's, and one live 2-of-2 node pair
// ---------------------------------------------------------------------------

test {
    _ = registry;
    _ = @import("rpc.zig");
    _ = @import("history.zig");
}

const testing = std.testing;

const Track = struct {
    /// head hash by slot (slots 1..max_slots), null until applied.
    hashes: [max_slots + 1]?[32]u8 = @splat(null),
    /// Consensus close time by slot, used to prove skew convergence and the
    /// deterministic per-ledger bound across a restart.
    close_times: [max_slots + 1]?u64 = @splat(null),
    last_slot: u64 = 0,
    /// An owned clone of the last applied observation (the applied item
    /// itself is released by the pump after `note`).
    last_state: ?registry.State = null,
    const max_slots = 8;

    fn deinit(self: *Track, gpa: std.mem.Allocator) void {
        if (self.last_state) |*s| s.deinit(gpa);
        self.last_state = null;
    }

    fn note(self: *Track, gpa: std.mem.Allocator, item: Node.Applied) !void {
        // Roadmap §3.8: the header's slot must be the delivered slot.
        try testing.expectEqual(item.slot, item.obs.head.slot);
        try testing.expectEqual(item.obs.head.close_time, item.obs.last_value.?.close_time);
        if (item.slot <= max_slots) {
            self.hashes[item.slot] = item.obs.head.hash;
            self.close_times[item.slot] = item.obs.head.close_time;
        }
        self.last_slot = item.slot;
        if (self.last_state) |*s| s.deinit(gpa);
        self.last_state = try item.obs.clone(gpa);
    }
};

/// What a node proposes after an applied slot, given its new state — the
/// node loop's rule in miniature: pending transactions until they apply,
/// then the empty set.
const Proposer = *const fn (*const registry.State) registry.LedgerValue;

var test_claim_set: registry.TxSet = .{ .count = 0 };

fn proposeClaimUntilApplied(state: *const registry.State) registry.LedgerValue {
    const pending = if (state.findName("alice") == null) test_claim_set.slice() else &.{};
    return registry.proposal(state, pending, state.head.close_time +| registry.max_close_time_step).?;
}

fn proposeEmpty(state: *const registry.State) registry.LedgerValue {
    return registry.proposal(state, &.{}, state.head.close_time +| 1).?;
}

/// Drive both nodes until each has applied `target`: after every applied
/// slot below `target` a node proposes again (2-of-2 needs both proposers).
/// `ta` / `tb` record the head hashes and the last state.
fn pump(a: *Node, b: *Node, pa: Proposer, pb: Proposer, ta: *Track, tb: *Track, target: u64, deadline_ms: u64) !void {
    const gpa = testing.allocator;
    var waited: u64 = 0;
    while (ta.last_slot < target or tb.last_slot < target) {
        if (waited > deadline_ms) return error.PumpTimeout;
        if (try a.waitApplied(.{ .timeout_ms = 20 })) |x| {
            try ta.note(gpa, x);
            if (x.slot < target) try a.propose(pa(&x.obs));
            a.release(x);
        }
        if (try b.waitApplied(.{ .timeout_ms = 20 })) |x| {
            try tb.note(gpa, x);
            if (x.slot < target) try b.propose(pb(&x.obs));
            b.release(x);
        }
        waited += 40;
    }
}

// Non-vacuity: without `initialSlot` reading the loaded state's head slot the
// restarted node re-applies slots 1..3 on top of the slot-3 snapshot and its
// first applied item is slot 1 with a header at slot 4 (the §3.8 check
// fails); without the custom codec the set does not round-trip and the claim
// is never applied; a different `network_id` in the context makes validate
// reject the claim (bad signature) and the pump times out.
test "registry over OwnedAppNode (2-of-2 loopback): skewed clocks converge and the snapshot context preserves the exact predecessor" {
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

    const network = "registry app test v3";
    const genesis_close_time: u64 = 1_700_000_000;
    var network_buf: [128]u8 = undefined;
    const network_descriptor = registry.networkDescriptor(genesis_close_time, network, &network_buf);
    const seed_a: [32]u8 = @splat(0x81);
    const seed_b: [32]u8 = @splat(0x82);
    const ids = [2][32]u8{ try registry.publicKeyOf(seed_a), try registry.publicKeyOf(seed_b) };
    const nid = registry.networkId(network, genesis_close_time);
    var diag: slcp.node.Diagnostic = .{};
    var spec_buf: [32]u8 = undefined;

    // A client transaction: alice claims "alice".
    const client_seed: [32]u8 = @splat(0x91);
    const client_pk = try registry.publicKeyOf(client_seed);
    var claim = registry.Tx.init(client_pk, 1, .claim, "alice", "", registry.zero_key).?;
    try claim.sign(client_seed, nid);
    test_claim_set = .{ .count = 1 };
    test_claim_set.txs[0] = claim;

    var genesis = try registry.State.genesis(nid, genesis_close_time, gpa);
    defer genesis.deinit(gpa);
    var ta: Track = .{};
    var tb: Track = .{};
    defer ta.deinit(gpa);
    defer tb.deinit(gpa);

    const b = blk: {
        const a = try Node.create(gpa, io, .{
            .network = network_descriptor,
            .secret_seed = seed_a,
            .quorum = slcp.Quorum.of(2, &ids),
            .listen_port = 0,
            .data_dir = dir_a,
            .max_value_bytes = registry.max_value_bytes,
            .diagnostic = &diag,
        }, genesis);
        defer a.deinit();
        const b = try Node.create(gpa, io, .{
            .network = network_descriptor,
            .secret_seed = seed_b,
            .quorum = slcp.Quorum.of(2, &ids),
            .listen_port = 0,
            .peers = &.{try std.fmt.bufPrint(&spec_buf, "127.0.0.1:{d}", .{a.raw().boundPort()})},
            .data_dir = dir_b,
            .max_value_bytes = registry.max_value_bytes,
            .diagnostic = &diag,
        }, genesis);
        errdefer b.deinit();

        // The proposers disagree by the full permitted clock window. Close
        // time remains a deterministic consensus value: both nodes must
        // externalize the same value and resulting header.
        try a.propose(registry.proposal(&genesis, test_claim_set.slice(), genesis_close_time + registry.max_close_time_step).?);
        try b.propose(registry.proposal(&genesis, &.{}, genesis_close_time + 1).?);
        try pump(a, b, proposeClaimUntilApplied, proposeEmpty, &ta, &tb, 3, 60_000);

        // The claim landed (a re-proposes it until it does — the node
        // loop's rule; which slot carries it depends on who led each
        // round) and both nodes agree on every head.
        for (1..4) |s| {
            try testing.expect(ta.hashes[s] != null and tb.hashes[s] != null);
            try testing.expectEqualSlices(u8, &ta.hashes[s].?, &tb.hashes[s].?);
            try testing.expectEqual(ta.close_times[s].?, tb.close_times[s].?);
            const previous = if (s == 1) genesis_close_time else ta.close_times[s - 1].?;
            try testing.expect(ta.close_times[s].? > previous);
            try testing.expect(ta.close_times[s].? - previous <= registry.max_close_time_step);
        }
        // A 2-of-2 first slot has observed both endpoint proposals. The
        // composite must choose the minimum, not merely a mutually agreed
        // time somewhere inside the permitted interval.
        try testing.expectEqual(genesis_close_time + 1, ta.close_times[1].?);
        break :blk b;
    };
    defer b.deinit();

    // Phase 2 needs a's slot-3 STATE (the observation `waitApplied` handed
    // out), not just its hash. Which slot carried the claim depends on
    // who led the first round; the entry is there either way.
    const s3 = ta.last_state.?;
    try testing.expectEqual(@as(u64, 3), s3.head.slot);
    try testing.expectEqualSlices(u8, &ta.hashes[3].?, &s3.head.hash);
    try testing.expectEqualSlices(u8, &client_pk, &s3.findName("alice").?.owner);
    try testing.expectEqual(@as(u64, 1), s3.accountSeq(client_pk));

    // Snapshot round-trip through the file format, then restart a from it —
    // the snapshot travels in the create CONTEXT, not a global.
    const snap = try registry.writeSnapshot(&s3, gpa);
    defer gpa.free(snap);
    var restored = (try registry.readSnapshot(gpa, snap)).?;
    defer restored.deinit(gpa);
    const a2 = try Node.create(gpa, io, .{
        .network = network_descriptor,
        .secret_seed = seed_a,
        .quorum = slcp.Quorum.of(2, &ids),
        .listen_port = 0,
        .peers = &.{try std.fmt.bufPrint(&spec_buf, "127.0.0.1:{d}", .{b.raw().boundPort()})},
        .data_dir = dir_a,
        .max_value_bytes = registry.max_value_bytes,
        .diagnostic = &diag,
    }, restored);
    defer a2.deinit();
    var ta2: Track = .{};
    defer ta2.deinit(gpa);
    try a2.propose(proposeClaimUntilApplied(&restored));
    try b.propose(proposeEmpty(&s3));
    try pump(a2, b, proposeClaimUntilApplied, proposeEmpty, &ta2, &tb, 4, 90_000);
    // First applied item after the restart is slot 4 (1..3 skipped), and it
    // matches b's slot 4.
    try testing.expect(ta2.hashes[1] == null and ta2.hashes[2] == null and ta2.hashes[3] == null);
    try testing.expect(ta2.hashes[4] != null and tb.hashes[4] != null);
    try testing.expectEqualSlices(u8, &ta2.hashes[4].?, &tb.hashes[4].?);
    try testing.expectEqual(ta2.close_times[4].?, tb.close_times[4].?);
    try testing.expect(ta2.close_times[4].? > s3.head.close_time);
    try testing.expect(ta2.close_times[4].? - s3.head.close_time <= registry.max_close_time_step);
}
