//! End-to-end cluster test (design §13.6 / §14-M5 accept). Four full
//! `slcp.Node`s in one process over real loopback TCP, 3-of-4 quorum:
//!
//!   1. happy path — 200 slots externalized, agreement + validity;
//!   2. kill/restart — a node is killed mid-run, restarted from its own.log
//!      only once the others are more than an answering window ahead (so it
//!      must gap-jump past what nobody can answer any more), catches up,
//!      agreement preserved (no stale-vs-self) — and then REJOINS VOTING: a
//!      survivor is killed so 3-of-4 needs the restarted node (S8b: a
//!      restarted node that stayed mute would halt the cluster here);
//!   3. partition/heal — the cluster is split 2/2 (no half has quorum → it
//!      halts, which is CORRECT FBA behavior), then healed → progress resumes;
//!   4. equivocator — a quorum member floods two contradictory PREPAREs;
//!      the honest nodes still agree;
//!   5. double restart — two of four restart together, three times; the
//!      network resumes every time (the S8 D1 shape over real sockets).
//!
//! Partition uses `slcp.overlay.setTestLinkFilter` — a test-only seam that
//! gates frame delivery by (local nodeId, peer nodeId) without touching the
//! wire or the public Node surface.
//!
//! This is minutes-scale and needs real sockets/files, so it is excluded from
//! `zig build test` and run explicitly: `zig build e2e`.

const std = @import("std");
const slcp = @import("slcp");
const core = @import("slcp-core");

const Node = slcp.Node;
const qset = core.qset;
const crypto = core.crypto;

const NETWORK = "slcp-e2e-v1";
const N = 4;

// Per-scenario slot targets — the §14-M5 gate numbers.
const HAPPY_SLOTS: u64 = 200;
const RESTART_SLOTS: u64 = 60;
const PARTITION_SLOTS: u64 = 50;
const EQUIV_SLOTS: u64 = 40;
const DOUBLE_RESTART_SLOTS: u64 = 45;
/// node.zig `purge_window`: peers answer at most this many slots back.
const ANSWERING_WINDOW: u64 = 16;

// Deterministic identities (seed i = all-byte i+1). Index N is the
// equivocator's key (only used by scenario 4's 5-node config).
fn seedFor(i: usize) [32]u8 {
    return @splat(@intCast(i + 1));
}

fn pubFor(i: usize) [32]u8 {
    return crypto.publicKeyFromSeed(seedFor(i)) catch unreachable;
}

fn addrList(gpa: std.mem.Allocator, base_port: u16, count: usize, skip: usize) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |s| gpa.free(s);
        list.deinit(gpa);
    }
    for (0..count) |i| {
        if (i == skip) continue;
        const s = try std.fmt.allocPrint(gpa, "127.0.0.1:{d}", .{base_port + @as(u16, @intCast(i))});
        try list.append(gpa, s);
    }
    return try list.toOwnedSlice(gpa);
}

fn freeAddrList(gpa: std.mem.Allocator, list: []const []const u8) void {
    for (list) |s| gpa.free(s);
    gpa.free(list);
}

/// Drains one node's externalized stream into a slot→value map on its own
/// thread, until `stop` is set.
const Consumer = struct {
    node: *Node,
    gpa: std.mem.Allocator,
    io: std.Io,
    mu: std.Io.Mutex = .init,
    records: std.AutoHashMapUnmanaged(u64, []u8) = .empty,
    highest: u64 = 0,
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,

    fn start(self: *Consumer) !void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    fn run(self: *Consumer) void {
        while (!self.stop.load(.acquire)) {
            if (self.node.waitExternalized(.{ .timeout_ms = 100 })) |ext| {
                self.mu.lockUncancelable(self.io);
                if (self.records.fetchRemove(ext.slot)) |old| self.gpa.free(old.value);
                self.records.put(self.gpa, ext.slot, ext.value) catch self.gpa.free(ext.value);
                if (ext.slot > self.highest) self.highest = ext.slot;
                self.mu.unlock(self.io);
            }
        }
    }

    fn highestSlot(self: *Consumer) u64 {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        return self.highest;
    }

    fn valueAt(self: *Consumer, slot: u64, buf: *std.ArrayList(u8)) !bool {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        if (self.records.get(slot)) |v| {
            buf.clearRetainingCapacity();
            try buf.appendSlice(self.gpa, v);
            return true;
        }
        return false;
    }

    fn stopJoin(self: *Consumer) void {
        self.stop.store(true, .release);
        if (self.thread) |t| t.join();
        self.thread = null;
    }

    /// Idempotent: killNode frees a replaced consumer eagerly and the final
    /// cluster deinit sweeps every slot again.
    fn deinit(self: *Consumer) void {
        var it = self.records.iterator();
        while (it.next()) |e| self.gpa.free(e.value_ptr.*);
        self.records.deinit(self.gpa);
        self.records = .empty;
    }
};

const Cluster = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    base_port: u16,
    data_root: []const u8,
    /// Number of validators in the shared quorum set (default 4). May exceed
    /// the number of spawned real nodes — the extra slots are external peers
    /// (e.g. the equivocator).
    n_validators: usize = N,
    threshold: u32 = 3,
    nodes: [N]?*Node = @splat(null),
    consumers: [N]Consumer = undefined,
    /// consumers[i] is initialized (spawnNode can fail partway; deinit must
    /// not touch undefined Consumer memory — review finding).
    consumers_live: [N]bool = @splat(false),

    fn dataDir(self: *Cluster, gpa: std.mem.Allocator, i: usize) ![]u8 {
        return std.fmt.allocPrint(gpa, "{s}/node{d}", .{ self.data_root, i });
    }

    fn spawnNode(self: *Cluster, i: usize) !void {
        const gpa = self.gpa;
        var pubs: [N + 1][32]u8 = undefined;
        for (0..self.n_validators) |k| pubs[k] = pubFor(k);
        const peers = try addrList(gpa, self.base_port, N, i);
        defer freeAddrList(gpa, peers);
        const dir = try self.dataDir(gpa, i);
        defer gpa.free(dir);

        const node = try Node.create(gpa, self.io, .{
            .network = NETWORK,
            .node_id = pubFor(i),
            .secret_seed = seedFor(i),
            // The spec borrows `pubs`; Node.create deep-copies it (toOwned).
            .quorum = slcp.Quorum.of(self.threshold, pubs[0..self.n_validators]),
            .listen_port = self.base_port + @as(u16, @intCast(i)),
            .peers = peers,
            .data_dir = dir,
        });
        self.nodes[i] = node;
        self.consumers[i] = .{ .node = node, .gpa = gpa, .io = self.io };
        self.consumers_live[i] = true;
        try self.consumers[i].start();
    }

    fn killNode(self: *Cluster, i: usize) void {
        if (self.consumers_live[i]) {
            self.consumers[i].stopJoin();
            self.consumers[i].deinit(); // spawnNode overwrites the slot; free now
        }
        if (self.nodes[i]) |n| {
            n.deinit();
            self.nodes[i] = null;
        }
    }

    fn allReached(self: *Cluster, target: u64) bool {
        for (0..N) |i| {
            if (self.nodes[i] == null) return false;
            if (self.consumers[i].highestSlot() < target) return false;
        }
        return true;
    }

    /// Wait until every LIVE node reaches `target` (a killed node does not
    /// count — `waitAllReached` needs all four), or `deadline_ms` elapses.
    fn waitLiveReached(self: *Cluster, target: u64, deadline_ms: u64) !void {
        const step: u64 = 100;
        var waited: u64 = 0;
        while (waited < deadline_ms) : (waited += step) {
            if (self.minHighestLive() >= target) return;
            sleepMs(self.io, step);
        }
        return error.ConsensusTimeout;
    }

    /// The lowest slot `consumers[i]` recorded ABOVE `floor` (0 if none):
    /// what a restarted node's stream resumes at, after the journal replay.
    fn lowestRecordedAbove(self: *Cluster, i: usize, floor: u64) u64 {
        const c = &self.consumers[i];
        c.mu.lockUncancelable(self.io);
        defer c.mu.unlock(self.io);
        var lowest: u64 = 0;
        var it = c.records.keyIterator();
        while (it.next()) |k| {
            if (k.* > floor and (lowest == 0 or k.* < lowest)) lowest = k.*;
        }
        return lowest;
    }

    /// Re-queue a restarted node's proposal fuel (the queue died with the
    /// process; values are per-node).
    fn refuel(self: *Cluster, i: usize, prefix: []const u8, upto: u64) !void {
        var vbuf: [48]u8 = undefined;
        for (1..upto + 8 + 1) |s| {
            const v = try std.fmt.bufPrint(&vbuf, "{s}-{d}-n{d}", .{ prefix, s, i });
            try self.nodes[i].?.propose(v);
        }
    }

    fn minHighestLive(self: *Cluster) u64 {
        var m: u64 = std.math.maxInt(u64);
        var any = false;
        for (0..N) |i| {
            if (self.nodes[i] == null) continue;
            any = true;
            m = @min(m, self.consumers[i].highestSlot());
        }
        return if (any) m else 0;
    }

    /// Wait until every live node reaches `target`, or `deadline_ms` elapses.
    fn waitAllReached(self: *Cluster, target: u64, deadline_ms: u64) !void {
        const step: u64 = 100;
        var waited: u64 = 0;
        while (waited < deadline_ms) : (waited += step) {
            if (self.allReached(target)) return;
            sleepMs(self.io, step);
        }
        return error.ConsensusTimeout;
    }

    /// Wait until every live node sees every other live node (full mesh).
    fn waitMesh(self: *Cluster, deadline_ms: u64) !void {
        const step: u64 = 50;
        var waited: u64 = 0;
        outer: while (waited < deadline_ms) : (waited += step) {
            var live: usize = 0;
            for (0..N) |i| {
                if (self.nodes[i] != null) live += 1;
            }
            for (0..N) |i| {
                const n = self.nodes[i] orelse continue;
                if (n.ov.peerCount() < live - 1) {
                    sleepMs(self.io, step);
                    continue :outer;
                }
            }
            return;
        }
        return error.MeshTimeout;
    }

    /// SCP nomination advances only where the local app proposed (stellar
    /// semantics: every validator nominates every ledger). So EVERY node
    /// proposes a distinct per-node value for each slot; the deterministic
    /// highest-wins combine picks the winner, and the agreement assertions
    /// prove all nodes picked the SAME one.
    fn proposeAll(self: *Cluster, prefix: []const u8, upto: u64) !void {
        var vbuf: [48]u8 = undefined;
        for (0..N) |i| {
            const n = self.nodes[i] orelse continue;
            // +8 slack: a nominate that loses a race to an already-closed slot
            // consumes one queued value; spares keep late slots fueled.
            for (1..upto + 8 + 1) |s| {
                const v = try std.fmt.bufPrint(&vbuf, "{s}-{d}-n{d}", .{ prefix, s, i });
                try n.propose(v);
            }
        }
    }

    fn deinit(self: *Cluster) void {
        for (0..N) |i| self.killNode(i);
        for (0..N) |i| {
            if (self.consumers_live[i]) self.consumers[i].deinit();
        }
        removeTree(self.io, self.data_root);
    }
};

/// Bounded progress wait (a stalled cluster must FAIL the test with a
/// timeout, never hang the runner — review finding).
fn waitFor(io: std.Io, deadline_ms: u64, cl: *Cluster, pred: *const fn (*Cluster) bool) !void {
    var waited: u64 = 0;
    while (!pred(cl)) {
        if (waited >= deadline_ms) return error.ProgressTimeout;
        sleepMs(io, 100);
        waited += 100;
    }
}

fn sleepMs(io: std.Io, ms: u64) void {
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(@intCast(ms)), .awake) catch {};
}

/// Scratch root for every cluster's data dirs: under the (gitignored) build
/// cache, like example-smoke, so a killed run leaves nothing untracked.
/// Relative to the build root — build.zig pins cwd with setCwd.
const scratch_root = ".zig-cache/e2e";

fn removeTree(io: std.Io, path: []const u8) void {
    std.Io.Dir.cwd().deleteTree(io, path) catch {};
}

/// Assert every pair of consumers agrees on the value of each slot in
/// [1, upto] that both have recorded (agreement); and that no slot is empty
/// (validity: a recorded value is nonempty — it traces to a real nomination).
fn assertAgreement(cl: *Cluster, upto: u64) !void {
    const gpa = cl.gpa;
    var a: std.ArrayList(u8) = .empty;
    defer a.deinit(gpa);
    var b: std.ArrayList(u8) = .empty;
    defer b.deinit(gpa);
    var slot: u64 = 1;
    while (slot <= upto) : (slot += 1) {
        var ref_set = false;
        for (0..N) |i| {
            if (cl.nodes[i] == null) continue;
            const has = try cl.consumers[i].valueAt(slot, if (ref_set) &b else &a);
            if (!has) continue;
            if (!ref_set) {
                ref_set = true;
                try std.testing.expect(a.items.len > 0); // validity: nonempty
            } else {
                try std.testing.expectEqualSlices(u8, a.items, b.items); // agreement
            }
        }
    }
}

// Non-vacuity: every cluster below opens its scratch tree by a RELATIVE path
// through Dir.cwd() (node.zig checkDataDir / store.zig open), so the e2e
// binary must run with cwd = the build root or the tree lands wherever
// `zig build` was invoked from. build.zig pins that with
// `run_e2e.setCwd(b.path("."))`; drop that line and `cd src && zig build
// e2e` goes red here (S8 review: it was the one side-effectful run step
// without setCwd, and left untracked `src/e2e-*` after a killed run).
test "e2e: runs from the build root (build.zig and this file are reachable by relative path)" {
    const io = std.testing.io;
    std.Io.Dir.cwd().access(io, "build.zig", .{}) catch return error.E2eNotAtBuildRoot;
    std.Io.Dir.cwd().access(io, "tests/e2e/cluster_test.zig", .{}) catch return error.E2eNotAtBuildRoot;
}

test "e2e: 4 nodes externalize 200 slots with agreement" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var cl = Cluster{
        .gpa = gpa,
        .io = io,
        .base_port = 39100,
        .data_root = scratch_root ++ "/happy",
    };
    removeTree(io, cl.data_root);
    defer cl.deinit();

    for (0..N) |i| try cl.spawnNode(i);
    try cl.waitMesh(20_000);
    try cl.proposeAll("v", HAPPY_SLOTS);

    try cl.waitAllReached(HAPPY_SLOTS, 240_000);
    try assertAgreement(&cl, HAPPY_SLOTS);
}

// S8b (D1 catch-up pin on real nodes): the restart happens only once the
// survivors are more than an answering window ahead, so node 3 must learn the
// live frontier from EXTERNALIZE statements alone (held like everything else
// until a v-blocking set of signers has sent them for a slot, then released
// ahead of the frontier — `HoldBuffer.admit` → `.ready`),
// gap-jump past the slots nobody answers any more (its held statements for
// the skipped range are dropped), release the new frontier's statements and
// vote again — proven by killing node 0 afterwards: 3-of-4 then needs node
// 3, and a mute node 3 leaves 2 of 4 → the final wait times out.
test "e2e: kill and restart a node mid-run; it gap-jumps, catches up, rejoins voting; agreement holds" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var cl = Cluster{
        .gpa = gpa,
        .io = io,
        .base_port = 39200,
        .data_root = scratch_root ++ "/restart",
    };
    removeTree(io, cl.data_root);
    defer cl.deinit();

    for (0..N) |i| try cl.spawnNode(i);
    try cl.waitMesh(20_000);

    // Watchdog peer (§14-M5 accept): observes node 3's emissions and asserts
    // no stale-vs-self conflict, especially after the restart.
    var wd = try Watchdog.create(gpa, io, cl.base_port, pubFor(3));
    defer wd.deinit();

    const target: u64 = RESTART_SLOTS;
    try cl.proposeAll("r", target);

    // Let the cluster make progress, then kill node 3 mid-run.
    try waitFor(io, 120_000, &cl, struct {
        fn ok(c: *Cluster) bool {
            return c.minHighestLive() >= @max(4, RESTART_SLOTS / 4);
        }
    }.ok);
    const hwm_at_kill = cl.consumers[3].highestSlot();
    cl.killNode(3);

    // Cluster keeps going with 3 of 4 (still a quorum) — until it is more
    // than an answering window past where node 3 died, so the restart below
    // cannot be answered slot by slot (a guaranteed gap of >= 8 slots).
    const restart_when = @max(40, hwm_at_kill + ANSWERING_WINDOW + 8);
    {
        var waited: u64 = 0;
        while (cl.consumers[0].highestSlot() < restart_when) : (waited += 100) {
            if (waited >= 120_000) return error.ProgressTimeout;
            sleepMs(io, 100);
        }
    }

    // Restart node 3 from its own.log; it must catch up. Re-queue its
    // proposals (the queue died with the process; values are per-node fuel).
    wd.mark(); // everything from here on is post-restart
    try cl.spawnNode(3);
    try cl.refuel(3, "rr", target);

    // Node 3 rejoins the live frontier ...
    try waitFor(io, 120_000, &cl, struct {
        fn ok(c: *Cluster) bool {
            return c.consumers[3].highestSlot() >= 50;
        }
    }.ok);
    // ... by gap-jumping: the restart replays its journal tail (which can
    // run past what the consumer had drained before the kill), and nothing
    // in (tail, resume) was recoverable — its live stream resumed strictly
    // past the slot after the last one it journaled.
    const tail_last = cl.nodes[3].?.journal_tail.?.last;
    const resumed_at = cl.lowestRecordedAbove(3, tail_last);
    std.debug.print("restart: node 3 died at consumer slot {d} (journal tail ends at {d}), resumed its stream at slot {d}\n", .{ hwm_at_kill, tail_last, resumed_at });
    try std.testing.expect(tail_last >= hwm_at_kill);
    try std.testing.expect(resumed_at > tail_last + 1);

    // Now make node 3 NECESSARY: kill node 0, so 3-of-4 is {1, 2, 3}. A
    // restarted node that stayed mute (the S8 D1 finding) halts here.
    cl.killNode(0);
    try cl.waitLiveReached(target, 90_000);
    try assertAgreement(&cl, target);

    // Watchdog verdict: node 3 was observed BOTH overall and after the
    // restart (non-vacuity), and never conflicted with itself.
    try std.testing.expect(wd.seen.load(.acquire) > 0);
    try std.testing.expect(wd.checked_after_mark.load(.acquire) > 0);
    try std.testing.expectEqual(@as(u32, 0), wd.violations.load(.acquire));
}

// The S8 D1 shape over real sockets: two of four go down together mid-run
// (in-process `Node.deinit` — the persisted state is what a crash leaves,
// persist-before-broadcast) and come back a second later, three times.
// Each round must resume progress; with the bytes-level default driver the
// mute-node mechanism itself cannot trigger, so this is the regression
// scenario for the hold / release / catch-up path under a real restart
// storm: a release bug (statements held and never fed, or fed for the
// wrong frontier) stalls a round and the 60 s wait fails.
test "e2e: two of four restart together, three times; the network always resumes" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var cl = Cluster{
        .gpa = gpa,
        .io = io,
        .base_port = 39500,
        .data_root = scratch_root ++ "/double-restart",
    };
    removeTree(io, cl.data_root);
    defer cl.deinit();

    for (0..N) |i| try cl.spawnNode(i);
    try cl.waitMesh(20_000);
    const target: u64 = DOUBLE_RESTART_SLOTS;
    try cl.proposeAll("d", target);

    var round: usize = 0;
    while (round < 3) : (round += 1) {
        // Let it run a little past the last checkpoint, then take 2 and 3
        // down together.
        const before = cl.minHighestLive();
        try waitFor(io, 60_000, &cl, struct {
            fn ok(c: *Cluster) bool {
                return c.minHighestLive() >= 4 and c.consumers[0].highestSlot() >= 4;
            }
        }.ok);
        const at_kill = cl.consumers[0].highestSlot();
        cl.killNode(2);
        cl.killNode(3);
        sleepMs(io, 1_000);
        try cl.spawnNode(2);
        try cl.spawnNode(3);
        var pbuf: [16]u8 = undefined;
        const prefix = try std.fmt.bufPrint(&pbuf, "dr{d}", .{round});
        try cl.refuel(2, prefix, target);
        try cl.refuel(3, prefix, target);
        try cl.waitMesh(20_000);
        // The network resumes: every node, the two restarted ones included,
        // moves at least 5 slots past where the survivors were at the kill.
        const goal = at_kill + 5;
        var waited: u64 = 0;
        while (cl.minHighestLive() < goal) : (waited += 100) {
            if (waited >= 60_000) {
                std.debug.print("double restart round {d}: stalled at min-live {d} (goal {d}, before {d})\n", .{ round, cl.minHighestLive(), goal, before });
                return error.ProgressTimeout;
            }
            sleepMs(io, 100);
        }
        std.debug.print("double restart round {d}: killed at {d}, resumed to {d}\n", .{ round, at_kill, cl.minHighestLive() });
    }

    try cl.waitAllReached(target, 120_000);
    try assertAgreement(&cl, target);
}

test "e2e: partition halts without quorum, heals on reconnect" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var cl = Cluster{
        .gpa = gpa,
        .io = io,
        .base_port = 39300,
        .data_root = scratch_root ++ "/partition",
    };
    removeTree(io, cl.data_root);
    defer cl.deinit();

    for (0..N) |i| try cl.spawnNode(i);
    try cl.waitMesh(20_000);
    const target: u64 = PARTITION_SLOTS;
    try cl.proposeAll("p", target);

    try waitFor(io, 120_000, &cl, struct {
        fn ok(c: *Cluster) bool {
            return c.minHighestLive() >= @max(4, PARTITION_SLOTS / 5);
        }
    }.ok);

    // Partition {0,1} | {2,3}. Neither half has 3-of-4 → the cluster halts.
    slcp.overlay.setTestLinkFilter(partitionFilter);
    const stalled = cl.minHighestLive();
    // Give it time to prove it is NOT advancing (halting is correct here).
    sleepMs(io, 8_000);
    try std.testing.expect(cl.minHighestLive() <= stalled + 1);

    // Heal.
    slcp.overlay.setTestLinkFilter(null);
    try cl.waitAllReached(target, 180_000);
    try assertAgreement(&cl, target);
}

/// Allow links only within each half of the {0,1} | {2,3} split.
fn partitionFilter(local: [32]u8, peer: [32]u8) bool {
    return halfOf(local) == halfOf(peer);
}

fn halfOf(pk: [32]u8) u8 {
    // Map a pubkey back to its node index by comparing against the known set.
    for (0..N) |i| {
        if (std.mem.eql(u8, &pk, &pubFor(i))) return if (i < 2) 0 else 1;
    }
    return 2; // unknown (e.g. equivocator) — its own island
}

// -----------------------------------------------------------------------
// Watchdog peer (§14-M5 accept): a raw overlay observer that records every
// envelope a TARGET node emits and asserts the per-(slot, protocol) stream
// is never stale-vs-self — each successive statement must be strictly newer
// (core.statement.isNewerStatement) or a byte-identical rebroadcast (the
// §10 crash-window carve-out; flood re-delivery also repeats bytes).
// -----------------------------------------------------------------------

/// Human-readable one-liner for a statement, for violation diagnostics.
/// Writes into the CALLER's buffer so two descriptions can be formatted into
/// one print without clobbering each other.
fn describeStatement(buf: []u8, sr: gen_slcp.Statement.Reader) []const u8 {
    const describe_buf = buf;
    const which = sr.getPledges().which() catch return "<bad-union>";
    const p = sr.getPledges();
    return switch (which) {
        .unset => "unset",
        .nominate => blk: {
            const n = p.getNominate() catch break :blk "<bad-nominate>";
            const v = n.getVotes() catch break :blk "<bad-votes>";
            const a = n.getAccepted() catch break :blk "<bad-accepted>";
            break :blk std.fmt.bufPrint(describe_buf, "NOMINATE votes={d} accepted={d}", .{ v.len(), a.len() }) catch "<fmt>";
        },
        .prepare => blk: {
            const pr = p.getPrepare() catch break :blk "<bad-prepare>";
            const b = pr.getBallot() catch break :blk "<bad-ballot>";
            break :blk std.fmt.bufPrint(describe_buf, "PREPARE b.n={d} nC={d} nH={d}", .{
                b.getCounter() catch 0, pr.getNC() catch 0, pr.getNH() catch 0,
            }) catch "<fmt>";
        },
        .confirm => blk: {
            const c = p.getConfirm() catch break :blk "<bad-confirm>";
            const b = c.getBallot() catch break :blk "<bad-ballot>";
            break :blk std.fmt.bufPrint(describe_buf, "CONFIRM b.n={d} nPrep={d} nCommit={d} nH={d}", .{
                b.getCounter() catch 0, c.getNPrepared() catch 0, c.getNCommit() catch 0, c.getNH() catch 0,
            }) catch "<fmt>";
        },
        .externalize => blk: {
            const e = p.getExternalize() catch break :blk "<bad-ext>";
            const b = e.getCommit() catch break :blk "<bad-commit>";
            break :blk std.fmt.bufPrint(describe_buf, "EXTERNALIZE commit.n={d} nH={d}", .{
                b.getCounter() catch 0, e.getNH() catch 0,
            }) catch "<fmt>";
        },
    };
}

/// The committed VALUE if this statement is an EXTERNALIZE, else null.
/// Borrows from the reader's message — use before it is deinitialized.
fn externalizeCommits(sr: gen_slcp.Statement.Reader) ?[]const u8 {
    const which = sr.getPledges().which() catch return null;
    if (which != .externalize) return null;
    const e = sr.getPledges().getExternalize() catch return null;
    const commit = e.getCommit() catch return null;
    return commit.getValue() catch return null;
}

const Watchdog = struct {
    const Key = struct { slot: u64, is_nom: bool };

    gpa: std.mem.Allocator,
    io: std.Io,
    target: [32]u8,
    ov: *slcp.overlay.Overlay,
    peers_owned: []const []const u8 = &.{},
    mu: std.Io.Mutex = .init,
    /// Pre-mark: the newest statement seen per key (kept fresh under flood
    /// reordering). At mark() this map FREEZES and becomes the §10 baseline:
    /// every post-mark statement for a baselined key must be byte-identical
    /// to it (the allowed rebroadcast) or strictly newer — anything else is
    /// exactly the stale-vs-self / self-conflict Byzantine signature. A
    /// frozen baseline cannot false-positive on flood reordering of
    /// POST-restart emissions (those are all newer than the baseline), and a
    /// stale re-emission is flagged WHENEVER it arrives, so the dialer's
    /// reconnect-backoff window only delays detection, never loses it.
    latest: std.AutoHashMapUnmanaged(Key, []u8) = .empty,
    violations: std.atomic.Value(u32) = .init(0),
    seen: std.atomic.Value(u32) = .init(0),
    /// Post-mark statements actually CHECKED against a frozen baseline —
    /// the non-vacuity witness (a raw seen-counter could be satisfied by
    /// unbaselined new-slot traffic).
    checked_after_mark: std.atomic.Value(u32) = .init(0),
    /// Legitimate same-value EXTERNALIZE re-emissions (nH growth) observed.
    ext_regrow: std.atomic.Value(u32) = .init(0),
    marked: std.atomic.Value(bool) = .init(false),

    fn create(gpa: std.mem.Allocator, io: std.Io, base_port: u16, target: [32]u8) !*Watchdog {
        const self = try gpa.create(Watchdog);
        errdefer gpa.destroy(self);
        self.* = .{ .gpa = gpa, .io = io, .target = target, .ov = undefined };

        const network_id = crypto.networkIdFromPassphrase(NETWORK);
        const peers = try addrList(gpa, base_port, N, N); // dial all real nodes
        errdefer freeAddrList(gpa, peers);
        const ov = try gpa.create(slcp.overlay.Overlay);
        errdefer gpa.destroy(ov);
        ov.* = try slcp.overlay.Overlay.init(gpa, io, .{
            .listen_port = 0,
            .peers = peers,
            .network_id_prefix = network_id[0..8].*,
            .node_id = pubFor(N + 1),
        }, .{ .ctx = self, .on_recv = onRecv, .on_peer_up = onPeerUp });
        self.ov = ov;
        self.peers_owned = peers;
        try self.ov.start();
        return self;
    }

    /// Everything from here on counts as "after the restart".
    fn mark(self: *Watchdog) void {
        self.marked.store(true, .release);
    }

    fn onPeerUp(ctx: ?*anyopaque, peer_id: usize) void {
        _ = ctx;
        _ = peer_id;
    }

    fn onRecv(ctx: ?*anyopaque, peer_id: usize, frame: *const slcp.wire.OverlayFrame) void {
        _ = peer_id;
        const self: *Watchdog = @ptrCast(@alignCast(ctx.?));
        switch (frame.*) {
            .envelope => |bytes| self.observe(bytes),
            else => {},
        }
    }

    fn observe(self: *Watchdog, framed_env: []const u8) void {
        const gpa = self.gpa;
        // Decode: framed envelope -> statement reader; filter to the target.
        var emsg = core.capnpc.message.Message.init(gpa, framed_env, .{}) catch return;
        defer emsg.deinit();
        const er = gen_slcp.Envelope.Reader.init(&emsg) catch return;
        const stmt_bytes = er.getStatementBytes() catch return;
        var smsg = core.canonical.decodeFlat(gpa, stmt_bytes, .{}) catch return;
        defer smsg.deinit();
        const sr = gen_slcp.Statement.Reader.init(&smsg) catch return;
        const nid = sr.getNodeId() catch return;
        if (nid.len != 32 or !std.mem.eql(u8, nid, &self.target)) return;

        const slot = sr.getSlotIndex() catch return;
        const which = sr.getPledges().which() catch return;
        const key = Key{ .slot = slot, .is_nom = which == .nominate };

        _ = self.seen.fetchAdd(1, .monotonic);
        const post_mark = self.marked.load(.acquire);

        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        if (self.latest.get(key)) |prev| {
            if (std.mem.eql(u8, prev, framed_env)) {
                // Byte-identical: the §10-allowed rebroadcast. Post-mark it is
                // a real baseline check (the carve-out being exercised).
                if (post_mark) _ = self.checked_after_mark.fetchAdd(1, .monotonic);
                return;
            }
            var pmsg = core.capnpc.message.Message.init(gpa, prev, .{}) catch return;
            defer pmsg.deinit();
            const per = gen_slcp.Envelope.Reader.init(&pmsg) catch return;
            const pstmt = per.getStatementBytes() catch return;
            var psmsg = core.canonical.decodeFlat(gpa, pstmt, .{}) catch return;
            defer psmsg.deinit();
            const psr = gen_slcp.Statement.Reader.init(&psmsg) catch return;

            // EXTERNALIZE/EXTERNALIZE needs its own rule. `isNewerStatement`
            // returns false for ANY such pair ("can't have duplicate
            // EXTERNALIZE") — that is the right answer for the STORAGE
            // question it exists to answer, but it is not a §10 verdict: a
            // node legitimately re-emits EXTERNALIZE for one slot with a
            // GROWN nH as it learns more, and those bytes differ. Judging
            // that pair by "not newer" would flag normal operation.
            // What actually matters here is the COMMIT VALUE: two
            // EXTERNALIZEs committing DIFFERENT values for one slot is a
            // fork — the most serious violation this watchdog can find — so
            // check that directly and treat same-value nH growth as legal.
            if (externalizeCommits(psr)) |base_commit| {
                if (externalizeCommits(sr)) |new_commit| {
                    if (post_mark) _ = self.checked_after_mark.fetchAdd(1, .monotonic);
                    if (!std.mem.eql(u8, base_commit, new_commit)) {
                        _ = self.violations.fetchAdd(1, .monotonic);
                        std.debug.print(
                            "WATCHDOG: FORK — target externalized two different values for slot {d}\n",
                            .{slot},
                        );
                    } else {
                        // Same value, different bytes ⇒ nH growth. Counted so
                        // the suite can PROVE this is the shape that a
                        // comparator-only check would have mis-flagged.
                        const n = self.ext_regrow.fetchAdd(1, .monotonic);
                        if (n == 0) {
                            var b1: [256]u8 = undefined;
                            var b2: [256]u8 = undefined;
                            std.debug.print(
                                "WATCHDOG(info): legitimate EXTERNALIZE re-emit, slot {d}\n  was: {s}\n  now: {s}\n",
                                .{ slot, describeStatement(&b1, psr), describeStatement(&b2, sr) },
                            );
                        }
                    }
                    return; // same commit value: nH growth is legitimate
                }
            }

            const newer = core.statement.isNewerStatement(psr, sr) catch return;

            if (post_mark) {
                // FROZEN-BASELINE check (§10 across the restart): anything
                // not byte-identical and not strictly newer than the
                // pre-kill baseline — an older re-emission OR a same-level
                // conflict — is the stale-vs-self violation. (Late flood
                // copies of PRE-kill statements cannot arrive here: in-flight
                // deliveries are millisecond-scale and peers' anti-entropy
                // re-floods only their own latest.)
                _ = self.checked_after_mark.fetchAdd(1, .monotonic);
                if (!newer) {
                    _ = self.violations.fetchAdd(1, .monotonic);
                    var b1: [256]u8 = undefined;
                    var b2: [256]u8 = undefined;
                    std.debug.print(
                        "WATCHDOG: stale-vs-self slot {d} nom={}\n  baseline: {s}\n  offender: {s}\n",
                        .{ slot, key.is_nom, describeStatement(&b1, psr), describeStatement(&b2, sr) },
                    );
                }
                return; // baseline stays frozen
            }

            // Pre-mark: keep the newest (flood reordering makes strictly
            // older arrivals benign), but a same-level DIFFERENT statement is
            // live equivocation — flag it.
            if (!newer) {
                const older = core.statement.isNewerStatement(sr, psr) catch return;
                if (older) return; // late delivery of a superseded statement
                _ = self.violations.fetchAdd(1, .monotonic);
                std.debug.print("WATCHDOG: self-conflict from target at slot {d} (nom={})\n", .{ slot, key.is_nom });
                return;
            }
        } else if (post_mark) {
            return; // new key post-mark: no baseline to check against
        }
        const copy = gpa.dupe(u8, framed_env) catch return;
        if (self.latest.fetchPut(gpa, key, copy) catch {
            gpa.free(copy);
            return;
        }) |old| gpa.free(old.value);
    }

    fn deinit(self: *Watchdog) void {
        self.ov.stop();
        self.ov.deinit();
        self.gpa.destroy(self.ov);
        var it = self.latest.valueIterator();
        while (it.next()) |v| self.gpa.free(v.*);
        self.latest.deinit(self.gpa);
        freeAddrList(self.gpa, self.peers_owned);
        const gpa = self.gpa;
        gpa.destroy(self);
    }
};

// -----------------------------------------------------------------------
// Scenario 4: an equivocating quorum member
// -----------------------------------------------------------------------

const MessageBuilder = core.capnpc.message.MessageBuilder;
const gen_slcp = core.gen.slcp;

/// The normalized-qset hash of a flat {threshold, validators=0..n} set — the
/// same value every honest Node computes (so its statements never park).
fn sharedQsetHash(gpa: std.mem.Allocator, n_validators: usize, threshold: u32) ![32]u8 {
    var pubs: [N + 1][32]u8 = undefined;
    for (0..n_validators) |k| pubs[k] = pubFor(k);
    var qs = try slcp.Quorum.of(threshold, pubs[0..n_validators]).toOwned(gpa);
    defer qs.deinit(gpa);
    try qset.validateAndNormalize(gpa, &qs);
    const flat = try qset.canonicalBytes(gpa, &qs);
    defer gpa.free(flat);
    return crypto.qsetHash(flat);
}

/// Craft a validly-signed PREPARE envelope (framed) — the equivocator sends
/// two of these per (slot, counter) with different ballot values.
fn craftPrepare(
    gpa: std.mem.Allocator,
    seed: [32]u8,
    network_id: [32]u8,
    node_id: [32]u8,
    qset_hash: [32]u8,
    slot: u64,
    counter: u32,
    value: []const u8,
) ![]u8 {
    var mb = MessageBuilder.init(gpa);
    defer mb.deinit();
    var st = try gen_slcp.Statement.Builder.init(&mb);
    try st.setNodeId(&node_id);
    try st.setSlotIndex(slot);
    var pledges = st.getPledges();
    var prep = try pledges.initPrepare();
    try prep.setQuorumSetHash(&qset_hash);
    var ballot = try prep.initBallot();
    try ballot.setCounter(counter);
    try ballot.setValue(value);
    try prep.setNC(0);
    try prep.setNH(0);

    const stmt_bytes = try core.canonical.canonicalFlatFromBuilder(gpa, &mb);
    defer gpa.free(stmt_bytes);
    const digest = crypto.statementDigest(network_id, stmt_bytes);
    const sig = try crypto.sign(seed, digest);

    var emb = MessageBuilder.init(gpa);
    defer emb.deinit();
    var env = try gen_slcp.Envelope.Builder.init(&emb);
    try env.setStatementBytes(stmt_bytes);
    try env.setSignature(&sig);
    return @constCast(try emb.toBytes());
}

/// A raw Byzantine peer (validator index N): connects to the honest nodes and
/// floods two contradictory PREPAREs per slot, forever, on its own thread.
const Equivocator = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    ov: *slcp.overlay.Overlay,
    evil: std.ArrayList([]u8) = .empty,
    peers_owned: []const []const u8 = &.{},
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,

    fn create(gpa: std.mem.Allocator, io: std.Io, base_port: u16, max_slot: u64) !*Equivocator {
        const self = try gpa.create(Equivocator);
        errdefer gpa.destroy(self);
        self.* = .{ .gpa = gpa, .io = io, .ov = undefined };

        const network_id = crypto.networkIdFromPassphrase(NETWORK);
        const seed = seedFor(N);
        const node_id = pubFor(N);
        const qh = try sharedQsetHash(gpa, N + 1, 3);

        // Pre-craft two contradictory PREPAREs per slot in [1, max_slot].
        var slot: u64 = 1;
        while (slot <= max_slot) : (slot += 1) {
            var vbuf: [32]u8 = undefined;
            const va = try std.fmt.bufPrint(&vbuf, "evil-A-{d}", .{slot});
            try self.evil.append(gpa, try craftPrepare(gpa, seed, network_id, node_id, qh, slot, 1, va));
            var vbuf2: [32]u8 = undefined;
            const vb = try std.fmt.bufPrint(&vbuf2, "evil-B-{d}", .{slot});
            try self.evil.append(gpa, try craftPrepare(gpa, seed, network_id, node_id, qh, slot, 1, vb));
        }

        // Dial all honest nodes (indices 0..N-1).
        const peers = try addrList(gpa, base_port, N, N); // skip=N ⇒ include 0..N-1
        errdefer freeAddrList(gpa, peers);

        const ov = try gpa.create(slcp.overlay.Overlay);
        errdefer gpa.destroy(ov);
        ov.* = try slcp.overlay.Overlay.init(gpa, io, .{
            .listen_port = base_port + @as(u16, @intCast(N)),
            .peers = peers,
            .network_id_prefix = network_id[0..8].*,
            .node_id = node_id,
        }, .{ .ctx = self, .on_recv = onRecv, .on_peer_up = onPeerUp });
        self.ov = ov;
        self.peers_owned = peers;
        return self;
    }

    fn start(self: *Equivocator) !void {
        try self.ov.start();
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    fn run(self: *Equivocator) void {
        while (!self.stop.load(.acquire)) {
            for (self.evil.items) |env| self.ov.broadcast(.{ .envelope = env });
            std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(500), .awake) catch {};
        }
    }

    fn onRecv(ctx: ?*anyopaque, peer_id: usize, frame: *const slcp.wire.OverlayFrame) void {
        _ = ctx;
        _ = peer_id;
        _ = frame; // the equivocator ignores everything it receives
    }

    fn onPeerUp(ctx: ?*anyopaque, peer_id: usize) void {
        const self: *Equivocator = @ptrCast(@alignCast(ctx.?));
        for (self.evil.items) |env| self.ov.send(peer_id, .{ .envelope = env });
    }

    fn deinit(self: *Equivocator) void {
        self.stop.store(true, .release);
        if (self.thread) |t| t.join();
        self.ov.stop();
        self.ov.deinit();
        self.gpa.destroy(self.ov);
        for (self.evil.items) |e| self.gpa.free(e);
        self.evil.deinit(self.gpa);
        freeAddrList(self.gpa, self.peers_owned);
        const gpa = self.gpa;
        gpa.destroy(self);
    }
};

test "e2e: an equivocating quorum member cannot fork the honest nodes" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var cl = Cluster{
        .gpa = gpa,
        .io = io,
        .base_port = 39400,
        .data_root = scratch_root ++ "/equiv",
        .n_validators = N + 1, // 4 honest + the equivocator
        .threshold = 3,
    };
    removeTree(io, cl.data_root);
    defer cl.deinit();

    for (0..N) |i| try cl.spawnNode(i);
    try cl.waitMesh(20_000);

    const target: u64 = EQUIV_SLOTS;
    var eq = try Equivocator.create(gpa, io, cl.base_port, target);
    defer eq.deinit();
    try eq.start();

    try cl.proposeAll("good", target);

    try cl.waitAllReached(target, 240_000);
    try assertAgreement(&cl, target);

    // The honest nodes agreed on their own values, never the equivocator's.
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    var slot: u64 = 1;
    while (slot <= target) : (slot += 1) {
        if (try cl.consumers[0].valueAt(slot, &buf)) {
            try std.testing.expect(!std.mem.startsWith(u8, buf.items, "evil-"));
        }
    }
}

// -----------------------------------------------------------------------
// Why the watchdog needs an EXTERNALIZE-specific rule (deterministic proof
// of the mechanism, so this does not rely on catching a race in a live run).
//
// `isNewerStatement` answers a STORAGE question — "should this replace my
// stored latest for this node+slot?" — and for two EXTERNALIZEs it always
// answers no ("can't have duplicate EXTERNALIZE"). But the engine
// legitimately re-emits EXTERNALIZE for one slot with a GROWN nH, and those
// bytes differ. A watchdog judging §10 by "not byte-identical and not
// newer ⇒ stale-vs-self" therefore mis-flags normal operation — which is
// exactly what happened before `externalizeCommits` was introduced.
// -----------------------------------------------------------------------

fn buildExternalize(gpa: std.mem.Allocator, slot: u64, value: []const u8, n_h: u32) ![]u8 {
    var mb = MessageBuilder.init(gpa);
    defer mb.deinit();
    var st = try gen_slcp.Statement.Builder.init(&mb);
    const node_id = pubFor(0);
    try st.setNodeId(&node_id);
    try st.setSlotIndex(slot);
    var pledges = st.getPledges();
    var ext = try pledges.initExternalize();
    var commit = try ext.initCommit();
    try commit.setCounter(1);
    try commit.setValue(value);
    try ext.setNH(n_h);
    const qh: [32]u8 = @splat(7);
    try ext.setCommitQuorumSetHash(&qh);
    return core.canonical.canonicalFlatFromBuilder(gpa, &mb);
}

test "watchdog rule: same-value EXTERNALIZE with grown nH is legal but never 'newer'" {
    const gpa = std.testing.allocator;

    const a = try buildExternalize(gpa, 15, "the-value", 5);
    defer gpa.free(a);
    const b = try buildExternalize(gpa, 15, "the-value", 8); // same commit, higher nH
    defer gpa.free(b);

    // The engine really does produce DIFFERENT bytes for these.
    try std.testing.expect(!std.mem.eql(u8, a, b));

    var amsg = try core.canonical.decodeFlat(gpa, a, .{});
    defer amsg.deinit();
    var bmsg = try core.canonical.decodeFlat(gpa, b, .{});
    defer bmsg.deinit();
    const ar = try gen_slcp.Statement.Reader.init(&amsg);
    const br = try gen_slcp.Statement.Reader.init(&bmsg);

    // The comparator says "not newer" in BOTH directions — so a
    // comparator-only watchdog would call this pair a self-conflict.
    try std.testing.expect(!try core.statement.isNewerStatement(ar, br));
    try std.testing.expect(!try core.statement.isNewerStatement(br, ar));

    // The rule the watchdog actually uses sees them as the same commitment,
    // which is the truth: no fork, so no §10 violation.
    const av = externalizeCommits(ar).?;
    const bv = externalizeCommits(br).?;
    try std.testing.expectEqualSlices(u8, av, bv);

    // And it still catches the case that IS a violation: a different value.
    const c = try buildExternalize(gpa, 15, "OTHER-value", 5);
    defer gpa.free(c);
    var cmsg = try core.canonical.decodeFlat(gpa, c, .{});
    defer cmsg.deinit();
    const cr = try gen_slcp.Statement.Reader.init(&cmsg);
    try std.testing.expect(!std.mem.eql(u8, av, externalizeCommits(cr).?));
}
