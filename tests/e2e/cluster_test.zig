//! End-to-end cluster test (design §13.6 / §14-M5 accept). Four full
//! `slcp.Node`s in one process over real loopback TCP, 3-of-4 quorum:
//!
//!   1. happy path — 200 slots externalized, agreement + validity;
//!   2. kill/restart — a node is killed -9 mid-run, restarted from its
//!      own.log, catches up, agreement preserved (no stale-vs-self);
//!   3. partition/heal — the cluster is split 2/2 (no half has quorum → it
//!      halts, which is CORRECT FBA behavior), then healed → progress resumes;
//!   4. equivocator — a quorum member floods two contradictory PREPAREs;
//!      the honest nodes still agree.
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

// Deterministic identities (seed i = all-byte i+1). Index N is the
// equivocator's key (only used by scenario 4's 5-node config).
fn seedFor(i: usize) [32]u8 {
    return @splat(@intCast(i + 1));
}

fn pubFor(i: usize) [32]u8 {
    return crypto.publicKeyFromSeed(seedFor(i)) catch unreachable;
}

/// Build a fresh flat {threshold, validators} quorum set (each Node consumes
/// its own copy).
fn buildFlatQset(gpa: std.mem.Allocator, pubkeys: []const [32]u8, threshold: u32) !qset.QuorumSetOwned {
    const validators = try gpa.alloc(qset.NodeId, pubkeys.len);
    for (pubkeys, 0..) |pk, i| validators[i] = pk;
    return .{
        .threshold = threshold,
        .validators = validators,
        .inner_sets = &.{},
    };
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

    fn dataDir(self: *Cluster, gpa: std.mem.Allocator, i: usize) ![]u8 {
        return std.fmt.allocPrint(gpa, "{s}/node{d}", .{ self.data_root, i });
    }

    fn spawnNode(self: *Cluster, i: usize) !void {
        const gpa = self.gpa;
        var pubs: [N + 1][32]u8 = undefined;
        for (0..self.n_validators) |k| pubs[k] = pubFor(k);
        const qs = try buildFlatQset(gpa, pubs[0..self.n_validators], self.threshold);
        const peers = try addrList(gpa, self.base_port, N, i);
        defer freeAddrList(gpa, peers);
        const dir = try self.dataDir(gpa, i);
        defer gpa.free(dir);

        const node = try Node.create(gpa, self.io, .{
            .network = NETWORK,
            .node_id = pubFor(i),
            .secret_seed = seedFor(i),
            .quorum_set = qs,
            .listen_port = self.base_port + @as(u16, @intCast(i)),
            .peers = peers,
            .data_dir = dir,
        });
        self.nodes[i] = node;
        self.consumers[i] = .{ .node = node, .gpa = gpa, .io = self.io };
        try self.consumers[i].start();
    }

    fn killNode(self: *Cluster, i: usize) void {
        self.consumers[i].stopJoin();
        self.consumers[i].deinit(); // spawnNode overwrites the slot; free now
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
        for (0..N) |i| self.consumers[i].deinit();
        removeTree(self.io, self.data_root);
    }
};

fn sleepMs(io: std.Io, ms: u64) void {
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(@intCast(ms)), .awake) catch {};
}

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

test "e2e: 4 nodes externalize 200 slots with agreement" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var cl = Cluster{
        .gpa = gpa,
        .io = io,
        .base_port = 39100,
        .data_root = "e2e-happy",
    };
    removeTree(io, cl.data_root);
    defer cl.deinit();

    for (0..N) |i| try cl.spawnNode(i);
    try cl.waitMesh(20_000);
    try cl.proposeAll("v", HAPPY_SLOTS);

    try cl.waitAllReached(HAPPY_SLOTS, 240_000);
    try assertAgreement(&cl, HAPPY_SLOTS);
}

test "e2e: kill and restart a node mid-run; it catches up, agreement holds" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var cl = Cluster{
        .gpa = gpa,
        .io = io,
        .base_port = 39200,
        .data_root = "e2e-restart",
    };
    removeTree(io, cl.data_root);
    defer cl.deinit();

    for (0..N) |i| try cl.spawnNode(i);
    try cl.waitMesh(20_000);
    const target: u64 = RESTART_SLOTS;
    try cl.proposeAll("r", target);

    // Let the cluster make progress, then kill node 3 mid-run.
    while (cl.minHighestLive() < @max(4, target / 4)) sleepMs(io, 100);
    cl.killNode(3);

    // Cluster keeps going with 3 of 4 (still a quorum).
    while (cl.consumers[0].highestSlot() < @max(8, target / 2)) sleepMs(io, 100);

    // Restart node 3 from its own.log; it must catch up. Re-queue its
    // proposals (the queue died with the process; values are per-node fuel).
    try cl.spawnNode(3);
    {
        var vbuf: [48]u8 = undefined;
        for (1..target + 8 + 1) |s| {
            const v = try std.fmt.bufPrint(&vbuf, "rr-{d}-n3", .{s});
            try cl.nodes[3].?.propose(v);
        }
    }

    try cl.waitAllReached(target, 180_000);
    try assertAgreement(&cl, target);
}

test "e2e: partition halts without quorum, heals on reconnect" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var cl = Cluster{
        .gpa = gpa,
        .io = io,
        .base_port = 39300,
        .data_root = "e2e-partition",
    };
    removeTree(io, cl.data_root);
    defer cl.deinit();

    for (0..N) |i| try cl.spawnNode(i);
    try cl.waitMesh(20_000);
    const target: u64 = PARTITION_SLOTS;
    try cl.proposeAll("p", target);

    while (cl.minHighestLive() < @max(4, target / 5)) sleepMs(io, 100);

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
// Scenario 4: an equivocating quorum member
// -----------------------------------------------------------------------

const MessageBuilder = core.capnpc.message.MessageBuilder;
const gen_slcp = core.gen.slcp;

/// The normalized-qset hash of a flat {threshold, validators=0..n} set — the
/// same value every honest Node computes (so its statements never park).
fn sharedQsetHash(gpa: std.mem.Allocator, n_validators: usize, threshold: u32) ![32]u8 {
    var pubs: [N + 1][32]u8 = undefined;
    for (0..n_validators) |k| pubs[k] = pubFor(k);
    var qs = try buildFlatQset(gpa, pubs[0..n_validators], threshold);
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
        .data_root = "e2e-equiv",
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
