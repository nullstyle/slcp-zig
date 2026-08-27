//! Verified quorum-set cache + advertised-qset map + transitive quorum graph
//! (design §5.4: qset LRU cache, relevance filter).
//!
//! Every stored qset is validated+normalized and keyed by its qsetHash
//! (recomputation-verified before insertion — the store never trusts a
//! claimed hash). Node → advertised-hash tracks each node's latest statement
//! qset. The transitive quorum graph seeds from the local qset and expands
//! through the advertised qsets of in-graph nodes as they are fetched;
//! envelopes from outside the graph are dropped as `ignored` (§5.4).
//!
//! Borrow contract (local_node.QSetLookup): pointers handed out stay valid
//! until the qset is evicted; eviction only happens in `insert` (never
//! during a lookup), and the engine never holds lookups across inserts.

const std = @import("std");
const qset = @import("qset.zig");
const local_node = @import("local_node.zig");

pub const Store = struct {
    gpa: std.mem.Allocator,
    max_cached: u32,
    /// hash → heap-owned normalized qset. Pointer-stable (values boxed).
    by_hash: std.AutoHashMapUnmanaged([32]u8, *qset.QuorumSetOwned) = .empty,
    /// insertion order for crude FIFO eviction (LRU polish is M6 territory).
    order: std.ArrayList([32]u8) = .empty,
    /// node → the qset hash its latest statement advertises.
    advertised: std.AutoHashMapUnmanaged([32]u8, [32]u8) = .empty,
    /// transitive quorum graph membership (§5.4 relevance filter).
    graph: std.AutoHashMapUnmanaged([32]u8, void) = .empty,

    pub fn init(gpa: std.mem.Allocator, max_cached: u32) Store {
        return .{ .gpa = gpa, .max_cached = max_cached };
    }

    pub fn deinit(self: *Store) void {
        var it = self.by_hash.valueIterator();
        while (it.next()) |boxed| {
            boxed.*.deinit(self.gpa);
            self.gpa.destroy(boxed.*);
        }
        self.by_hash.deinit(self.gpa);
        self.order.deinit(self.gpa);
        self.advertised.deinit(self.gpa);
        self.graph.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn count(self: *const Store) usize {
        return self.by_hash.count();
    }

    pub fn get(self: *const Store, hash: [32]u8) ?*const qset.QuorumSetOwned {
        return if (self.by_hash.get(hash)) |p| p else null;
    }

    /// Take ownership of a validated+normalized qset whose recomputed hash
    /// is `hash` (caller verified — see Engine's qset_received path).
    /// Evicts oldest entries beyond the cap. No-op if already present.
    pub fn insert(self: *Store, hash: [32]u8, qs: qset.QuorumSetOwned) !void {
        var owned = qs;
        if (self.by_hash.contains(hash)) {
            owned.deinit(self.gpa);
            return;
        }
        const boxed = self.gpa.create(qset.QuorumSetOwned) catch |err| {
            owned.deinit(self.gpa);
            return err;
        };
        boxed.* = owned;
        errdefer {
            boxed.deinit(self.gpa);
            self.gpa.destroy(boxed);
        }
        try self.order.append(self.gpa, hash);
        errdefer _ = self.order.pop();
        try self.by_hash.put(self.gpa, hash, boxed);
        while (self.by_hash.count() > self.max_cached and self.order.items.len > 0) {
            const victim = self.order.orderedRemove(0);
            if (self.by_hash.fetchRemove(victim)) |kv| {
                kv.value.deinit(self.gpa);
                self.gpa.destroy(kv.value);
            }
        }
    }

    /// Record `node` advertising `hash`, expanding the transitive graph when
    /// the node is already in-graph and the qset is known.
    pub fn setAdvertised(self: *Store, node: [32]u8, hash: [32]u8) !void {
        try self.advertised.put(self.gpa, node, hash);
        if (self.graph.contains(node)) {
            if (self.get(hash)) |qs| try self.addToGraph(qs);
        }
    }

    pub fn inGraph(self: *const Store, node: [32]u8) bool {
        return self.graph.contains(node);
    }

    /// Seed / expand the graph with every validator in `qs`, then chase
    /// already-known advertised qsets of newly added nodes to a fixpoint.
    pub fn addToGraph(self: *Store, qs: *const qset.QuorumSetOwned) !void {
        var frontier: std.ArrayList([32]u8) = .empty;
        defer frontier.deinit(self.gpa);
        try collectNodes(self.gpa, qs, &frontier);
        while (frontier.pop()) |node| {
            const gop = try self.graph.getOrPut(self.gpa, node);
            if (gop.found_existing) continue;
            if (self.advertised.get(node)) |h| {
                if (self.get(h)) |advertised_qs| {
                    try collectNodes(self.gpa, advertised_qs, &frontier);
                }
            }
        }
    }

    /// local_node.QSetLookup over advertised qsets (statement-advertised
    /// semantics for isQuorum — §5.4).
    pub fn lookup(self: *const Store) local_node.QSetLookup {
        return .{ .ctx = self, .get = lookupGet };
    }

    fn lookupGet(ctx: *const anyopaque, node: qset.NodeId) ?*const qset.QuorumSetOwned {
        const self: *const Store = @ptrCast(@alignCast(ctx));
        const h = self.advertised.get(node) orelse return null;
        return self.get(h);
    }
};

fn collectNodes(gpa: std.mem.Allocator, qs: *const qset.QuorumSetOwned, out: *std.ArrayList([32]u8)) !void {
    try out.appendSlice(gpa, qs.validators);
    for (qs.inner_sets) |*inner| try collectNodes(gpa, inner, out);
}

fn nodeOf(byte: u8) [32]u8 {
    return @splat(byte);
}

fn flatOwned(gpa: std.mem.Allocator, threshold: u32, bytes: []const u8) !qset.QuorumSetOwned {
    const vals = try gpa.alloc(qset.NodeId, bytes.len);
    for (bytes, 0..) |b, i| vals[i] = nodeOf(b);
    var qs: qset.QuorumSetOwned = .{ .threshold = threshold, .validators = vals, .inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0) };
    try qset.validateAndNormalize(gpa, &qs);
    return qs;
}

test "store: insert/get, dedup, FIFO eviction at cap" {
    const gpa = std.testing.allocator;
    var s = Store.init(gpa, 2);
    defer s.deinit();

    const qa = try flatOwned(gpa, 1, &.{1});
    const ha = try qset.hashNormalized(gpa, &qa);
    try s.insert(ha, qa);
    try std.testing.expect(s.get(ha) != null);

    var dup = try flatOwned(gpa, 1, &.{1});
    _ = &dup;
    try s.insert(ha, dup); // dedup consumes it
    try std.testing.expectEqual(@as(usize, 1), s.count());

    const qb = try flatOwned(gpa, 1, &.{2});
    const hb = try qset.hashNormalized(gpa, &qb);
    try s.insert(hb, qb);
    const qc = try flatOwned(gpa, 1, &.{3});
    const hc = try qset.hashNormalized(gpa, &qc);
    try s.insert(hc, qc);
    try std.testing.expectEqual(@as(usize, 2), s.count());
    try std.testing.expect(s.get(ha) == null); // oldest evicted
    try std.testing.expect(s.get(hb) != null and s.get(hc) != null);
}

test "graph: seeds, expands through advertised qsets to a fixpoint" {
    const gpa = std.testing.allocator;
    var s = Store.init(gpa, 8);
    defer s.deinit();

    // local qset over {1,2}; node 2 advertises a qset over {3}; 3 unknown.
    var local = try flatOwned(gpa, 2, &.{ 1, 2 });
    defer local.deinit(gpa);
    try s.addToGraph(&local);
    try std.testing.expect(s.inGraph(nodeOf(1)) and s.inGraph(nodeOf(2)));
    try std.testing.expect(!s.inGraph(nodeOf(3)));

    const q3 = try flatOwned(gpa, 1, &.{3});
    const h3 = try qset.hashNormalized(gpa, &q3);
    try s.insert(h3, q3);
    try s.setAdvertised(nodeOf(2), h3); // in-graph node advertises → expand
    try std.testing.expect(s.inGraph(nodeOf(3)));

    // outsider advertising does not add anyone
    const q9 = try flatOwned(gpa, 1, &.{9});
    const h9 = try qset.hashNormalized(gpa, &q9);
    try s.insert(h9, q9);
    try s.setAdvertised(nodeOf(8), h9);
    try std.testing.expect(!s.inGraph(nodeOf(8)) and !s.inGraph(nodeOf(9)));

    // lookup serves advertised qsets
    const lk = s.lookup();
    try std.testing.expect(lk.get(lk.ctx, nodeOf(2)) != null);
    try std.testing.expect(lk.get(lk.ctx, nodeOf(7)) == null);
}
