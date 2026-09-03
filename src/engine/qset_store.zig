//! Verified quorum-set cache + live-statement references + transitive graph
//! (design §5.4: bounded qset cache, relevance filter).
//!
//! Every stored qset is validated+normalized and keyed by its qsetHash
//! (recomputation-verified before insertion — the store never trusts a
//! claimed hash). Live remote statements retain their exact qset hashes.
//! Exact transitive reachability seeds from the local qset and expands through
//! the union of qsets carried by every live statement from each reachable
//! node. `graph` publishes that exact relation at fixed checkpoints. Between
//! checkpoints it is a conservative superset: additions expand immediately,
//! while removals are pruned after 64 qualifying lifecycle updates, at qset
//! replay boundaries, or at slot purge. Thus an exact member is never filtered
//! out; a recently disconnected signer can be a temporary resource-policy
//! false positive, but quorum math always resolves the statement's exact hash.
//!
//! Borrow contract (local_node.QSetLookup): pointers handed out stay valid
//! until the qset is evicted. Eviction happens only at lifecycle boundaries
//! (`insert`, `replaceStatementReference`, `release`), and the engine never
//! holds a lookup across one of those calls.

const std = @import("std");
const qset = @import("qset.zig");

const HashCounts = std.AutoHashMapUnmanaged([32]u8, u32);
/// One generation can retire at most one qset body per qualifying update.
/// Each body has at most 255 validators, so it can leave at most 16,320 raw
/// node ids in the conservative graph beyond the bodies that remain active.
const graph_checkpoint_updates: u8 = 64;
const max_retired_qset_nodes_per_generation: usize =
    @as(usize, graph_checkpoint_updates) * qset.max_total_validators;

pub const StatementReference = struct {
    node: [32]u8,
    hash: [32]u8,
};

pub const Store = struct {
    gpa: std.mem.Allocator,
    max_cached: u32,
    /// Explicitly remembers a configured zero after `max_cached` is raised
    /// to the mandatory local slot. This mode must not inherit the normal
    /// one-entry rotation overflow.
    local_only: bool,
    /// hash → heap-owned normalized qset. Pointer-stable (values boxed).
    by_hash: std.AutoHashMapUnmanaged([32]u8, *qset.QuorumSetOwned) = .empty,
    /// Insertion order for deterministic FIFO eviction.
    order: std.ArrayList([32]u8) = .empty,
    /// node → (qset hash → number of live statements carrying it).
    /// A node may use different qsets in different live slots/protocols;
    /// graph reachability is the union of those exact statements.
    node_refs: std.AutoHashMapUnmanaged([32]u8, HashCounts) = .empty,
    /// qset hash → number of live remote statements carrying it. This is
    /// the O(1) eviction-protection index for `node_refs`.
    statement_refs: HashCounts = .empty,
    /// Permanent pins (the local qset) plus short-lived installation leases
    /// while a fetched qset's parked statements replay.
    retained: std.AutoHashMapUnmanaged([32]u8, u32) = .empty,
    /// Immutable roots of the local transitive quorum graph. Unlike `graph`,
    /// these survive rebuilds as live statement references change.
    roots: std.AutoHashMapUnmanaged([32]u8, void) = .empty,
    /// Published relevance membership. Exact after a checkpoint; otherwise a
    /// conservative superset of reachability through current live references.
    graph: std.AutoHashMapUnmanaged([32]u8, void) = .empty,
    /// A nonzero count means `graph` is a conservative superset awaiting an
    /// exact checkpoint. Successful reference lifecycle updates and verified
    /// in-graph unknown-qset attempts advance the count. Known-qset inputs
    /// rejected before reference commit do not, so 64 is a work/growth bound,
    /// not a wall-clock or total-input duration guarantee.
    deferred_reference_updates: u8 = 0,
    /// A qset response replays parked statements synchronously. Deferring
    /// their graph publication coalesces up to the pending-envelope cap into
    /// one exact rebuild; no network input can observe the intermediate graph.
    reference_batch_active: bool = false,
    reference_batch_dirty: bool = false,

    pub fn init(gpa: std.mem.Allocator, max_cached: u32) Store {
        // An engine always owns one mandatory local qset. Treat zero as a
        // local-only cache instead of immediately evicting that set during
        // Engine.init (host.capnp already uses zero as "engine default").
        return .{
            .gpa = gpa,
            .max_cached = @max(1, max_cached),
            .local_only = max_cached == 0,
        };
    }

    pub fn deinit(self: *Store) void {
        var it = self.by_hash.valueIterator();
        while (it.next()) |boxed| {
            boxed.*.deinit(self.gpa);
            self.gpa.destroy(boxed.*);
        }
        self.by_hash.deinit(self.gpa);
        self.order.deinit(self.gpa);
        var node_refs = self.node_refs.valueIterator();
        while (node_refs.next()) |hashes| hashes.deinit(self.gpa);
        self.node_refs.deinit(self.gpa);
        self.statement_refs.deinit(self.gpa);
        self.retained.deinit(self.gpa);
        self.roots.deinit(self.gpa);
        self.graph.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn count(self: *const Store) usize {
        return self.by_hash.count();
    }

    pub fn get(self: *const Store, hash: [32]u8) ?*const qset.QuorumSetOwned {
        return if (self.by_hash.get(hash)) |p| p else null;
    }

    /// Keep `hash` eviction-proof until the matching `release`. The qset may
    /// be retained before it is inserted, which makes qset replacement at a
    /// full cache an atomic install/reference operation to callers.
    pub fn retain(self: *Store, hash: [32]u8) !void {
        const gop = try self.retained.getOrPut(self.gpa, hash);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += 1;
    }

    pub fn release(self: *Store, hash: [32]u8) void {
        const retain_count = self.retained.getPtr(hash) orelse return;
        if (retain_count.* > 1) {
            retain_count.* -= 1;
        } else {
            _ = self.retained.remove(hash);
        }
        self.trimToCapacity();
    }

    /// Take ownership of a validated+normalized qset whose recomputed hash
    /// is `hash` (caller verified — see Engine's qset_received path).
    /// Evicts the oldest unreferenced entries beyond the cap. A retained
    /// install may exceed the cap transiently until its matching release.
    /// No-op if already present.
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
        self.trimToCapacity();
    }

    /// Whether one statement-reference replacement fits the active-qset
    /// bound. A rotation may use one extra distinct set while other live
    /// statements still reference the old set; no second overflow is
    /// admitted. References to an already-active set never grow the bound.
    pub fn canReplaceStatementReference(self: *const Store, replaced: ?[32]u8, replacement: ?[32]u8) bool {
        if (replacement == null) return true;
        var projected = self.statement_refs.count();
        var pins = self.retained.iterator();
        while (pins.next()) |entry| {
            if (!self.statement_refs.contains(entry.key_ptr.*)) projected += 1;
        }

        if (replaced) |old_hash| {
            const same = if (replacement) |new_hash| std.mem.eql(u8, &old_hash, &new_hash) else false;
            const old_count = self.statement_refs.get(old_hash) orelse 0;
            if (!same and old_count == 1 and !self.retained.contains(old_hash)) projected -= 1;
        }
        if (replacement) |new_hash| {
            if (!self.statement_refs.contains(new_hash) and !self.retained.contains(new_hash)) projected += 1;
        }
        if (projected <= self.max_cached) return true;
        if (self.local_only) return false;
        if (projected != @as(usize, self.max_cached) + 1) return false;
        const new_hash = replacement orelse return false;
        // An existing live hash consumes no new stable cache entry. A new
        // hash may consume the sole overflow only while replacing an old one.
        return self.statement_refs.contains(new_hash) or replaced != null;
    }

    /// Commit the qset-reference side of a successful Slot.storeLatest.
    /// `replaced`/`replacement` are null for EXTERNALIZE and local-node
    /// statements, whose quorum math uses a singleton/configured qset. A
    /// replacement must already be verified and cached, and the matching
    /// capacity check must have succeeded. Live references are pins and are
    /// never sacrificed to enforce the bound.
    pub fn replaceStatementReference(
        self: *Store,
        node: [32]u8,
        replaced: ?[32]u8,
        replacement: ?[32]u8,
    ) !void {
        const same = replaced != null and replacement != null and
            std.mem.eql(u8, &replaced.?, &replacement.?);
        if (same) {
            if (!self.reference_batch_active) _ = try self.recordDeferredUpdate(false);
            return;
        }
        if (replacement) |hash| std.debug.assert(self.by_hash.contains(hash));
        std.debug.assert(self.canReplaceStatementReference(replaced, replacement));

        const source_in_graph = self.graph.contains(node);
        var added_edge = false;
        var removed_edge = false;
        if (replacement) |hash| added_edge = try self.addStatementReference(node, hash);
        if (replaced) |hash| removed_edge = self.removeStatementReference(node, hash);
        if (self.reference_batch_active) {
            self.reference_batch_dirty = self.reference_batch_dirty or removed_edge or added_edge;
            // Defer only pruning/full publication. Expanding a new edge keeps
            // exact reachability inside the published conservative superset,
            // including during a synchronous replay batch.
            if (added_edge) try self.expandGraphThrough(node, replacement.?);
        } else if (!try self.recordDeferredUpdate(removed_edge and source_in_graph) and added_edge) {
            // A pure addition cannot invalidate existing reachability. Chase
            // only the new edge. When a prune is deferred this preserves the
            // invariant that graph is a superset of exact reachability.
            try self.expandGraphThrough(node, replacement.?);
        }
        self.trimToCapacity();
    }

    /// Record one successful reference lifecycle update. The first removal
    /// that can shrink reachable graph state opens a conservative generation;
    /// its 64th update publishes an exact graph. The counter saturates while a
    /// failed publication is retried, so direct Store callers cannot wrap it.
    /// Returns true when it rebuilt.
    fn recordDeferredUpdate(self: *Store, starts_generation: bool) !bool {
        if (self.deferred_reference_updates == 0 and !starts_generation) return false;
        if (self.deferred_reference_updates < graph_checkpoint_updates) {
            self.deferred_reference_updates += 1;
        }
        if (self.deferred_reference_updates < graph_checkpoint_updates) return false;
        try self.rebuildGraph();
        return true;
    }

    /// Before an unknown-qset envelope consumes pending capacity, advance an
    /// open conservative generation. Callers have already verified the
    /// envelope's signature and initial graph membership. The membership
    /// guard here ensures an arbitrary outside signer cannot force rebuilds;
    /// a checkpoint may prove that a formerly reachable signer is now stale.
    pub fn recheckBeforeParking(self: *Store, node: [32]u8) !bool {
        if (!self.graph.contains(node)) return false;
        if (self.deferred_reference_updates == 0) return true;
        _ = try self.recordDeferredUpdate(false);
        return self.graph.contains(node);
    }

    /// Begin a synchronous reference-update batch. The caller must finish a
    /// successful batch before accepting another input. If any update fails,
    /// the Engine's sticky-failure rule makes the unfinished batch terminal.
    pub fn beginReferenceBatch(self: *Store) void {
        std.debug.assert(!self.reference_batch_active);
        std.debug.assert(!self.reference_batch_dirty);
        self.reference_batch_active = true;
    }

    /// Publish the exact graph for the active batch and for any conservative
    /// generation opened before it. The refcount changes are already committed;
    /// an allocation failure is terminal, but leaves ownership safe for teardown.
    pub fn finishReferenceBatch(self: *Store) !void {
        std.debug.assert(self.reference_batch_active);
        self.reference_batch_active = false;
        if (!self.reference_batch_dirty and self.deferred_reference_updates == 0) return;
        try self.rebuildGraph();
        self.reference_batch_dirty = false;
    }

    /// Remove a batch of live statement references and publish exact
    /// reachability once. Purge calls this even for an empty victim set, so it
    /// is also an explicit checkpoint for a previously open generation.
    pub fn removeStatementReferences(self: *Store, refs: []const StatementReference) !void {
        var graph_changed = false;
        for (refs) |ref| {
            graph_changed = self.removeStatementReference(ref.node, ref.hash) or graph_changed;
        }
        if (graph_changed or self.deferred_reference_updates != 0) {
            if (self.reference_batch_active) {
                // Entering a batch is also an exact-publication boundary for
                // a conservative generation opened by an earlier input.
                self.reference_batch_dirty = true;
            } else {
                try self.rebuildGraph();
            }
        }
        self.trimToCapacity();
    }

    pub fn inGraph(self: *const Store, node: [32]u8) bool {
        return self.graph.contains(node);
    }

    /// Add the validators in a local quorum set as permanent graph roots,
    /// then chase qsets carried by current live statements to a fixpoint.
    pub fn addToGraph(self: *Store, qs: *const qset.QuorumSetOwned) !void {
        var seeds: std.ArrayList([32]u8) = .empty;
        defer seeds.deinit(self.gpa);
        try collectNodes(self.gpa, qs, &seeds);
        for (seeds.items) |node| try self.roots.put(self.gpa, node, {});
        try self.rebuildGraph();
    }

    /// Add a permanent graph root not necessarily present in the local qset
    /// (the engine uses this to make its own node id relevant).
    pub fn addGraphRoot(self: *Store, node: [32]u8) !void {
        try self.roots.put(self.gpa, node, {});
        try self.rebuildGraph();
    }

    fn buildGraph(self: *Store) !std.AutoHashMapUnmanaged([32]u8, void) {
        var rebuilt: std.AutoHashMapUnmanaged([32]u8, void) = .empty;
        errdefer rebuilt.deinit(self.gpa);
        var frontier: std.ArrayList([32]u8) = .empty;
        defer frontier.deinit(self.gpa);
        var expanded_hashes: std.AutoHashMapUnmanaged([32]u8, void) = .empty;
        defer expanded_hashes.deinit(self.gpa);

        var roots = self.roots.keyIterator();
        while (roots.next()) |node| try enqueueNode(self.gpa, &rebuilt, &frontier, node.*);
        while (frontier.pop()) |node| {
            if (self.node_refs.get(node)) |hashes| {
                var live_hashes = hashes.keyIterator();
                while (live_hashes.next()) |hash| {
                    try self.expandHashOnce(hash.*, &expanded_hashes, &rebuilt, &frontier);
                }
            }
        }

        return rebuilt;
    }

    /// Incrementally chase one newly added association from an already-
    /// reachable node. Existing hashes for `node` are not rescanned; every
    /// newly discovered validator then expands through all of its live refs.
    /// `graph` doubles as the node seen set, while `expanded_hashes` ensures
    /// an identical qset body is walked once even when many validators carry
    /// it. Thus work follows newly reachable nodes plus distinct qset hashes,
    /// not node/hash multiplicity.
    fn expandGraphThrough(self: *Store, node: [32]u8, new_hash: [32]u8) !void {
        if (!self.graph.contains(node)) return;
        var frontier: std.ArrayList([32]u8) = .empty;
        defer frontier.deinit(self.gpa);
        var expanded_hashes: std.AutoHashMapUnmanaged([32]u8, void) = .empty;
        defer expanded_hashes.deinit(self.gpa);
        try self.expandHashOnce(new_hash, &expanded_hashes, &self.graph, &frontier);
        while (frontier.pop()) |current| {
            if (self.node_refs.get(current)) |hashes| {
                var live_hashes = hashes.keyIterator();
                while (live_hashes.next()) |hash| {
                    try self.expandHashOnce(hash.*, &expanded_hashes, &self.graph, &frontier);
                }
            }
        }
    }

    fn expandHashOnce(
        self: *Store,
        hash: [32]u8,
        expanded_hashes: *std.AutoHashMapUnmanaged([32]u8, void),
        seen_nodes: *std.AutoHashMapUnmanaged([32]u8, void),
        frontier: *std.ArrayList([32]u8),
    ) !void {
        const qs = self.get(hash) orelse return;
        const gop = try expanded_hashes.getOrPut(self.gpa, hash);
        if (gop.found_existing) return;
        try enqueueQsetNodes(self.gpa, qs, seen_nodes, frontier);
    }

    fn rebuildGraph(self: *Store) !void {
        // Each unique live node/hash association is backed by a latest
        // statement under the engine-wide stored-byte cap. Exact rebuild work
        // is bounded by those associations plus one walk per distinct reachable
        // qset (at most max_cached + the rotation entry) and one visit per
        // validator. The old conservative graph can additionally hold node ids
        // from at most 64 qset bodies retired during this generation; it is not
        // traversed here. A checkpoint deliberately pays this bounded O(W)
        // latency spike after amortizing it across up to 64 qualifying updates.
        var rebuilt = try self.buildGraph();
        errdefer rebuilt.deinit(self.gpa);
        try self.installGraph(&rebuilt);
        self.deferred_reference_updates = 0;
    }

    fn installGraph(self: *Store, rebuilt: *std.AutoHashMapUnmanaged([32]u8, void)) !void {
        self.graph.deinit(self.gpa);
        self.graph = rebuilt.*;
        rebuilt.* = .empty;
    }

    fn addStatementReference(self: *Store, node: [32]u8, hash: [32]u8) !bool {
        const node_gop = try self.node_refs.getOrPut(self.gpa, node);
        if (!node_gop.found_existing) node_gop.value_ptr.* = .empty;
        const hash_gop = node_gop.value_ptr.getOrPut(self.gpa, hash) catch |err| {
            if (!node_gop.found_existing) {
                var removed = self.node_refs.fetchRemove(node).?;
                removed.value.deinit(self.gpa);
            }
            return err;
        };
        if (!hash_gop.found_existing) hash_gop.value_ptr.* = 0;

        const total_gop = self.statement_refs.getOrPut(self.gpa, hash) catch |err| {
            if (!hash_gop.found_existing) _ = node_gop.value_ptr.remove(hash);
            if (node_gop.value_ptr.count() == 0) {
                var removed = self.node_refs.fetchRemove(node).?;
                removed.value.deinit(self.gpa);
            }
            return err;
        };
        if (!total_gop.found_existing) total_gop.value_ptr.* = 0;
        hash_gop.value_ptr.* += 1;
        total_gop.value_ptr.* += 1;
        return !hash_gop.found_existing;
    }

    fn removeStatementReference(self: *Store, node: [32]u8, hash: [32]u8) bool {
        const hashes = self.node_refs.getPtr(node) orelse unreachable;
        const ref_count = hashes.getPtr(hash) orelse unreachable;
        const last_for_node = ref_count.* == 1;
        if (last_for_node) {
            _ = hashes.remove(hash);
        } else {
            ref_count.* -= 1;
        }
        if (hashes.count() == 0) {
            var removed = self.node_refs.fetchRemove(node).?;
            removed.value.deinit(self.gpa);
        }

        const total = self.statement_refs.getPtr(hash) orelse unreachable;
        if (total.* == 1) {
            _ = self.statement_refs.remove(hash);
        } else {
            total.* -= 1;
        }
        return last_for_node;
    }

    fn oldestUnreferencedIndex(self: *const Store) ?usize {
        for (self.order.items, 0..) |candidate, i| {
            if (self.retained.contains(candidate)) continue;
            if (!self.statement_refs.contains(candidate)) return i;
        }
        return null;
    }
    fn trimToCapacity(self: *Store) void {
        while (self.by_hash.count() > self.max_cached) {
            const victim_index = self.oldestUnreferencedIndex() orelse break;
            const victim = self.order.orderedRemove(victim_index);
            const kv = self.by_hash.fetchRemove(victim).?;
            kv.value.deinit(self.gpa);
            self.gpa.destroy(kv.value);
        }
    }
};

fn collectNodes(gpa: std.mem.Allocator, qs: *const qset.QuorumSetOwned, out: *std.ArrayList([32]u8)) !void {
    try out.appendSlice(gpa, qs.validators);
    for (qs.inner_sets) |*inner| try collectNodes(gpa, inner, out);
}

fn enqueueNode(
    gpa: std.mem.Allocator,
    seen: *std.AutoHashMapUnmanaged([32]u8, void),
    frontier: *std.ArrayList([32]u8),
    node: [32]u8,
) !void {
    const gop = try seen.getOrPut(gpa, node);
    if (gop.found_existing) return;
    frontier.append(gpa, node) catch |err| {
        std.debug.assert(seen.remove(node));
        return err;
    };
}

fn enqueueQsetNodes(
    gpa: std.mem.Allocator,
    qs: *const qset.QuorumSetOwned,
    seen: *std.AutoHashMapUnmanaged([32]u8, void),
    frontier: *std.ArrayList([32]u8),
) !void {
    for (qs.validators) |node| try enqueueNode(gpa, seen, frontier, node);
    for (qs.inner_sets) |*inner| try enqueueQsetNodes(gpa, inner, seen, frontier);
}

fn nodeOf(byte: u8) [32]u8 {
    return @splat(byte);
}

fn flatOwned(gpa: std.mem.Allocator, threshold: u32, bytes: []const u8) !qset.QuorumSetOwned {
    const vals = try gpa.alloc(qset.NodeId, bytes.len);
    for (bytes, 0..) |b, i| vals[i] = nodeOf(b);
    const inners = gpa.alloc(qset.QuorumSetOwned, 0) catch |err| {
        gpa.free(vals);
        return err;
    };
    var qs: qset.QuorumSetOwned = .{ .threshold = threshold, .validators = vals, .inner_sets = inners };
    errdefer qs.deinit(gpa);
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

test "store: a live-referenced quorum set survives cache pressure" {
    const gpa = std.testing.allocator;
    var s = Store.init(gpa, 1);
    defer s.deinit();

    const referenced = try flatOwned(gpa, 1, &.{1});
    const referenced_hash = try qset.hashNormalized(gpa, &referenced);
    try s.insert(referenced_hash, referenced);
    try s.addToGraph(s.get(referenced_hash).?);
    try s.replaceStatementReference(nodeOf(1), null, referenced_hash);

    const newcomer = try flatOwned(gpa, 1, &.{2});
    const newcomer_hash = try qset.hashNormalized(gpa, &newcomer);
    try s.insert(newcomer_hash, newcomer);

    try std.testing.expect(s.get(referenced_hash) != null);
    try std.testing.expect(s.get(newcomer_hash) == null);
    try std.testing.expectEqual(@as(usize, 1), s.count());
}

test "store: a zero cache setting still has room for the mandatory local set" {
    const gpa = std.testing.allocator;
    var s = Store.init(gpa, 0);
    defer s.deinit();

    const local = try flatOwned(gpa, 1, &.{1});
    const local_hash = try qset.hashNormalized(gpa, &local);
    try s.insert(local_hash, local);
    try s.retain(local_hash);

    try std.testing.expect(s.get(local_hash) != null);
    try std.testing.expectEqual(@as(usize, 1), s.count());

    const fetched = try flatOwned(gpa, 1, &.{2});
    const fetched_hash = try qset.hashNormalized(gpa, &fetched);
    try s.retain(fetched_hash);
    try s.insert(fetched_hash, fetched);
    try std.testing.expectEqual(@as(usize, 2), s.count());
    s.release(fetched_hash);

    try std.testing.expectEqual(@as(usize, 1), s.count());
    try std.testing.expect(s.get(local_hash) != null);
    try std.testing.expect(s.get(fetched_hash) == null);
}

test "store: one fetched lease bounds a nonzero rotation peak at N plus two" {
    const gpa = std.testing.allocator;
    var s = Store.init(gpa, 2);
    defer s.deinit();

    const local = try flatOwned(gpa, 1, &.{1});
    const local_hash = try qset.hashNormalized(gpa, &local);
    try s.insert(local_hash, local);
    try s.retain(local_hash);

    const old = try flatOwned(gpa, 1, &.{2});
    const old_hash = try qset.hashNormalized(gpa, &old);
    try s.insert(old_hash, old);
    try s.replaceStatementReference(nodeOf(1), null, old_hash);
    try s.replaceStatementReference(nodeOf(1), null, old_hash);

    const replacement = try flatOwned(gpa, 1, &.{3});
    const replacement_hash = try qset.hashNormalized(gpa, &replacement);
    try s.retain(replacement_hash);
    try s.insert(replacement_hash, replacement);
    try s.replaceStatementReference(nodeOf(1), old_hash, replacement_hash);
    s.release(replacement_hash);
    try std.testing.expectEqual(@as(usize, 3), s.count()); // N + rotation

    const fetched = try flatOwned(gpa, 1, &.{4});
    const fetched_hash = try qset.hashNormalized(gpa, &fetched);
    try s.retain(fetched_hash);
    try s.insert(fetched_hash, fetched);
    try std.testing.expectEqual(@as(usize, 4), s.count()); // N + rotation + fetch
    s.release(fetched_hash);

    try std.testing.expectEqual(@as(usize, 3), s.count());
    try std.testing.expect(s.get(fetched_hash) == null);
}

test "store: a node can replace a live statement qset at capacity" {
    const gpa = std.testing.allocator;
    var s = Store.init(gpa, 1);
    defer s.deinit();

    const old = try flatOwned(gpa, 1, &.{1});
    const old_hash = try qset.hashNormalized(gpa, &old);
    try s.insert(old_hash, old);
    try s.addToGraph(s.get(old_hash).?);
    try s.replaceStatementReference(nodeOf(1), null, old_hash);

    const replacement = try flatOwned(gpa, 1, &.{2});
    const replacement_hash = try qset.hashNormalized(gpa, &replacement);
    try s.retain(replacement_hash);
    try s.insert(replacement_hash, replacement);
    try s.replaceStatementReference(nodeOf(1), old_hash, replacement_hash);
    s.release(replacement_hash);

    const current = s.get(replacement_hash).?;
    try std.testing.expectEqualSlices(qset.NodeId, &.{nodeOf(2)}, current.validators);
    try std.testing.expect(s.get(old_hash) == null);
    try std.testing.expectEqual(@as(usize, 1), s.count());
}

test "store: a new distinct reference cannot consume the rotation overflow" {
    const gpa = std.testing.allocator;
    var s = Store.init(gpa, 1);
    defer s.deinit();

    const first = try flatOwned(gpa, 1, &.{ 1, 2 });
    const first_hash = try qset.hashNormalized(gpa, &first);
    try s.insert(first_hash, first);
    try s.addToGraph(s.get(first_hash).?);
    try s.replaceStatementReference(nodeOf(1), null, first_hash);

    const second = try flatOwned(gpa, 1, &.{2});
    const second_hash = try qset.hashNormalized(gpa, &second);
    try s.retain(second_hash);
    try s.insert(second_hash, second);
    const accepted = s.canReplaceStatementReference(null, second_hash);
    s.release(second_hash);

    try std.testing.expect(!accepted);
    try std.testing.expect(s.get(first_hash) != null);
    try std.testing.expect(s.get(second_hash) == null);
    try std.testing.expectEqual(@as(usize, 1), s.count());
}

test "graph: seeds, expands through live statement qsets to a fixpoint" {
    const gpa = std.testing.allocator;
    var s = Store.init(gpa, 8);
    defer s.deinit();

    // Local qset over {1,2}; node 2 has a live qset over {3}; 3 is unknown.
    var local = try flatOwned(gpa, 2, &.{ 1, 2 });
    defer local.deinit(gpa);
    try s.addToGraph(&local);
    try std.testing.expect(s.inGraph(nodeOf(1)) and s.inGraph(nodeOf(2)));
    try std.testing.expect(!s.inGraph(nodeOf(3)));

    const q3 = try flatOwned(gpa, 1, &.{3});
    const h3 = try qset.hashNormalized(gpa, &q3);
    try s.insert(h3, q3);
    try s.replaceStatementReference(nodeOf(2), null, h3); // in-graph live edge → expand
    try std.testing.expect(s.inGraph(nodeOf(3)));

    // An outsider's stored edge does not add anyone.
    const q9 = try flatOwned(gpa, 1, &.{9});
    const h9 = try qset.hashNormalized(gpa, &q9);
    try s.insert(h9, q9);
    try s.replaceStatementReference(nodeOf(8), null, h9);
    try std.testing.expect(!s.inGraph(nodeOf(8)) and !s.inGraph(nodeOf(9)));

    try std.testing.expect(s.get(h3) != null);
}

test "graph: one node contributes the union of all live statement qsets" {
    const gpa = std.testing.allocator;
    var s = Store.init(gpa, 4);
    defer s.deinit();

    var local = try flatOwned(gpa, 1, &.{1});
    defer local.deinit(gpa);
    try s.addToGraph(&local);

    const via_two = try flatOwned(gpa, 1, &.{2});
    const via_two_hash = try qset.hashNormalized(gpa, &via_two);
    try s.insert(via_two_hash, via_two);
    const via_three = try flatOwned(gpa, 1, &.{3});
    const via_three_hash = try qset.hashNormalized(gpa, &via_three);
    try s.insert(via_three_hash, via_three);

    // Two live statements share via_two; a third (for another slot or
    // protocol) carries via_three. Both branches remain reachable.
    try s.replaceStatementReference(nodeOf(1), null, via_two_hash);
    try s.replaceStatementReference(nodeOf(1), null, via_two_hash);
    try s.replaceStatementReference(nodeOf(1), null, via_three_hash);
    try std.testing.expect(s.inGraph(nodeOf(2)));
    try std.testing.expect(s.inGraph(nodeOf(3)));

    // Releasing only one of the duplicate live references preserves its
    // branch and cache protection. Releasing the last prunes just that edge.
    try s.removeStatementReferences(&.{.{ .node = nodeOf(1), .hash = via_two_hash }});
    try std.testing.expect(s.inGraph(nodeOf(2)));
    try std.testing.expect(s.get(via_two_hash) != null);
    try s.removeStatementReferences(&.{.{ .node = nodeOf(1), .hash = via_two_hash }});
    try std.testing.expect(!s.inGraph(nodeOf(2)));
    try std.testing.expect(s.inGraph(nodeOf(3)));
}

test "graph: a purge checkpoint prunes nodes that are no longer reachable" {
    const gpa = std.testing.allocator;
    var s = Store.init(gpa, 8);
    defer s.deinit();

    var local = try flatOwned(gpa, 1, &.{1});
    defer local.deinit(gpa);
    try s.addToGraph(&local);

    const via_two = try flatOwned(gpa, 1, &.{2});
    const via_two_hash = try qset.hashNormalized(gpa, &via_two);
    try s.insert(via_two_hash, via_two);
    try s.replaceStatementReference(nodeOf(1), null, via_two_hash);

    const via_four = try flatOwned(gpa, 1, &.{4});
    const via_four_hash = try qset.hashNormalized(gpa, &via_four);
    try s.insert(via_four_hash, via_four);
    try s.replaceStatementReference(nodeOf(2), null, via_four_hash);
    try std.testing.expect(s.inGraph(nodeOf(2)));
    try std.testing.expect(s.inGraph(nodeOf(4)));

    const via_three = try flatOwned(gpa, 1, &.{3});
    const via_three_hash = try qset.hashNormalized(gpa, &via_three);
    try s.insert(via_three_hash, via_three);
    try s.replaceStatementReference(nodeOf(1), via_two_hash, via_three_hash);

    // Ordinary replacement keeps a bounded conservative superset until a
    // fixed update, replay-batch, or purge checkpoint.
    try std.testing.expect(s.inGraph(nodeOf(1)));
    try std.testing.expect(s.inGraph(nodeOf(3)));
    try std.testing.expect(s.inGraph(nodeOf(2)));
    try std.testing.expect(s.inGraph(nodeOf(4)));

    // removeStatementReferences is the purge lifecycle seam. Even an empty
    // reference batch publishes any previously deferred exact graph.
    try s.removeStatementReferences(&.{});
    try std.testing.expect(!s.inGraph(nodeOf(2)));
    try std.testing.expect(!s.inGraph(nodeOf(4)));
    // Node 2's statement remains live (and its qset retained), but is no
    // longer reachable after node 1's replacement removes the only edge.
    try std.testing.expect(s.get(via_four_hash) != null);
}

test "graph: cached qset rotations publish an exact graph every 64 reference updates" {
    const gpa = std.testing.allocator;
    var s = Store.init(gpa, 4);
    defer s.deinit();

    var local = try flatOwned(gpa, 1, &.{1});
    defer local.deinit(gpa);
    try s.addToGraph(&local);

    const branch_a = try flatOwned(gpa, 1, &.{2});
    const hash_a = try qset.hashNormalized(gpa, &branch_a);
    try s.insert(hash_a, branch_a);
    const branch_b = try flatOwned(gpa, 1, &.{3});
    const hash_b = try qset.hashNormalized(gpa, &branch_b);
    try s.insert(hash_b, branch_b);
    try s.replaceStatementReference(nodeOf(1), null, hash_a);

    var current = hash_a;
    for (1..65) |update| {
        const replacement = if (std.mem.eql(u8, &current, &hash_a)) hash_b else hash_a;
        try s.replaceStatementReference(nodeOf(1), current, replacement);
        current = replacement;

        if (update < 64) {
            // Between checkpoints relevance is a conservative superset.
            try std.testing.expect(s.inGraph(nodeOf(2)) and s.inGraph(nodeOf(3)));
        }
    }

    // The 64th update returns to A and publishes exact current reachability.
    try std.testing.expect(s.inGraph(nodeOf(2)));
    try std.testing.expect(!s.inGraph(nodeOf(3)));
}

test "graph: unchanged references advance an open generation to its checkpoint" {
    const gpa = std.testing.allocator;
    var s = Store.init(gpa, 4);
    defer s.deinit();

    var local = try flatOwned(gpa, 1, &.{1});
    defer local.deinit(gpa);
    try s.addToGraph(&local);

    const branch_a = try flatOwned(gpa, 1, &.{2});
    const hash_a = try qset.hashNormalized(gpa, &branch_a);
    try s.insert(hash_a, branch_a);
    const branch_b = try flatOwned(gpa, 1, &.{3});
    const hash_b = try qset.hashNormalized(gpa, &branch_b);
    try s.insert(hash_b, branch_b);
    try s.replaceStatementReference(nodeOf(1), null, hash_a);
    try s.replaceStatementReference(nodeOf(1), hash_a, hash_b); // update 1

    for (0..62) |_| try s.replaceStatementReference(nodeOf(1), hash_b, hash_b);
    try std.testing.expect(s.inGraph(nodeOf(2)) and s.inGraph(nodeOf(3)));

    try s.replaceStatementReference(nodeOf(1), hash_b, hash_b); // update 64
    try std.testing.expect(!s.inGraph(nodeOf(2)));
    try std.testing.expect(s.inGraph(nodeOf(3)));
}

test "graph: only a verified conservative member can advance the pre-park checkpoint" {
    const gpa = std.testing.allocator;
    var s = Store.init(gpa, 4);
    defer s.deinit();

    var local = try flatOwned(gpa, 1, &.{1});
    defer local.deinit(gpa);
    try s.addToGraph(&local);

    const branch_a = try flatOwned(gpa, 1, &.{2});
    const hash_a = try qset.hashNormalized(gpa, &branch_a);
    try s.insert(hash_a, branch_a);
    const branch_b = try flatOwned(gpa, 1, &.{3});
    const hash_b = try qset.hashNormalized(gpa, &branch_b);
    try s.insert(hash_b, branch_b);
    try s.replaceStatementReference(nodeOf(1), null, hash_a);
    try s.replaceStatementReference(nodeOf(1), hash_a, hash_b); // update 1

    // A signer outside even the conservative graph cannot force checkpoint
    // work, no matter how many valid signatures it can produce.
    for (0..100) |_| try std.testing.expect(!try s.recheckBeforeParking(nodeOf(9)));
    try std.testing.expectEqual(@as(u8, 1), s.deferred_reference_updates);

    // A formerly reachable signer can consume only the remaining grace
    // updates before an exact rebuild filters it again.
    for (0..62) |_| try std.testing.expect(try s.recheckBeforeParking(nodeOf(2)));
    try std.testing.expectEqual(@as(u8, 63), s.deferred_reference_updates);
    try std.testing.expect(!try s.recheckBeforeParking(nodeOf(2)));
    try std.testing.expectEqual(@as(u8, 0), s.deferred_reference_updates);
}

test "graph: removing an unreachable source edge does not open a generation" {
    const gpa = std.testing.allocator;
    var s = Store.init(gpa, 4);
    defer s.deinit();

    var local = try flatOwned(gpa, 1, &.{1});
    defer local.deinit(gpa);
    try s.addToGraph(&local);

    const old = try flatOwned(gpa, 1, &.{9});
    const old_hash = try qset.hashNormalized(gpa, &old);
    try s.insert(old_hash, old);
    const replacement = try flatOwned(gpa, 1, &.{10});
    const replacement_hash = try qset.hashNormalized(gpa, &replacement);
    try s.insert(replacement_hash, replacement);

    try s.replaceStatementReference(nodeOf(8), null, old_hash);
    try s.replaceStatementReference(nodeOf(8), old_hash, replacement_hash);

    try std.testing.expectEqual(@as(u8, 0), s.deferred_reference_updates);
    try std.testing.expect(!s.inGraph(nodeOf(8)));
    try std.testing.expect(!s.inGraph(nodeOf(9)));
    try std.testing.expect(!s.inGraph(nodeOf(10)));
}

test "graph: one generation adds at most 64 retired qset validator lists" {
    const gpa = std.testing.allocator;
    var s = Store.init(gpa, 70);
    defer s.deinit();

    try std.testing.expectEqual(@as(usize, 16_320), max_retired_qset_nodes_per_generation);
    var local = try flatOwned(gpa, 1, &.{1});
    defer local.deinit(gpa);
    try s.addToGraph(&local);

    const first = try flatOwned(gpa, 1, &.{2});
    var current_hash = try qset.hashNormalized(gpa, &first);
    try s.insert(current_hash, first);
    try s.replaceStatementReference(nodeOf(1), null, current_hash);

    for (0..graph_checkpoint_updates) |i| {
        const validator: u8 = @intCast(i + 3);
        const replacement = try flatOwned(gpa, 1, &.{validator});
        const replacement_hash = try qset.hashNormalized(gpa, &replacement);
        try s.insert(replacement_hash, replacement);
        try s.replaceStatementReference(nodeOf(1), current_hash, replacement_hash);
        current_hash = replacement_hash;

        if (i + 1 < graph_checkpoint_updates) {
            // One root plus the current and at most 63 retired one-node sets.
            try std.testing.expect(s.graph.count() <= graph_checkpoint_updates + 1);
        }
    }

    // The checkpoint collapses the union back to root + current validator.
    try std.testing.expectEqual(@as(usize, 2), s.graph.count());
    try std.testing.expect(s.inGraph(nodeOf(66)));
}

test "graph: a reference batch publishes one exact post-replay graph" {
    const gpa = std.testing.allocator;
    var s = Store.init(gpa, 8);
    defer s.deinit();

    var local = try flatOwned(gpa, 2, &.{ 1, 2 });
    defer local.deinit(gpa);
    try s.addToGraph(&local);

    const old_left = try flatOwned(gpa, 1, &.{3});
    const old_left_hash = try qset.hashNormalized(gpa, &old_left);
    try s.insert(old_left_hash, old_left);
    const old_right = try flatOwned(gpa, 1, &.{4});
    const old_right_hash = try qset.hashNormalized(gpa, &old_right);
    try s.insert(old_right_hash, old_right);
    try s.replaceStatementReference(nodeOf(1), null, old_left_hash);
    try s.replaceStatementReference(nodeOf(2), null, old_right_hash);
    try std.testing.expect(s.inGraph(nodeOf(3)) and s.inGraph(nodeOf(4)));

    const new_left = try flatOwned(gpa, 1, &.{5});
    const new_left_hash = try qset.hashNormalized(gpa, &new_left);
    try s.insert(new_left_hash, new_left);
    const new_right = try flatOwned(gpa, 1, &.{6});
    const new_right_hash = try qset.hashNormalized(gpa, &new_right);
    try s.insert(new_right_hash, new_right);

    s.beginReferenceBatch();
    try s.replaceStatementReference(nodeOf(1), old_left_hash, new_left_hash);
    try s.replaceStatementReference(nodeOf(2), old_right_hash, new_right_hash);

    // No input can interleave with a synchronous replay batch. Removals stay
    // conservative, while additions are still visible so the published graph
    // never becomes a false-negative even within the batch.
    try std.testing.expect(s.inGraph(nodeOf(3)) and s.inGraph(nodeOf(4)));
    try std.testing.expect(s.inGraph(nodeOf(5)) and s.inGraph(nodeOf(6)));
    try s.finishReferenceBatch();

    try std.testing.expect(!s.inGraph(nodeOf(3)) and !s.inGraph(nodeOf(4)));
    try std.testing.expect(s.inGraph(nodeOf(5)) and s.inGraph(nodeOf(6)));
}

test "graph: a reference batch checkpoints an already-open generation" {
    const gpa = std.testing.allocator;
    var s = Store.init(gpa, 4);
    defer s.deinit();

    var local = try flatOwned(gpa, 1, &.{1});
    defer local.deinit(gpa);
    try s.addToGraph(&local);

    const old = try flatOwned(gpa, 1, &.{2});
    const old_hash = try qset.hashNormalized(gpa, &old);
    try s.insert(old_hash, old);
    const replacement = try flatOwned(gpa, 1, &.{3});
    const replacement_hash = try qset.hashNormalized(gpa, &replacement);
    try s.insert(replacement_hash, replacement);
    try s.replaceStatementReference(nodeOf(1), null, old_hash);
    try s.replaceStatementReference(nodeOf(1), old_hash, replacement_hash);
    try std.testing.expect(s.inGraph(nodeOf(2)));

    // Even when this batch has no additional edge mutation, finishing it is
    // an exact publication boundary for the generation already in flight.
    s.beginReferenceBatch();
    try s.removeStatementReferences(&.{});
    try s.finishReferenceBatch();

    try std.testing.expect(!s.inGraph(nodeOf(2)));
    try std.testing.expect(s.inGraph(nodeOf(3)));
    try std.testing.expectEqual(@as(u8, 0), s.deferred_reference_updates);
}

test "graph: a failed exact checkpoint saturates its generation counter" {
    const gpa = std.testing.allocator;
    var s = Store.init(gpa, 1);
    defer s.deinit();

    var local = try flatOwned(gpa, 1, &.{1});
    defer local.deinit(gpa);
    try s.addToGraph(&local);
    s.deferred_reference_updates = graph_checkpoint_updates - 1;

    // Once exact publication is due, every retry attempts that publication
    // directly. Repeated OOM cannot wrap the compact generation counter.
    var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
    s.gpa = failing.allocator();
    defer s.gpa = gpa;
    try std.testing.expectError(error.OutOfMemory, s.recheckBeforeParking(nodeOf(1)));
    try std.testing.expectEqual(graph_checkpoint_updates, s.deferred_reference_updates);
    try std.testing.expectError(error.OutOfMemory, s.recheckBeforeParking(nodeOf(1)));
    try std.testing.expectEqual(graph_checkpoint_updates, s.deferred_reference_updates);
}

fn exerciseReferenceLifecycleUnderAllocationFailure(gpa: std.mem.Allocator) !void {
    var s = Store.init(gpa, 4);
    defer s.deinit();

    var local = try flatOwned(gpa, 1, &.{1});
    defer local.deinit(gpa);
    try s.addToGraph(&local);

    var first = try flatOwned(gpa, 1, &.{2});
    const first_hash = qset.hashNormalized(gpa, &first) catch |err| {
        first.deinit(gpa);
        return err;
    };
    try s.insert(first_hash, first);
    try s.replaceStatementReference(nodeOf(1), null, first_hash);

    var second = try flatOwned(gpa, 1, &.{3});
    const second_hash = qset.hashNormalized(gpa, &second) catch |err| {
        second.deinit(gpa);
        return err;
    };
    try s.insert(second_hash, second);
    s.beginReferenceBatch();
    try s.replaceStatementReference(nodeOf(1), first_hash, second_hash);
    try s.finishReferenceBatch();

    var third = try flatOwned(gpa, 1, &.{4});
    const third_hash = qset.hashNormalized(gpa, &third) catch |err| {
        third.deinit(gpa);
        return err;
    };
    try s.insert(third_hash, third);
    try s.replaceStatementReference(nodeOf(1), second_hash, third_hash);
    for (0..graph_checkpoint_updates - 1) |_| {
        try s.replaceStatementReference(nodeOf(1), third_hash, third_hash);
    }
    try s.removeStatementReferences(&.{.{ .node = nodeOf(1), .hash = third_hash }});
}

test "store: replacement checkpoints and removal leak nothing on allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        exerciseReferenceLifecycleUnderAllocationFailure,
        .{},
    );
}
