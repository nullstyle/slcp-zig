//! Federated-voting primitives over node sets (design §5.4 `slot.zig`).
//!
//! Line-level transcription of the quorum/v-blocking composition in
//! stellar-core's Slot::federatedAccept / Slot::federatedRatify
//! (stellar-core/src/scp/Slot.cpp:409-436 and 438-445). The oracle phrases
//! both over statement predicates evaluated against the latest-envelope map;
//! here they are phrased over the resulting NODE SETS — M2's per-slot state
//! (NominationState + BallotState + latest_envelopes) and its statement
//! predicates layer on top of these functions, mapping each predicate to the
//! set of nodes whose latest statement satisfies it.
//!
//! The freshness partial orders of §5.4's slot.zig bullet (nomination
//! superset-growth, ballot PREPARE < CONFIRM < EXTERNALIZE ordering) live in
//! statement.zig, not here.
//!
//! Contract for all `[]const NodeId` arguments: an unsorted small SET — no
//! duplicate entries (the local_node.zig contract). `federatedAccept` builds
//! the voted∪accepted union itself, deduplicating across the two inputs.

const std = @import("std");
const qset = @import("qset.zig");
const local_node = @import("local_node.zig");

pub const NodeId = qset.NodeId;

fn contains(nodes: []const NodeId, node: NodeId) bool {
    for (nodes) |*n| {
        if (std.mem.eql(u8, n, &node)) return true;
    }
    return false;
}

/// voted ∪ accepted with cross-input duplicates dropped (each input is
/// already duplicate-free per the set contract). Caller frees.
fn unionNodes(gpa: std.mem.Allocator, voted: []const NodeId, accepted: []const NodeId) ![]NodeId {
    var out = try gpa.alloc(NodeId, voted.len + accepted.len);
    errdefer gpa.free(out);
    @memcpy(out[0..accepted.len], accepted);
    var len: usize = accepted.len;
    for (voted) |v| {
        if (!contains(accepted, v)) {
            out[len] = v;
            len += 1;
        }
    }
    return gpa.realloc(out, len);
}

/// Can the local node ACCEPT a statement, given the set of nodes seen voting
/// for it and the set seen accepting it? Transcribed from
/// Slot::federatedAccept (Slot.cpp:409-436):
///   1. accepted is v-blocking for the local qset (Slot.cpp:414-417) — pure
///      local-qset structure, no advertised-qset lookup involved; OR
///   2. voted ∪ accepted is a quorum (the oracle's `ratifyFilter` =
///      `accepted(st) || voted(st)`, Slot.cpp:421-433) — runs the isQuorum
///      fixpoint over advertised qsets via `lookup`.
pub fn federatedAccept(
    gpa: std.mem.Allocator,
    local_qset: *const qset.QuorumSetOwned,
    voted: []const NodeId,
    accepted: []const NodeId,
    lookup: local_node.QSetLookup,
) !bool {
    // Checks if the nodes that claimed to accept the statement form a
    // v-blocking set (Slot.cpp:412-417).
    if (local_node.isVBlocking(local_qset, accepted)) {
        return true;
    }

    // Checks if the set of nodes that accepted or voted for it form a quorum
    // (Slot.cpp:419-433).
    const un = try unionNodes(gpa, voted, accepted);
    defer gpa.free(un);
    return local_node.isQuorum(gpa, local_qset, un, lookup);
}

/// Can the local node RATIFY (confirm) a statement, given the set of nodes
/// seen accepting it? Transcribed from Slot::federatedRatify
/// (Slot.cpp:438-445): isQuorum over that set alone.
pub fn federatedRatify(
    gpa: std.mem.Allocator,
    local_qset: *const qset.QuorumSetOwned,
    accepted: []const NodeId,
    lookup: local_node.QSetLookup,
) !bool {
    return local_node.isQuorum(gpa, local_qset, accepted, lookup);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn nid(byte: u8) NodeId {
    return @splat(byte);
}

/// Test-only qset built over borrowed slices (no allocator, no deinit).
fn flatQs(threshold: u32, validators: []NodeId) qset.QuorumSetOwned {
    return .{ .threshold = threshold, .validators = validators, .inner_sets = &.{} };
}

const TestLookup = struct {
    const Entry = struct { id: NodeId, qs: *const qset.QuorumSetOwned };
    entries: []const Entry,

    fn get(ctx: *const anyopaque, node: NodeId) ?*const qset.QuorumSetOwned {
        const self: *const TestLookup = @alignCast(@ptrCast(ctx));
        for (self.entries) |e| {
            if (std.mem.eql(u8, &e.id, &node)) return e.qs;
        }
        return null;
    }

    fn lookup(self: *const TestLookup) local_node.QSetLookup {
        return .{ .ctx = self, .get = get };
    }
};

/// Lookup with no entries: every advertised qset is unknown.
const empty_lookup = TestLookup{ .entries = &.{} };

test "federatedAccept: v-blocking arm alone (no advertised qsets needed)" {
    const gpa = testing.allocator;
    var vals = [_]NodeId{ nid(1), nid(2), nid(3) };
    const two_of_three = flatQs(2, &vals);

    // 2-of-3: any 2 members are v-blocking (n - t + 1 = 2). The v-blocking
    // arm is pure local-qset structure — an EMPTY lookup proves no advertised
    // qset is consulted on this path.
    try testing.expect(try federatedAccept(
        gpa,
        &two_of_three,
        &.{},
        &.{ nid(1), nid(3) },
        empty_lookup.lookup(),
    ));

    // A single accepter is not v-blocking, and with every advertised qset
    // unknown the quorum arm collapses to the empty fixpoint → false.
    try testing.expect(!try federatedAccept(
        gpa,
        &two_of_three,
        &.{},
        &.{nid(1)},
        empty_lookup.lookup(),
    ));
}

test "federatedAccept: quorum arm alone via voted-only nodes" {
    const gpa = testing.allocator;
    var vals = [_]NodeId{ nid(1), nid(2), nid(3) };
    const two_of_three = flatQs(2, &vals);

    // One accepter (not v-blocking) + one voter, both advertising 2-of-3:
    // {1, 2} survives the fixpoint and satisfies the local 2-of-3 → accept
    // through the quorum arm.
    const tl = TestLookup{ .entries = &.{
        .{ .id = nid(1), .qs = &two_of_three },
        .{ .id = nid(2), .qs = &two_of_three },
    } };
    try testing.expect(try federatedAccept(
        gpa,
        &two_of_three,
        &.{nid(2)},
        &.{nid(1)},
        tl.lookup(),
    ));

    // Purely voted nodes (no accepter at all) can also carry the quorum arm.
    try testing.expect(try federatedAccept(
        gpa,
        &two_of_three,
        &.{ nid(1), nid(2) },
        &.{},
        tl.lookup(),
    ));
}

test "federatedAccept: neither arm fires" {
    const gpa = testing.allocator;
    var vals = [_]NodeId{ nid(1), nid(2), nid(3) };
    const two_of_three = flatQs(2, &vals);

    const tl = TestLookup{ .entries = &.{
        .{ .id = nid(1), .qs = &two_of_three },
        .{ .id = nid(2), .qs = &two_of_three },
        .{ .id = nid(3), .qs = &two_of_three },
    } };

    // One accepter, no voters: not v-blocking, and {1} alone satisfies no
    // 2-of-3 slice → false.
    try testing.expect(!try federatedAccept(
        gpa,
        &two_of_three,
        &.{},
        &.{nid(1)},
        tl.lookup(),
    ));

    // Nobody at all.
    try testing.expect(!try federatedAccept(gpa, &two_of_three, &.{}, &.{}, tl.lookup()));

    // An outsider voting contributes to neither arm.
    try testing.expect(!try federatedAccept(
        gpa,
        &two_of_three,
        &.{nid(9)},
        &.{nid(1)},
        tl.lookup(),
    ));
}

test "federatedAccept: union dedup — node in both voted and accepted counted once" {
    const gpa = testing.allocator;
    var vals = [_]NodeId{ nid(1), nid(2), nid(3) };
    const two_of_three = flatQs(2, &vals);
    const three_of_three = flatQs(3, &vals);

    // Direct check on the union builder: overlap collapses.
    const un = try unionNodes(gpa, &.{ nid(1), nid(2) }, &.{ nid(2), nid(3) });
    defer gpa.free(un);
    try testing.expectEqual(@as(usize, 3), un.len);
    try testing.expect(contains(un, nid(1)));
    try testing.expect(contains(un, nid(2)));
    try testing.expect(contains(un, nid(3)));

    // Behavioral: node 1 votes AND accepts against a local 3-of-3 (so a lone
    // accepter is v-blocking only with... n - t + 1 = 1 — pick 2-of-3 local
    // to keep the v-blocking arm cold) with everyone advertising 3-of-3. The
    // union {1, 2} must NOT double-count node 1 into a 3-node quorum.
    const tl3 = TestLookup{ .entries = &.{
        .{ .id = nid(1), .qs = &three_of_three },
        .{ .id = nid(2), .qs = &three_of_three },
    } };
    try testing.expect(!try federatedAccept(
        gpa,
        &two_of_three,
        &.{ nid(1), nid(2) },
        &.{nid(1)},
        tl3.lookup(),
    ));

    // Same overlap with a genuine 3-node union does ratify a 3-of-3 quorum.
    const tl3_full = TestLookup{ .entries = &.{
        .{ .id = nid(1), .qs = &three_of_three },
        .{ .id = nid(2), .qs = &three_of_three },
        .{ .id = nid(3), .qs = &three_of_three },
    } };
    try testing.expect(try federatedAccept(
        gpa,
        &three_of_three,
        &.{ nid(1), nid(2), nid(3) },
        &.{nid(1)},
        tl3_full.lookup(),
    ));
}

test "federatedAccept: missing advertised qset drops node from quorum arm; v-blocking arm unaffected" {
    const gpa = testing.allocator;
    var vals = [_]NodeId{ nid(1), nid(2), nid(3) };
    const two_of_three = flatQs(2, &vals);

    // Node 2's advertised qset is unknown: the quorum-arm fixpoint drops it,
    // {1} alone is no quorum, and one accepter is not v-blocking → false.
    const tl_partial = TestLookup{ .entries = &.{
        .{ .id = nid(1), .qs = &two_of_three },
    } };
    try testing.expect(!try federatedAccept(
        gpa,
        &two_of_three,
        &.{nid(2)},
        &.{nid(1)},
        tl_partial.lookup(),
    ));

    // Same lookup, but two accepters: the v-blocking arm needs no advertised
    // qsets and still accepts.
    try testing.expect(try federatedAccept(
        gpa,
        &two_of_three,
        &.{},
        &.{ nid(1), nid(2) },
        tl_partial.lookup(),
    ));
}

test "federatedRatify: quorum over accepted alone" {
    const gpa = testing.allocator;
    var vals = [_]NodeId{ nid(1), nid(2), nid(3) };
    const two_of_three = flatQs(2, &vals);

    const tl = TestLookup{ .entries = &.{
        .{ .id = nid(1), .qs = &two_of_three },
        .{ .id = nid(2), .qs = &two_of_three },
        .{ .id = nid(3), .qs = &two_of_three },
    } };

    // {1, 2} satisfies everyone's 2-of-3 and the local 2-of-3 → ratified.
    try testing.expect(try federatedRatify(gpa, &two_of_three, &.{ nid(1), nid(2) }, tl.lookup()));

    // A single accepter is v-blocking for 2-of-3 — but ratify has NO
    // v-blocking arm, so it stays false.
    try testing.expect(!try federatedRatify(gpa, &two_of_three, &.{nid(1)}, tl.lookup()));

    // Empty set never ratifies.
    try testing.expect(!try federatedRatify(gpa, &two_of_three, &.{}, tl.lookup()));

    // Missing advertised qset: node 2 is dropped by the fixpoint, {1} alone
    // is no quorum.
    const tl_partial = TestLookup{ .entries = &.{
        .{ .id = nid(1), .qs = &two_of_three },
    } };
    try testing.expect(!try federatedRatify(
        gpa,
        &two_of_three,
        &.{ nid(1), nid(2) },
        tl_partial.lookup(),
    ));
}

// ---------------------------------------------------------------------------
// M2: the per-slot container (design §5.4 slot.zig bullet): nomination +
// ballot state plus the latest_envelopes maps (one latest statement per node
// per protocol — engine freshness IS the relay dedup, §5.3). Protocol logic
// lives in nomination.zig / ballot.zig; the envelope pipeline dispatches.
// ---------------------------------------------------------------------------

const ballot_mod = @import("ballot.zig");
const nomination_mod = @import("nomination.zig");
const stored = @import("stored.zig");
const values_mod = @import("values.zig");

pub const Slot = struct {
    index: u64,
    nom: nomination_mod.State = .{},
    ballot: ballot_mod.State = .{},
    /// Latest stored envelope per node, per protocol (freshness-gated).
    /// Values are BOXED for pointer stability: protocol dispatch can
    /// self-store into these maps while callers hold a `latestFor` pointer,
    /// and an inline-value rehash would dangle it (engine bug #1, found by
    /// the M2 simulator at n>=6). Replacement reuses the box, so a held
    /// pointer stays valid across updates too.
    latest_nom: std.AutoHashMapUnmanaged([32]u8, *stored.StoredEnvelope) = .empty,
    latest_ballot: std.AutoHashMapUnmanaged([32]u8, *stored.StoredEnvelope) = .empty,
    /// Own last-emitted envelopes (persist/rebroadcast source).
    own_nom: ?stored.StoredEnvelope = null,
    own_ballot: ?stored.StoredEnvelope = null,
    /// §5.4: peers' maybe_valid statements mark the slot not fully validated
    /// and suppress own emissions (watchers/laggers run passively).
    fully_validated: bool = true,
    externalized_value: ?[]u8 = null,
    /// Per-slot driver-verdict cache (§5.4 values.zig bullet).
    validation_cache: values_mod.ValidationCache = .{},

    pub fn init(index: u64) Slot {
        return .{ .index = index };
    }

    pub fn deinit(self: *Slot, gpa: std.mem.Allocator) void {
        self.nom.deinit(gpa);
        self.ballot.deinit(gpa);
        inline for (.{ &self.latest_nom, &self.latest_ballot }) |map| {
            var it = map.valueIterator();
            while (it.next()) |boxed| {
                boxed.*.deinit(gpa);
                gpa.destroy(boxed.*);
            }
            map.deinit(gpa);
        }
        if (self.own_nom) |*e| e.deinit(gpa);
        if (self.own_ballot) |*e| e.deinit(gpa);
        if (self.externalized_value) |v| gpa.free(v);
        self.validation_cache.deinit(gpa);
        self.* = undefined;
    }

    /// Total stored envelope bytes in this slot (for the engine-wide
    /// max_stored_statement_bytes budget, §5.1).
    pub fn storedBytes(self: *const Slot) usize {
        var total: usize = 0;
        inline for (.{ &self.latest_nom, &self.latest_ballot }) |map| {
            var it = map.valueIterator();
            while (it.next()) |boxed| total += boxed.*.byteSize();
        }
        return total;
    }

    /// Replace the stored latest envelope for (node, protocol), returning
    /// the byte-size delta (new - old). Takes ownership of `env`.
    pub fn storeLatest(self: *Slot, gpa: std.mem.Allocator, env: stored.StoredEnvelope) !isize {
        var owned = env;
        const map = if (owned.statement.isNomination()) &self.latest_nom else &self.latest_ballot;
        const new_size: isize = @intCast(owned.byteSize());
        const gop = map.getOrPut(gpa, owned.statement.node_id) catch |err| {
            owned.deinit(gpa);
            return err;
        };
        if (gop.found_existing) {
            // Reuse the box: held pointers stay valid across replacement.
            const old_size: isize = @intCast(gop.value_ptr.*.byteSize());
            gop.value_ptr.*.deinit(gpa);
            gop.value_ptr.*.* = owned;
            return new_size - old_size;
        }
        const boxed = gpa.create(stored.StoredEnvelope) catch |err| {
            map.removeByPtr(gop.key_ptr);
            owned.deinit(gpa);
            return err;
        };
        boxed.* = owned;
        gop.value_ptr.* = boxed;
        return new_size;
    }

    pub fn latestFor(self: *Slot, node: [32]u8, nomination_protocol: bool) ?*stored.StoredEnvelope {
        const map = if (nomination_protocol) &self.latest_nom else &self.latest_ballot;
        return map.get(node);
    }
};
