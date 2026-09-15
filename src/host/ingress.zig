//! Transport-neutral ingress support for hosts of the sans-io Engine.
//!
//! A host owns the ordered application frontier and supplies complete framed
//! Envelope bytes from its transport. Serialize buffer operations with Engine
//! inputs; feed one input and drain every effect before releasing more work.
//! Metadata decoding is bounded inspection, not the Engine's full validation.
//! The host still enforces its purge floor, authenticates transport peers,
//! and provides retransmission for bounded admission drops.
//!
//! Experimental. Native Node and foreign single-thread hosts share this
//! implementation; it imports no sockets, clocks, storage, or QUIC runtime.

const std = @import("std");
const builtin = @import("builtin");
const capnpc = @import("capnpc-zig");
const engine = @import("../engine/engine.zig");
const crypto = @import("../crypto.zig");
const qset = @import("../engine/qset.zig");
const gen_slcp = @import("../gen/slcp.zig");
const canonical = @import("../canonical.zig");
const limits = @import("../engine/limits.zig");
const host_codec = @import("../engine/host_codec.zig");
const local_node = @import("../engine/local_node.zig");

// Threaded native hosts retain the exact std.atomic.Value field types.
// In a single-threaded build, including wasm32-freestanding, observations
// share the host's serialized ownership and need no atomic instructions.
// wasm32 without the atomics feature cannot lower a 64-bit atomic fetchAdd.
fn ObservationCounter(comptime T: type) type {
    if (!builtin.single_threaded) return std.atomic.Value(T);
    return struct {
        const Self = @This();
        raw: T,

        pub fn init(value: T) Self {
            return .{ .raw = value };
        }

        pub fn load(self: *const Self, comptime order: std.builtin.AtomicOrder) T {
            _ = order;
            return self.raw;
        }

        pub fn store(self: *Self, value: T, comptime order: std.builtin.AtomicOrder) void {
            _ = order;
            self.raw = value;
        }

        pub fn fetchAdd(self: *Self, value: T, comptime order: std.builtin.AtomicOrder) T {
            _ = order;
            const previous = self.raw;
            self.raw +%= value;
            return previous;
        }
    };
}

/// An owned engine input and an optional opaque host route token. The token
/// can index a TCP peer or a QUIC connection; it is not a socket or identity.
/// `HoldBuffer.admit` takes ownership except when it returns `.fed`.
pub const InputItem = struct {
    input: engine.Input,
    source_peer: ?usize,
};

/// Host-side per-slot hold buffer (S8 D1, the stellar-core Herder shape —
/// `processSCPQueueUpToIndex(lcl + 1)` with `PendingEnvelopes` for later
/// slots). Inbound statements — NOMINATE / PREPARE / CONFIRM **and
/// EXTERNALIZE** — for slots beyond the next delivery slot are parked
/// here and fed to the engine once the host applies their preceding slot.
/// The `frontier` argument is that next delivery slot (`last_applied + 1`),
/// so for a typed app `apply(N)` has always run
/// before any `validate` for N + 1 and the engine's per-slot verdict cache
/// can never be filled with a `.maybe_valid`-because-behind verdict that
/// then mutes the node for that slot forever (the mute-node halt: n − t + 1
/// such nodes halt the network; the S8b skeptic showed a lone peer's
/// EXTERNALIZE(N + 1) does it just as well as a NOMINATE).
///
/// Catch-up (`admit` → `.ready`): a held slot is released ahead of the
/// frontier as soon as its held EXTERNALIZE statements come from a
/// **v-blocking set** of the local quorum set — SCP's own accept condition,
/// applied host-side. Under the FBAS assumption a v-blocking set contains an
/// honest node, so the network finished that slot and this node's vote on
/// it can never be needed: validating it against a stale state (and going
/// mute on it) is harmless, while feeding it lets the engine externalize
/// the slot from those statements alone and the delivery gap-jump (§10)
/// follow. A single signer — the case that halted — is never v-blocking.
/// Once released this way a slot is `open`: later statements for it pass
/// straight through (the engine already holds its EXTERNALIZEs; a third
/// signer's must not wait for the next re-flood).
///
/// The host serializes all buffer operations with its Engine calls; only
/// the observation counters are atomic in threaded builds. Single-threaded
/// builds also serialize observations and use plain counters. Bounded:
/// `window` slots ahead, `max_entries` / `max_bytes` in total, one entry
/// per (slot, signer, kind)
/// — every entry was signature-verified before it was stored, so a spoofed
/// node id cannot displace a genuine statement, and an honest sender's
/// re-floods replace rather than accumulate; only signers inside the
/// transitive quorum graph are held at all (a stranger goes straight to the
/// engine's §5.4 step-8 relevance filter, which `ignored`s it before any
/// state — so no stranger can occupy the buffer). Drops are never fatal:
/// the host must provide anti-entropy or retransmission to recover them.
pub const HoldBuffer = struct {
    /// Slots more than this far past the delivery frontier are dropped
    /// (counted `dropped_far`). Equals `Limits.max_live_slots`'s default:
    /// the engine would refuse to open more live slots anyway.
    pub const window: u64 = 64;
    /// Total caps, mirroring the engine's parking caps (§5.4).
    pub const max_entries: usize = 1024;
    pub const max_bytes: usize = 8 * 1024 * 1024;

    pub const Kind = enum(u8) { nominate, prepare, confirm, externalize };
    pub const Entry = struct { node_id: [32]u8, kind: Kind, item: InputItem };
    const List = std.ArrayList(Entry);
    pub const PutResult = enum { held, replaced, dropped_full };
    /// `admit`'s verdict. `.fed`: not consumed — the caller feeds the item
    /// now. `.ready`: held, and the slot's EXTERNALIZE signers are now
    /// v-blocking — the caller releases the whole slot (`takeSlot`). The
    /// rest consumed the item (held, or freed and counted).
    pub const Admit = enum { fed, held, ready, dropped_far, dropped_full, dropped_badsig };

    slots: std.AutoHashMapUnmanaged(u64, List) = .empty,
    /// Slots released ahead of the frontier on v-blocking EXTERNALIZE
    /// evidence: later statements for them pass straight through. Pruned
    /// below the frontier with the held slots (≤ `window` entries).
    open: std.AutoHashMapUnmanaged(u64, void) = .empty,
    count: usize = 0,
    bytes: usize = 0,
    /// Entries held right now (= `count`; reads may cross threads only in
    /// threaded builds, where the observation counters are atomic).
    held_now: ObservationCounter(usize) = ObservationCounter(usize).init(0),
    /// Entries handed to the engine at the frontier.
    released: ObservationCounter(u64) = ObservationCounter(u64).init(0),
    /// Entries handed to the engine AHEAD of the frontier (catch-up: the
    /// slot's EXTERNALIZE signers were v-blocking).
    released_early: ObservationCounter(u64) = ObservationCounter(u64).init(0),
    /// Statements for a slot above the frontier from a signer outside the
    /// quorum graph: fed, never held (the engine ignores them statelessly).
    fed_out_of_graph: ObservationCounter(u64) = ObservationCounter(u64).init(0),
    /// Drops: slot beyond `window`; caps hit; signature failed; slot fell
    /// below the frontier while held (delivered or gap-jumped past).
    dropped_far: ObservationCounter(u64) = ObservationCounter(u64).init(0),
    dropped_full: ObservationCounter(u64) = ObservationCounter(u64).init(0),
    dropped_badsig: ObservationCounter(u64) = ObservationCounter(u64).init(0),
    dropped_behind: ObservationCounter(u64) = ObservationCounter(u64).init(0),

    fn itemBytes(item: *const InputItem) usize {
        return switch (item.input) {
            .envelope_received => |a| a.bytes.len,
            else => 0,
        };
    }

    /// Free an entry's owned input (the frame bytes).
    pub fn freeEntry(gpa: std.mem.Allocator, e: *Entry) void {
        host_codec.freeInput(gpa, &e.item.input);
    }

    /// Hold `item` (ownership is taken on EVERY path, including the error
    /// one) for `slot`, keyed by (signer, kind): an existing entry for the
    /// same key is replaced — removed from its position, the newcomer
    /// appended, so a slot's list stays in arrival order of its survivors.
    /// A cap breach drops the INCOMING item (`.dropped_full`): no eviction,
    /// the nearest slots are the useful ones and the sender's next re-flood
    /// heals the drop.
    pub fn put(self: *HoldBuffer, gpa: std.mem.Allocator, slot: u64, node_id: [32]u8, kind: Kind, item: InputItem) std.mem.Allocator.Error!PutResult {
        var owned = item;
        const len = itemBytes(&owned);
        const gop = self.slots.getOrPut(gpa, slot) catch |e| {
            host_codec.freeInput(gpa, &owned.input);
            return e;
        };
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        const list = gop.value_ptr;
        var dup: ?usize = null;
        for (list.items, 0..) |*e, i| {
            if (e.kind == kind and std.mem.eql(u8, &e.node_id, &node_id)) {
                dup = i;
                break;
            }
        }
        // Caps are judged on the projected state (a replacement frees its
        // predecessor first), so a re-flood of an already-held statement
        // never trips them.
        const old_len: usize = if (dup) |i| itemBytes(&list.items[i].item) else 0;
        const projected_count = self.count + 1 - @as(usize, if (dup != null) 1 else 0);
        const projected_bytes = self.bytes + len - old_len;
        if (projected_count > max_entries or projected_bytes > max_bytes) {
            host_codec.freeInput(gpa, &owned.input);
            if (list.items.len == 0) self.removeEmpty(gpa, slot);
            _ = self.dropped_full.fetchAdd(1, .monotonic);
            return .dropped_full;
        }
        if (dup) |i| {
            var old = list.orderedRemove(i);
            self.count -= 1;
            self.bytes -= old_len;
            freeEntry(gpa, &old);
        }
        list.append(gpa, .{ .node_id = node_id, .kind = kind, .item = owned }) catch |e| {
            host_codec.freeInput(gpa, &owned.input);
            if (list.items.len == 0) self.removeEmpty(gpa, slot);
            self.held_now.store(self.count, .release);
            return e;
        };
        self.count += 1;
        self.bytes += len;
        self.held_now.store(self.count, .release);
        return if (dup != null) .replaced else .held;
    }

    fn removeEmpty(self: *HoldBuffer, gpa: std.mem.Allocator, slot: u64) void {
        if (self.slots.fetchRemove(slot)) |kv| {
            var l = kv.value;
            l.deinit(gpa);
        }
    }

    fn dropList(self: *HoldBuffer, gpa: std.mem.Allocator, list: *List) void {
        for (list.items) |*e| {
            self.count -= 1;
            self.bytes -= itemBytes(&e.item);
            freeEntry(gpa, e);
        }
        _ = self.dropped_behind.fetchAdd(list.items.len, .monotonic);
        list.deinit(gpa);
    }

    /// Frees every held slot BELOW `frontier` (statements for a slot this
    /// node already delivered or skipped are useless — `dropped_behind`)
    /// and forgets `open` slots below it.
    fn pruneBelow(self: *HoldBuffer, gpa: std.mem.Allocator, frontier: u64) void {
        while (true) {
            var doomed: ?u64 = null;
            var it = self.slots.keyIterator();
            while (it.next()) |k| {
                if (k.* < frontier) {
                    doomed = k.*;
                    break;
                }
            }
            const key = doomed orelse break;
            var kv = self.slots.fetchRemove(key).?;
            self.dropList(gpa, &kv.value);
        }
        while (true) {
            var doomed: ?u64 = null;
            var it = self.open.keyIterator();
            while (it.next()) |k| {
                if (k.* < frontier) {
                    doomed = k.*;
                    break;
                }
            }
            const key = doomed orelse break;
            _ = self.open.remove(key);
        }
        self.held_now.store(self.count, .release);
    }

    /// Remove and hand back the list held for `slot` (the caller owns the
    /// entries and the list), or null.
    pub fn takeSlot(self: *HoldBuffer, slot: u64) ?List {
        const kv = self.slots.fetchRemove(slot) orelse return null;
        for (kv.value.items) |*e| {
            self.count -= 1;
            self.bytes -= itemBytes(&e.item);
        }
        self.held_now.store(self.count, .release);
        return kv.value;
    }

    /// Frees every held slot BELOW `frontier` (see `pruneBelow`), then
    /// hands back the list for slot == `frontier` (exactly lcl + 1, Herder
    /// shape; the caller owns the entries and the list) or null. Nothing
    /// held is ever returned for a slot below the frontier.
    pub fn takeReleasable(self: *HoldBuffer, gpa: std.mem.Allocator, frontier: u64) ?List {
        self.pruneBelow(gpa, frontier);
        return self.takeSlot(frontier);
    }

    /// Do the EXTERNALIZE statements held for `slot` come from a v-blocking
    /// set of `qs` (the local quorum set)? OOM ⇒ false (the next EXTERNALIZE
    /// for the slot re-asks).
    pub fn extSignersVBlocking(self: *const HoldBuffer, gpa: std.mem.Allocator, slot: u64, qs: *const qset.QuorumSetOwned) bool {
        const list = self.slots.getPtr(slot) orelse return false;
        const ids = gpa.alloc([32]u8, list.items.len) catch return false;
        defer gpa.free(ids);
        var n: usize = 0;
        for (list.items) |*e| {
            if (e.kind != .externalize) continue;
            ids[n] = e.node_id;
            n += 1;
        }
        return n > 0 and local_node.isVBlocking(qs, ids[0..n]);
    }

    /// The gate for one inbound envelope whose `meta` decoded, given the
    /// delivery frontier (`next_deliver`), whether the signer is inside the
    /// transitive quorum graph, and the local quorum set. Ownership of
    /// `item` is taken on every path except `.fed`. Rules, in order:
    /// a statement for the frontier slot or anything behind it, from a
    /// signer outside the graph, or for an `open` slot is fed now; a slot
    /// more than `window` past the frontier is dropped; a bad signature is
    /// dropped (a forged signer must not occupy or displace a genuine
    /// entry); otherwise held — and if it is an EXTERNALIZE that completes
    /// a v-blocking set for its slot, the slot becomes `open` and `.ready`.
    pub fn admit(self: *HoldBuffer, gpa: std.mem.Allocator, meta: *const Meta, frontier: u64, in_graph: bool, qs: *const qset.QuorumSetOwned, item: InputItem) Admit {
        var owned = item;
        if (meta.slot <= frontier or self.open.contains(meta.slot)) return .fed;
        if (!in_graph) {
            _ = self.fed_out_of_graph.fetchAdd(1, .monotonic);
            return .fed;
        }
        if (meta.slot - frontier > window) {
            host_codec.freeInput(gpa, &owned.input);
            _ = self.dropped_far.fetchAdd(1, .monotonic);
            return .dropped_far;
        }
        if (!crypto.verify(meta.node_id, meta.digest, meta.signature)) {
            host_codec.freeInput(gpa, &owned.input);
            _ = self.dropped_badsig.fetchAdd(1, .monotonic);
            return .dropped_badsig;
        }
        const r = self.put(gpa, meta.slot, meta.node_id, meta.kind, owned) catch {
            // OOM: `put` freed the item; count it with the cap drops.
            _ = self.dropped_full.fetchAdd(1, .monotonic);
            return .dropped_full;
        };
        if (r == .dropped_full) return .dropped_full;
        if (meta.kind == .externalize and self.extSignersVBlocking(gpa, meta.slot, qs)) {
            // Best effort: without the mark a later statement for the slot
            // is held again and the next v-blocking EXTERNALIZE re-releases.
            self.open.put(gpa, meta.slot, {}) catch {};
            return .ready;
        }
        return .held;
    }

    pub fn deinit(self: *HoldBuffer, gpa: std.mem.Allocator) void {
        var it = self.slots.valueIterator();
        while (it.next()) |list| {
            for (list.items) |*e| freeEntry(gpa, e);
            list.deinit(gpa);
        }
        self.slots.deinit(gpa);
        self.open.deinit(gpa);
        self.count = 0;
        self.bytes = 0;
        self.held_now.store(0, .release);
    }
};

/// What the hold gate needs to know about a framed Envelope, decoded with
/// the pipeline's validating options (nesting 32, traversal scaled to the
/// frame / statement caps). `digest` is the signed preimage so the gate can
/// verify BEFORE holding (a spoofed signer must not displace a genuine
/// entry); the engine re-verifies whatever it is eventually fed.
pub const Meta = struct {
    slot: u64,
    node_id: [32]u8,
    kind: HoldBuffer.Kind,
    digest: [32]u8,
    signature: [64]u8,
};

pub fn envelopeMeta(gpa: std.mem.Allocator, network_id: [32]u8, framed_env: []const u8) !Meta {
    if (framed_env.len > limits.frozen_max_frame_bytes) return error.FrameTooLarge;
    var emsg = try capnpc.message.Message.init(gpa, framed_env, .{
        .nesting_limit = 32,
        .traversal_limit_words = limits.frozen_max_frame_bytes / 8,
    });
    defer emsg.deinit();
    const er = try gen_slcp.Envelope.Reader.init(&emsg);
    const stmt_bytes = try er.getStatementBytes();
    if (stmt_bytes.len == 0 or stmt_bytes.len > limits.frozen_max_statement_bytes) return error.BadStatementLength;
    const sig = try er.getSignature();
    if (sig.len != 64) return error.BadSignatureLength;
    var smsg = try canonical.decodeFlat(gpa, stmt_bytes, .{
        .nesting_limit = 32,
        .traversal_limit_words = limits.frozen_max_statement_bytes / 8,
    });
    defer smsg.deinit();
    const sr = try gen_slcp.Statement.Reader.init(&smsg);
    const nid = try sr.getNodeId();
    if (nid.len != 32) return error.BadNodeIdLength;
    const kind: HoldBuffer.Kind = switch (try sr.getPledges().which()) {
        .nominate => .nominate,
        .prepare => .prepare,
        .confirm => .confirm,
        .externalize => .externalize,
        .unset => return error.UnsetPledges,
    };
    return .{
        .slot = try sr.getSlotIndex(),
        .node_id = nid[0..32].*,
        .kind = kind,
        .digest = crypto.statementDigest(network_id, stmt_bytes),
        .signature = sig[0..64].*,
    };
}

fn holdItem(gpa: std.mem.Allocator, payload: []const u8) !InputItem {
    return .{ .input = .{ .envelope_received = .{ .bytes = try gpa.dupe(u8, payload) } }, .source_peer = null };
}

fn heldBytes(e: *const HoldBuffer.Entry) []const u8 {
    return e.item.input.envelope_received.bytes;
}

// Non-vacuity: dropping the (node_id, kind) dedup scan in `put` makes the
// second A-nominate a `.held` (count 2, and the released order shows two
// A-nominates); appending in place instead of remove + append breaks the
// `{b, p, a3}` order; judging the caps on `count` before subtracting the
// replaced entry makes the 1024-entry replacement a `.dropped_full`;
// skipping the below-frontier sweep in `takeReleasable` leaves slots 2 and
// 3 held (count 3, dropped_behind 0); a missing `deinit` free is reported
// by the testing allocator.
test "HoldBuffer: dedup per (signer, kind) replaces and re-appends; caps drop the newcomer; takeReleasable frees below the frontier and hands back exactly the frontier slot" {
    const gpa = std.testing.allocator;
    var hb: HoldBuffer = .{};
    defer hb.deinit(gpa);
    const a: [32]u8 = @splat(0xa1);
    const b: [32]u8 = @splat(0xb2);

    try std.testing.expectEqual(HoldBuffer.PutResult.held, try hb.put(gpa, 5, a, .nominate, try holdItem(gpa, "a1")));
    try std.testing.expectEqual(HoldBuffer.PutResult.replaced, try hb.put(gpa, 5, a, .nominate, try holdItem(gpa, "a2")));
    try std.testing.expectEqual(HoldBuffer.PutResult.held, try hb.put(gpa, 5, b, .nominate, try holdItem(gpa, "b")));
    try std.testing.expectEqual(HoldBuffer.PutResult.held, try hb.put(gpa, 5, a, .prepare, try holdItem(gpa, "p")));
    try std.testing.expectEqual(@as(usize, 3), hb.count);
    try std.testing.expectEqual(@as(usize, 3), hb.held_now.load(.acquire));
    try std.testing.expectEqual(@as(usize, 4), hb.bytes); // "a2" + "b" + "p"
    // A re-flood of A's nomination moves it to the back of the line.
    try std.testing.expectEqual(HoldBuffer.PutResult.replaced, try hb.put(gpa, 5, a, .nominate, try holdItem(gpa, "a3")));
    try std.testing.expectEqual(@as(usize, 3), hb.count);
    {
        var list = hb.takeReleasable(gpa, 5).?;
        defer {
            for (list.items) |*e| HoldBuffer.freeEntry(gpa, e);
            list.deinit(gpa);
        }
        try std.testing.expectEqual(@as(usize, 3), list.items.len);
        try std.testing.expectEqualStrings("b", heldBytes(&list.items[0]));
        try std.testing.expectEqualStrings("p", heldBytes(&list.items[1]));
        try std.testing.expectEqualStrings("a3", heldBytes(&list.items[2]));
        try std.testing.expectEqual(@as(usize, 0), hb.count);
        try std.testing.expectEqual(@as(usize, 0), hb.bytes);
    }

    // Entry cap: 1024 distinct signers fit, the 1025th is dropped (and
    // freed); a replacement at the cap is not a drop.
    var i: usize = 0;
    while (i < HoldBuffer.max_entries) : (i += 1) {
        var id: [32]u8 = @splat(0);
        std.mem.writeInt(u32, id[0..4], @intCast(i), .little);
        try std.testing.expectEqual(HoldBuffer.PutResult.held, try hb.put(gpa, 7, id, .nominate, try holdItem(gpa, "x")));
    }
    try std.testing.expectEqual(HoldBuffer.max_entries, hb.count);
    try std.testing.expectEqual(HoldBuffer.PutResult.dropped_full, try hb.put(gpa, 8, a, .nominate, try holdItem(gpa, "overflow")));
    try std.testing.expectEqual(@as(u64, 1), hb.dropped_full.load(.acquire));
    try std.testing.expectEqual(HoldBuffer.max_entries, hb.count);
    {
        const id0: [32]u8 = @splat(0);
        try std.testing.expectEqual(HoldBuffer.PutResult.replaced, try hb.put(gpa, 7, id0, .nominate, try holdItem(gpa, "y")));
        try std.testing.expectEqual(HoldBuffer.max_entries, hb.count);
    }
    {
        var list = hb.takeReleasable(gpa, 7).?;
        for (list.items) |*e| HoldBuffer.freeEntry(gpa, e);
        list.deinit(gpa);
        try std.testing.expectEqual(@as(usize, 0), hb.count);
    }
    // Byte cap: one oversized item is dropped, nothing is held.
    {
        const big = try gpa.alloc(u8, HoldBuffer.max_bytes + 1);
        try std.testing.expectEqual(HoldBuffer.PutResult.dropped_full, try hb.put(gpa, 9, a, .prepare, .{ .input = .{ .envelope_received = .{ .bytes = big } }, .source_peer = null }));
        try std.testing.expectEqual(@as(usize, 0), hb.count);
        try std.testing.expect(hb.takeReleasable(gpa, 9) == null);
    }

    // Frontier sweep: {2, 3, 20, 21} at frontier 20 → 2 and 3 freed, 20
    // returned, 21 kept.
    for ([_]u64{ 2, 3, 20, 21 }) |slot| {
        try std.testing.expectEqual(HoldBuffer.PutResult.held, try hb.put(gpa, slot, a, .confirm, try holdItem(gpa, "c")));
    }
    try std.testing.expectEqual(@as(usize, 4), hb.count);
    {
        var list = hb.takeReleasable(gpa, 20).?;
        defer {
            for (list.items) |*e| HoldBuffer.freeEntry(gpa, e);
            list.deinit(gpa);
        }
        try std.testing.expectEqual(@as(usize, 1), list.items.len);
    }
    try std.testing.expectEqual(@as(u64, 2), hb.dropped_behind.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), hb.count);
    try std.testing.expect(hb.takeReleasable(gpa, 20) == null);
    try std.testing.expect(hb.slots.contains(21));
    // `deinit` (the defer) frees the remaining slot-21 entry.
}

fn signedExternalize(gpa: std.mem.Allocator, seed: [32]u8, network_id: [32]u8, qset_hash: [32]u8, slot: u64) ![]u8 {
    const node_id = try crypto.publicKeyFromSeed(seed);
    var statement_builder = capnpc.message.MessageBuilder.init(gpa);
    defer statement_builder.deinit();
    var statement = try gen_slcp.Statement.Builder.init(&statement_builder);
    try statement.setNodeId(&node_id);
    try statement.setSlotIndex(slot);
    var pledges = statement.getPledges();
    var ext = try pledges.initExternalize();
    var commit = try ext.initCommit();
    try commit.setCounter(1);
    try commit.setValue("agreed");
    try ext.setNH(1);
    try ext.setCommitQuorumSetHash(&qset_hash);
    const flat = try canonical.canonicalFlatFromBuilder(gpa, &statement_builder);
    defer gpa.free(flat);
    const signature = try crypto.sign(seed, crypto.statementDigest(network_id, flat));

    var envelope_builder = capnpc.message.MessageBuilder.init(gpa);
    defer envelope_builder.deinit();
    var envelope = try gen_slcp.Envelope.Builder.init(&envelope_builder);
    try envelope.setStatementBytes(flat);
    try envelope.setSignature(&signature);
    return @constCast(try envelope_builder.toBytes());
}

fn testQuorum(gpa: std.mem.Allocator) !qset.QuorumSetOwned {
    const ids = try gpa.alloc([32]u8, 3);
    errdefer gpa.free(ids);
    for (ids, [_]u8{ 0xa1, 0xb2, 0xc3 }) |*id, seed_byte| {
        id.* = try crypto.publicKeyFromSeed(@splat(seed_byte));
    }
    const inner = try gpa.alloc(qset.QuorumSetOwned, 0);
    errdefer gpa.free(inner);
    var qs = qset.QuorumSetOwned{ .threshold = 2, .validators = ids, .inner_sets = inner };
    try qset.validateAndNormalize(gpa, &qs);
    return qs;
}

test "foreign host: authenticated future envelopes release into a bare Engine with route tokens intact" {
    const gpa = std.testing.allocator;
    var qs = try testQuorum(gpa);
    defer qs.deinit(gpa);
    const network_id = crypto.networkIdFromPassphrase("foreign ingress test");
    const hash = try qset.hashNormalized(gpa, &qs);
    // A watcher externalizes from peer evidence without a Node, sockets,
    // timers, filesystem, or transport-specific module in this compilation.
    var eng = try engine.Engine.init(gpa, .{
        .network_id = network_id,
        .node_id = try crypto.publicKeyFromSeed(@splat(0xc3)),
        .secret_seed = null,
        .quorum_set = try qset.clone(gpa, &qs),
    }, @import("../driver.zig").Driver.default());
    defer eng.deinit();
    var hold: HoldBuffer = .{};
    defer hold.deinit(gpa);

    const first = try signedExternalize(gpa, @splat(0xa1), network_id, hash, 2);
    defer gpa.free(first);
    const first_meta = try envelopeMeta(gpa, network_id, first);
    var first_item = try holdItem(gpa, first);
    first_item.source_peer = 71;
    try std.testing.expectEqual(.held, hold.admit(gpa, &first_meta, 1, eng.qsets.inGraph(first_meta.node_id), &eng.cfg.quorum_set, first_item));
    try std.testing.expectEqual(@as(usize, 0), eng.stats().live_slots);

    const second = try signedExternalize(gpa, @splat(0xb2), network_id, hash, 2);
    defer gpa.free(second);
    const second_meta = try envelopeMeta(gpa, network_id, second);
    const forged = try gpa.dupe(u8, second);
    defer gpa.free(forged);
    const signature_at = std.mem.lastIndexOf(u8, forged, &second_meta.signature).?;
    forged[signature_at] ^= 1;
    const forged_meta = try envelopeMeta(gpa, network_id, forged);
    try std.testing.expectEqual(.dropped_badsig, hold.admit(gpa, &forged_meta, 1, true, &eng.cfg.quorum_set, try holdItem(gpa, forged)));
    try std.testing.expectEqual(@as(usize, 1), hold.count);
    try std.testing.expectEqual(@as(usize, 0), eng.stats().live_slots);

    var second_item = try holdItem(gpa, second);
    second_item.source_peer = 72;
    try std.testing.expectEqual(.ready, hold.admit(gpa, &second_meta, 1, eng.qsets.inGraph(second_meta.node_id), &eng.cfg.quorum_set, second_item));
    var released = hold.takeSlot(2).?;
    defer {
        for (released.items) |*entry| HoldBuffer.freeEntry(gpa, entry);
        released.deinit(gpa);
    }
    try std.testing.expectEqual(@as(usize, 2), released.items.len);
    var externalized: usize = 0;
    var statuses: usize = 0;
    for (released.items, 0..) |entry, i| {
        try std.testing.expectEqual(@as(?usize, 71 + i), entry.item.source_peer);
        try eng.pushInput(entry.item.input);
        // Every input finishes its complete drain before the next input.
        while (eng.popEffect()) |effect| {
            switch (effect.*) {
                .externalized => |value| {
                    try std.testing.expectEqual(@as(u64, 2), value.slot);
                    try std.testing.expectEqualStrings("agreed", value.bytes);
                    externalized += 1;
                },
                .input_status => |status| {
                    try std.testing.expectEqual(.applied, status.code);
                    statuses += 1;
                },
                else => {},
            }
            eng.commitEffect();
        }
    }
    try std.testing.expectEqual(@as(usize, 1), externalized);
    try std.testing.expectEqual(@as(usize, 2), statuses);
    try std.testing.expectEqual(@as(usize, 0), hold.count);
}

test "HoldBuffer: future window remains bounded near the final slot index" {
    const gpa = std.testing.allocator;
    var qs = try testQuorum(gpa);
    defer qs.deinit(gpa);
    const network_id = crypto.networkIdFromPassphrase("final slot ingress test");
    const last_slot = std.math.maxInt(u64);
    const framed = try signedExternalize(gpa, @splat(0xa1), network_id, try qset.hashNormalized(gpa, &qs), last_slot);
    defer gpa.free(framed);
    const meta = try envelopeMeta(gpa, network_id, framed);
    var hold: HoldBuffer = .{};
    defer hold.deinit(gpa);

    try std.testing.expectEqual(.dropped_far, hold.admit(gpa, &meta, last_slot - HoldBuffer.window - 1, true, &qs, try holdItem(gpa, framed)));
    try std.testing.expectEqual(.held, hold.admit(gpa, &meta, last_slot - HoldBuffer.window, true, &qs, try holdItem(gpa, framed)));
    // A replacement one slot ahead used to overflow frontier + window.
    try std.testing.expectEqual(.held, hold.admit(gpa, &meta, last_slot - 1, true, &qs, try holdItem(gpa, framed)));
    try std.testing.expectEqual(@as(usize, 1), hold.count);
    var released = hold.takeReleasable(gpa, last_slot).?;
    defer {
        for (released.items) |*entry| HoldBuffer.freeEntry(gpa, entry);
        released.deinit(gpa);
    }
    try std.testing.expectEqual(@as(usize, 1), released.items.len);
    try std.testing.expectEqualSlices(u8, framed, heldBytes(&released.items[0]));
    try std.testing.expectEqual(@as(usize, 0), hold.count);
    try std.testing.expectEqual(@as(u64, 1), hold.dropped_far.load(.acquire));
}
