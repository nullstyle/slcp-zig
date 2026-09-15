//! Compile witness for public host ingress and managed adaptivity on freestanding
//! WASM. Exporting an actual consumer forces code generation for metadata,
//! signature verification, buffer admission, release and counter operations;
//! an unused import would miss unsupported 64-bit atomics on wasm32.
//! `zig build host-ingress-wasm` compiles this object; `zig build test` does too.
//! These exported consumers are test-only and do not extend the Stable ABI.
//! Effect commits below simulate durability to force compilation; they are
//! not an implementation of a persistent foreign host.

const std = @import("std");
const core = @import("slcp-core");

comptime {
    if (!@import("builtin").single_threaded)
        @compileError("host ingress WASM witness must exercise single-threaded counters");
}

export fn exerciseHostIngress(bytes: [*]const u8, len: usize, frontier: u64) u8 {
    const gpa = std.heap.wasm_allocator;
    const meta = core.host.envelopeMeta(gpa, @splat(0x42), bytes[0..len]) catch return 0;
    var hold: core.host.HoldBuffer = .{};
    defer hold.deinit(gpa);
    var ids = [_][32]u8{meta.node_id};
    var children: [0]core.qset.QuorumSetOwned = .{};
    const qs = core.qset.QuorumSetOwned{ .threshold = 1, .validators = &ids, .inner_sets = &children };
    const owned = gpa.dupe(u8, bytes[0..len]) catch return 0;
    const result = hold.admit(gpa, &meta, frontier, true, &qs, .{
        .input = .{ .envelope_received = .{ .bytes = owned } },
        .source_peer = 0,
    });
    if (result == .fed) gpa.free(owned);
    if (hold.takeReleasable(gpa, frontier)) |value| {
        var list = value;
        defer list.deinit(gpa);
        for (list.items) |*entry| core.host.HoldBuffer.freeEntry(gpa, entry);
    }
    return @backingInt(result);
}

const session = core.adaptivity.session;
const policy = core.adaptivity.policy;

fn consumeEffects(managed: *session.Session) !void {
    while (try managed.popEffect() != null) try managed.commitEffect();
}

/// Dynamic arguments keep the compiler from reducing this to unused imports.
export fn exerciseManagedSession(seed: *const [32]u8, payload: [*]const u8, len: usize, first_changed_slot: u64) u8 {
    const gpa = std.heap.wasm_allocator;
    var ids = [_][32]u8{core.crypto.publicKeyFromSeed(seed.*) catch return 0};
    var children: [0]core.qset.QuorumSetOwned = .{};
    const qs = core.qset.QuorumSetOwned{ .threshold = 1, .validators = &ids, .inner_sets = &children };
    const floor = policy.Config{ .anchors = &ids, .max_faulty_anchors = 0, .min_slice_anchors = 1 };
    const managed = session.Session.createGenesis(gpa, .{
        .network_id = @splat(0x43),
        .policy = floor,
        .host = .{ .node_id = ids[0], .secret_seed = seed.*, .quorum_set = &qs, .driver = core.driver.Driver.default() },
    }) catch return 0;
    defer managed.deinit();
    consumeEffects(managed) catch return 0;
    const revision = managed.prepareQuorumChange(first_changed_slot, &qs) catch return 0;
    if (revision.quorum_bytes.len == 0) {
        managed.abortQuorumChange();
        return 0;
    }
    managed.commitQuorumChange() catch return 0;
    managed.proposeApplication(payload[0..len]) catch return 0;
    consumeEffects(managed) catch return 0;
    managed.acknowledgeApplied(managed.nextSlot(), payload[0..len]) catch return 0;
    consumeEffects(managed) catch return 0;
    return 1;
}

export fn exerciseManagedRecovery(seed: *const [32]u8, own: [*]const u8, own_len: usize, previous: [*]const u8, previous_len: usize, slot: u64) u8 {
    const gpa = std.heap.wasm_allocator;
    var ids = [_][32]u8{core.crypto.publicKeyFromSeed(seed.*) catch return 0};
    var children: [0]core.qset.QuorumSetOwned = .{};
    const qs = core.qset.QuorumSetOwned{ .threshold = 1, .validators = &ids, .inner_sets = &children };
    const records = [_][]const u8{own[0..own_len]};
    const managed = session.Session.restore(gpa, .{
        .network_id = @splat(0x43),
        .policy = .{ .anchors = &ids, .max_faulty_anchors = 0, .min_slice_anchors = 1 },
        .host = .{ .node_id = ids[0], .secret_seed = seed.*, .quorum_set = &qs, .driver = core.driver.Driver.default() },
    }, .{
        .next_slot = slot,
        .previous_value = previous[0..previous_len],
        .checkpoint_digest = session.checkpointDigest(previous[0..previous_len]),
        .own_envelopes = &records,
    }) catch return 0;
    defer managed.deinit();
    consumeEffects(managed) catch return 0;
    return 1;
}

export fn exerciseManagedSuccessor(old_seed: *const [32]u8, new_seed: *const [32]u8, parent_domain: *const [32]u8, parent_generation: u64, manifest: [*]const u8, manifest_len: usize, certificate: [*]const u8, certificate_len: usize, checkpoint: [*]const u8, checkpoint_len: usize) u8 {
    const gpa = std.heap.wasm_allocator;
    const old_ids = [_][32]u8{core.crypto.publicKeyFromSeed(old_seed.*) catch return 0};
    var trust = policy.Policy.init(gpa, .{ .anchors = &old_ids, .max_faulty_anchors = 0, .min_slice_anchors = 1 }) catch return 0;
    defer trust.deinit();
    var new_ids = [_][32]u8{core.crypto.publicKeyFromSeed(new_seed.*) catch return 0};
    var children: [0]core.qset.QuorumSetOwned = .{};
    const qs = core.qset.QuorumSetOwned{ .threshold = 1, .validators = &new_ids, .inner_sets = &children };
    const certificates = [_][]const u8{certificate[0..certificate_len]};
    const managed = session.Session.createSuccessor(gpa, .{
        .network_id = parent_domain.*,
        .generation = parent_generation,
        .policy = &trust,
    }, manifest[0..manifest_len], &certificates, checkpoint[0..checkpoint_len], .{
        .node_id = new_ids[0],
        .secret_seed = new_seed.*,
        .quorum_set = &qs,
        .driver = core.driver.Driver.default(),
    }) catch return 0;
    defer managed.deinit();
    consumeEffects(managed) catch return 0;
    return 1;
}
