//! The sans-io deterministic engine (design §5): zero I/O, zero clock, zero
//! RNG — a pure function of (config, input sequence) → effect sequence,
//! modulo the driver (§8), whose calls are deterministic by contract.
//!
//! Contract (§5.1): feed exactly ONE input via pushInput, then drain ALL
//! effects (popEffect → commitEffect two-phase, borrowed until commit)
//! before the next input. Exactly one input_status effect per input, always
//! the final effect of its drain. Effects appear in the normative order —
//! in particular persist_own_envelope always precedes the
//! broadcast_envelope for the same statement.

const std = @import("std");
const capnpc = @import("capnpc-zig");
const canonical = @import("../canonical.zig");
const crypto = @import("../crypto.zig");
const driver_mod = @import("../driver.zig");
const limits_mod = @import("limits.zig");
const local_node = @import("local_node.zig");
const pending_mod = @import("pending.zig");
const qset = @import("qset.zig");
const qset_store = @import("qset_store.zig");
const slot_mod = @import("slot.zig");
const stored = @import("stored.zig");
const values = @import("values.zig");

pub const TimerId = enum(u8) { nomination = 0, ballot = 1 };

/// §5.2 — the input union. Byte slices are BORROWED for the duration of the
/// pushInput call; the engine copies what it keeps.
pub const Input = union(enum) {
    /// Raw Envelope frame bytes from the network (untrusted).
    envelope_received: struct { bytes: []const u8 },
    /// Host timer (slot, id) armed by an earlier arm_timer effect has fired.
    timer_fired: struct { slot: u64, timer: TimerId },
    /// Application proposes: start/continue nomination for `slot`.
    nominate: struct { slot: u64, value: []const u8, prev_value: []const u8 },
    /// Host answers an earlier request_qset effect.
    qset_received: struct { bytes: []const u8 },
    /// Startup only, before any other input: replay own persisted envelope.
    restore_own_envelope: struct { bytes: []const u8 },
    /// Drop all state for slots < max_slot (checkpoint / GC).
    purge_slots: struct { max_slot: u64 },
};

pub const InputStatus = enum(u16) {
    applied,
    stale,
    invalid_signature,
    insane,
    parked_awaiting_qset,
    over_limit,
    ignored,
};

pub const PhaseKind = enum(u16) {
    nominating,
    candidate_updated,
    started_ballot,
    accepted_prepared,
    confirmed_prepared,
    accepted_commit,
    heard_from_quorum,
    parked_evicted,
};

/// §5.3 — the effect union. Byte payloads are OWNED by the effect queue;
/// borrowed by the host between popEffect and commitEffect.
pub const Effect = union(enum) {
    pub const SlotBytes = struct { slot: u64, bytes: []u8 };

    persist_own_envelope: SlotBytes,
    broadcast_envelope: SlotBytes,
    forward_envelope: SlotBytes,
    arm_timer: struct { slot: u64, timer: TimerId, delay_ms: u32 },
    cancel_timer: struct { slot: u64, timer: TimerId },
    request_qset: struct { hash: [32]u8 },
    externalized: SlotBytes,
    input_status: struct { code: InputStatus },
    phase_event: struct { slot: u64, kind: PhaseKind, detail: u64 },

    pub fn deinitPayload(self: *Effect, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .persist_own_envelope, .broadcast_envelope, .forward_envelope, .externalized => |sb| gpa.free(sb.bytes),
            else => {},
        }
        self.* = undefined;
    }

    fn byteSize(self: *const Effect) usize {
        return switch (self.*) {
            .persist_own_envelope, .broadcast_envelope, .forward_envelope, .externalized => |sb| sb.bytes.len,
            else => 0,
        };
    }
};

/// Deterministic timeout schedule (§5.4): timeout(n) = min(1000·(n+1), cap).
pub fn timeoutMs(l: limits_mod.Limits, n: u32) u32 {
    const raw = std.math.mul(u32, 1000, n +| 1) catch return l.timeout_cap_ms;
    return @min(raw, l.timeout_cap_ms);
}

pub const EngineError = error{ EffectBudgetExceeded, EngineFailed, OutOfMemory };

/// Bounded FIFO effect queue with two-phase borrowed pop (§5.1, §7.2:
/// budget breach → sticky error state, never unbounded growth).
pub const EffectQueue = struct {
    pub const max_effects: usize = 4096;
    pub const max_bytes: usize = 16 * 1024 * 1024;

    gpa: std.mem.Allocator,
    items: std.ArrayList(Effect) = .empty,
    head: usize = 0,
    total_bytes: usize = 0,

    pub fn init(gpa: std.mem.Allocator) EffectQueue {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *EffectQueue) void {
        for (self.items.items[self.head..]) |*e| e.deinitPayload(self.gpa);
        self.items.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn len(self: *const EffectQueue) usize {
        return self.items.items.len - self.head;
    }

    pub fn bytes(self: *const EffectQueue) usize {
        return self.total_bytes;
    }

    /// Push an effect; the queue takes ownership of any byte payload even on
    /// failure (budget breach frees it and returns error).
    pub fn push(self: *EffectQueue, effect: Effect) EngineError!void {
        var e = effect;
        const sz = e.byteSize();
        if (self.len() + 1 > max_effects or self.total_bytes + sz > max_bytes) {
            e.deinitPayload(self.gpa);
            return error.EffectBudgetExceeded;
        }
        self.items.append(self.gpa, e) catch |err| {
            e.deinitPayload(self.gpa);
            return err;
        };
        self.total_bytes += sz;
    }

    /// Borrow the head effect (stable until commit()).
    pub fn peek(self: *EffectQueue) ?*const Effect {
        if (self.head >= self.items.items.len) return null;
        return &self.items.items[self.head];
    }

    pub fn commit(self: *EffectQueue) void {
        if (self.head >= self.items.items.len) return;
        self.total_bytes -= self.items.items[self.head].byteSize();
        self.items.items[self.head].deinitPayload(self.gpa);
        self.head += 1;
        if (self.head == self.items.items.len) {
            self.items.clearRetainingCapacity();
            self.head = 0;
        }
    }
};

/// §5.1 Config. The engine takes ownership of `quorum_set` on successful
/// init (deinit frees it).
pub const Config = struct {
    network_id: [32]u8,
    node_id: [32]u8,
    /// null => watcher mode: full tracking, zero emissions.
    secret_seed: ?[32]u8,
    /// Pre-validated + normalized (qset.validateAndNormalize).
    quorum_set: qset.QuorumSetOwned,
    strict_canonical: bool = true,
    limits: limits_mod.Limits = .{},
};

pub const Stats = struct {
    live_slots: usize,
    parked: usize,
    cached_qsets: usize,
    effects_queued: usize,
    stored_statement_bytes: usize,
    failed: bool,
};

/// Shared context handed to slot/protocol code (the seam between the engine
/// shell and the per-slot state machines). One value per Engine.
pub const Ctx = struct {
    gpa: std.mem.Allocator,
    cfg: *const Config,
    drv: *const driver_mod.Driver,
    effects: *EffectQueue,
    qsets: *qset_store.Store,
    /// Self-excised local qset for leader election (null when excision
    /// emptied it — §5.4/§12).
    excised: ?*const qset.QuorumSetOwned,
    /// qsetHash of cfg.quorum_set (advertised in own statements).
    local_qset_hash: [32]u8,
    /// The engine-wide §5.1 latest-envelope byte budget counter. Protocol
    /// code that self-stores into a slot's latest maps MUST account through
    /// `addStoredBytes`, or the counter under-counts and `purge_slots`
    /// (which subtracts the slot's real storedBytes) underflows — the
    /// native-vs-wasm divergence the M4 differential harness caught.
    stored_bytes: *usize,

    /// Apply a storeLatest byte delta to the engine-wide counter.
    pub fn addStoredBytes(self: *Ctx, delta: isize) void {
        const cur: isize = @intCast(self.stored_bytes.*);
        self.stored_bytes.* = @intCast(@max(0, cur + delta));
    }

    pub fn isWatcher(self: *const Ctx) bool {
        return self.cfg.secret_seed == null;
    }

    /// Driver validation with the per-slot cache applied by the caller
    /// (values.ValidationCache lives in slot state).
    pub fn driverValidate(self: *const Ctx, slot_index: u64, value: []const u8, is_nomination: bool) driver_mod.Validity {
        if (value.len == 0 or value.len > self.cfg.limits.max_value_bytes) return .invalid;
        return self.drv.validate_value(self.drv.ctx, slot_index, value, is_nomination);
    }

    pub fn phaseEvent(self: *Ctx, slot_index: u64, kind: PhaseKind, detail: u64) EngineError!void {
        try self.effects.push(.{ .phase_event = .{ .slot = slot_index, .kind = kind, .detail = detail } });
    }

    pub fn armTimer(self: *Ctx, slot_index: u64, timer: TimerId, delay_ms: u32) EngineError!void {
        try self.effects.push(.{ .arm_timer = .{ .slot = slot_index, .timer = timer, .delay_ms = delay_ms } });
    }

    pub fn cancelTimer(self: *Ctx, slot_index: u64, timer: TimerId) EngineError!void {
        try self.effects.push(.{ .cancel_timer = .{ .slot = slot_index, .timer = timer } });
    }
};

pub const PushError = EngineError;

pub const Engine = struct {
    gpa: std.mem.Allocator,
    cfg: Config,
    drv: driver_mod.Driver,
    effects: EffectQueue,
    qsets: qset_store.Store,
    pending: pending_mod.Pending,
    excised: ?qset.QuorumSetOwned,
    ctx: Ctx,
    slots: std.AutoArrayHashMapUnmanaged(u64, *slot_mod.Slot) = .empty,
    stored_statement_bytes: usize = 0,
    /// Sticky failure: once set, pushInput always fails (§7.2 discipline).
    failed: bool = false,

    /// Takes ownership of config.quorum_set. `config.limits` must already
    /// satisfy limits.validate.
    pub fn init(gpa: std.mem.Allocator, config: Config, drv: driver_mod.Driver) !Engine {
        try limits_mod.validate(config.limits);
        var self = Engine{
            .gpa = gpa,
            .cfg = config,
            .drv = drv,
            .effects = EffectQueue.init(gpa),
            .qsets = qset_store.Store.init(gpa, config.limits.max_cached_qsets),
            .pending = pending_mod.Pending.init(gpa, config.limits.max_pending_envelopes, config.limits.max_pending_bytes),
            .excised = undefined,
            .ctx = undefined,
        };
        errdefer {
            self.effects.deinit();
            self.qsets.deinit();
            self.pending.deinit();
        }
        // Relevance-filter seed: the local qset's transitive graph (§5.4);
        // self is always relevant.
        try self.qsets.addToGraph(&self.cfg.quorum_set);
        try self.qsets.graph.put(gpa, self.cfg.node_id, {});
        self.excised = if (try qset.exciseNode(gpa, &self.cfg.quorum_set, config.node_id)) |e| e else null;
        errdefer if (self.excised) |*e| e.deinit(gpa);
        const flat = try qset.canonicalBytes(gpa, &self.cfg.quorum_set);
        defer gpa.free(flat);
        const local_hash = crypto.qsetHash(flat);
        // Self-insert the local qset: peers advertising our hash must never
        // park on a qset this engine already knows by construction.
        try self.qsets.insert(local_hash, try qset.clone(gpa, &self.cfg.quorum_set));
        // Self-advertise it too: quorum checks resolve every voter's qset
        // through the advertised map, and the local node's own statements
        // (self-processed on emission, §5.4) always advertise local_hash —
        // without this a quorum that NEEDS self (e.g. a 1-of-{self}
        // configuration) can never form. Oracle: stellar-core's
        // getQuorumSetFromStatement always resolves the local node's own
        // qset. The hash never changes for the engine's lifetime.
        try self.qsets.setAdvertised(config.node_id, local_hash);
        self.ctx = .{
            .gpa = gpa,
            .cfg = &self.cfg,
            .drv = &self.drv,
            .effects = &self.effects,
            .qsets = &self.qsets,
            .excised = if (self.excised) |*e| e else null,
            .local_qset_hash = local_hash,
            .stored_bytes = &self.stored_statement_bytes,
        };
        return self;
    }

    pub fn deinit(self: *Engine) void {
        var it = self.slots.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit(self.gpa);
            self.gpa.destroy(entry.value_ptr.*);
        }
        self.slots.deinit(self.gpa);
        self.effects.deinit();
        self.qsets.deinit();
        self.pending.deinit();
        if (self.excised) |*e| e.deinit(self.gpa);
        self.cfg.quorum_set.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn stats(self: *const Engine) Stats {
        return .{
            .live_slots = self.slots.count(),
            .parked = self.pending.count(),
            .cached_qsets = self.qsets.count(),
            .effects_queued = self.effects.len(),
            .stored_statement_bytes = self.stored_statement_bytes,
            .failed = self.failed,
        };
    }

    /// Feed exactly one input; then drain ALL effects before the next input.
    /// Implemented by the M2 pipeline (pipeline.zig).
    pub fn pushInput(self: *Engine, input: Input) PushError!void {
        return @import("pipeline.zig").pushInput(self, input);
    }

    /// Borrowed until commitEffect (two-phase pop, §5.1).
    pub fn popEffect(self: *Engine) ?*const Effect {
        return self.effects.peek();
    }

    pub fn commitEffect(self: *Engine) void {
        self.effects.commit();
    }
};

test "timeout schedule: linear then capped" {
    const l = limits_mod.Limits{};
    try std.testing.expectEqual(@as(u32, 1000), timeoutMs(l, 0));
    try std.testing.expectEqual(@as(u32, 5000), timeoutMs(l, 4));
    try std.testing.expectEqual(@as(u32, 60_000), timeoutMs(l, 90));
}

test "effect queue: fifo, two-phase, byte accounting, budget breach" {
    const gpa = std.testing.allocator;
    var q = EffectQueue.init(gpa);
    defer q.deinit();

    try q.push(.{ .input_status = .{ .code = .applied } });
    const payload = try gpa.dupe(u8, "abc");
    try q.push(.{ .broadcast_envelope = .{ .slot = 1, .bytes = payload } });
    try std.testing.expectEqual(@as(usize, 2), q.len());
    try std.testing.expectEqual(@as(usize, 3), q.bytes());

    const first = q.peek().?;
    try std.testing.expect(first.* == .input_status);
    q.commit();
    const second = q.peek().?;
    try std.testing.expectEqualSlices(u8, "abc", second.broadcast_envelope.bytes);
    q.commit();
    try std.testing.expectEqual(@as(usize, 0), q.len());
    try std.testing.expectEqual(@as(usize, 0), q.bytes());
    try std.testing.expect(q.peek() == null);
}
