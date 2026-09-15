//! Managed, strictly sequential epochs over the sans-io Engine.
//!
//! Application values are tagged; terminal migration manifests never reach
//! application drivers. A host must durably install activation, persist every
//! own envelope, and durably retire before committing the respective effect.
//! It applies/checkpoints an application outcome before acknowledgeApplied.
//! These persistence acknowledgements are assertions of host durability, as
//! with Engine's persist-before-broadcast contract. The opaque façade prevents
//! accidentally bypassing its admission and retirement gates.
const std = @import("std");
const capnpc = @import("capnpc-zig");
const engine = @import("../engine/engine.zig");
const driver = @import("../driver.zig");
const limits = @import("../engine/limits.zig");
const qset = @import("../engine/qset.zig");
const crypto = @import("../crypto.zig");
const canonical = @import("../canonical.zig");
const ingress = @import("../host/ingress.zig");
const policy = @import("policy.zig");
const migration = @import("migration.zig");

pub const application_magic = "SLCP-APP-V1\x00";
pub const HostOptions = struct {
    node_id: [32]u8,
    secret_seed: ?[32]u8,
    quorum_set: *const qset.QuorumSetOwned,
    /// The context must outlive the Session. Only untagged application values
    /// reach this driver; host application/checkpoint code owns mutable state.
    driver: driver.Driver,
    limits: limits.Limits = .{ .max_value_bytes = 16384 },
    max_revisions: u32 = 64,
    /// Required for a live trust-pool change. Deterministic authorization is
    /// independent of manifest shape and the checkpoint digest. Null denies.
    /// ctx is migration_context when set, otherwise the application driver ctx.
    authorize_migration: ?*const fn (ctx: *anyopaque, manifest: *const migration.Manifest) bool = null,
    migration_context: ?*anyopaque = null,
};
pub const Genesis = struct {
    network_id: [32]u8,
    policy: policy.Config,
    previous_value: []const u8 = "",
    checkpoint: []const u8 = "",
    host: HostOptions,
};
pub const ParentEpoch = struct {
    network_id: [32]u8,
    generation: u64,
    policy: *const policy.Policy,
};
pub const QuorumRevision = struct { first_slot: u64, quorum_bytes: []const u8 };
pub const Recovery = struct {
    next_slot: u64,
    previous_value: []const u8,
    checkpoint_digest: [32]u8,
    /// Durable own records in journal order. Repeated records are reduced to
    /// the latest nomination/ballot at next_slot only after the complete log
    /// has been checked for terminal EXTERNALIZE evidence.
    own_envelopes: []const []const u8 = &.{},
    /// Matches the default native journal bound, independently of the live
    /// Engine effect queue. Hosts with larger bounded journals may raise it.
    max_own_history_bytes: usize = 64 * 1024 * 1024,
    retirement_manifest: ?[]const u8 = null,
    quorum_revisions: []const QuorumRevision = &.{},
};
pub const Activation = struct {
    network_id: [32]u8,
    generation: u64,
    first_slot: u64,
    previous_value: []const u8,
    checkpoint_digest: [32]u8,
    checkpoint: []const u8,
    policy: policy.Config,
    quorum_bytes: []const u8,
    parent: ?ParentEpoch,
    manifest: ?[]const u8,
    certificate_envelopes: []const []const u8,
};
pub const Retirement = struct {
    network_id: [32]u8,
    generation: u64,
    slot: u64,
    manifest: []const u8,
    /// When present this same durable retirement record must also preserve
    /// the own envelope. A crash before any externalized record still retires.
    own_envelope: ?[]const u8,
};
pub const Application = struct { slot: u64, payload: []const u8, consensus_value: []const u8 };
pub const Terminal = struct { slot: u64, manifest: []const u8 };
pub const Effect = union(enum) {
    persist_activation: Activation,
    persist_retirement: Retirement,
    /// Never contains an externalized outcome or terminal own persistence.
    engine: *const engine.Effect,
    application: Application,
    terminal: Terminal,
};
pub const Status = enum { activation_pending, active, awaiting_application, retiring, retired, failed };
pub const Error = engine.PushError || engine.AdaptivityError || migration.VerifyError || limits.ValidateError || error{
    ActivationPending,
    EffectsNotDrained,
    NoEffect,
    SessionRetired,
    ApplicationNotApplied,
    NoApplication,
    WrongApplicationSlot,
    SlotNotCurrent,
    SlotExhausted,
    ValueTooLarge,
    InvalidApplicationValue,
    InvalidMigration,
    WrongCheckpoint,
    KeyIdentityMismatch,
    SignerOutsidePool,
    MigrationCapacityTooSmall,
    MigrationNotAuthorized,
    InvalidRecovery,
    ConflictingRetirement,
    RecoveryTooLarge,
    QuorumChangePending,
};

pub fn checkpointDigest(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

pub const Session = opaque {
    pub fn createGenesis(gpa: std.mem.Allocator, options: Genesis) Error!*Session {
        return @ptrCast(try State.create(gpa, options.network_id, 0, 1, options.policy, options.previous_value, options.checkpoint, options.host));
    }

    /// Verifies the OLD anchor threshold and hashes the supplied checkpoint.
    /// A new/disjoint anchor can join from this proof. A removed identity may
    /// observe as a watcher, but cannot construct a signing successor.
    pub fn createSuccessor(gpa: std.mem.Allocator, parent: ParentEpoch, manifest_bytes: []const u8, envelopes: []const []const u8, checkpoint_bytes: []const u8, host: HostOptions) Error!*Session {
        if (parent.generation == std.math.maxInt(u64)) return error.WrongGeneration;
        _ = try migration.verifyCertificate(gpa, parent.policy, parent.network_id, parent.generation + 1, manifest_bytes, envelopes);
        var manifest = try migration.Manifest.parse(gpa, manifest_bytes);
        defer manifest.deinit();
        if (!same(checkpointDigest(checkpoint_bytes), manifest.checkpoint_digest)) return error.WrongCheckpoint;
        const created = try State.create(gpa, manifest.successorNetworkId(), manifest.generation, manifest.terminal_slot + 1, policyConfig(&manifest.successor_policy), manifest_bytes, checkpoint_bytes, host);
        errdefer created.destroy();
        created.parent_policy = try policy.Policy.init(gpa, policyConfig(parent.policy));
        created.parent_domain = parent.network_id;
        created.parent_generation = parent.generation;
        created.activation_manifest = try gpa.dupe(u8, manifest_bytes);
        for (envelopes) |bytes| {
            const owned = try gpa.dupe(u8, bytes);
            errdefer gpa.free(owned);
            try created.certificates.append(gpa, owned);
        }
        return @ptrCast(created);
    }

    /// The caller asserts these records came from an already durable initial
    /// install. Every quorum revision is replayed before any own envelope.
    pub fn restore(gpa: std.mem.Allocator, genesis: Genesis, recovery: Recovery) Error!*Session {
        const result = try createGenesis(gpa, genesis);
        errdefer result.deinit();
        try result.state().restore(recovery);
        return result;
    }

    /// Successor recovery re-verifies its certified initial install; arbitrary
    /// generation/domain fields cannot bypass the migration certificate.
    pub fn restoreSuccessor(gpa: std.mem.Allocator, parent: ParentEpoch, manifest: []const u8, envelopes: []const []const u8, installed_checkpoint: []const u8, host: HostOptions, recovery: Recovery) Error!*Session {
        const result = try createSuccessor(gpa, parent, manifest, envelopes, installed_checkpoint, host);
        errdefer result.deinit();
        try result.state().restore(recovery);
        return result;
    }

    pub fn deinit(self: *Session) void {
        self.state().destroy();
    }
    pub fn status(self: *const Session) Status {
        return self.constState().status();
    }
    pub fn nextSlot(self: *const Session) u64 {
        return self.constState().slot;
    }
    pub fn networkId(self: *const Session) [32]u8 {
        return self.constState().network_id;
    }
    pub fn nodeId(self: *const Session) [32]u8 {
        return self.constState().host.node_id;
    }
    pub fn generation(self: *const Session) u64 {
        return self.constState().generation;
    }
    pub fn checkpoint(self: *const Session) [32]u8 {
        return self.constState().checkpoint_digest;
    }
    pub fn previousValue(self: *const Session) []const u8 {
        return self.constState().previous_value;
    }
    pub fn trustPolicy(self: *const Session) *const policy.Policy {
        return &self.constState().trust_policy;
    }

    pub fn proposeApplication(self: *Session, payload: []const u8) Error!void {
        const s = self.state();
        try s.ready();
        if (payload.len == 0) return error.InvalidApplicationValue;
        if (payload.len > s.host.limits.max_value_bytes - application_magic.len) return error.ValueTooLarge;
        const bytes = try s.gpa.alloc(u8, application_magic.len + payload.len);
        defer s.gpa.free(bytes);
        @memcpy(bytes[0..application_magic.len], application_magic);
        @memcpy(bytes[application_magic.len..], payload);
        if (s.app_driver.validate_value(s.app_driver.ctx, s.slot, payload, true) == .invalid) return error.InvalidApplicationValue;
        try s.push(.{ .nominate = .{ .slot = s.slot, .value = bytes, .prev_value = s.previous_value } });
    }
    pub fn proposeMigration(self: *Session, bytes: []const u8) Error!void {
        const s = self.state();
        try s.ready();
        try s.validateManifest(bytes);
        try s.push(.{ .nominate = .{ .slot = s.slot, .value = bytes, .prev_value = s.previous_value } });
    }
    pub fn receiveEnvelope(self: *Session, bytes: []const u8) Error!void {
        const s = self.state();
        try s.ready();
        const meta = ingress.envelopeMeta(s.gpa, s.network_id, bytes) catch |err| return mapError(err);
        // No future slot ever reaches parking, verdict caches or timer state.
        // Qset replay therefore cannot reopen a future admission path.
        if (meta.slot != s.slot) return error.SlotNotCurrent;
        try s.push(.{ .envelope_received = .{ .bytes = bytes } });
    }
    pub fn receiveQuorumSet(self: *Session, bytes: []const u8) Error!void {
        const s = self.state();
        try s.ready();
        try s.push(.{ .qset_received = .{ .bytes = bytes } });
    }
    pub fn timerFired(self: *Session, slot: u64, timer: engine.TimerId) Error!void {
        const s = self.state();
        try s.ready();
        if (slot != s.slot) return error.SlotNotCurrent;
        try s.push(.{ .timer_fired = .{ .slot = slot, .timer = timer } });
    }

    /// Borrowed until commitEffect. Committing a persistence effect asserts
    /// the exact returned record is durable; a transport enqueue is not one.
    pub fn popEffect(self: *Session) Error!?*const Effect {
        const s = self.state();
        if (s.failed) return error.EngineFailed;
        if (s.current != null) return &s.current.?;
        if (!s.activated) {
            s.current = .{ .persist_activation = s.activation() };
            return &s.current.?;
        }
        if (s.head == s.queue.items.len) return null;
        const item = &s.queue.items[s.head];
        s.current = switch (item.*) {
            .engine => |*effect| .{ .engine = effect },
            .retirement => |own| .{ .persist_retirement = .{
                .network_id = s.network_id,
                .generation = s.generation,
                .slot = s.slot,
                .manifest = s.retirement_manifest.?,
                .own_envelope = own,
            } },
            .application => .{ .application = .{ .slot = s.slot, .payload = appPayload(s.pending_application.?).?, .consensus_value = s.pending_application.? } },
            .terminal => .{ .terminal = .{ .slot = s.slot, .manifest = s.retirement_manifest.? } },
        };
        return &s.current.?;
    }
    pub fn commitEffect(self: *Session) Error!void {
        const s = self.state();
        if (s.failed) return error.EngineFailed;
        const current = s.current orelse return error.NoEffect;
        switch (current) {
            .persist_activation => {
                s.initializeEngine() catch |err| {
                    s.failed = true;
                    return err;
                };
                s.activated = true;
                s.current = null;
                return;
            },
            .persist_retirement => s.retired = true,
            .application => s.application_delivered = true,
            else => {},
        }
        s.queue.items[s.head].deinit(s.gpa);
        s.head += 1;
        s.current = null;
        if (s.head == s.queue.items.len) {
            s.queue.clearRetainingCapacity();
            s.head = 0;
            s.queue_bytes = 0;
        }
    }

    /// Call after this exact application outcome and snapshot are durably
    /// installed, and after draining all effects. Only this unlocks N+1.
    pub fn acknowledgeApplied(self: *Session, slot: u64, checkpoint_bytes: []const u8) Error!void {
        const s = self.state();
        if (s.failed) return error.EngineFailed;
        if (s.retired or s.retiring) return error.SessionRetired;
        if (!s.activated) return error.ActivationPending;
        if (s.current != null or s.queue.items.len != 0) return error.EffectsNotDrained;
        if (s.pending_application == null or !s.application_delivered) return error.NoApplication;
        if (slot != s.slot) return error.WrongApplicationSlot;
        if (slot == std.math.maxInt(u64)) return error.SlotExhausted;
        // checkpoint_bytes may borrow previousValue(), whose storage is retired below.
        const next_checkpoint = checkpointDigest(checkpoint_bytes);
        s.gpa.free(s.previous_value);
        s.previous_value = s.pending_application.?;
        s.pending_application = null;
        s.application_delivered = false;
        s.checkpoint_digest = next_checkpoint;
        s.slot += 1;
        try s.push(.{ .purge_slots = .{ .max_slot = s.slot } });
    }
    pub fn prepareQuorumChange(self: *Session, first_slot: u64, next: *const qset.QuorumSetOwned) Error!engine.QuorumChangeView {
        const s = self.state();
        try s.ready();
        if (first_slot < s.slot) return error.SlotNotCurrent;
        const view = try s.eng.?.prepareQuorumChange(first_slot, next);
        s.quorum_prepared = true;
        return view;
    }
    pub fn commitQuorumChange(self: *Session) Error!void {
        const s = self.state();
        if (s.failed) return error.EngineFailed;
        if (!s.activated) return error.ActivationPending;
        if (s.retired or s.retiring) return error.SessionRetired;
        if (!s.quorum_prepared) return error.NoPreparedChange;
        s.eng.?.commitQuorumChange() catch |err| {
            s.failed = true;
            return err;
        };
        s.quorum_prepared = false;
    }
    pub fn abortQuorumChange(self: *Session) void {
        const s = self.state();
        if (s.eng) |*eng| eng.abortQuorumChange();
        s.quorum_prepared = false;
    }
    fn state(self: *Session) *State {
        return @ptrCast(@alignCast(self));
    }
    fn constState(self: *const Session) *const State {
        return @ptrCast(@alignCast(self));
    }
};

const Item = union(enum) {
    engine: engine.Effect,
    retirement: ?[]u8,
    application,
    terminal,
    fn deinit(self: *Item, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .engine => |*effect| effect.deinitPayload(gpa),
            .retirement => |bytes| if (bytes) |b| gpa.free(b),
            else => {},
        }
    }
};
const State = struct {
    gpa: std.mem.Allocator,
    network_id: [32]u8,
    generation: u64,
    first_slot: u64,
    slot: u64,
    host: HostOptions,
    app_driver: driver.Driver,
    trust_policy: policy.Policy,
    initial_quorum: qset.QuorumSetOwned,
    quorum_bytes: []u8,
    previous_value: []u8,
    installed_checkpoint: []u8,
    checkpoint_digest: [32]u8,
    parent_policy: ?policy.Policy = null,
    parent_domain: [32]u8 = @splat(0),
    parent_generation: u64 = 0,
    activation_manifest: ?[]u8 = null,
    certificates: std.ArrayList([]const u8) = .empty,
    eng: ?engine.Engine = null,
    activated: bool = false,
    failed: bool = false,
    retired: bool = false,
    retiring: bool = false,
    quorum_prepared: bool = false,
    pending_application: ?[]u8 = null,
    application_delivered: bool = false,
    retirement_manifest: ?[]u8 = null,
    queue: std.ArrayList(Item) = .empty,
    head: usize = 0,
    queue_bytes: usize = 0,
    current: ?Effect = null,

    fn create(gpa: std.mem.Allocator, domain: [32]u8, generation: u64, first_slot: u64, cfg: policy.Config, previous: []const u8, checkpoint_bytes: []const u8, host: HostOptions) Error!*State {
        try limits.validate(host.limits);
        if (host.max_revisions == 0 or host.max_revisions > 4096) return error.InvalidRevisionLimit;
        if (host.limits.max_value_bytes < migration.max_manifest_bytes) return error.MigrationCapacityTooSmall;
        if (host.secret_seed) |seed| {
            if (!same(crypto.publicKeyFromSeed(seed) catch return error.KeyIdentityMismatch, host.node_id)) return error.KeyIdentityMismatch;
            var member = false;
            for (cfg.anchors) |id| if (same(id, host.node_id)) {
                member = true;
                break;
            };
            if (!member) return error.SignerOutsidePool;
        }
        var trust = try policy.Policy.init(gpa, cfg);
        errdefer trust.deinit();
        if (!(try trust.assess(host.quorum_set)).permitted) return error.QuorumOutsidePolicy;
        var owned = qset.clone(gpa, host.quorum_set) catch |err| return mapError(err);
        errdefer owned.deinit(gpa);
        qset.validateAndNormalize(gpa, &owned) catch |err| return mapError(err);
        const flat = canonicalQset(gpa, &owned) catch |err| return mapError(err);
        errdefer gpa.free(flat);
        const prev = try gpa.dupe(u8, previous);
        errdefer gpa.free(prev);
        const snapshot = try gpa.dupe(u8, checkpoint_bytes);
        errdefer gpa.free(snapshot);
        const s = try gpa.create(State);
        s.* = .{ .gpa = gpa, .network_id = domain, .generation = generation, .first_slot = first_slot, .slot = first_slot, .host = host, .app_driver = host.driver, .trust_policy = trust, .initial_quorum = owned, .quorum_bytes = flat, .previous_value = prev, .installed_checkpoint = snapshot, .checkpoint_digest = checkpointDigest(snapshot) };
        s.host.quorum_set = &s.initial_quorum;
        return s;
    }
    fn destroy(s: *State) void {
        if (s.eng) |*eng| eng.deinit();
        for (s.queue.items[s.head..]) |*item| item.deinit(s.gpa);
        s.queue.deinit(s.gpa);
        if (s.pending_application) |bytes| s.gpa.free(bytes);
        if (s.retirement_manifest) |bytes| s.gpa.free(bytes);
        if (s.activation_manifest) |bytes| s.gpa.free(bytes);
        for (s.certificates.items) |bytes| s.gpa.free(bytes);
        s.certificates.deinit(s.gpa);
        if (s.parent_policy) |*p| p.deinit();
        s.trust_policy.deinit();
        s.initial_quorum.deinit(s.gpa);
        s.gpa.free(s.quorum_bytes);
        s.gpa.free(s.previous_value);
        s.gpa.free(s.installed_checkpoint);
        const gpa = s.gpa;
        gpa.destroy(s);
    }
    fn status(s: *const State) Status {
        if (s.failed) return .failed;
        if (!s.activated) return .activation_pending;
        if (s.retired) return .retired;
        if (s.retiring) return .retiring;
        if (s.pending_application != null) return .awaiting_application;
        return .active;
    }
    fn ready(s: *State) Error!void {
        if (s.failed) return error.EngineFailed;
        if (!s.activated) return error.ActivationPending;
        if (s.retired or s.retiring) return error.SessionRetired;
        if (s.quorum_prepared) return error.QuorumChangePending;
        if (s.current != null or s.queue.items.len != 0) return error.EffectsNotDrained;
        if (s.pending_application != null) return error.ApplicationNotApplied;
    }
    fn activation(s: *State) Activation {
        return .{ .network_id = s.network_id, .generation = s.generation, .first_slot = s.first_slot, .previous_value = s.previous_value, .checkpoint_digest = s.checkpoint_digest, .checkpoint = s.installed_checkpoint, .policy = policyConfig(&s.trust_policy), .quorum_bytes = s.quorum_bytes, .parent = if (s.parent_policy) |*p| .{ .network_id = s.parent_domain, .generation = s.parent_generation, .policy = p } else null, .manifest = s.activation_manifest, .certificate_envelopes = s.certificates.items };
    }
    fn initializeEngine(s: *State) Error!void {
        try s.initializeEngineAt(&s.initial_quorum, s.first_slot);
    }
    fn initializeEngineAt(s: *State, initial: *const qset.QuorumSetOwned, first_slot: u64) Error!void {
        var owned = try qset.clone(s.gpa, initial);
        errdefer if (s.eng == null) owned.deinit(s.gpa);
        s.eng = engine.Engine.init(s.gpa, .{ .network_id = s.network_id, .node_id = s.host.node_id, .secret_seed = s.host.secret_seed, .quorum_set = owned, .limits = s.host.limits }, .{ .ctx = s, .validate_value = validateValue, .combine_candidates = combineValues, .extract_valid_value = if (s.app_driver.extract_valid_value != null) extractValue else null }) catch |err| return mapError(err);
        try s.eng.?.enableQuorumAdaptivity(.{ .policy = policyConfig(&s.trust_policy), .admission_floor = first_slot, .max_revisions = s.host.max_revisions });
    }
    fn push(s: *State, input: engine.Input) Error!void {
        s.eng.?.pushInput(input) catch |err| {
            s.failed = true;
            return err;
        };
        // Validation's boolean callback cannot return allocation failures.
        // Stop before exposing any signed effects if it ran out of memory.
        if (s.failed) return error.OutOfMemory;
        s.collect() catch |err| {
            s.failed = true;
            return err;
        };
    }
    fn append(s: *State, item: Item, bytes: usize) Error!void {
        if (s.queue.items.len >= engine.EffectQueue.max_effects or bytes > engine.EffectQueue.max_bytes -| s.queue_bytes) return error.EffectBudgetExceeded;
        try s.queue.append(s.gpa, item);
        s.queue_bytes += bytes;
    }
    fn setRetirement(s: *State, value: []const u8, require_authorization: bool) Error!void {
        try s.validateManifestWithAuthorization(value, require_authorization);
        if (s.retirement_manifest) |existing| {
            if (!std.mem.eql(u8, existing, value)) return error.ConflictingRetirement;
        } else s.retirement_manifest = try s.gpa.dupe(u8, value);
        s.retiring = true;
    }
    fn collect(s: *State) Error!void {
        while (s.eng.?.popEffect()) |effect| {
            switch (effect.*) {
                .persist_own_envelope => |record| {
                    const meta = ingress.envelopeMeta(s.gpa, s.network_id, record.bytes) catch |err| return mapError(err);
                    if (meta.kind == .externalize) {
                        const ext = try migration.verifyExternalize(s.gpa, s.network_id, record.bytes);
                        if (migration.isManifest(ext.value)) {
                            try s.setRetirement(ext.value, true);
                            const copy = try s.gpa.dupe(u8, record.bytes);
                            errdefer s.gpa.free(copy);
                            try s.append(.{ .retirement = copy }, copy.len);
                            s.eng.?.commitEffect();
                            continue;
                        }
                    }
                    try s.copyEngine(effect.*);
                },
                .externalized => |outcome| {
                    if (outcome.slot != s.slot) return error.SlotNotCurrent;
                    if (migration.isManifest(outcome.bytes)) {
                        const already_retiring = s.retiring;
                        try s.setRetirement(outcome.bytes, true);
                        if (!already_retiring) try s.append(.{ .retirement = null }, 0);
                        try s.append(.terminal, 0);
                    } else {
                        if (appPayload(outcome.bytes) == null or s.pending_application != null) return error.InvalidApplicationValue;
                        s.pending_application = try s.gpa.dupe(u8, outcome.bytes);
                        try s.append(.application, outcome.bytes.len);
                    }
                },
                else => try s.copyEngine(effect.*),
            }
            s.eng.?.commitEffect();
        }
    }
    fn copyEngine(s: *State, original: engine.Effect) Error!void {
        var copy = original;
        const bytes: usize = switch (original) {
            .persist_own_envelope, .broadcast_envelope, .forward_envelope, .externalized => |sb| blk: {
                const owned = try s.gpa.dupe(u8, sb.bytes);
                switch (copy) {
                    .persist_own_envelope, .broadcast_envelope, .forward_envelope, .externalized => |*target| target.bytes = owned,
                    else => unreachable,
                }
                break :blk owned.len;
            },
            else => 0,
        };
        errdefer copy.deinitPayload(s.gpa);
        try s.append(.{ .engine = copy }, bytes);
    }
    fn validateManifest(s: *State, bytes: []const u8) Error!void {
        try s.validateManifestWithAuthorization(bytes, true);
    }
    fn validateManifestWithAuthorization(s: *State, bytes: []const u8, require_authorization: bool) Error!void {
        if (bytes.len > s.host.limits.max_value_bytes) return error.ValueTooLarge;
        var value = try migration.Manifest.parse(s.gpa, bytes);
        defer value.deinit();
        if (!same(value.parent_network_id, s.network_id)) return error.WrongParentDomain;
        if (s.generation == std.math.maxInt(u64) or value.generation != s.generation + 1) return error.WrongGeneration;
        if (value.terminal_slot != s.slot) return error.WrongTerminalSlot;
        if (!same(value.checkpoint_digest, s.checkpoint_digest)) return error.WrongCheckpoint;
        if (require_authorization) {
            const authorize = s.host.authorize_migration orelse return error.MigrationNotAuthorized;
            if (!authorize(s.host.migration_context orelse s.app_driver.ctx, &value)) return error.MigrationNotAuthorized;
        }
    }

    fn restore(s: *State, recovery: Recovery) Error!void {
        if (recovery.next_slot < s.first_slot) return error.InvalidRecovery;
        if (recovery.own_envelopes.len > recovery.max_own_history_bytes / 8) return error.RecoveryTooLarge;
        const prev = try s.gpa.dupe(u8, recovery.previous_value);
        s.gpa.free(s.previous_value);
        s.previous_value = prev;
        s.slot = recovery.next_slot;
        s.checkpoint_digest = recovery.checkpoint_digest;
        // Validate all historical policies, but retain only the revision at
        // the durable frontier and future revisions. Runtime purge retires old
        // revisions; replaying the entire journal into its bounded live table
        // would make otherwise healthy long-lived epochs unrecoverable.
        var effective: ?qset.QuorumSetOwned = null;
        defer if (effective) |*qs| qs.deinit(s.gpa);
        var effective_first = s.first_slot;
        const RevisionHash = struct { first_slot: u64, hash: [32]u8 };
        var revision_hashes: std.ArrayList(RevisionHash) = .empty;
        defer revision_hashes.deinit(s.gpa);
        const initial_flat = qset.canonicalBytes(s.gpa, &s.initial_quorum) catch |err| return mapError(err);
        defer s.gpa.free(initial_flat);
        try revision_hashes.append(s.gpa, .{ .first_slot = s.first_slot, .hash = crypto.qsetHash(initial_flat) });
        var last_boundary = s.first_slot;
        var retained: usize = 1;
        for (recovery.quorum_revisions) |revision| {
            if (revision.first_slot <= last_boundary) return error.InvalidRecovery;
            last_boundary = revision.first_slot;
            var qs = try decodeQuorum(s.gpa, revision.quorum_bytes);
            errdefer qs.deinit(s.gpa);
            if (!(try s.trust_policy.assess(&qs)).permitted) return error.QuorumOutsidePolicy;
            const flat = qset.canonicalBytes(s.gpa, &qs) catch |err| return mapError(err);
            defer s.gpa.free(flat);
            try revision_hashes.append(s.gpa, .{ .first_slot = revision.first_slot, .hash = crypto.qsetHash(flat) });
            if (revision.first_slot <= s.slot) {
                if (effective) |*old| old.deinit(s.gpa);
                effective = qs;
                effective_first = revision.first_slot;
            } else {
                retained += 1;
                if (retained > s.host.max_revisions) return error.RevisionLimitExceeded;
                qs.deinit(s.gpa);
            }
        }
        var latest_nom: ?usize = null;
        var latest_ballot: ?usize = null;
        var recovered_application: ?[]const u8 = null;
        var terminal_envelope: ?[]const u8 = null;
        if (recovery.retirement_manifest) |value| try s.setRetirement(value, false);
        var total_bytes: usize = 0;
        for (recovery.own_envelopes, 0..) |bytes, i| {
            if (bytes.len > recovery.max_own_history_bytes -| total_bytes) return error.RecoveryTooLarge;
            total_bytes += bytes.len;
            const meta = ingress.envelopeMeta(s.gpa, s.network_id, bytes) catch |err| return mapError(err);
            if (!same(meta.node_id, s.host.node_id) or !crypto.verify(meta.node_id, meta.digest, meta.signature)) return error.InvalidRecovery;
            if (meta.slot < s.first_slot or meta.slot > s.slot) return error.InvalidRecovery;
            // Validate the complete signed history, including superseded and
            // already-applied records, before reducing it to live Engine state.
            var low: usize = 0;
            var high = revision_hashes.items.len;
            while (low + 1 < high) {
                const middle = low + (high - low) / 2;
                if (revision_hashes.items[middle].first_slot <= meta.slot) low = middle else high = middle;
            }
            const signed_hash = try ownQuorumHash(s.gpa, bytes);
            if (!same(signed_hash, revision_hashes.items[low].hash)) return error.InvalidRecovery;
            if (meta.kind == .externalize) {
                const ext = try migration.verifyExternalize(s.gpa, s.network_id, bytes);
                if (migration.isManifest(ext.value)) {
                    // The manifest check below binds its terminal_slot to the
                    // frontier; the signed statement must name that same slot.
                    if (ext.slot != s.slot) return error.InvalidRecovery;
                    try s.setRetirement(ext.value, false);
                    terminal_envelope = bytes;
                } else if (meta.slot == s.slot) {
                    if (appPayload(ext.value) == null) return error.InvalidRecovery;
                    recovered_application = ext.value;
                }
            }
            if (meta.slot == s.slot) {
                if (meta.kind == .nominate) latest_nom = i else latest_ballot = i;
            }
        }
        s.activated = true;
        // This preflight precedes even Engine construction. A terminal own
        // record (or separate durable marker) permanently disables old signing.
        if (s.retiring) {
            if (recovered_application != null) return error.ConflictingRetirement;
            s.retired = true;
            // Re-send only verified durable bytes after full preflight. No
            // Engine or signer is constructed for a retired epoch.
            if (terminal_envelope) |bytes| try s.copyEngine(.{ .broadcast_envelope = .{ .slot = s.slot, .bytes = @constCast(bytes) } });
            try s.append(.terminal, 0);
            return;
        }
        try s.initializeEngineAt(if (effective) |*qs| qs else &s.initial_quorum, effective_first);
        for (recovery.quorum_revisions) |revision| {
            if (revision.first_slot <= s.slot) continue;
            var qs = try decodeQuorum(s.gpa, revision.quorum_bytes);
            defer qs.deinit(s.gpa);
            _ = try s.eng.?.prepareQuorumChange(revision.first_slot, &qs);
            try s.eng.?.commitQuorumChange();
        }
        for ([_]?usize{ latest_nom, latest_ballot }) |index| if (index) |i| {
            try s.push(.{ .restore_own_envelope = .{ .bytes = recovery.own_envelopes[i] } });
            // Engine reports rejected restore records as a nonfatal status.
            // Missing signed state must never be treated as a fresh slot.
            const last = s.queue.items[s.queue.items.len - 1];
            if (last != .engine or last.engine != .input_status or last.engine.input_status.code != .applied) return error.InvalidRecovery;
        };
        if (recovered_application) |value| {
            s.pending_application = try s.gpa.dupe(u8, value);
            try s.append(.application, value.len);
        }
    }
};

fn validateValue(ctx: *anyopaque, slot: u64, value: []const u8, is_nomination: bool) driver.Validity {
    const s: *State = @ptrCast(@alignCast(ctx));
    if (slot != s.slot) return .invalid;
    if (migration.isManifest(value)) {
        s.validateManifest(value) catch |err| {
            if (err == error.OutOfMemory) s.failed = true;
            return .invalid;
        };
        return .valid;
    }
    const payload = appPayload(value) orelse return .invalid;
    return s.app_driver.validate_value(s.app_driver.ctx, slot, payload, is_nomination);
}
fn combineValues(ctx: *anyopaque, slot: u64, candidates: []const []const u8, gpa: std.mem.Allocator, out: *std.ArrayList(u8)) driver.DriverError!void {
    const s: *State = @ptrCast(@alignCast(ctx));
    var transition: ?[]const u8 = null;
    var applications: std.ArrayList([]const u8) = .empty;
    defer applications.deinit(gpa);
    for (candidates) |value| {
        if (migration.isManifest(value)) {
            s.validateManifest(value) catch return error.DriverFault;
            if (transition == null or std.mem.order(u8, value, transition.?) == .lt) transition = value;
        } else try applications.append(gpa, appPayload(value) orelse return error.DriverFault);
    }
    // Controls dominate applications; competing controls have a deterministic
    // byte order. The application combine function never sees a control value.
    if (transition) |value| {
        try out.appendSlice(gpa, value);
        return;
    }
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(gpa);
    try s.app_driver.combine_candidates(s.app_driver.ctx, slot, applications.items, gpa, &payload);
    if (payload.items.len == 0 or payload.items.len > s.host.limits.max_value_bytes - application_magic.len) return error.DriverFault;
    try out.appendSlice(gpa, application_magic);
    try out.appendSlice(gpa, payload.items);
}
fn extractValue(ctx: *anyopaque, slot: u64, value: []const u8, gpa: std.mem.Allocator, out: *std.ArrayList(u8)) driver.DriverError!bool {
    const s: *State = @ptrCast(@alignCast(ctx));
    const payload = appPayload(value) orelse return false;
    const extract = s.app_driver.extract_valid_value orelse return false;
    var result: std.ArrayList(u8) = .empty;
    defer result.deinit(gpa);
    if (!try extract(s.app_driver.ctx, slot, payload, gpa, &result)) return false;
    if (result.items.len == 0 or result.items.len > s.host.limits.max_value_bytes - application_magic.len) return error.DriverFault;
    try out.appendSlice(gpa, application_magic);
    try out.appendSlice(gpa, result.items);
    return true;
}
fn appPayload(bytes: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, bytes, application_magic) or bytes.len == application_magic.len) return null;
    return bytes[application_magic.len..];
}
fn policyConfig(p: *const policy.Policy) policy.Config {
    return .{ .anchors = p.anchors, .max_faulty_anchors = p.max_faulty_anchors, .min_slice_anchors = p.min_slice_anchors, .require_availability = p.require_availability };
}
fn same(a: [32]u8, b: [32]u8) bool {
    return std.mem.eql(u8, &a, &b);
}
fn mapError(err: anyerror) Error {
    return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidRecovery;
}
fn canonicalQset(gpa: std.mem.Allocator, qs: *const qset.QuorumSetOwned) ![]u8 {
    const flat = try qset.canonicalBytes(gpa, qs);
    defer gpa.free(flat);
    return canonical.frameFlat(gpa, flat);
}
fn decodeQuorum(gpa: std.mem.Allocator, bytes: []const u8) Error!qset.QuorumSetOwned {
    if (bytes.len > limits.frozen_max_frame_bytes) return error.InvalidRecovery;
    var msg = capnpc.message.Message.init(gpa, bytes, .{ .nesting_limit = 32, .traversal_limit_words = limits.frozen_max_frame_bytes / 8 }) catch |err| return mapError(err);
    defer msg.deinit();
    const reader = @import("../gen/slcp.zig").QuorumSet.Reader.init(&msg) catch |err| return mapError(err);
    var owned = qset.fromReader(gpa, reader) catch |err| return mapError(err);
    errdefer owned.deinit(gpa);
    qset.validateAndNormalize(gpa, &owned) catch |err| return mapError(err);
    return owned;
}

/// Recovery authenticates signatures separately, but every signed record also
/// needs canonical/sane contents and the quorum assigned to its original slot.
/// Use frozen bounds here: earlier applied slots may predate a host limit change.
fn ownQuorumHash(gpa: std.mem.Allocator, bytes: []const u8) Error![32]u8 {
    const gen = @import("../gen/slcp.zig");
    var envelope = capnpc.message.Message.init(gpa, bytes, .{ .nesting_limit = 32, .traversal_limit_words = limits.frozen_max_frame_bytes / 8 }) catch |err| return mapError(err);
    defer envelope.deinit();
    const reader = gen.Envelope.Reader.init(&envelope) catch |err| return mapError(err);
    const flat = reader.getStatementBytes() catch |err| return mapError(err);
    var message = canonical.decodeFlat(gpa, flat, .{ .nesting_limit = 32, .traversal_limit_words = limits.frozen_max_statement_bytes / 8 }) catch |err| return mapError(err);
    defer message.deinit();
    if (!capnpc.canonical.isCanonical(&message)) return error.InvalidRecovery;
    const stmt = gen.Statement.Reader.init(&message) catch |err| return mapError(err);
    if (@import("../engine/statement.zig").checkStatementSane(stmt, .{ .max_value_bytes = limits.frozen_max_value_bytes_cap }) != null) return error.InvalidRecovery;
    const pledges = stmt.getPledges();
    const hash = switch (pledges.which() catch |err| return mapError(err)) {
        .nominate => (pledges.getNominate() catch |err| return mapError(err)).getQuorumSetHash(),
        .prepare => (pledges.getPrepare() catch |err| return mapError(err)).getQuorumSetHash(),
        .confirm => (pledges.getConfirm() catch |err| return mapError(err)).getQuorumSetHash(),
        .externalize => (pledges.getExternalize() catch |err| return mapError(err)).getCommitQuorumSetHash(),
        .unset => return error.InvalidRecovery,
    } catch |err| return mapError(err);
    return hash[0..32].*; // sanity checked
}

fn allowMigration(_: *anyopaque, _: *const migration.Manifest) bool {
    return true;
}
fn singleton(gpa: std.mem.Allocator, seed: [32]u8) !qset.QuorumSetOwned {
    const validators = try gpa.alloc([32]u8, 1);
    errdefer gpa.free(validators);
    validators[0] = try crypto.publicKeyFromSeed(seed);
    return .{ .threshold = 1, .validators = validators, .inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0) };
}
fn singletonGenesis(qs: *const qset.QuorumSetOwned, seed: [32]u8) Genesis {
    return .{ .network_id = @splat(0x31), .policy = .{ .anchors = qs.validators, .max_faulty_anchors = 0, .min_slice_anchors = 1 }, .host = .{ .node_id = qs.validators[0], .secret_seed = seed, .quorum_set = qs, .driver = driver.Driver.default(), .authorize_migration = allowMigration } };
}
const TestRecords = struct {
    gpa: std.mem.Allocator,
    own: std.ArrayList([]const u8) = .empty,
    application: ?[]u8 = null,
    retirement: ?[]u8 = null,
    terminal_broadcasts: usize = 0,
    applications: usize = 0,
    fn deinit(r: *TestRecords) void {
        for (r.own.items) |bytes| r.gpa.free(bytes);
        r.own.deinit(r.gpa);
        if (r.application) |bytes| r.gpa.free(bytes);
        if (r.retirement) |bytes| r.gpa.free(bytes);
    }
    fn ownRecord(r: *TestRecords, bytes: []const u8) !void {
        const copy = try r.gpa.dupe(u8, bytes);
        errdefer r.gpa.free(copy);
        try r.own.append(r.gpa, copy);
    }
    fn drain(r: *TestRecords, s: *Session) !void {
        while (try s.popEffect()) |effect| {
            switch (effect.*) {
                .persist_retirement => |value| {
                    try std.testing.expect(s.status() == .retiring or s.status() == .retired);
                    if (s.status() == .retiring) try std.testing.expectEqual(@as(usize, 0), r.terminal_broadcasts);
                    try std.testing.expectError(error.SessionRetired, s.proposeApplication("forbidden"));
                    if (r.retirement == null) r.retirement = try r.gpa.dupe(u8, value.manifest);
                    if (value.own_envelope) |bytes| try r.ownRecord(bytes);
                    // Repeated observation cannot advance the persistence gate.
                    try std.testing.expectEqual(effect, (try s.popEffect()).?);
                },
                .engine => |value| switch (value.*) {
                    .persist_own_envelope => |record| try r.ownRecord(record.bytes),
                    .broadcast_envelope => |record| {
                        const meta = try ingress.envelopeMeta(r.gpa, s.networkId(), record.bytes);
                        if (meta.kind == .externalize) {
                            const ext = try migration.verifyExternalize(r.gpa, s.networkId(), record.bytes);
                            if (migration.isManifest(ext.value)) {
                                try std.testing.expectEqual(.retired, s.status());
                                try std.testing.expect(r.retirement != null);
                                r.terminal_broadcasts += 1;
                            }
                        }
                    },
                    else => {},
                },
                .application => |value| {
                    if (r.application) |old| r.gpa.free(old);
                    r.application = try r.gpa.dupe(u8, value.payload);
                    r.applications += 1;
                },
                else => {},
            }
            try s.commitEffect();
        }
    }
};

test "Session: activation and durable application acknowledgement gate every admission path" {
    const gpa = std.testing.allocator;
    const seed: [32]u8 = @splat(0x11);
    var qs = try singleton(gpa, seed);
    defer qs.deinit(gpa);
    const genesis = singletonGenesis(&qs, seed);
    const s = try Session.createGenesis(gpa, genesis);
    defer s.deinit();
    var records: TestRecords = .{ .gpa = gpa };
    defer records.deinit();
    try std.testing.expectError(error.ActivationPending, s.proposeApplication("one"));
    try std.testing.expectError(error.ActivationPending, s.commitQuorumChange());
    try records.drain(s);
    try std.testing.expectEqual(.active, s.status());
    // An application payload resembling the control prefix remains data.
    try s.proposeApplication(migration.magic ++ "opaque user bytes");
    try records.drain(s);
    try std.testing.expectEqual(@as(usize, 1), records.applications);
    try std.testing.expectEqualStrings(migration.magic ++ "opaque user bytes", records.application.?);
    try std.testing.expect(records.retirement == null);
    try std.testing.expectEqual(.awaiting_application, s.status());
    try std.testing.expectError(error.ApplicationNotApplied, s.proposeApplication("two"));
    try std.testing.expectError(error.ApplicationNotApplied, s.receiveQuorumSet("late qset"));
    try std.testing.expectError(error.ApplicationNotApplied, s.receiveEnvelope("late envelope"));
    try std.testing.expectError(error.ApplicationNotApplied, s.timerFired(2, .nomination));
    try std.testing.expectError(error.WrongApplicationSlot, s.acknowledgeApplied(2, "snapshot"));
    try s.acknowledgeApplied(1, "snapshot");
    try records.drain(s);
    try std.testing.expectEqual(@as(u64, 2), s.nextSlot());
    try std.testing.expectEqual(checkpointDigest("snapshot"), s.checkpoint());
    try std.testing.expectError(error.SlotNotCurrent, s.timerFired(3, .nomination));
    try s.proposeApplication("two");
    try records.drain(s);
    try std.testing.expectEqual(@as(usize, 2), records.applications);
}

test "Session: terminal own persistence retires before broadcast and survives every recovery cut" {
    const gpa = std.testing.allocator;
    const seed: [32]u8 = @splat(0x21);
    const new_seed: [32]u8 = @splat(0x22);
    var qs = try singleton(gpa, seed);
    defer qs.deinit(gpa);
    var next_qs = try singleton(gpa, new_seed);
    defer next_qs.deinit(gpa);
    const genesis = singletonGenesis(&qs, seed);
    const s = try Session.createGenesis(gpa, genesis);
    defer s.deinit();
    var records: TestRecords = .{ .gpa = gpa };
    defer records.deinit();
    try records.drain(s);
    var manifest = try migration.Manifest.init(gpa, .{ .parent_network_id = s.networkId(), .generation = 1, .terminal_slot = 1, .checkpoint_digest = s.checkpoint(), .successor_policy = .{ .anchors = next_qs.validators, .max_faulty_anchors = 0, .min_slice_anchors = 1 } });
    defer manifest.deinit();
    const bytes = try manifest.encode(gpa);
    defer gpa.free(bytes);
    try s.proposeMigration(bytes);
    try records.drain(s);
    try std.testing.expectEqual(.retired, s.status());
    try std.testing.expect(records.terminal_broadcasts >= 1);
    try std.testing.expectError(error.SessionRetired, s.receiveQuorumSet("qset"));
    try std.testing.expectError(error.SessionRetired, s.timerFired(2, .nomination));
    try std.testing.expectError(error.SessionRetired, s.prepareQuorumChange(2, &qs));

    const last_own = records.own.items[records.own.items.len - 1];
    const own_recovery = try Session.restore(gpa, genesis, .{ .next_slot = 1, .previous_value = "", .checkpoint_digest = checkpointDigest(""), .own_envelopes = records.own.items });
    defer own_recovery.deinit();
    try std.testing.expectEqual(.retired, own_recovery.status());
    try std.testing.expectError(error.SessionRetired, own_recovery.proposeApplication("after crash"));
    const marker_recovery = try Session.restore(gpa, genesis, .{ .next_slot = 1, .previous_value = "", .checkpoint_digest = checkpointDigest(""), .retirement_manifest = bytes });
    defer marker_recovery.deinit();
    try std.testing.expectEqual(.retired, marker_recovery.status());
    // Governance changes cannot revive an epoch which already retired.
    var denied = genesis;
    denied.host.authorize_migration = null;
    const denied_recovery = try Session.restore(gpa, denied, .{ .next_slot = 1, .previous_value = "", .checkpoint_digest = checkpointDigest(""), .own_envelopes = &.{last_own} });
    defer denied_recovery.deinit();
    try std.testing.expectEqual(.retired, denied_recovery.status());

    var new_host = genesis.host;
    new_host.node_id = next_qs.validators[0];
    new_host.secret_seed = new_seed;
    new_host.quorum_set = &next_qs;
    const parent = ParentEpoch{ .network_id = s.networkId(), .generation = 0, .policy = s.trustPolicy() };
    try std.testing.expectError(error.WrongCheckpoint, Session.createSuccessor(gpa, parent, bytes, &.{last_own}, "wrong snapshot", new_host));
    const successor = try Session.createSuccessor(gpa, parent, bytes, &.{last_own}, "", new_host);
    defer successor.deinit();
    try std.testing.expectEqual(.activation_pending, successor.status());
    try std.testing.expectEqualSlices(u8, bytes, successor.previousValue());
    try std.testing.expectError(error.ActivationPending, successor.proposeApplication("new epoch"));
    var new_records: TestRecords = .{ .gpa = gpa };
    defer new_records.deinit();
    try new_records.drain(successor);
    try successor.proposeApplication("new epoch");
    try new_records.drain(successor);
    try std.testing.expectEqualStrings("new epoch", new_records.application.?);
    var removed_host = new_host;
    removed_host.node_id = qs.validators[0];
    removed_host.secret_seed = seed;
    try std.testing.expectError(error.SignerOutsidePool, Session.createSuccessor(gpa, parent, bytes, &.{last_own}, "", removed_host));
}

test "Session: restore deduplicates history, reconstructs pending application, and rejects missing signed state" {
    const gpa = std.testing.allocator;
    const seed: [32]u8 = @splat(0x45);
    var qs = try singleton(gpa, seed);
    defer qs.deinit(gpa);
    var genesis = singletonGenesis(&qs, seed);
    genesis.host.limits.max_value_bytes = 32768;
    const s = try Session.createGenesis(gpa, genesis);
    defer s.deinit();
    var records: TestRecords = .{ .gpa = gpa };
    defer records.deinit();
    try records.drain(s);
    const payload = try gpa.alloc(u8, 20000);
    defer gpa.free(payload);
    @memset(payload, 'x');
    try s.proposeApplication(payload);
    try records.drain(s);
    var before_externalize: usize = 0;
    while (before_externalize < records.own.items.len) : (before_externalize += 1) {
        if ((try ingress.envelopeMeta(gpa, s.networkId(), records.own.items[before_externalize])).kind == .externalize) break;
    }
    try std.testing.expect(before_externalize > 0);
    const cut: Recovery = .{ .next_slot = 1, .previous_value = "", .checkpoint_digest = checkpointDigest(""), .own_envelopes = records.own.items[0..before_externalize] };
    const restored_cut = try Session.restore(gpa, genesis, cut);
    defer restored_cut.deinit();
    try std.testing.expectEqual(.active, restored_cut.status());
    var lowered = genesis;
    lowered.host.limits.max_value_bytes = 16384;
    try std.testing.expectError(error.InvalidRecovery, Session.restore(gpa, lowered, cut));
    lowered = genesis;
    lowered.host.limits.max_live_slots = 0;
    try std.testing.expectError(error.InvalidRecovery, Session.restore(gpa, lowered, cut));
    const restored_outcome = try Session.restore(gpa, genesis, .{ .next_slot = 1, .previous_value = "", .checkpoint_digest = checkpointDigest(""), .own_envelopes = records.own.items });
    defer restored_outcome.deinit();
    try std.testing.expectEqual(.awaiting_application, restored_outcome.status());
    var outcome_records: TestRecords = .{ .gpa = gpa };
    defer outcome_records.deinit();
    try outcome_records.drain(restored_outcome);
    try std.testing.expectEqualSlices(u8, payload, outcome_records.application.?);
    try std.testing.expectError(error.ApplicationNotApplied, restored_outcome.proposeApplication("next"));
    try s.acknowledgeApplied(1, "checkpoint one");
    try records.drain(s);
    const future_start = records.own.items.len;
    try s.proposeApplication("two");
    try records.drain(s);
    const lagging = try Session.createGenesis(gpa, genesis);
    defer lagging.deinit();
    var lagging_records: TestRecords = .{ .gpa = gpa };
    defer lagging_records.deinit();
    try lagging_records.drain(lagging);
    try std.testing.expectError(error.SlotNotCurrent, lagging.receiveEnvelope(records.own.items[future_start]));
    try std.testing.expectEqual(@as(usize, 0), lagging_records.own.items.len);
    try std.testing.expectEqual(@as(?*const Effect, null), try lagging.popEffect());
    // Full preflight fails before any of the earlier valid restore broadcasts
    // can escape, even when the future record is at the end of a long history.
    try std.testing.expectError(error.InvalidRecovery, Session.restore(gpa, genesis, .{ .next_slot = 1, .previous_value = "", .checkpoint_digest = checkpointDigest(""), .own_envelopes = records.own.items }));
}

fn restoreAllocationProbe(gpa: std.mem.Allocator, genesis: Genesis, recovery: Recovery) !void {
    const restored = try Session.restore(gpa, genesis, recovery);
    defer restored.deinit();
    try std.testing.expectEqual(recovery.next_slot, restored.nextSlot());
}

test "Session: long epoch recovery retains frontier policy and enforces future revision budget" {
    const gpa = std.testing.allocator;
    const seed: [32]u8 = @splat(0x46);
    var qs = try singleton(gpa, seed);
    defer qs.deinit(gpa);
    var genesis = singletonGenesis(&qs, seed);
    genesis.host.max_revisions = 2;
    const s = try Session.createGenesis(gpa, genesis);
    defer s.deinit();
    var records: TestRecords = .{ .gpa = gpa };
    defer records.deinit();
    try records.drain(s);
    const quorum_bytes = try canonicalQset(gpa, &qs);
    defer gpa.free(quorum_bytes);
    const revisions = [_]QuorumRevision{
        .{ .first_slot = 2, .quorum_bytes = quorum_bytes },
        .{ .first_slot = 3, .quorum_bytes = quorum_bytes },
        .{ .first_slot = 4, .quorum_bytes = quorum_bytes },
    };
    for (revisions) |revision| {
        _ = try s.prepareQuorumChange(revision.first_slot, &qs);
        try std.testing.expectError(error.QuorumChangePending, s.proposeApplication("blocked until persisted"));
        try s.commitQuorumChange();
        try s.proposeApplication("applied");
        try records.drain(s);
        try s.acknowledgeApplied(s.nextSlot(), "snapshot");
        try records.drain(s);
    }
    try s.proposeApplication("current");
    try records.drain(s);
    const recovered = try Session.restore(gpa, genesis, .{ .next_slot = 4, .previous_value = s.previousValue(), .checkpoint_digest = s.checkpoint(), .own_envelopes = records.own.items, .quorum_revisions = &revisions });
    defer recovered.deinit();
    try std.testing.expectEqual(.awaiting_application, recovered.status());
    var recovered_records: TestRecords = .{ .gpa = gpa };
    defer recovered_records.deinit();
    try recovered_records.drain(recovered);
    try std.testing.expectEqualStrings("current", recovered_records.application.?);
    // A future timeline really does consume the retained budget; rejecting it
    // must release the decoded tree exactly once.
    try std.testing.expectError(error.RevisionLimitExceeded, Session.restore(gpa, genesis, .{ .next_slot = 1, .previous_value = "", .checkpoint_digest = checkpointDigest(""), .quorum_revisions = revisions[0..2] }));
    try std.testing.checkAllAllocationFailures(gpa, restoreAllocationProbe, .{ genesis, Recovery{ .next_slot = 4, .previous_value = "previous", .checkpoint_digest = checkpointDigest("snapshot"), .quorum_revisions = &revisions } });
}

const MigrationAuthorization = struct {
    allowed: bool,
    calls: usize = 0,
    fn authorize(ctx: *anyopaque, _: *const migration.Manifest) bool {
        const self: *MigrationAuthorization = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        return self.allowed;
    }
};

test "Session: governance authorization is explicit and independent of a matching checkpoint" {
    const gpa = std.testing.allocator;
    const seed: [32]u8 = @splat(0x47);
    var qs = try singleton(gpa, seed);
    defer qs.deinit(gpa);
    var genesis = singletonGenesis(&qs, seed);
    genesis.host.authorize_migration = null;
    const denied = try Session.createGenesis(gpa, genesis);
    defer denied.deinit();
    var records: TestRecords = .{ .gpa = gpa };
    defer records.deinit();
    try records.drain(denied);
    var manifest = try migration.Manifest.init(gpa, .{ .parent_network_id = denied.networkId(), .generation = 1, .terminal_slot = 1, .checkpoint_digest = denied.checkpoint(), .successor_policy = genesis.policy });
    defer manifest.deinit();
    const bytes = try manifest.encode(gpa);
    defer gpa.free(bytes);
    try std.testing.expectError(error.MigrationNotAuthorized, denied.proposeMigration(bytes));
    try std.testing.expectEqual(.invalid, validateValue(denied.state(), 1, bytes, true));
    var governance: MigrationAuthorization = .{ .allowed = false };
    genesis.host.authorize_migration = MigrationAuthorization.authorize;
    genesis.host.migration_context = &governance;
    const managed = try Session.createGenesis(gpa, genesis);
    defer managed.deinit();
    try records.drain(managed);
    try std.testing.expectError(error.MigrationNotAuthorized, managed.proposeMigration(bytes));
    try std.testing.expectEqual(.invalid, validateValue(managed.state(), 1, bytes, false));
    var combined: std.ArrayList(u8) = .empty;
    defer combined.deinit(gpa);
    try std.testing.expectError(error.DriverFault, combineValues(managed.state(), 1, &.{bytes}, gpa, &combined));
    try std.testing.expectEqual(@as(usize, 3), governance.calls);
    governance.allowed = true;
    try managed.proposeMigration(bytes);
    try records.drain(managed);
    try std.testing.expectEqual(.retired, managed.status());
}

test "Session: invalid host configuration cannot install and activation failure stays stopped" {
    const gpa = std.testing.allocator;
    const seed: [32]u8 = @splat(0x48);
    var qs = try singleton(gpa, seed);
    defer qs.deinit(gpa);
    var genesis = singletonGenesis(&qs, seed);
    genesis.host.max_revisions = 0;
    try std.testing.expectError(error.InvalidRevisionLimit, Session.createGenesis(gpa, genesis));
    genesis.host.max_revisions = 4097;
    try std.testing.expectError(error.InvalidRevisionLimit, Session.createGenesis(gpa, genesis));
    genesis.host.max_revisions = 2;
    var failing = std.testing.FailingAllocator.init(gpa, .{});
    const s = try Session.createGenesis(failing.allocator(), genesis);
    defer s.deinit();
    try std.testing.expect((try s.popEffect()).?.* == .persist_activation);
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, s.commitEffect());
    failing.fail_index = std.math.maxInt(usize);
    try std.testing.expectEqual(.failed, s.status());
    try std.testing.expectError(error.EngineFailed, s.commitEffect());
    try std.testing.expectError(error.EngineFailed, s.proposeApplication("cannot retry after durable installation"));
}

fn signedNomination(gpa: std.mem.Allocator, seed: [32]u8, domain: [32]u8, slot: u64, hash: [32]u8) ![]u8 {
    const gen = @import("../gen/slcp.zig");
    var builder = capnpc.message.MessageBuilder.init(gpa);
    defer builder.deinit();
    var stmt = try gen.Statement.Builder.init(&builder);
    try stmt.setNodeId(&(try crypto.publicKeyFromSeed(seed)));
    try stmt.setSlotIndex(slot);
    var pledges = stmt.getPledges();
    var nomination = try pledges.initNominate();
    try nomination.setQuorumSetHash(&hash);
    const votes = try nomination.initVotes(1);
    try votes.set(0, application_magic ++ "one");
    const flat = try canonical.canonicalFlatFromBuilder(gpa, &builder);
    defer gpa.free(flat);
    var envelope_builder = capnpc.message.MessageBuilder.init(gpa);
    defer envelope_builder.deinit();
    var envelope = try gen.Envelope.Builder.init(&envelope_builder);
    try envelope.setStatementBytes(flat);
    try envelope.setSignature(&(try crypto.sign(seed, crypto.statementDigest(domain, flat))));
    return @constCast(try envelope_builder.toBytes());
}

fn expectInvalidRecovery(genesis: Genesis, recovery: Recovery) !void {
    if (Session.restore(std.testing.allocator, genesis, recovery)) |unexpected| {
        unexpected.deinit();
        return error.TestExpectedInvalidRecovery;
    } else |err| try std.testing.expectEqual(error.InvalidRecovery, err);
}

test "Session: every historical own quorum hash is checked before replay or retirement" {
    const gpa = std.testing.allocator;
    const seed: [32]u8 = @splat(0x49);
    var qs = try singleton(gpa, seed);
    defer qs.deinit(gpa);
    const genesis = singletonGenesis(&qs, seed);
    for ([_]bool{ false, true }) |terminal| {
        const s = try Session.createGenesis(gpa, genesis);
        defer s.deinit();
        var records: TestRecords = .{ .gpa = gpa };
        defer records.deinit();
        try records.drain(s);
        // A valid signature does not make this history consistent with the
        // installed local quorum. A later same-slot statement must not hide it.
        const wrong = try signedNomination(gpa, seed, s.networkId(), 1, @splat(0x99));
        defer gpa.free(wrong);
        try records.ownRecord(wrong);
        if (terminal) {
            var manifest = try migration.Manifest.init(gpa, .{ .parent_network_id = s.networkId(), .generation = 1, .terminal_slot = 1, .checkpoint_digest = s.checkpoint(), .successor_policy = genesis.policy });
            defer manifest.deinit();
            const bytes = try manifest.encode(gpa);
            defer gpa.free(bytes);
            try s.proposeMigration(bytes);
        } else try s.proposeApplication("one");
        try records.drain(s);
        var recovery: Recovery = .{ .next_slot = 1, .previous_value = "", .checkpoint_digest = checkpointDigest(""), .own_envelopes = records.own.items };
        try expectInvalidRecovery(genesis, recovery);
        var valid = recovery;
        valid.own_envelopes = records.own.items[1..];
        try std.testing.checkAllAllocationFailures(gpa, restoreAllocationProbe, .{ genesis, valid });
        if (terminal) {
            recovery.own_envelopes = records.own.items[1..];
            recovery.quorum_revisions = &.{.{ .first_slot = 2, .quorum_bytes = "malformed durable revision" }};
            try expectInvalidRecovery(genesis, recovery);
        } else {
            try s.acknowledgeApplied(1, "snapshot");
            try records.drain(s);
            recovery.next_slot = 2;
            recovery.previous_value = s.previousValue();
            recovery.checkpoint_digest = s.checkpoint();
            try expectInvalidRecovery(genesis, recovery);
        }
    }
}

test "Session: checkpoint acknowledgement may borrow the previous consensus value" {
    const gpa = std.testing.allocator;
    const seed: [32]u8 = @splat(0x50);
    var qs = try singleton(gpa, seed);
    defer qs.deinit(gpa);
    const s = try Session.createGenesis(gpa, singletonGenesis(&qs, seed));
    defer s.deinit();
    var records: TestRecords = .{ .gpa = gpa };
    defer records.deinit();
    try records.drain(s);
    try s.proposeApplication("one");
    try records.drain(s);
    try s.acknowledgeApplied(1, "snapshot");
    try records.drain(s);
    try s.proposeApplication("two");
    try records.drain(s);
    const previous = s.previousValue();
    const expected = checkpointDigest(previous);
    try s.acknowledgeApplied(2, previous);
    try records.drain(s);
    try std.testing.expectEqual(expected, s.checkpoint());
}

test "Session: terminal recovery rejects a signed slot different from the manifest slot" {
    const gpa = std.testing.allocator;
    const seed: [32]u8 = @splat(0x51);
    var qs = try singleton(gpa, seed);
    defer qs.deinit(gpa);
    const genesis = singletonGenesis(&qs, seed);
    var manifest = try migration.Manifest.init(gpa, .{
        .parent_network_id = genesis.network_id,
        .generation = 1,
        .terminal_slot = 2,
        .checkpoint_digest = checkpointDigest("snapshot"),
        .successor_policy = genesis.policy,
    });
    defer manifest.deinit();
    const value = try manifest.encode(gpa);
    defer gpa.free(value);
    const flat_quorum = try qset.canonicalBytes(gpa, &qs);
    defer gpa.free(flat_quorum);
    const gen = @import("../gen/slcp.zig");
    var builder = capnpc.message.MessageBuilder.init(gpa);
    defer builder.deinit();
    var stmt = try gen.Statement.Builder.init(&builder);
    try stmt.setNodeId(&genesis.host.node_id);
    // Structurally valid and correctly signed, but Session could never emit a
    // manifest for slot 2 inside an EXTERNALIZE statement for slot 1.
    try stmt.setSlotIndex(1);
    var pledges = stmt.getPledges();
    var externalize = try pledges.initExternalize();
    var ballot = try externalize.initCommit();
    try ballot.setCounter(1);
    try ballot.setValue(value);
    try externalize.setNH(1);
    try externalize.setCommitQuorumSetHash(&crypto.qsetHash(flat_quorum));
    const flat = try canonical.canonicalFlatFromBuilder(gpa, &builder);
    defer gpa.free(flat);
    var envelope_builder = capnpc.message.MessageBuilder.init(gpa);
    defer envelope_builder.deinit();
    var envelope = try gen.Envelope.Builder.init(&envelope_builder);
    try envelope.setStatementBytes(flat);
    try envelope.setSignature(&(try crypto.sign(seed, crypto.statementDigest(genesis.network_id, flat))));
    const bytes = try envelope_builder.toBytes();
    defer gpa.free(bytes);
    try expectInvalidRecovery(genesis, .{
        .next_slot = 2,
        .previous_value = application_magic ++ "previous",
        .checkpoint_digest = checkpointDigest("snapshot"),
        .own_envelopes = &.{bytes},
    });
}
