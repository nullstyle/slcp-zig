//! Native durability bridge for an Experimental managed Session.
//!
//! Each epoch uses its own journal directory. Old directories remain retired
//! history; successor recovery re-verifies its stored certificate against a
//! caller-pinned ParentEpoch. Restore the returned application snapshot before
//! constructing the recovered Session, so its Driver sees the recovered state.
const std = @import("std");
const core = @import("slcp-core");
const session = core.adaptivity.session;
const migration = core.adaptivity.migration;
const policy = core.adaptivity.policy;
const journal_mod = @import("adaptivity_journal.zig");

const ParentRecord = struct { network_id: [32]u8, generation: u64, policy: policy.Config };
const ActivationRecord = struct {
    version: u8 = 1,
    network_id: [32]u8,
    generation: u64,
    first_slot: u64,
    previous_value: []const u8,
    checkpoint: []const u8,
    policy: policy.Config,
    quorum_bytes: []const u8,
    parent: ?ParentRecord,
    manifest: ?[]const u8,
    certificate_envelopes: []const []const u8,
};
const AppliedRecord = struct { slot: u64, consensus_value: []const u8, checkpoint: []const u8 };

pub const Store = struct {
    journal: journal_mod.Journal,
    activated: bool = false,
    pending_application: ?struct { slot: u64, checkpoint: []u8 } = null,

    /// `path` is an existing durably provisioned directory. Creation is
    /// explicit and exclusive; it never overwrites an old signing history.
    pub fn create(gpa: std.mem.Allocator, io: std.Io, path: []const u8, managed: *const session.Session, limits: journal_mod.Limits) !Store {
        if (managed.status() != .activation_pending) return error.ActivationRequired;
        return .{ .journal = try journal_mod.Journal.create(gpa, io, path, .{ .node_id = managed.nodeId(), .root_network_id = managed.networkId() }, limits) };
    }

    pub fn open(gpa: std.mem.Allocator, io: std.Io, path: []const u8, identity: journal_mod.Identity, limits: journal_mod.Limits) !Store {
        return .{ .journal = try journal_mod.Journal.open(gpa, io, path, identity, limits) };
    }

    pub fn deinit(self: *Store) void {
        if (self.pending_application) |pending| self.journal.gpa.free(pending.checkpoint);
        self.journal.deinit();
        self.* = undefined;
    }

    fn checkSession(self: *const Store, managed: *const session.Session) !void {
        if (self.journal.failed) return error.JournalFailed;
        if (!std.mem.eql(u8, &managed.nodeId(), &self.journal.identity.node_id) or
            !std.mem.eql(u8, &managed.networkId(), &self.journal.identity.root_network_id)) return error.WrongIdentity;
    }

    /// Fsync and commit the current persistence effect. Returns false for
    /// transport/timer/application effects, which the host handles itself.
    pub fn persistEffect(self: *Store, managed: *session.Session) !bool {
        try self.checkSession(managed);
        const effect = (try managed.popEffect()) orelse return false;
        switch (effect.*) {
            .persist_activation => |activation| {
                if (self.activated or self.journal.sequence != 0) return error.DuplicateActivation;
                const encoded = try encodeActivation(self.journal.gpa, activation);
                defer self.journal.gpa.free(encoded);
                try self.journal.append(if (activation.generation == 0) .initial else .successor_install, encoded);
                self.activated = true;
            },
            .persist_retirement => |retirement| {
                if (!self.activated) return error.ActivationRequired;
                try self.appendJson(.retirement, retirement);
            },
            .engine => |inner| switch (inner.*) {
                .persist_own_envelope => |own| {
                    if (!self.activated) return error.ActivationRequired;
                    try self.journal.append(.own_envelope, own.bytes);
                },
                else => return false,
            },
            else => return false,
        }
        managed.commitEffect() catch |err| {
            self.journal.failed = true;
            return err;
        };
        return true;
    }

    /// The host has applied the current application effect to these exact
    /// checkpoint bytes. Persist outcome+snapshot atomically, then consume the
    /// effect. Drain remaining effects before acknowledgeApplied().
    pub fn checkpointApplication(self: *Store, managed: *session.Session, checkpoint: []const u8) !void {
        try self.checkSession(managed);
        if (!self.activated) return error.ActivationRequired;
        if (self.pending_application != null) return error.ApplicationPending;
        const effect = (try managed.popEffect()) orelse return error.NoApplication;
        const application = switch (effect.*) {
            .application => |a| a,
            else => return error.NoApplication,
        };
        const owned = try self.journal.gpa.dupe(u8, checkpoint);
        errdefer self.journal.gpa.free(owned);
        try self.appendJson(.applied, AppliedRecord{ .slot = application.slot, .consensus_value = application.consensus_value, .checkpoint = checkpoint });
        managed.commitEffect() catch |err| {
            self.journal.failed = true;
            return err;
        };
        self.pending_application = .{ .slot = application.slot, .checkpoint = owned };
    }

    pub fn acknowledgeApplied(self: *Store, managed: *session.Session) !void {
        try self.checkSession(managed);
        const pending = self.pending_application orelse return error.NoApplication;
        // A host can finish draining and retry this precondition without
        // making another disk record or changing application state.
        if (try managed.popEffect() != null) return error.EffectsNotDrained;
        managed.acknowledgeApplied(pending.slot, pending.checkpoint) catch |err| {
            self.journal.failed = true;
            return err;
        };
        self.journal.gpa.free(pending.checkpoint);
        self.pending_application = null;
    }

    /// Assessment, durable revision record, commit in one host operation.
    /// On any uncertain persistence error stop this instance and recover.
    pub fn changeQuorum(self: *Store, managed: *session.Session, first_slot: u64, next: *const core.qset.QuorumSetOwned) !void {
        try self.checkSession(managed);
        if (!self.activated) return error.ActivationRequired;
        const view = try managed.prepareQuorumChange(first_slot, next);
        const encoded = std.json.Stringify.valueAlloc(self.journal.gpa, view, .{}) catch |err| {
            managed.abortQuorumChange();
            return err;
        };
        defer self.journal.gpa.free(encoded);
        self.journal.append(.quorum_change, encoded) catch |err| {
            if (!self.journal.failed) managed.abortQuorumChange();
            return err;
        };
        managed.commitQuorumChange() catch |err| {
            self.journal.failed = true;
            return err;
        };
    }

    fn appendJson(self: *Store, kind: journal_mod.Kind, value: anytype) !void {
        const bytes = try std.json.Stringify.valueAlloc(self.journal.gpa, value, .{});
        defer self.journal.gpa.free(bytes);
        try self.journal.append(kind, bytes);
    }

    /// Ordered decoding and continuity checks. Load Recovered.checkpoint into
    /// the application's Driver context BEFORE calling its restore method.
    pub fn recover(self: *Store) !Recovered {
        var log = try self.journal.recover();
        errdefer log.deinit();
        errdefer self.journal.failed = true;
        const result = try Recovered.init(self.journal.gpa, self.journal.identity, log);
        self.activated = true;
        return result;
    }
};

pub const Recovered = struct {
    gpa: std.mem.Allocator,
    identity: journal_mod.Identity,
    log: journal_mod.Recovery,
    activation: std.json.Parsed(ActivationRecord),
    /// Latest durably applied application state, or installed genesis/successor
    /// checkpoint. Borrowed from this Recovered; valid until deinit.
    checkpoint: []const u8,
    previous_value: []const u8,
    next_slot: u64,
    own_envelopes: std.ArrayList([]const u8) = .empty,
    revisions: std.ArrayList(session.QuorumRevision) = .empty,
    parsed_changes: std.ArrayList(std.json.Parsed(core.engine.QuorumChangeView)) = .empty,
    parsed_applied: std.ArrayList(std.json.Parsed(AppliedRecord)) = .empty,
    parsed_retirements: std.ArrayList(std.json.Parsed(session.Retirement)) = .empty,

    fn init(gpa: std.mem.Allocator, identity: journal_mod.Identity, log: journal_mod.Recovery) !Recovered {
        if (log.records.len == 0) return error.MissingActivation;
        const first = log.records[0];
        if (first.kind != .initial and first.kind != .successor_install) return error.MissingActivation;
        const activation = try std.json.parseFromSlice(ActivationRecord, gpa, first.payload, .{ .allocate = .alloc_always });
        // init owns decoded fields on failure but caller still owns log.
        var result: Recovered = .{ .gpa = gpa, .identity = identity, .log = log, .activation = activation, .checkpoint = activation.value.checkpoint, .previous_value = activation.value.previous_value, .next_slot = activation.value.first_slot };
        errdefer result.deinitParsed();
        const a = activation.value;
        if (a.version != 1 or !std.mem.eql(u8, &a.network_id, &identity.root_network_id) or
            (a.generation == 0) != (first.kind == .initial)) return error.InvalidActivation;
        if (a.first_slot == 0) return error.InvalidActivation;
        var trust = try policy.Policy.init(gpa, a.policy);
        defer trust.deinit();
        var last_revision = a.first_slot;
        var highest_signed: ?u64 = null;
        for (log.records[1..]) |record| switch (record.kind) {
            .initial, .successor_install => return error.DuplicateActivation,
            .own_envelope => {
                if (result.parsed_retirements.items.len != 0) return error.RecordAfterRetirement;
                // Preserve the admission ordering which is lost when the
                // Session receives separate envelope and revision lists.
                // Session restoration also validates every signed statement.
                const meta = try core.host.envelopeMeta(gpa, a.network_id, record.payload);
                highest_signed = if (highest_signed) |highest| @max(highest, meta.slot) else meta.slot;
                try result.own_envelopes.append(gpa, record.payload);
            },
            .quorum_change => {
                if (result.parsed_retirements.items.len != 0) return error.RecordAfterRetirement;
                const parsed = try std.json.parseFromSlice(core.engine.QuorumChangeView, gpa, record.payload, .{ .allocate = .alloc_always });
                errdefer parsed.deinit();
                if (parsed.value.first_slot <= last_revision or parsed.value.first_slot < result.next_slot or
                    !std.mem.eql(u8, &parsed.value.policy_fingerprint, &trust.fingerprint())) return error.InvalidQuorumHistory;
                if (highest_signed) |highest| if (parsed.value.first_slot <= highest) return error.InvalidQuorumHistory;
                var qs = try decodeQuorum(gpa, parsed.value.quorum_bytes);
                defer qs.deinit(gpa);
                const flat = try core.qset.canonicalBytes(gpa, &qs);
                defer gpa.free(flat);
                if (!std.mem.eql(u8, &core.crypto.qsetHash(flat), &parsed.value.qset_hash)) return error.InvalidQuorumHistory;
                try result.revisions.ensureUnusedCapacity(gpa, 1);
                try result.parsed_changes.append(gpa, parsed);
                result.revisions.appendAssumeCapacity(.{ .first_slot = parsed.value.first_slot, .quorum_bytes = parsed.value.quorum_bytes });
                last_revision = parsed.value.first_slot;
            },
            .applied => {
                if (result.parsed_retirements.items.len != 0) return error.RecordAfterRetirement;
                const parsed = try std.json.parseFromSlice(AppliedRecord, gpa, record.payload, .{ .allocate = .alloc_always });
                errdefer parsed.deinit();
                if (parsed.value.slot != result.next_slot or result.next_slot == std.math.maxInt(u64) or
                    !std.mem.startsWith(u8, parsed.value.consensus_value, session.application_magic) or
                    parsed.value.consensus_value.len <= session.application_magic.len) return error.InvalidApplicationHistory;
                try result.parsed_applied.append(gpa, parsed);
                result.next_slot += 1;
                result.previous_value = parsed.value.consensus_value;
                result.checkpoint = parsed.value.checkpoint;
            },
            .retirement => {
                const parsed = try std.json.parseFromSlice(session.Retirement, gpa, record.payload, .{ .allocate = .alloc_always });
                errdefer parsed.deinit();
                if (!std.mem.eql(u8, &parsed.value.network_id, &a.network_id) or parsed.value.generation != a.generation or parsed.value.slot != result.next_slot) return error.InvalidRetirement;
                var manifest = try migration.Manifest.parse(gpa, parsed.value.manifest);
                defer manifest.deinit();
                if (!std.mem.eql(u8, &manifest.parent_network_id, &a.network_id) or manifest.generation != a.generation +| 1 or
                    manifest.terminal_slot != result.next_slot or !std.mem.eql(u8, &manifest.checkpoint_digest, &session.checkpointDigest(result.checkpoint))) return error.InvalidRetirement;
                if (result.parsed_retirements.items.len != 0 and !std.mem.eql(u8, result.parsed_retirements.items[0].value.manifest, parsed.value.manifest)) return error.ConflictingRetirement;
                try result.parsed_retirements.ensureUnusedCapacity(gpa, 1);
                if (parsed.value.own_envelope) |envelope| try result.own_envelopes.append(gpa, envelope);
                result.parsed_retirements.appendAssumeCapacity(parsed);
            },
        };
        return result;
    }

    pub fn deinit(self: *Recovered) void {
        self.deinitParsed();
        self.log.deinit();
        self.* = undefined;
    }

    fn deinitParsed(self: *Recovered) void {
        self.activation.deinit();
        for (self.parsed_changes.items) |parsed| parsed.deinit();
        self.parsed_changes.deinit(self.gpa);
        for (self.parsed_applied.items) |parsed| parsed.deinit();
        self.parsed_applied.deinit(self.gpa);
        for (self.parsed_retirements.items) |parsed| parsed.deinit();
        self.parsed_retirements.deinit(self.gpa);
        self.own_envelopes.deinit(self.gpa);
        self.revisions.deinit(self.gpa);
    }

    fn recovery(self: *const Recovered) session.Recovery {
        return .{ .next_slot = self.next_slot, .previous_value = self.previous_value, .checkpoint_digest = session.checkpointDigest(self.checkpoint), .own_envelopes = self.own_envelopes.items, .max_own_history_bytes = self.log.bytes.len, .retirement_manifest = if (self.parsed_retirements.items.len != 0) self.parsed_retirements.items[0].value.manifest else null, .quorum_revisions = self.revisions.items };
    }

    /// Rejects a stale/different genesis trust floor or initial local quorum.
    pub fn restoreGenesis(self: *const Recovered, genesis: session.Genesis) !*session.Session {
        const candidate = try session.Session.createGenesis(self.gpa, genesis);
        defer candidate.deinit();
        try self.checkActivation(candidate);
        return session.Session.restore(self.gpa, genesis, self.recovery());
    }

    /// Parent trust is explicitly pinned by the application. The stored
    /// manifest, certificate and initial checkpoint are verified again.
    pub fn restoreSuccessor(self: *const Recovered, parent: session.ParentEpoch, host: session.HostOptions) !*session.Session {
        const a = self.activation.value;
        const manifest = a.manifest orelse return error.InvalidActivation;
        const candidate = try session.Session.createSuccessor(self.gpa, parent, manifest, a.certificate_envelopes, a.checkpoint, host);
        defer candidate.deinit();
        try self.checkActivation(candidate);
        return session.Session.restoreSuccessor(self.gpa, parent, manifest, a.certificate_envelopes, a.checkpoint, host, self.recovery());
    }

    fn checkActivation(self: *const Recovered, candidate: *session.Session) !void {
        if (!std.mem.eql(u8, &candidate.nodeId(), &self.identity.node_id)) return error.WrongIdentity;
        const effect = (try candidate.popEffect()) orelse return error.InvalidActivation;
        const actual = switch (effect.*) {
            .persist_activation => |a| a,
            else => return error.InvalidActivation,
        };
        const expected_bytes = try encodeActivation(self.gpa, actual);
        defer self.gpa.free(expected_bytes);
        // The original encoder uses canonical ordering for anchors and local
        // quorum bytes. Comparing exact records detects changed boot choices.
        if (!std.mem.eql(u8, expected_bytes, self.log.records[0].payload)) return error.ActivationMismatch;
    }
};

fn policyConfig(p: *const policy.Policy) policy.Config {
    return .{ .anchors = p.anchors, .max_faulty_anchors = p.max_faulty_anchors, .min_slice_anchors = p.min_slice_anchors, .require_availability = p.require_availability };
}

fn encodeActivation(gpa: std.mem.Allocator, a: session.Activation) ![]u8 {
    return std.json.Stringify.valueAlloc(gpa, ActivationRecord{
        .network_id = a.network_id,
        .generation = a.generation,
        .first_slot = a.first_slot,
        .previous_value = a.previous_value,
        .checkpoint = a.checkpoint,
        .policy = a.policy,
        .quorum_bytes = a.quorum_bytes,
        .parent = if (a.parent) |parent| .{ .network_id = parent.network_id, .generation = parent.generation, .policy = policyConfig(parent.policy) } else null,
        .manifest = a.manifest,
        .certificate_envelopes = a.certificate_envelopes,
    }, .{});
}

fn decodeQuorum(gpa: std.mem.Allocator, bytes: []const u8) !core.qset.QuorumSetOwned {
    if (bytes.len > core.limits.frozen_max_frame_bytes) return error.InvalidQuorumHistory;
    var msg = try core.capnpc.message.Message.init(gpa, bytes, .{ .nesting_limit = 32, .traversal_limit_words = core.limits.frozen_max_frame_bytes / 8 });
    defer msg.deinit();
    var qs = try core.qset.fromReader(gpa, try core.gen.slcp.QuorumSet.Reader.init(&msg));
    errdefer qs.deinit(gpa);
    try core.qset.validateAndNormalize(gpa, &qs);
    return qs;
}

const testing = std.testing;

fn allowMigration(_: *anyopaque, _: *const migration.Manifest) bool {
    return true;
}

fn testQuorum(seed: [32]u8) !core.qset.QuorumSetOwned {
    const ids = try testing.allocator.alloc([32]u8, 1);
    errdefer testing.allocator.free(ids);
    ids[0] = try core.crypto.publicKeyFromSeed(seed);
    return .{ .threshold = 1, .validators = ids, .inner_sets = try testing.allocator.alloc(core.qset.QuorumSetOwned, 0) };
}

fn testGenesis(qs: *const core.qset.QuorumSetOwned, seed: [32]u8) session.Genesis {
    return .{ .network_id = @splat(0x71), .policy = .{ .anchors = qs.validators, .max_faulty_anchors = 0, .min_slice_anchors = 1 }, .host = .{
        .node_id = qs.validators[0],
        .secret_seed = seed,
        .quorum_set = qs,
        .driver = core.driver.Driver.default(),
        .authorize_migration = allowMigration,
    } };
}

fn testPath(tmp: *testing.TmpDir, buffer: []u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, ".zig-cache/tmp/{s}", .{tmp.sub_path});
}

fn drain(store: *Store, managed: *session.Session) !void {
    while (try managed.popEffect()) |effect| {
        if (try store.persistEffect(managed)) continue;
        switch (effect.*) {
            .application => |application| try store.checkpointApplication(managed, application.payload),
            else => try managed.commitEffect(),
        }
    }
    if (store.pending_application != null) {
        try store.acknowledgeApplied(managed);
        while (try managed.popEffect() != null) try managed.commitEffect();
    }
}

test "managed store recovers checkpoint and recycled quorum history before restoring own votes" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [256]u8 = undefined;
    const path = try testPath(&tmp, &path_buffer);
    const seed: [32]u8 = @splat(0x65);
    var qs = try testQuorum(seed);
    defer qs.deinit(testing.allocator);
    var genesis = testGenesis(&qs, seed);
    genesis.host.max_revisions = 2;
    const identity: journal_mod.Identity = .{ .node_id = qs.validators[0], .root_network_id = genesis.network_id };
    {
        const managed = try session.Session.createGenesis(testing.allocator, genesis);
        defer managed.deinit();
        var store = try Store.create(testing.allocator, testing.io, path, managed, .{});
        defer store.deinit();
        try drain(&store, managed);
        // More history than the simultaneously retained revision budget.
        for (1..9) |slot| {
            try store.changeQuorum(managed, @intCast(slot + 1), &qs);
            try managed.proposeApplication("durable state");
            try drain(&store, managed);
        }
        try testing.expectEqual(@as(u64, 9), managed.nextSlot());
        // Crash after the application snapshot is durable but before the
        // acknowledgement unlocks the next slot.
        try managed.proposeApplication("newest snapshot");
        while (try managed.popEffect()) |effect| {
            if (try store.persistEffect(managed)) continue;
            if (effect.* == .application) {
                try store.checkpointApplication(managed, "newest snapshot");
                break;
            }
            try managed.commitEffect();
        }
    }
    var store = try Store.open(testing.allocator, testing.io, path, identity, .{});
    defer store.deinit();
    var recovered = try store.recover();
    defer recovered.deinit();
    try testing.expectEqualStrings("newest snapshot", recovered.checkpoint);
    try testing.expectEqual(@as(u64, 10), recovered.next_slot);
    const managed = try recovered.restoreGenesis(genesis);
    defer managed.deinit();
    try drain(&store, managed);
    try testing.expectEqual(@as(u64, 10), managed.nextSlot());
    try managed.proposeApplication("continues after restart");
    try drain(&store, managed);
    try testing.expectEqual(@as(u64, 11), managed.nextSlot());
    var stale = genesis;
    stale.checkpoint = "stale boot checkpoint";
    try testing.expectError(error.ActivationMismatch, recovered.restoreGenesis(stale));
}

test "managed store retirement survives crash before broadcast with or without a separate marker" {
    for ([_]bool{ false, true }) |separate_marker| {
        var old_tmp = testing.tmpDir(.{});
        defer old_tmp.cleanup();
        var new_tmp = testing.tmpDir(.{});
        defer new_tmp.cleanup();
        var old_buffer: [256]u8 = undefined;
        var new_buffer: [256]u8 = undefined;
        const old_path = try testPath(&old_tmp, &old_buffer);
        const new_path = try testPath(&new_tmp, &new_buffer);
        const seed: [32]u8 = @splat(0x61);
        const next_seed: [32]u8 = @splat(0x62);
        var qs = try testQuorum(seed);
        defer qs.deinit(testing.allocator);
        var next_qs = try testQuorum(next_seed);
        defer next_qs.deinit(testing.allocator);
        const genesis = testGenesis(&qs, seed);
        const old_identity: journal_mod.Identity = .{ .node_id = qs.validators[0], .root_network_id = genesis.network_id };
        var trust = try policy.Policy.init(testing.allocator, genesis.policy);
        defer trust.deinit();
        const parent: session.ParentEpoch = .{ .network_id = genesis.network_id, .generation = 0, .policy = &trust };
        var manifest = try migration.Manifest.init(testing.allocator, .{
            .parent_network_id = genesis.network_id,
            .generation = 1,
            .terminal_slot = 2,
            .checkpoint_digest = session.checkpointDigest("state before migration"),
            .successor_policy = .{ .anchors = next_qs.validators, .max_faulty_anchors = 0, .min_slice_anchors = 1 },
        });
        defer manifest.deinit();
        const value = try manifest.encode(testing.allocator);
        defer testing.allocator.free(value);
        var terminal_envelope: ?[]u8 = null;
        defer if (terminal_envelope) |bytes| testing.allocator.free(bytes);
        {
            const managed = try session.Session.createGenesis(testing.allocator, genesis);
            defer managed.deinit();
            var store = try Store.create(testing.allocator, testing.io, old_path, managed, .{});
            defer store.deinit();
            try drain(&store, managed);
            try managed.proposeApplication("state before migration");
            try drain(&store, managed);
            try managed.proposeMigration(value);
            while (try managed.popEffect()) |effect| {
                if (effect.* == .persist_retirement) {
                    const own = effect.persist_retirement.own_envelope orelse {
                        if (separate_marker) {
                            try testing.expect(try store.persistEffect(managed));
                        } else {
                            // Model imported own-only crash history. No network
                            // output is dispatched between this omitted marker
                            // and the terminal own record below; production
                            // Store consumers must persist every offered gate.
                            try managed.commitEffect();
                        }
                        continue;
                    };
                    terminal_envelope = try testing.allocator.dupe(u8, own);
                    if (separate_marker) {
                        try testing.expect(try store.persistEffect(managed));
                    } else {
                        // Crash window of an own-envelope journal without any
                        // separate retirement/externalized/application record.
                        try store.journal.append(.own_envelope, own);
                    }
                    break; // no terminal broadcast or later effect dispatched
                }
                if (!try store.persistEffect(managed)) try managed.commitEffect();
            }
            try testing.expect(terminal_envelope != null);
        }
        {
            var store = try Store.open(testing.allocator, testing.io, old_path, old_identity, .{});
            defer store.deinit();
            var recovered = try store.recover();
            defer recovered.deinit();
            const retired = try recovered.restoreGenesis(genesis);
            defer retired.deinit();
            try testing.expectEqual(session.Status.retired, retired.status());
            try testing.expectError(error.SessionRetired, retired.proposeApplication("fork old history"));
            try drain(&store, retired);
        }
        const next_host = testGenesis(&next_qs, next_seed).host;
        const cert = [_][]const u8{terminal_envelope.?};
        const successor_identity: journal_mod.Identity = .{ .node_id = next_qs.validators[0], .root_network_id = manifest.successorNetworkId() };
        // Crash immediately after durable successor install, before first vote.
        {
            const successor = try session.Session.createSuccessor(testing.allocator, parent, value, &cert, "state before migration", next_host);
            defer successor.deinit();
            var store = try Store.create(testing.allocator, testing.io, new_path, successor, .{});
            defer store.deinit();
            try testing.expectError(error.ActivationPending, successor.proposeApplication("too soon"));
            try testing.expect(try store.persistEffect(successor));
        }
        {
            var store = try Store.open(testing.allocator, testing.io, new_path, successor_identity, .{});
            defer store.deinit();
            var recovered = try store.recover();
            defer recovered.deinit();
            try testing.expectEqualStrings("state before migration", recovered.checkpoint);
            const successor = try recovered.restoreSuccessor(parent, next_host);
            defer successor.deinit();
            try testing.expectEqual(@as(u64, 3), successor.nextSlot());
            try testing.expectEqualSlices(u8, value, successor.previousValue());
            try drain(&store, successor);
            try successor.proposeApplication("new pool makes progress");
            try drain(&store, successor);
            try testing.expectEqual(@as(u64, 4), successor.nextSlot());
            var wrong_parent = parent;
            wrong_parent.network_id[0] ^= 1;
            try testing.expectError(error.WrongParentDomain, recovered.restoreSuccessor(wrong_parent, next_host));
        }
    }
}

test "managed store rejects a quorum revision recorded after its first signed slot" {
    var original_tmp = testing.tmpDir(.{});
    defer original_tmp.cleanup();
    var reordered_tmp = testing.tmpDir(.{});
    defer reordered_tmp.cleanup();
    var original_buffer: [256]u8 = undefined;
    var reordered_buffer: [256]u8 = undefined;
    const original_path = try testPath(&original_tmp, &original_buffer);
    const reordered_path = try testPath(&reordered_tmp, &reordered_buffer);
    const seed: [32]u8 = @splat(0x66);
    var qs = try testQuorum(seed);
    defer qs.deinit(testing.allocator);
    const genesis = testGenesis(&qs, seed);
    const identity: journal_mod.Identity = .{ .node_id = qs.validators[0], .root_network_id = genesis.network_id };
    {
        const managed = try session.Session.createGenesis(testing.allocator, genesis);
        defer managed.deinit();
        var store = try Store.create(testing.allocator, testing.io, original_path, managed, .{});
        defer store.deinit();
        try drain(&store, managed);
        try managed.proposeApplication("first");
        try drain(&store, managed);
        // Keeping the same qset makes every signed hash valid even when the
        // activation record is moved past the slot's first signed envelope.
        try store.changeQuorum(managed, 2, &qs);
        try managed.proposeApplication("second");
        try drain(&store, managed);
    }
    var original = try journal_mod.Journal.open(testing.allocator, testing.io, original_path, identity, .{});
    defer original.deinit();
    var log = try original.recover();
    defer log.deinit();
    {
        var reordered = try journal_mod.Journal.create(testing.allocator, testing.io, reordered_path, identity, .{});
        defer reordered.deinit();
        var delayed: ?[]const u8 = null;
        var moved = false;
        for (log.records) |record| {
            if (record.kind == .quorum_change) {
                delayed = record.payload;
                continue;
            }
            try reordered.append(record.kind, record.payload);
            if (record.kind == .own_envelope and delayed != null) {
                const meta = try core.host.envelopeMeta(testing.allocator, genesis.network_id, record.payload);
                if (meta.slot == 2) {
                    try reordered.append(.quorum_change, delayed.?);
                    delayed = null;
                    moved = true;
                }
            }
        }
        try testing.expect(moved);
        try testing.expect(delayed == null);
    }
    var store = try Store.open(testing.allocator, testing.io, reordered_path, identity, .{});
    defer store.deinit();
    var recovered = store.recover() catch |err| {
        try testing.expectEqual(error.InvalidQuorumHistory, err);
        try testing.expect(store.journal.failed);
        return;
    };
    defer recovered.deinit();
    return error.AcceptedLateQuorumRevision;
}
