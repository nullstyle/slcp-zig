//! Whole managed Sessions driven through their public effects: application
//! drivers, local quorum revisions, terminal consensus, and disjoint successors.
//! Persistence effects are acknowledged by an in-memory journal; native disk
//! crash tests exercise the concrete durable adapter separately.
const std = @import("std");
const core = @import("slcp-core");
const session = core.adaptivity.session;
const migration = core.adaptivity.migration;
const policy = core.adaptivity.policy;
const Session = session.Session;
const max_peers = 7;

const AppKind = enum { maximum_register, consecutive_counter };
const App = struct {
    kind: AppKind = .maximum_register,
    value: u64 = 0,
    control_leaks: usize = 0,
    applied: usize = 0,

    fn driver(self: *App) core.driver.Driver {
        return .{ .ctx = self, .validate_value = validate, .combine_candidates = combine };
    }
    fn validate(ctx: *anyopaque, _: u64, bytes: []const u8, _: bool) core.driver.Validity {
        const self: *App = @ptrCast(@alignCast(ctx));
        if (bytes.len != 8) {
            self.control_leaks += 1;
            return .invalid;
        }
        const value = std.mem.readInt(u64, bytes[0..8], .big);
        return switch (self.kind) {
            .maximum_register => if (value > 0) .valid else .invalid,
            .consecutive_counter => if (value == self.value + 1) .valid else .invalid,
        };
    }
    fn combine(ctx: *anyopaque, _: u64, candidates: []const []const u8, gpa: std.mem.Allocator, out: *std.ArrayList(u8)) core.driver.DriverError!void {
        const self: *App = @ptrCast(@alignCast(ctx));
        var maximum: u64 = 0;
        for (candidates) |candidate| {
            if (candidate.len != 8) {
                self.control_leaks += 1;
                return error.DriverFault;
            }
            maximum = @max(maximum, std.mem.readInt(u64, candidate[0..8], .big));
        }
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, maximum, .big);
        try out.appendSlice(gpa, &bytes);
    }
    fn checkpoint(self: *const App) [8]u8 {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, self.value, .big);
        return bytes;
    }
    fn apply(self: *App, value: []const u8) !void {
        try std.testing.expectEqual(@as(usize, 8), value.len);
        const next = std.mem.readInt(u64, value[0..8], .big);
        if (self.kind == .consecutive_counter) try std.testing.expectEqual(self.value + 1, next);
        self.value = next;
        self.applied += 1;
    }
};

const Timer = struct { slot: u64, id: core.engine.TimerId, deadline: u64 };
const Peer = struct {
    managed: ?*Session = null,
    app: App = .{},
    online: bool = true,
    journal: std.ArrayList([]const u8) = .empty,
    retirement: ?[]u8 = null,
    certificate: ?[]u8 = null,
    timers: [2]?Timer = @splat(null),
    activations: usize = 0,
    revisions: usize = 0,
    initial_qset_hash: [32]u8 = @splat(0),
    expected_revision: ?struct { first_slot: u64, hash: [32]u8 } = null,
    old_revision_emissions: usize = 0,
    new_revision_emissions: usize = 0,
};
const Event = struct { to: usize, bytes: []u8, quorum: bool = false };
const QuorumBytes = struct { hash: [32]u8, bytes: []u8 };
const Applied = struct { slot: u64, value: u64 };
const ParentInstall = struct { parent: session.ParentEpoch, manifest: []const u8, certificate: []const []const u8, checkpoint: []const u8 };

const Cluster = struct {
    gpa: std.mem.Allocator,
    count: usize,
    peers: [max_peers]Peer = @splat(.{}),
    ids: [max_peers][32]u8 = undefined,
    seeds: [max_peers][32]u8 = undefined,
    events: std.ArrayList(Event) = .empty,
    head: usize = 0,
    quorums: std.ArrayList(QuorumBytes) = .empty,
    outcomes: std.ArrayList(Applied) = .empty,
    now: u64 = 0,

    fn create(gpa: std.mem.Allocator, kind: AppKind, seed_start: u8, count: usize, install: ?ParentInstall) !*Cluster {
        const self = try gpa.create(Cluster);
        self.* = .{ .gpa = gpa, .count = count };
        errdefer self.destroy();
        for (0..count) |i| {
            self.seeds[i] = @splat(seed_start + @as(u8, @intCast(i)));
            self.ids[i] = try core.crypto.publicKeyFromSeed(self.seeds[i]);
            self.peers[i].app.kind = kind;
            if (install) |prior| self.peers[i].app.value = std.mem.readInt(u64, prior.checkpoint[0..8], .big);
        }
        var qs = self.quorum();
        try self.rememberQuorum(&qs);
        for (0..count) |i| {
            self.peers[i].initial_qset_hash = self.quorums.items[0].hash;
            const host: session.HostOptions = .{
                .node_id = self.ids[i],
                .secret_seed = self.seeds[i],
                .quorum_set = &qs,
                .driver = self.peers[i].app.driver(),
                .authorize_migration = authorize,
            };
            self.peers[i].managed = if (install) |prior|
                try Session.createSuccessor(gpa, prior.parent, prior.manifest, prior.certificate, prior.checkpoint, host)
            else
                try Session.createGenesis(gpa, .{
                    .network_id = @splat(55),
                    .policy = self.policyConfig(),
                    .checkpoint = &self.peers[i].app.checkpoint(),
                    .host = host,
                });
            try std.testing.expectEqual(session.Status.activation_pending, self.peers[i].managed.?.status());
            var proposal: [8]u8 = @splat(0);
            proposal[7] = 1;
            try std.testing.expectError(error.ActivationPending, self.peers[i].managed.?.proposeApplication(&proposal));
            try self.drain(i);
        }
        return self;
    }

    fn authorize(_: *anyopaque, _: *const migration.Manifest) bool {
        // Test operator policy explicitly authorizes fixture manifests. Real
        // applications must make their own trust/administrative decision.
        return true;
    }
    fn policyConfig(self: *const Cluster) policy.Config {
        return .{ .anchors = self.ids[0..self.count], .max_faulty_anchors = 1, .min_slice_anchors = @intCast((self.count + 1) / 2 + 1) };
    }
    fn quorum(self: *Cluster) core.qset.QuorumSetOwned {
        return .{ .threshold = self.policyConfig().min_slice_anchors, .validators = self.ids[0..self.count], .inner_sets = &.{} };
    }
    fn rememberQuorum(self: *Cluster, qs: *const core.qset.QuorumSetOwned) !void {
        var normalized = try core.qset.clone(self.gpa, qs);
        defer normalized.deinit(self.gpa);
        try core.qset.validateAndNormalize(self.gpa, &normalized);
        const hash = try core.qset.hashNormalized(self.gpa, &normalized);
        for (self.quorums.items) |record| if (std.mem.eql(u8, &record.hash, &hash)) return;
        const flat = try core.qset.canonicalBytes(self.gpa, &normalized);
        defer self.gpa.free(flat);
        const framed = try core.canonical.frameFlat(self.gpa, flat);
        errdefer self.gpa.free(framed);
        try self.quorums.append(self.gpa, .{ .hash = hash, .bytes = framed });
    }
    fn destroy(self: *Cluster) void {
        for (self.peers[0..self.count]) |*peer| {
            if (peer.managed) |managed| managed.deinit();
            for (peer.journal.items) |bytes| self.gpa.free(bytes);
            peer.journal.deinit(self.gpa);
            if (peer.retirement) |bytes| self.gpa.free(bytes);
            if (peer.certificate) |bytes| self.gpa.free(bytes);
        }
        for (self.events.items[self.head..]) |event| self.gpa.free(event.bytes);
        self.events.deinit(self.gpa);
        for (self.quorums.items) |record| self.gpa.free(record.bytes);
        self.quorums.deinit(self.gpa);
        self.outcomes.deinit(self.gpa);
        self.gpa.destroy(self);
    }
    fn journal(self: *Cluster, peer: *Peer, bytes: []const u8) !void {
        const owned = try self.gpa.dupe(u8, bytes);
        errdefer self.gpa.free(owned);
        try peer.journal.append(self.gpa, owned);
    }
    fn enqueue(self: *Cluster, to: usize, bytes: []const u8, quorum_message: bool) !void {
        const owned = try self.gpa.dupe(u8, bytes);
        errdefer self.gpa.free(owned);
        try self.events.append(self.gpa, .{ .to = to, .bytes = owned, .quorum = quorum_message });
    }
    fn drain(self: *Cluster, index: usize) !void {
        const peer = &self.peers[index];
        const managed = peer.managed.?;
        while (true) {
            var application_slot: ?u64 = null;
            while (try managed.popEffect()) |effect| {
                switch (effect.*) {
                    .persist_activation => |activation| {
                        try std.testing.expectEqual(managed.networkId(), activation.network_id);
                        try std.testing.expectEqual(managed.checkpoint(), session.checkpointDigest(activation.checkpoint));
                        peer.activations += 1;
                    },
                    .persist_retirement => |retirement| {
                        if (peer.retirement == null) peer.retirement = try self.gpa.dupe(u8, retirement.manifest);
                        try std.testing.expectEqualSlices(u8, peer.retirement.?, retirement.manifest);
                        if (retirement.own_envelope) |bytes| try self.journal(peer, bytes);
                    },
                    .terminal => |terminal| {
                        try std.testing.expectEqual(session.Status.retired, managed.status());
                        try std.testing.expectEqualSlices(u8, peer.retirement.?, terminal.manifest);
                    },
                    .application => |delivery| {
                        try peer.app.apply(delivery.payload);
                        application_slot = delivery.slot;
                        if (index == 0) try self.outcomes.append(self.gpa, .{ .slot = delivery.slot, .value = peer.app.value });
                    },
                    .engine => |raw| switch (raw.*) {
                        .persist_own_envelope => |record| try self.journal(peer, record.bytes),
                        .broadcast_envelope => |record| {
                            var persisted = false;
                            for (peer.journal.items) |bytes| if (std.mem.eql(u8, bytes, record.bytes)) {
                                persisted = true;
                                break;
                            };
                            try std.testing.expect(persisted);
                            const meta = try core.host.envelopeMeta(self.gpa, managed.networkId(), record.bytes);
                            if (meta.kind == .externalize) {
                                const ext = try migration.verifyExternalize(self.gpa, managed.networkId(), record.bytes);
                                if (peer.expected_revision) |revision| {
                                    if (ext.slot < revision.first_slot) {
                                        try std.testing.expectEqual(peer.initial_qset_hash, ext.commit_qset_hash);
                                        peer.old_revision_emissions += 1;
                                    } else {
                                        try std.testing.expectEqual(revision.hash, ext.commit_qset_hash);
                                        peer.new_revision_emissions += 1;
                                    }
                                }
                                if (migration.isManifest(ext.value)) {
                                    try std.testing.expectEqual(session.Status.retired, managed.status());
                                    if (peer.certificate == null) peer.certificate = try self.gpa.dupe(u8, record.bytes);
                                }
                            }
                            for (0..self.count) |to| if (to != index) try self.enqueue(to, record.bytes, false);
                        },
                        .forward_envelope => {}, // full mesh already delivers the authenticated original
                        .arm_timer => |timer| peer.timers[@backingInt(timer.timer)] = .{ .slot = timer.slot, .id = timer.timer, .deadline = self.now + timer.delay_ms },
                        .cancel_timer => |timer| peer.timers[@backingInt(timer.timer)] = null,
                        .request_qset => |request| {
                            var found = false;
                            for (self.quorums.items) |record| if (std.mem.eql(u8, &record.hash, &request.hash)) {
                                try self.enqueue(index, record.bytes, true);
                                found = true;
                                break;
                            };
                            try std.testing.expect(found);
                        },
                        .externalized => return error.UnmanagedExternalization,
                        .input_status, .phase_event => {},
                    },
                }
                try managed.commitEffect();
            }
            if (application_slot) |slot| {
                try managed.acknowledgeApplied(slot, &peer.app.checkpoint());
            } else break;
        }
    }
    fn step(self: *Cluster) !bool {
        if (self.head < self.events.items.len) {
            const event = self.events.items[self.head];
            self.head += 1;
            defer self.gpa.free(event.bytes);
            const peer = &self.peers[event.to];
            if (!peer.online or peer.managed.?.status() == .retired) return true;
            if (event.quorum) {
                try peer.managed.?.receiveQuorumSet(event.bytes);
            } else peer.managed.?.receiveEnvelope(event.bytes) catch |err| switch (err) {
                error.SlotNotCurrent => return true, // duplicate from an already-applied slot
                else => return err,
            };
            try self.drain(event.to);
            return true;
        }
        self.events.clearRetainingCapacity();
        self.head = 0;
        var first: ?struct { peer: usize, timer: Timer } = null;
        for (self.peers[0..self.count], 0..) |*peer, i| {
            if (!peer.online or peer.managed.?.status() != .active) continue;
            for (peer.timers) |timer| if (timer) |t| {
                if (first == null or t.deadline < first.?.timer.deadline) first = .{ .peer = i, .timer = t };
            };
        }
        const next = first orelse return false;
        self.now = @max(self.now, next.timer.deadline);
        self.peers[next.peer].timers[@backingInt(next.timer.id)] = null;
        self.peers[next.peer].managed.?.timerFired(next.timer.slot, next.timer.id) catch |err| switch (err) {
            error.SlotNotCurrent => return true,
            else => return err,
        };
        try self.drain(next.peer);
        return true;
    }
    fn application(self: *Cluster) !void {
        const slot = self.peers[0].managed.?.nextSlot();
        for (self.peers[0..self.count], 0..) |*peer, i| {
            if (!peer.online) continue;
            const value = peer.app.value + 1 + if (peer.app.kind == .maximum_register) @as(u64, @intCast(i)) else 0;
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, value, .big);
            try peer.managed.?.proposeApplication(&bytes);
            try self.drain(i);
        }
        for (0..50000) |_| {
            var complete = true;
            for (self.peers[0..self.count]) |*peer| if (peer.managed.?.nextSlot() != slot + 1) {
                complete = false;
                break;
            };
            if (complete) {
                for (self.peers[0..self.count]) |*peer| {
                    try std.testing.expectEqual(self.peers[0].app.value, peer.app.value);
                    try std.testing.expectEqual(@as(usize, 0), peer.app.control_leaks);
                }
                return;
            }
            if (!try self.step()) break;
        }
        return error.ApplicationDidNotConverge;
    }
    fn manifest(self: *const Cluster, seed_start: u8, count: usize) ![]u8 {
        var anchors: [max_peers]policy.NodeId = undefined;
        for (0..count) |i| anchors[i] = try core.crypto.publicKeyFromSeed(@splat(seed_start + @as(u8, @intCast(i))));
        var value = try migration.Manifest.init(self.gpa, .{
            .parent_network_id = self.peers[0].managed.?.networkId(),
            .generation = self.peers[0].managed.?.generation() + 1,
            .terminal_slot = self.peers[0].managed.?.nextSlot(),
            .checkpoint_digest = self.peers[0].managed.?.checkpoint(),
            .successor_policy = .{ .anchors = anchors[0..count], .max_faulty_anchors = 1, .min_slice_anchors = @intCast((count + 1) / 2 + 1) },
        });
        defer value.deinit();
        return value.encode(self.gpa);
    }
    fn proposeMigration(self: *Cluster, bytes: []const u8) !void {
        for (self.peers[0..self.count], 0..) |*peer, i| {
            if (!peer.online) continue;
            try peer.managed.?.proposeMigration(bytes);
            try self.drain(i);
        }
    }
    fn finishMigration(self: *Cluster) !void {
        for (0..50000) |_| {
            var complete = true;
            for (self.peers[0..self.count]) |*peer| if (peer.managed.?.status() != .retired or peer.certificate == null) {
                complete = false;
                break;
            };
            if (complete) return;
            if (!try self.step()) break;
        }
        return error.MigrationDidNotConverge;
    }
    fn certificate(self: *const Cluster) ![][]const u8 {
        const result = try self.gpa.alloc([]const u8, self.count);
        errdefer self.gpa.free(result);
        var indexed: [max_peers]usize = undefined;
        for (0..self.count) |i| indexed[i] = i;
        std.mem.sort(usize, indexed[0..self.count], self, struct {
            fn less(cluster: *const Cluster, a: usize, b: usize) bool {
                return std.mem.order(u8, &cluster.ids[a], &cluster.ids[b]) == .lt;
            }
        }.less);
        for (indexed[0..self.count], 0..) |index, i| result[i] = self.peers[index].certificate orelse return error.MissingCertificate;
        return result;
    }
    fn parent(self: *const Cluster) session.ParentEpoch {
        const first = self.peers[0].managed.?;
        return .{ .network_id = first.networkId(), .generation = first.generation(), .policy = first.trustPolicy() };
    }
};

fn repeatedMigration(kind: AppKind) !void {
    const gpa = std.testing.allocator;
    const old = try Cluster.create(gpa, kind, 1, 4, null);
    defer old.destroy();
    try old.application();
    try old.application();
    const first_manifest = try old.manifest(32, 4);
    defer gpa.free(first_manifest);
    try old.proposeMigration(first_manifest);
    try old.finishMigration();
    const first_certificate = try old.certificate();
    defer gpa.free(first_certificate);
    const first_checkpoint = old.peers[0].app.checkpoint();
    const next = try Cluster.create(gpa, kind, 32, 4, .{ .parent = old.parent(), .manifest = first_manifest, .certificate = first_certificate[0..3], .checkpoint = &first_checkpoint });
    defer next.destroy();
    try std.testing.expectEqual(@as(u64, 1), next.peers[0].managed.?.generation());
    try std.testing.expectEqual(@as(u64, 4), next.peers[0].managed.?.nextSlot());
    try std.testing.expectError(error.SessionRetired, old.peers[0].managed.?.proposeMigration(first_manifest));
    try std.testing.expectError(error.SlotNotCurrent, next.peers[0].managed.?.receiveEnvelope(first_certificate[0]));
    try std.testing.expectError(error.InvalidSignature, migration.verifyExternalize(gpa, next.peers[0].managed.?.networkId(), first_certificate[0]));
    try next.application();
    try next.application();
    try std.testing.expectEqual(@as(u64, 4), next.outcomes.items[0].slot);
    try std.testing.expectEqual(@as(u64, 5), next.outcomes.items[1].slot);
    const second_manifest = try next.manifest(64, 4);
    defer gpa.free(second_manifest);
    try next.proposeMigration(second_manifest);
    try next.finishMigration();
    const second_certificate = try next.certificate();
    defer gpa.free(second_certificate);
    const second_checkpoint = next.peers[0].app.checkpoint();
    const last = try Cluster.create(gpa, kind, 64, 4, .{ .parent = next.parent(), .manifest = second_manifest, .certificate = second_certificate[0..3], .checkpoint = &second_checkpoint });
    defer last.destroy();
    try std.testing.expectEqual(@as(u64, 2), last.peers[0].managed.?.generation());
    try last.application();
    try last.application();
    try std.testing.expectEqual(@as(u64, 7), last.outcomes.items[0].slot);
    try std.testing.expectEqual(@as(u64, 8), last.outcomes.items[1].slot);
    if (kind == .consecutive_counter) try std.testing.expectEqual(@as(u64, 6), last.peers[0].app.value);
    for ([_]*Cluster{ old, next, last }) |cluster| for (cluster.peers[0..cluster.count]) |*peer| {
        try std.testing.expectEqual(@as(usize, 1), peer.activations);
        try std.testing.expectEqual(@as(usize, 2), peer.app.applied);
        try std.testing.expectEqual(@as(usize, 0), peer.app.control_leaks);
    };
}

test "managed consensus migrates disjoint pools twice with a stateless register driver" {
    try repeatedMigration(.maximum_register);
}
test "managed consensus migrates disjoint pools twice with a state-dependent counter driver" {
    try repeatedMigration(.consecutive_counter);
}

test "seven managed peers revise local subsets at different slot boundaries" {
    const gpa = std.testing.allocator;
    const cluster = try Cluster.create(gpa, .consecutive_counter, 100, 7, null);
    defer cluster.destroy();
    for (0..7) |i| {
        var members: [6]core.qset.NodeId = undefined;
        var count: usize = 0;
        for (cluster.ids[0..7], 0..) |id, member| if (member != (i + 1) % 7) {
            members[count] = id;
            count += 1;
        };
        var changed: core.qset.QuorumSetOwned = .{ .threshold = 5, .validators = &members, .inner_sets = &.{} };
        try core.qset.validateAndNormalize(gpa, &changed);
        // No singleton/nested normalization allocations occur for this flat,
        // stack-backed set; callers own the original arrays throughout.
        try cluster.rememberQuorum(&changed);
        const view = try cluster.peers[i].managed.?.prepareQuorumChange(2 + i % 3, &changed);
        try std.testing.expectEqual(@as(u64, 2 + i % 3), view.first_slot);
        cluster.peers[i].expected_revision = .{ .first_slot = view.first_slot, .hash = view.qset_hash };
        // The in-memory test journal synchronously persists this exact view.
        cluster.peers[i].revisions += 1;
        try cluster.peers[i].managed.?.commitQuorumChange();
    }
    for (0..5) |_| try cluster.application();
    for (cluster.peers[0..7]) |*peer| {
        try std.testing.expectEqual(@as(u64, 5), peer.app.value);
        try std.testing.expectEqual(@as(usize, 1), peer.revisions);
        try std.testing.expect(peer.old_revision_emissions > 0);
        try std.testing.expect(peer.new_revision_emissions > 0);
    }
}

test "actual terminal emissions require an old quorum and reject delayed or conflicting certificates" {
    const gpa = std.testing.allocator;
    const old = try Cluster.create(gpa, .consecutive_counter, 1, 4, null);
    defer old.destroy();
    try old.application();
    const terminal = try old.manifest(32, 4);
    defer gpa.free(terminal);
    const conflicting = try old.manifest(64, 4);
    defer gpa.free(conflicting);
    try old.proposeMigration(terminal);
    try old.finishMigration();
    const certificates = try old.certificate();
    defer gpa.free(certificates);
    const parent = old.parent();
    try std.testing.expectError(error.InsufficientSigners, migration.verifyCertificate(gpa, parent.policy, parent.network_id, 1, terminal, certificates[0..2]));
    try std.testing.expectError(error.DuplicateSigner, migration.verifyCertificate(gpa, parent.policy, parent.network_id, 1, terminal, &.{ certificates[0], certificates[0], certificates[1] }));
    try std.testing.expectError(error.WrongTerminalValue, migration.verifyCertificate(gpa, parent.policy, parent.network_id, 1, conflicting, certificates[0..3]));
    _ = try migration.verifyCertificate(gpa, parent.policy, parent.network_id, 1, terminal, certificates[0..3]);
    const checkpoint = old.peers[0].app.checkpoint();
    const successor = try Cluster.create(gpa, .consecutive_counter, 32, 4, .{ .parent = parent, .manifest = terminal, .certificate = certificates[0..3], .checkpoint = &checkpoint });
    defer successor.destroy();
    try std.testing.expectError(error.WrongParentDomain, migration.verifyCertificate(gpa, successor.parent().policy, successor.parent().network_id, 2, terminal, certificates[0..3]));
    try successor.application();
}

test "losing the old quorum halts migration without authorizing a new pool" {
    const cluster = try Cluster.create(std.testing.allocator, .consecutive_counter, 1, 4, null);
    defer cluster.destroy();
    cluster.peers[2].online = false;
    cluster.peers[3].online = false;
    const terminal = try cluster.manifest(32, 4);
    defer cluster.gpa.free(terminal);
    try cluster.proposeMigration(terminal);
    for (0..500) |_| if (!try cluster.step()) break;
    for (cluster.peers[0..4]) |*peer| {
        try std.testing.expect(peer.managed.?.status() != .retired);
        try std.testing.expect(peer.certificate == null);
        try std.testing.expectEqual(@as(u64, 0), peer.managed.?.generation());
    }
}
