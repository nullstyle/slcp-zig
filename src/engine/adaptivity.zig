//! Owned, immutable local quorum revisions. Runtime activation lives in
//! Engine; this module contains no consensus transitions or persistence.
const std = @import("std");
const qset = @import("qset.zig");
const policy_mod = @import("../adaptivity/policy.zig");
const canonical = @import("../canonical.zig");
const crypto = @import("../crypto.zig");

pub const Options = struct {
    policy: policy_mod.Config,
    admission_floor: u64,
    max_revisions: u32 = 64,
};

pub const Error = policy_mod.InitError || policy_mod.AssessError || error{
    EngineFailed,
    EngineNotPristine,
    AdaptivityAlreadyEnabled,
    AdaptivityDisabled,
    InvalidRevisionLimit,
    InvalidQuorumSet,
    QuorumOutsidePolicy,
    EffectsNotDrained,
    ChangeAlreadyPrepared,
    NoPreparedChange,
    BoundaryNotIncreasing,
    SlotAlreadyAdmitted,
    RevisionLimitExceeded,
};

pub const ChangeView = struct {
    first_slot: u64,
    policy_fingerprint: [32]u8,
    qset_hash: [32]u8,
    /// Framed, normalized QuorumSet. Borrowed until commit/abort for a
    /// prepared view, or until purge/deinit for an installed revision view.
    quorum_bytes: []const u8,
};

pub const Revision = struct {
    first_slot: u64,
    quorum_set: qset.QuorumSetOwned,
    excised: ?qset.QuorumSetOwned,
    hash: [32]u8,
    framed: []u8,

    pub fn create(gpa: std.mem.Allocator, policy: *const policy_mod.Policy, node: [32]u8, first_slot: u64, spec: *const qset.QuorumSetOwned) Error!*Revision {
        const assessment = try policy.assess(spec);
        if (!assessment.permitted) return error.QuorumOutsidePolicy;
        var owned = try qset.clone(gpa, spec);
        errdefer owned.deinit(gpa);
        qset.validateAndNormalize(gpa, &owned) catch |err| return mapError(err);
        var excised = qset.exciseNode(gpa, &owned, node) catch |err| return mapError(err);
        errdefer if (excised) |*e| e.deinit(gpa);
        const flat = qset.canonicalBytes(gpa, &owned) catch |err| return mapError(err);
        defer gpa.free(flat);
        const framed = canonical.frameFlat(gpa, flat) catch |err| return mapError(err);
        errdefer gpa.free(framed);
        const result = try gpa.create(Revision);
        result.* = .{
            .first_slot = first_slot,
            .quorum_set = owned,
            .excised = excised,
            .hash = crypto.qsetHash(flat),
            .framed = framed,
        };
        return result;
    }

    pub fn destroy(self: *Revision, gpa: std.mem.Allocator) void {
        self.quorum_set.deinit(gpa);
        if (self.excised) |*e| e.deinit(gpa);
        gpa.free(self.framed);
        gpa.destroy(self);
    }

    pub fn view(self: *const Revision, fingerprint: [32]u8) ChangeView {
        return .{ .first_slot = self.first_slot, .policy_fingerprint = fingerprint, .qset_hash = self.hash, .quorum_bytes = self.framed };
    }
};

pub const State = struct {
    policy: policy_mod.Policy,
    fingerprint: [32]u8,
    floor: u64,
    highest_admitted: ?u64 = null,
    max_revisions: u32,
    revisions: std.ArrayList(*Revision) = .empty,
    prepared: ?*Revision = null,

    pub fn deinit(self: *State, gpa: std.mem.Allocator) void {
        if (self.prepared) |r| r.destroy(gpa);
        for (self.revisions.items) |r| r.destroy(gpa);
        self.revisions.deinit(gpa);
        self.policy.deinit();
    }

    pub fn forSlot(self: *const State, slot: u64) ?*Revision {
        if (slot < self.floor) return null;
        var i = self.revisions.items.len;
        while (i > 0) {
            i -= 1;
            const r = self.revisions.items[i];
            if (r.first_slot <= slot) return r;
        }
        return null;
    }
};

fn mapError(err: anyerror) Error {
    return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidQuorumSet;
}
