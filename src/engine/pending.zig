//! QSet parking (design §5.4 pending.zig bullet): envelopes referencing
//! unknown qset hashes are parked until `qset_received` supplies the qset.
//! Caps: engine-wide envelope count and BYTE budget, per-node count; FIFO
//! eviction, each eviction signaled as phase_event(parked_evicted) by the
//! engine (evicting a PAST input must not consume the current input's 1:1
//! input_status). EXTERNALIZE statements never park (singleton qset).

const std = @import("std");
const stored = @import("stored.zig");

pub const Parked = struct {
    needed_hash: [32]u8,
    env: stored.StoredEnvelope,
};

pub const Pending = struct {
    gpa: std.mem.Allocator,
    max_envelopes: u32,
    max_bytes: u32,
    max_per_node: u32 = 4,
    /// FIFO of parked envelopes (oldest first).
    items: std.ArrayList(Parked) = .empty,
    total_bytes: usize = 0,

    pub fn init(gpa: std.mem.Allocator, max_envelopes: u32, max_bytes: u32) Pending {
        return .{ .gpa = gpa, .max_envelopes = max_envelopes, .max_bytes = max_bytes };
    }

    pub fn deinit(self: *Pending) void {
        for (self.items.items) |*p| p.env.deinit(self.gpa);
        self.items.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn count(self: *const Pending) usize {
        return self.items.items.len;
    }

    fn countForNode(self: *const Pending, node: [32]u8) u32 {
        var n: u32 = 0;
        for (self.items.items) |*p| {
            if (std.mem.eql(u8, &p.env.statement.node_id, &node)) n += 1;
        }
        return n;
    }

    /// Park an envelope awaiting `needed_hash`. Takes ownership of `env`
    /// (even on rejection, in which case it is freed). Returns the list of
    /// EVICTED envelopes' slots for phase_event signaling — caller frees the
    /// returned slice. Rejects (frees env, returns null) when the per-node
    /// cap is hit — the engine reports over_limit for the CURRENT input.
    pub fn park(self: *Pending, needed_hash: [32]u8, env: stored.StoredEnvelope, evicted_slots: *std.ArrayList(u64)) !bool {
        var owned = env;
        if (self.countForNode(owned.statement.node_id) >= self.max_per_node) {
            owned.deinit(self.gpa);
            return false;
        }
        self.items.append(self.gpa, .{ .needed_hash = needed_hash, .env = owned }) catch |err| {
            owned.deinit(self.gpa);
            return err;
        };
        self.total_bytes += owned.byteSize();
        // FIFO-evict past inputs until within caps (never the one just added
        // unless it alone exceeds the byte budget).
        while ((self.items.items.len > self.max_envelopes or self.total_bytes > self.max_bytes) and self.items.items.len > 0) {
            var victim = self.items.orderedRemove(0);
            self.total_bytes -= victim.env.byteSize();
            const victim_slot = victim.env.statement.slot;
            victim.env.deinit(self.gpa); // free BEFORE the fallible append: no leak on OOM
            try evicted_slots.append(self.gpa, victim_slot);
        }
        return true;
    }

    /// Remove and return every envelope parked on `hash`, oldest first.
    /// Caller takes ownership of the returned StoredEnvelopes and frees the
    /// slice.
    pub fn take(self: *Pending, hash: [32]u8) ![]stored.StoredEnvelope {
        var out: std.ArrayList(stored.StoredEnvelope) = .empty;
        errdefer {
            for (out.items) |*e| e.deinit(self.gpa);
            out.deinit(self.gpa);
        }
        var i: usize = 0;
        while (i < self.items.items.len) {
            if (std.mem.eql(u8, &self.items.items[i].needed_hash, &hash)) {
                var p = self.items.orderedRemove(i);
                self.total_bytes -= p.env.byteSize();
                out.append(self.gpa, p.env) catch |err| {
                    p.env.deinit(self.gpa);
                    return err;
                };
            } else {
                i += 1;
            }
        }
        return out.toOwnedSlice(self.gpa);
    }

    /// Drop all parked envelopes for slots < max_slot (purge support).
    pub fn purgeBelow(self: *Pending, max_slot: u64) void {
        var i: usize = 0;
        while (i < self.items.items.len) {
            if (self.items.items[i].env.statement.slot < max_slot) {
                var p = self.items.orderedRemove(i);
                self.total_bytes -= p.env.byteSize();
                p.env.deinit(self.gpa);
            } else {
                i += 1;
            }
        }
    }
};
