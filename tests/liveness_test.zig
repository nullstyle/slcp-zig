//! Liveness pin for the S8 D1 finding ("state-dependent validate + engine
//! verdict cache + sticky fully_validated: a node one slot behind that sees
//! the next slot's nomination goes permanently mute for that slot; n−t+1
//! such nodes halt the network forever"), promoted from the S8 review
//! harness (worktree s8-d1-typed-safety, tests/d1_review_test.zig) into
//! `zig build test` as `liveness-tests`.
//!
//! N real engines driven through the REAL `slcp.AppNode(App)` driver
//! (validate/combine compiled from the app), a deterministic per-link FIFO
//! bus, a virtual clock, "apply at externalize" done exactly as the AppNode
//! hook does it (decode → App.apply → state; then propose count+1 for the
//! next slot, as the §0 program does), plus a faithful model of the Node's
//! crash/restart path: own.log restore (`restore_own_envelope` of the latest
//! own nom/ballot per slot), the `onPeerUp` re-flood of own latest
//! envelopes, and the `getSlotState(0)` answer (OWN envelopes only, ballot
//! preferred — node.zig answerGetSlotState) — and, per harness node, the
//! REAL `slcp.node.HoldBuffer` + `slcp.node.envelopeMeta` in front of the
//! engine, modelling `Node.applyInput`'s gate through the real
//! `HoldBuffer.admit`: every statement kind for a slot beyond the delivery
//! frontier (`next_deliver`, slot-ordered like the Node's) is held
//! (signature-verified, window 64), a slot whose held EXTERNALIZEs come from
//! a v-blocking set is released early (catch-up), and held statements are
//! released at the frontier after each full drain. Delivery is slot-ordered
//! with the Node's gap-jump rule. `gate = false` bypasses it and is the
//! control that keeps the pin non-vacuous: the harness still reproduces the
//! halt when the gate is off.
//!
//! Every schedule here is one an honest asynchronous network can produce:
//! per-link FIFO order is preserved; only the cross-link interleaving (which
//! reconnect completes first) is chosen.

const std = @import("std");
const slcp = @import("slcp");
const core = @import("slcp-core");
const capnpc = @import("capnpc-zig");

const engine = core.engine;
const crypto = core.crypto;
const qset = core.qset;
const canonical = core.canonical;
const driver = core.driver;
const gen_slcp = core.gen.slcp;
const Validity = slcp.Validity;
const HoldBuffer = slcp.node.HoldBuffer;
const InputItem = slcp.node.InputItem;

const max_n = 7;
const max_slot = 16;

// ---------------------------------------------------------------------------
// Apps under test
// ---------------------------------------------------------------------------

/// The README / examples/counter app, verbatim.
const Counter = struct {
    pub const State = struct { count: u64 = 0 };
    pub const Command = struct { next: u64 };
    pub fn validate(state: State, cmd: Command) Validity {
        if (cmd.next == state.count + 1) return .valid;
        if (cmd.next > state.count + 1) return .maybe_valid; // this node may be behind
        return .invalid;
    }
    pub fn apply(state: State, cmd: Command) State {
        _ = state;
        return .{ .count = cmd.next };
    }
    pub fn proposal(state: State) Command {
        return .{ .next = state.count + 1 };
    }
};

/// Control: same Command, validate does NOT read State.
const Loose = struct {
    pub const State = struct { count: u64 = 0 };
    pub const Command = struct { next: u64 };
    pub fn validate(state: State, cmd: Command) Validity {
        _ = state;
        return if (cmd.next >= 1) .valid else .invalid;
    }
    pub fn apply(state: State, cmd: Command) State {
        _ = state;
        return .{ .count = cmd.next };
    }
    pub fn proposal(state: State) Command {
        return .{ .next = state.count + 1 };
    }
};

// ---------------------------------------------------------------------------
// Own-frame decode (what node.zig's recordOwnLatest keys on)
// ---------------------------------------------------------------------------

const OwnMeta = struct { slot: u64, is_nom: bool };

fn decodeOwnMeta(gpa: std.mem.Allocator, frame: []const u8) !OwnMeta {
    var env_msg = try capnpc.message.Message.init(gpa, frame, .{ .nesting_limit = 32, .traversal_limit_words = core.limits.frozen_max_frame_bytes / 8 });
    defer env_msg.deinit();
    const env_rdr = try gen_slcp.Envelope.Reader.init(&env_msg);
    const stmt_bytes = try env_rdr.getStatementBytes();
    var stmt_msg = try canonical.decodeFlat(gpa, stmt_bytes, .{ .nesting_limit = 32, .traversal_limit_words = core.limits.frozen_max_statement_bytes / 8 });
    defer stmt_msg.deinit();
    const stmt_rdr = try gen_slcp.Statement.Reader.init(&stmt_msg);
    var st = try core.stored.fromReader(gpa, stmt_rdr);
    defer st.deinit(gpa);
    return .{ .slot = st.slot, .is_nom = st.isNomination() };
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const Timer = struct { slot: u64, timer: engine.TimerId, deadline: u64 };
const OwnLatest = struct { nom: ?[]u8 = null, ballot: ?[]u8 = null };
const PumpResult = enum { stopped, quiescent, time_bound };

fn Harness(comptime App: type) type {
    return struct {
        const Self = @This();
        pub const AN = slcp.AppNode(App);

        const Wrap = struct { h: *Self, idx: u8, inner: driver.Driver };

        const Node = struct {
            eng: engine.Engine,
            app: AN,
            wrap: Wrap,
            live: bool = true,
            eng_alive: bool = true,
            inbox: [max_n]std.ArrayList([]u8) = @splat(.empty),
            timers: std.ArrayList(Timer) = .empty,
            ext: std.AutoArrayHashMapUnmanaged(u64, []u8) = .empty,
            /// node.zig `own_latest`: latest own nom/ballot frame per slot.
            own_latest: std.AutoHashMapUnmanaged(u64, OwnLatest) = .empty,
            /// node.zig `hold`: the real HoldBuffer in front of this engine
            /// (S8 D1); `next_deliver` is its frontier — the slot-ordered
            /// delivery frontier, exactly as on the real node: externalized
            /// slots wait in `pending` until contiguous (or the gap-jump).
            hold: HoldBuffer = .{},
            next_deliver: u64 = 1,
            pending: std.AutoHashMapUnmanaged(u64, void) = .empty,
            proposed_upto: u64 = 0,
            pending_propose: ?u64 = null,
            accepted_commit: [max_slot]bool = @splat(false),
            validated: [max_slot]bool = @splat(false),
            validated_before_prev_ext: [max_slot]bool = @splat(false),
            /// [slot][verdict] validate tally as seen at the driver boundary.
            tally: [max_slot][3]u32 = @splat(@splat(0)),
            status: [8]u32 = @splat(0),
            persist_count: usize = 0,
            broadcasts: usize = 0,
            restarts: u32 = 0,
        };

        gpa: std.mem.Allocator,
        n: u8,
        nodes: []Node,
        shared: qset.QuorumSetOwned,
        shared_framed: []u8,
        shared_hash: [32]u8,
        network_id: [32]u8,
        seeds: [max_n][32]u8 = undefined,
        pks: [max_n][32]u8 = undefined,
        now: u64 = 0,
        rr: u8 = 0,
        steps: u64 = 0,
        trace: bool = false,
        /// Delivery preference: for nodes in `prefer_mask`, frames from
        /// `prefer_from` are delivered before any other sender's (that
        /// connection came up first / is the fastest).
        prefer_mask: u8 = 0,
        prefer_from: u8 = 0,
        /// true: onPeerUp / answerGetSlotState iterate own_latest in the
        /// map's own (hash) order, exactly like node.zig; false: slot-ascending.
        hash_order: bool = false,
        /// The slot the crash scenario targets (the stragglers lose THIS slot).
        cs: u64 = 1,
        /// true: every node gates inbound envelopes through its HoldBuffer
        /// exactly as `Node.applyInput` does; false: fed straight to the
        /// engine (the pre-S8b node — the control).
        gate: bool = false,

        pub fn init(gpa: std.mem.Allocator, n: u8, threshold: u32) !*Self {
            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            var seeds: [max_n][32]u8 = undefined;
            var pks: [max_n][32]u8 = undefined;
            for (0..n) |i| {
                seeds[i] = @splat(@as(u8, 0x40) + @as(u8, @intCast(i)));
                pks[i] = try crypto.publicKeyFromSeed(seeds[i]);
            }
            var shared = blk: {
                const vals = try gpa.dupe([32]u8, pks[0..n]);
                errdefer gpa.free(vals);
                break :blk qset.QuorumSetOwned{ .threshold = threshold, .validators = vals, .inner_sets = try gpa.alloc(qset.QuorumSetOwned, 0) };
            };
            errdefer shared.deinit(gpa);
            try qset.validateAndNormalize(gpa, &shared);
            const flat = try qset.canonicalBytes(gpa, &shared);
            defer gpa.free(flat);
            const hash = crypto.qsetHash(flat);
            const framed = try canonical.frameFlat(gpa, flat);
            errdefer gpa.free(framed);
            const network_id = crypto.networkIdFromPassphrase("d1-review v1");

            const nodes = try gpa.alloc(Node, n);
            errdefer gpa.free(nodes);
            self.* = .{ .gpa = gpa, .n = n, .nodes = nodes, .shared = shared, .shared_framed = framed, .shared_hash = hash, .network_id = network_id, .seeds = seeds, .pks = pks };
            for (0..n) |i| {
                nodes[i] = .{ .eng = undefined, .app = undefined, .wrap = undefined };
                nodes[i].app = .{ .gpa = gpa, .io = std.testing.io, .state = .{}, .max_value_bytes = 4096 };
                nodes[i].wrap = .{ .h = self, .idx = @intCast(i), .inner = nodes[i].app.driver() };
                nodes[i].eng = try self.freshEngine(@intCast(i));
            }
            return self;
        }

        fn freshEngine(self: *Self, i: u8) !engine.Engine {
            return engine.Engine.init(self.gpa, .{
                .network_id = self.network_id,
                .node_id = self.pks[i],
                .secret_seed = self.seeds[i],
                .quorum_set = try qset.clone(self.gpa, &self.shared),
            }, .{ .ctx = @ptrCast(&self.nodes[i].wrap), .validate_value = wValidate, .combine_candidates = wCombine });
        }

        pub fn deinit(self: *Self) void {
            const gpa = self.gpa;
            for (self.nodes) |*nd| {
                if (nd.eng_alive) nd.eng.deinit();
                self.clearInbox(nd);
                nd.timers.deinit(gpa);
                for (nd.ext.values()) |v| gpa.free(v);
                nd.ext.deinit(gpa);
                var oit = nd.own_latest.valueIterator();
                while (oit.next()) |ol| {
                    if (ol.nom) |b| gpa.free(b);
                    if (ol.ballot) |b| gpa.free(b);
                }
                nd.own_latest.deinit(gpa);
                nd.hold.deinit(gpa);
                nd.pending.deinit(gpa);
                nd.app.queue.deinit(gpa);
            }
            gpa.free(self.nodes);
            gpa.free(self.shared_framed);
            self.shared.deinit(gpa);
            gpa.destroy(self);
        }

        fn clearInbox(self: *Self, nd: *Node) void {
            for (&nd.inbox) |*q| {
                for (q.items) |b| self.gpa.free(b);
                q.deinit(self.gpa);
                q.* = .empty;
            }
        }

        // -- driver wrapper: records what crosses the driver boundary ------
        fn wValidate(ctx: *anyopaque, slot: u64, value: []const u8, is_nom: bool) Validity {
            const w: *Wrap = @ptrCast(@alignCast(ctx));
            const v = w.inner.validate_value(w.inner.ctx, slot, value, is_nom);
            const nd = &w.h.nodes[w.idx];
            if (slot < max_slot) {
                nd.validated[slot] = true;
                if (slot >= 1 and !nd.ext.contains(slot - 1)) nd.validated_before_prev_ext[slot] = true;
                nd.tally[slot][@backingInt(v)] += 1;
            }
            if (w.h.trace) std.debug.print("    node {d} validate slot {d} -> {t} (state={any})\n", .{ w.idx, slot, v, nd.app.state });
            return v;
        }
        fn wCombine(ctx: *anyopaque, slot: u64, cands: []const []const u8, gpa: std.mem.Allocator, out: *std.ArrayList(u8)) driver.DriverError!void {
            const w: *Wrap = @ptrCast(@alignCast(ctx));
            return w.inner.combine_candidates(w.inner.ctx, slot, cands, gpa, out);
        }

        // -- timers -------------------------------------------------------
        fn setTimer(self: *Self, nd: *Node, slot: u64, id: engine.TimerId, deadline: u64) !void {
            for (nd.timers.items) |*t| {
                if (t.slot == slot and t.timer == id) {
                    t.deadline = deadline;
                    return;
                }
            }
            try nd.timers.append(self.gpa, .{ .slot = slot, .timer = id, .deadline = deadline });
        }
        fn cancelTimer(nd: *Node, slot: u64, id: engine.TimerId) void {
            var i: usize = 0;
            while (i < nd.timers.items.len) {
                const t = nd.timers.items[i];
                if (t.slot == slot and t.timer == id) {
                    _ = nd.timers.swapRemove(i);
                } else i += 1;
            }
        }

        // -- input + effect drain (one input, then ALL effects) -------------
        /// `Node.applyInput` minus the gate (which `deliverOne` applies to
        /// inbound frames): feed one input, drain every effect, and — only
        /// then, never re-entrantly — release the held statements for the
        /// frontier slot if the frontier moved (`Node.releaseHeld`).
        fn push(self: *Self, idx: u8, input: engine.Input) anyerror!void {
            const before = self.nodes[idx].next_deliver;
            try self.nodes[idx].eng.pushInput(input);
            try self.drain(idx);
            if (self.gate and self.nodes[idx].next_deliver != before) try self.releaseHeld(idx);
        }

        /// `Node.gateEnvelope`: true when the frame was consumed (held or
        /// dropped; ownership taken — or held and released early with its
        /// whole slot), false when it must be fed now.
        fn gateFrame(self: *Self, to: u8, frame: []u8) !bool {
            const gpa = self.gpa;
            const nd = &self.nodes[to];
            const meta = slcp.node.envelopeMeta(gpa, self.network_id, frame) catch return false;
            if (meta.slot <= nd.next_deliver) return false;
            const item: InputItem = .{ .input = .{ .envelope_received = .{ .bytes = frame } }, .source_peer = null };
            switch (nd.hold.admit(gpa, &meta, nd.next_deliver, nd.eng.qsets.inGraph(meta.node_id), &nd.eng.cfg.quorum_set, item)) {
                .fed => return false,
                .ready => {
                    if (self.trace) std.debug.print("    node {d} releases slot {d} early (v-blocking EXTERNALIZEs; frontier {d})\n", .{ to, meta.slot, nd.next_deliver });
                    try self.releaseSlot(to, meta.slot);
                    return true;
                },
                .held, .dropped_far, .dropped_full, .dropped_badsig => return true,
            }
        }

        /// `Node.releaseSlot`: feed everything held for `slot` (catch-up).
        fn releaseSlot(self: *Self, idx: u8, slot: u64) anyerror!void {
            const gpa = self.gpa;
            const nd = &self.nodes[idx];
            var list = nd.hold.takeSlot(slot) orelse return;
            defer list.deinit(gpa);
            for (list.items) |*e| {
                defer HoldBuffer.freeEntry(gpa, e);
                if (!nd.live or slot < nd.next_deliver) {
                    _ = nd.hold.dropped_behind.fetchAdd(1, .monotonic);
                    continue;
                }
                _ = nd.hold.released_early.fetchAdd(1, .monotonic);
                try self.push(idx, .{ .envelope_received = .{ .bytes = e.item.input.envelope_received.bytes } });
            }
        }

        /// `Node.releaseHeld`: feed the frontier slot's held statements,
        /// looping while they keep advancing the frontier; entries whose slot
        /// fell behind meanwhile are dropped.
        fn releaseHeld(self: *Self, idx: u8) anyerror!void {
            const gpa = self.gpa;
            const nd = &self.nodes[idx];
            while (nd.hold.takeReleasable(gpa, nd.next_deliver)) |taken| {
                var list = taken;
                defer list.deinit(gpa);
                const slot = nd.next_deliver;
                for (list.items) |*e| {
                    defer HoldBuffer.freeEntry(gpa, e);
                    if (!nd.live or slot < nd.next_deliver) {
                        _ = nd.hold.dropped_behind.fetchAdd(1, .monotonic);
                        continue;
                    }
                    _ = nd.hold.released.fetchAdd(1, .monotonic);
                    if (self.trace) std.debug.print("    node {d} releases held slot {d} frame\n", .{ idx, slot });
                    try self.push(idx, .{ .envelope_received = .{ .bytes = e.item.input.envelope_received.bytes } });
                }
            }
        }

        /// node.zig `onExternalized` + `drainDeliverable`: journal, buffer
        /// out-of-order externalizations, gap-jump once a buffered slot sits
        /// a full answering window (16) past the frontier, then apply the
        /// contiguous frontier in slot order (exactly what AppNode's hook
        /// does at delivery: decode → App.apply → state).
        fn onExternalized(self: *Self, idx: u8, slot: u64, bytes: []const u8) !void {
            const gpa = self.gpa;
            const nd = &self.nodes[idx];
            const gop = try nd.ext.getOrPut(gpa, slot);
            if (!gop.found_existing) gop.value_ptr.* = try gpa.dupe(u8, bytes);
            if (slot < nd.next_deliver) return;
            try nd.pending.put(gpa, slot, {});
            var highest: u64 = 0;
            var lowest: u64 = std.math.maxInt(u64);
            var it = nd.pending.keyIterator();
            while (it.next()) |k| {
                highest = @max(highest, k.*);
                lowest = @min(lowest, k.*);
            }
            if (highest >= nd.next_deliver + 16 and lowest > nd.next_deliver) {
                if (self.trace) std.debug.print("    node {d} externalized gap: slots {d}..{d} unrecoverable; resuming delivery at {d}\n", .{ idx, nd.next_deliver, lowest - 1, lowest });
                nd.next_deliver = lowest;
            }
            while (nd.pending.remove(nd.next_deliver)) {
                const cmd = AN.codec.decode(nd.ext.get(nd.next_deliver).?) orelse return error.UndecodableExternalizedValue;
                nd.app.state = App.apply(nd.app.state, cmd);
                nd.next_deliver += 1;
            }
        }

        fn recordOwnLatest(self: *Self, nd: *Node, bytes: []const u8) !void {
            const gpa = self.gpa;
            const meta = try decodeOwnMeta(gpa, bytes);
            const gop = try nd.own_latest.getOrPut(gpa, meta.slot);
            if (!gop.found_existing) gop.value_ptr.* = .{};
            const which = if (meta.is_nom) &gop.value_ptr.nom else &gop.value_ptr.ballot;
            if (which.*) |old| gpa.free(old);
            which.* = try gpa.dupe(u8, bytes);
        }

        fn fanOut(self: *Self, from: u8, bytes: []const u8) !void {
            for (0..self.n) |j| {
                if (j == from or !self.nodes[j].live) continue; // a crashed peer's socket is gone
                try self.nodes[j].inbox[from].append(self.gpa, try self.gpa.dupe(u8, bytes));
            }
        }

        fn drain(self: *Self, idx: u8) anyerror!void {
            const nd = &self.nodes[idx];
            var want_qset = false;
            while (nd.eng.popEffect()) |eff| {
                switch (eff.*) {
                    .persist_own_envelope => nd.persist_count += 1,
                    .broadcast_envelope => |sb| {
                        // node.zig dispatch: always record as own latest;
                        // only touch the network once live.
                        try self.recordOwnLatest(nd, sb.bytes);
                        if (nd.live) {
                            nd.broadcasts += 1;
                            try self.fanOut(idx, sb.bytes);
                        }
                    },
                    .forward_envelope => |sb| if (nd.live) try self.fanOut(idx, sb.bytes),
                    .arm_timer => |t| try self.setTimer(nd, t.slot, t.timer, self.now + t.delay_ms),
                    .cancel_timer => |t| cancelTimer(nd, t.slot, t.timer),
                    .request_qset => |r| {
                        std.debug.assert(std.mem.eql(u8, &r.hash, &self.shared_hash));
                        want_qset = true;
                    },
                    .externalized => |sb| {
                        // Journal + slot-ordered delivery (apply), then (the
                        // §0 loop) propose count + 1 for the next slot —
                        // off the RAW slot, as node.zig's current_slot.
                        if (self.trace) {
                            std.debug.print("    node {d} EXTERNALIZED slot {d}\n", .{ idx, sb.slot });
                            self.dumpBallots(idx, sb.slot);
                        }
                        try self.onExternalized(idx, sb.slot, sb.bytes);
                        if (sb.slot + 1 > nd.proposed_upto) nd.pending_propose = sb.slot + 1;
                    },
                    .input_status => |st| nd.status[@backingInt(st.code)] += 1,
                    .phase_event => |pe| {
                        if (self.trace) std.debug.print("    node {d} phase {t} slot {d}\n", .{ idx, pe.kind, pe.slot });
                        if (pe.kind == .accepted_commit and pe.slot < max_slot) nd.accepted_commit[pe.slot] = true;
                    },
                }
                nd.eng.commitEffect();
            }
            if (want_qset) try self.push(idx, .{ .qset_received = .{ .bytes = self.shared_framed } });
            if (nd.live) if (nd.pending_propose) |slot| {
                nd.pending_propose = null;
                try self.propose(idx, slot);
            };
        }

        /// The §0 loop's proposal: App.proposal(state) encoded through the
        /// AppNode codec, prev_value = the previous slot's externalized bytes.
        pub fn propose(self: *Self, idx: u8, slot: u64) anyerror!void {
            const nd = &self.nodes[idx];
            nd.proposed_upto = slot;
            var buf: [AN.codec.size]u8 = undefined;
            const value = AN.codec.encode(App.proposal(nd.app.state), &buf);
            const prev: []const u8 = if (slot >= 2) (nd.ext.get(slot - 1) orelse "genesis") else "genesis";
            if (self.trace) std.debug.print("    node {d} proposes {any} for slot {d}\n", .{ idx, App.proposal(nd.app.state), slot });
            try self.push(idx, .{ .nominate = .{ .slot = slot, .value = value, .prev_value = prev } });
        }

        fn deliverOne(self: *Self, to: u8, from: u8) anyerror!void {
            const q = &self.nodes[to].inbox[from];
            const frame = q.orderedRemove(0);
            if (self.gate) {
                if (try self.gateFrame(to, frame)) return; // held or dropped; the buffer owns the bytes now
            }
            defer self.gpa.free(frame);
            const tr = self.trace and (self.prefer_mask >> @intCast(to)) & 1 == 1;
            var before: [8]u32 = undefined;
            if (tr) {
                const meta = try decodeOwnMeta(self.gpa, frame);
                before = self.nodes[to].status;
                std.debug.print("    deliver {d}<-{d} slot={d} {s} len={d}", .{ to, from, meta.slot, if (meta.is_nom) "NOMINATE" else "BALLOT", frame.len });
            }
            try self.push(to, .{ .envelope_received = .{ .bytes = frame } });
            if (tr) {
                const names = [_][]const u8{ "applied", "stale", "badsig", "insane", "parked", "over_limit", "ignored" };
                for (0..7) |c| if (self.nodes[to].status[c] != before[c]) std.debug.print(" -> {s}", .{names[c]});
                std.debug.print("\n", .{});
            }
        }

        /// Deliver round-robin (one frame per node per round, per-link FIFO,
        /// honoring the connection preference); when quiescent fire the
        /// earliest timer; stop when `stop` says so, when nothing can ever
        /// progress, or when the next timer lies past `until_ms`.
        pub fn pump(self: *Self, stop: *const fn (*Self) bool, until_ms: u64) anyerror!PumpResult {
            while (true) {
                if (stop(self)) return .stopped;
                var progressed = false;
                for (0..self.n) |i_usize| {
                    const i: u8 = @intCast(i_usize);
                    if (!self.nodes[i].live) continue;
                    const preferred = (self.prefer_mask >> @intCast(i)) & 1 == 1;
                    for (0..self.n) |k| {
                        var j: u8 = @intCast((self.rr + k) % self.n);
                        if (preferred and self.nodes[i].inbox[self.prefer_from].items.len != 0) j = self.prefer_from;
                        if (j == i or self.nodes[i].inbox[j].items.len == 0) continue;
                        try self.deliverOne(i, j);
                        self.steps += 1;
                        progressed = true;
                        if (stop(self)) return .stopped;
                        break;
                    }
                }
                self.rr +%= 1;
                if (progressed) continue;

                var best: ?struct { node: u8, t: Timer } = null;
                for (self.nodes, 0..) |*nd, i| {
                    for (nd.timers.items) |t| {
                        if (best == null or t.deadline < best.?.t.deadline) best = .{ .node = @intCast(i), .t = t };
                    }
                }
                const b = best orelse return .quiescent;
                if (b.t.deadline > until_ms) return .time_bound;
                self.now = @max(self.now, b.t.deadline);
                cancelTimer(&self.nodes[b.node], b.t.slot, b.t.timer);
                try self.push(b.node, .{ .timer_fired = .{ .slot = b.t.slot, .timer = b.t.timer } });
            }
        }

        // -- crash / restart / reconnect (node.zig create + onPeerUp) --------

        /// Process crash: engine state gone, in-flight frames TO this node
        /// lost (its sockets are gone), timers gone. Frames it already sent
        /// stay in the peers' inboxes (they were on the wire).
        pub fn crash(self: *Self, idx: u8) void {
            const nd = &self.nodes[idx];
            nd.eng.deinit();
            nd.eng_alive = false;
            self.clearInbox(nd);
            nd.timers.clearRetainingCapacity();
            nd.hold.deinit(self.gpa); // the buffer dies with the process
            nd.hold = .{}; // a node that never restarts must not be deinit'ed twice (Harness.deinit)
            nd.live = false;
        }

        /// `Node.create` on the same data_dir: State = initialState() +
        /// the replayed externalized.log tail (here: whatever this node had
        /// externalized before the crash — `ext` is its journal), then the
        /// own.log restore of the latest own nom/ballot per slot, then live.
        pub fn restart(self: *Self, idx: u8) !void {
            const nd = &self.nodes[idx];
            nd.eng = try self.freshEngine(idx);
            nd.eng_alive = true;
            nd.restarts += 1;
            nd.app = .{ .gpa = self.gpa, .io = std.testing.io, .state = .{}, .max_value_bytes = 4096 };
            nd.proposed_upto = 0;
            nd.pending_propose = null;
            nd.accepted_commit = @splat(false);
            nd.validated = @splat(false);
            nd.validated_before_prev_ext = @splat(false);
            nd.hold = .{}; // Node.create: the buffer starts empty
            nd.pending.clearRetainingCapacity();
            // Journal tail replay (slot-ascending) through apply; the
            // frontier resumes after the journal's high-water mark.
            const slots = try self.gpa.dupe(u64, nd.ext.keys());
            defer self.gpa.free(slots);
            std.mem.sort(u64, slots, {}, std.sort.asc(u64));
            nd.next_deliver = 1;
            for (slots) |s| {
                const cmd = AN.codec.decode(nd.ext.get(s).?) orelse return error.UndecodableExternalizedValue;
                nd.app.state = App.apply(nd.app.state, cmd);
                nd.next_deliver = s + 1;
            }
            // own.log restore, before any thread exists / before live.
            const own_slots = try self.ownSlots(nd, false);
            defer self.gpa.free(own_slots);
            for (own_slots) |s| {
                const ol = nd.own_latest.get(s).?;
                if (ol.nom) |b| try self.push(idx, .{ .restore_own_envelope = .{ .bytes = b } });
                if (ol.ballot) |b| try self.push(idx, .{ .restore_own_envelope = .{ .bytes = b } });
            }
            nd.live = true;
            // The §0 program: propose from the (replayed) state right away.
            const next_slot: u64 = if (slots.len == 0) 1 else slots[slots.len - 1] + 1;
            try self.propose(idx, next_slot);
        }

        /// Both sides' `onPeerUp` for every peer of `idx`: each side re-floods
        /// its own latest nom + ballot per slot, then answers the other's
        /// getSlotState(0) with its OWN envelopes (ballot preferred), one per
        /// slot — node.zig onPeerUp / answerGetSlotState.
        pub fn reconnect(self: *Self, idx: u8) !void {
            for (0..self.n) |j_usize| {
                const j: u8 = @intCast(j_usize);
                if (j == idx) continue;
                try self.peerUp(idx, j);
                try self.peerUp(j, idx);
            }
        }

        /// The slots of `nd.own_latest`, in the map's own iteration order
        /// (node.zig iterates the map directly) or sorted ascending.
        fn ownSlots(self: *Self, nd: *Node, natural: bool) ![]u64 {
            var out = try self.gpa.alloc(u64, nd.own_latest.count());
            var i: usize = 0;
            var it = nd.own_latest.keyIterator();
            while (it.next()) |k| : (i += 1) out[i] = k.*;
            if (!natural) std.mem.sort(u64, out, {}, std.sort.asc(u64));
            return out;
        }

        fn peerUp(self: *Self, from: u8, to: u8) !void {
            const src = &self.nodes[from];
            const slots = try self.ownSlots(src, self.hash_order);
            defer self.gpa.free(slots);
            if (self.trace) std.debug.print("    peerUp {d}->{d}: own_latest slots in send order: {any}\n", .{ from, to, slots });
            // re-flood: own latest nom, then ballot, per slot
            for (slots) |s| {
                const ol = src.own_latest.get(s).?;
                if (ol.nom) |b| try self.nodes[to].inbox[from].append(self.gpa, try self.gpa.dupe(u8, b));
                if (ol.ballot) |b| try self.nodes[to].inbox[from].append(self.gpa, try self.gpa.dupe(u8, b));
            }
            // getSlotState(0) answer: own envelopes only, ballot preferred
            for (slots) |s| {
                const ol = src.own_latest.get(s).?;
                const env = ol.ballot orelse ol.nom orelse continue;
                try self.nodes[to].inbox[from].append(self.gpa, try self.gpa.dupe(u8, env));
            }
        }

        fn nodeIndex(self: *Self, id: [32]u8) usize {
            for (0..self.n) |i| if (std.mem.eql(u8, &self.pks[i], &id)) return i;
            return 99;
        }

        pub fn dumpBallots(self: *Self, idx: u8, slot: u64) void {
            const sp = self.nodes[idx].eng.slots.get(slot) orelse return;
            std.debug.print("      node {d} latest_ballot(slot {d}) phase={t} fully_validated={}:", .{ idx, slot, sp.ballot.phase, sp.fully_validated });
            var it = sp.latest_ballot.iterator();
            while (it.next()) |e| {
                const st = &e.value_ptr.*.statement;
                switch (st.pledges) {
                    .nominate => {},
                    .prepare => |*pp| std.debug.print(" [{d}: PREPARE b={d} nC={d} nH={d}]", .{ self.nodeIndex(e.key_ptr.*), pp.ballot.counter, pp.n_c, pp.n_h }),
                    .confirm => |*c| std.debug.print(" [{d}: CONFIRM b={d} nC={d} nH={d}]", .{ self.nodeIndex(e.key_ptr.*), c.ballot.counter, c.n_commit, c.n_h }),
                    .externalize => |*x| std.debug.print(" [{d}: EXTERNALIZE c={d} nH={d}]", .{ self.nodeIndex(e.key_ptr.*), x.commit.counter, x.n_h }),
                }
            }
            std.debug.print("\n", .{});
        }

        /// Has `idx` put a NOMINATE for `slot` on the wire (own latest)?
        pub fn hasNom(self: *Self, idx: u8, slot: u64) bool {
            const ol = self.nodes[idx].own_latest.get(slot) orelse return false;
            return ol.nom != null;
        }

        pub fn allExt(self: *Self, slot: u64) bool {
            for (self.nodes) |*nd| if (!nd.ext.contains(slot)) return false;
            return true;
        }

        pub fn report(self: *Self, label: []const u8, slot: u64) void {
            std.debug.print("\n[{s}] virtual t={d} ms, {d} deliveries (S = slot {d})\n", .{ label, self.now, self.steps, slot });
            for (self.nodes, 0..) |*nd, i| {
                if (!nd.eng_alive) {
                    std.debug.print("  node {d}: DEAD (engine gone)\n", .{i});
                    continue;
                }
                const sp = nd.eng.slots.get(slot);
                std.debug.print("  node {d}: restarts={d} state={any} ext(S-1)={} ext(S)={} broadcasts={d} validate(S)=[inv {d}, maybe {d}, valid {d}] validated_S_before_ext(S-1)={} S.fully_validated={?} status[applied,stale,badsig,insane,parked,over,ignored]={any} hold[released,far,full,badsig,behind]={any}\n", .{
                    i,                                                                                                                                                                                                nd.restarts,
                    nd.app.state,                                                                                                                                                                                     nd.ext.contains(slot - 1),
                    nd.ext.contains(slot),                                                                                                                                                                            nd.broadcasts,
                    nd.tally[slot][0],                                                                                                                                                                                nd.tally[slot][1],
                    nd.tally[slot][2],                                                                                                                                                                                nd.validated_before_prev_ext[slot],
                    if (sp) |s| s.fully_validated else null,                                                                                                                                                          nd.status[0..7],
                    [_]u64{ nd.hold.released.load(.acquire), nd.hold.dropped_far.load(.acquire), nd.hold.dropped_full.load(.acquire), nd.hold.dropped_badsig.load(.acquire), nd.hold.dropped_behind.load(.acquire) },
                });
            }
        }
    };
}

// ---------------------------------------------------------------------------
// E1: two nodes crash mid-slot and restart. Without the gate the network
// never recovers; with it, it converges.
// ---------------------------------------------------------------------------

const P: u8 = 0; // the peer whose connection comes back first
/// The nodes that crash mid-slot: the last two (1,2 for n = 3; 2,3 for n = 4).
fn stragglersOf(n: u8) [2]u8 {
    return .{ n - 2, n - 1 };
}

fn BothAcceptedCommit1(comptime H: type) type {
    return struct {
        fn stop(h: *H) bool {
            var any_accepted = false;
            for (stragglersOf(h.n)) |s| {
                if (h.nodes[s].ext.contains(h.cs)) return false;
                if (h.nodes[s].accepted_commit[h.cs]) any_accepted = true;
            }
            return any_accepted;
        }
    };
}

fn FastPairExt1(comptime H: type) type {
    return struct {
        fn stop(h: *H) bool {
            // ... and slot 2's nomination is on the wire from the fast peer.
            var ok = true;
            for (0..h.n - 2) |i| ok = ok and h.nodes[i].ext.contains(h.cs);
            return ok and h.hasNom(0, h.cs + 1);
        }
    };
}

fn AllExt2(comptime H: type) type {
    return struct {
        fn stop(h: *H) bool {
            return h.allExt(h.cs + 1);
        }
    };
}

fn AllExt3(comptime H: type) type {
    return struct {
        fn stop(h: *H) bool {
            return h.allExt(h.cs + 2);
        }
    };
}

fn AllExtBeforeCrashSlot(comptime H: type) type {
    return struct {
        fn stop(h: *H) bool {
            return h.allExt(h.cs - 1);
        }
    };
}

const SkewResult = struct {
    stalled: bool,
    before: [2]bool,
    maybe_seen: [2]bool,
    ext1_all: bool,
    /// Slot cs+2 externalized everywhere (only pumped for when cs+1 did).
    ext3_all: bool,
    /// Every node's slot cs+1 is fully validated and has its NOMINATE on the wire.
    all_voting: bool,
};

fn runCrashRestart(comptime App: type, label: []const u8, gate: bool, trace: bool) !SkewResult {
    return runCrashRestartN(App, 4, 3, 1, label, gate, trace, false);
}

fn runCrashRestartN(comptime App: type, n: u8, threshold: u32, crash_slot: u64, label: []const u8, gate: bool, trace: bool, hash_order: bool) !SkewResult {
    const H = Harness(App);
    const gpa = std.testing.allocator;
    const h = try H.init(gpa, n, threshold);
    defer h.deinit();
    h.trace = trace;
    h.hash_order = hash_order;
    h.gate = gate;
    h.cs = crash_slot;
    for (0..n) |i| try h.propose(@intCast(i), 1);
    if (crash_slot > 1) try std.testing.expectEqual(PumpResult.stopped, try h.pump(AllExtBeforeCrashSlot(H).stop, 600_000));
    const cs = crash_slot;

    // Phase A: run until the stragglers have ACCEPTED commit for slot cs
    // (their CONFIRMs are on the wire) but not yet externalized it.
    const ra = try h.pump(BothAcceptedCommit1(H).stop, 120_000);
    try std.testing.expectEqual(PumpResult.stopped, ra);
    // The double fault: both crash now (a rack reboot). Their CONFIRMs are
    // already in flight to the survivors.
    const stragglers = stragglersOf(n);
    for (stragglers) |st| h.crash(st);
    // The survivors finish slot cs (they hold the accept-commits) and, per
    // the §0 loop, propose {next = cs + 1} for slot cs + 1.
    const rb = try h.pump(FastPairExt1(H).stop, 120_000);
    if (rb != .stopped) {
        std.debug.print("  phase B did not complete ({t}): ext(cs) on node 0={any}; node 0 has NOM(cs+1)={} (t={d} ms)\n", .{ rb, h.nodes[0].ext.contains(cs), h.hasNom(0, cs + 1), h.now });
    }
    try std.testing.expectEqual(PumpResult.stopped, rb);
    if (trace) std.debug.print("  -- t={d} ms: survivors externalized slot {d}; node 0's NOMINATE({d}) is on the wire; restarting the stragglers --\n", .{ h.now, cs, cs + 1 });
    // Restart both on their data_dirs (journal: no slot cs; own.log: their
    // NOMINATE(cs) + CONFIRM(cs)), then reconnect; the connection to node 0
    // comes up first, so its re-flood + slotState answer are processed
    // before anything from the other survivor / the other straggler.
    for (stragglers) |st| try h.restart(st);
    for (stragglers) |st| try h.reconnect(st);
    h.prefer_mask = (@as(u8, 1) << @intCast(stragglers[0])) | (@as(u8, 1) << @intCast(stragglers[1]));
    h.prefer_from = P;
    const rc = try h.pump(AllExt2(H).stop, 600_000);
    h.report(label, cs + 1);
    std.debug.print("  phase C result: {t}\n", .{rc});
    var all_voting = true;
    for (h.nodes, 0..) |*nd, i| {
        const sp = nd.eng.slots.get(cs + 1);
        const fv = if (sp) |s| s.fully_validated else false;
        const on_wire = h.hasNom(@intCast(i), cs + 1);
        std.debug.print("  node {d} slot {d}: fully_validated={} votes_on_wire={}\n", .{ i, cs + 1, fv, on_wire });
        all_voting = all_voting and fv and on_wire;
    }
    var ext3_all = false;
    if (rc == .stopped) {
        // Phase D: the network keeps going — everyone externalizes cs + 2.
        const rd = try h.pump(AllExt3(H).stop, 600_000);
        ext3_all = rd == .stopped and h.allExt(cs + 2);
        std.debug.print("  phase D (slot {d}) result: {t}\n", .{ cs + 2, rd });
    }
    var before: [2]bool = .{ true, true };
    var maybe: [2]bool = .{ true, true };
    for (stragglers, 0..) |s, k| {
        before[k] = h.nodes[s].validated_before_prev_ext[cs + 1];
        maybe[k] = h.nodes[s].tally[cs + 1][1] > 0;
    }
    return .{ .stalled = rc != .stopped, .before = before, .maybe_seen = maybe, .ext1_all = h.allExt(cs), .ext3_all = ext3_all, .all_voting = all_voting };
}

// The S8 D1 liveness pin. Control (gate = false, the pre-S8b node): the two
// restarted nodes validated the in-flight slot-2 nomination while still one
// slot behind, cached `.maybe_valid`, and `fully_validated` is sticky — they
// never vote for slot 2 although they catch up on slot 1 moments later, and
// 2 of 4 voters cannot make 3-of-4. Red before the fix (the harness on main):
//   [E1 Counter (README app), 3-of-4, double crash mid-slot + restart] … phase C result: time_bound
//   node 2 slot 2: fully_validated=false votes_on_wire=false
// With the gate the same schedule converges: NOMINATE(2) waits in the hold
// buffer until slot 1 is applied, validate(2) then answers .valid, both
// stragglers vote, slots 2 and 3 externalize everywhere. Non-vacuity: the
// control arm asserts the halt still reproduces with the gate bypassed, so
// a harness that stopped modelling the finding would go red here first.
test "liveness D1-E1: 3-of-4 Counter, nodes 2+3 crash after CONFIRM(1) and restart — halts without the hold gate, converges with it" {
    const off = try runCrashRestart(Counter, "E1 Counter (README app), 3-of-4, double crash mid-slot + restart, gate OFF (control)", false, false);
    try std.testing.expect(off.ext1_all);
    try std.testing.expect(off.before[0] and off.before[1]);
    try std.testing.expect(off.maybe_seen[0] and off.maybe_seen[1]);
    try std.testing.expect(off.stalled); // the finding, still reproduced

    const on = try runCrashRestart(Counter, "E1 Counter (README app), 3-of-4, double crash mid-slot + restart, gate ON", true, false);
    try std.testing.expect(on.ext1_all);
    try std.testing.expect(!on.stalled); // the fix
    try std.testing.expect(on.ext3_all);
    try std.testing.expect(on.all_voting);
    try std.testing.expect(!on.before[0] and !on.before[1]); // apply(1) preceded every validate for 2
    try std.testing.expect(!on.maybe_seen[0] and !on.maybe_seen[1]); // no maybe_valid verdict was ever cached
}

test "liveness D1-E1-control: same crash/restart schedule, validate that ignores State -> slot 2 externalizes with and without the gate" {
    const off = try runCrashRestart(Loose, "E1 control: Loose (state-free validate), same schedule, gate OFF", false, false);
    try std.testing.expect(off.ext1_all);
    try std.testing.expect(!off.stalled);
    const on = try runCrashRestart(Loose, "E1 control: Loose (state-free validate), same schedule, gate ON", true, false);
    try std.testing.expect(on.ext1_all);
    try std.testing.expect(!on.stalled);
    try std.testing.expect(on.ext3_all);
}

test "liveness D1-E1-baseline: Counter, 3-of-4, no faults -> slot 2 externalizes everywhere (gate ON)" {
    const H = Harness(Counter);
    const gpa = std.testing.allocator;
    const h = try H.init(gpa, 4, 3);
    defer h.deinit();
    h.gate = true;
    for (0..4) |i| try h.propose(@intCast(i), 1);
    const rc = try h.pump(AllExt2(H).stop, 600_000);
    h.report("E1 baseline: Counter, no faults, gate ON", 2);
    try std.testing.expectEqual(PumpResult.stopped, rc);
    // Steady state: the buffer only ever holds the next slot's early
    // statements, and everything held is released, nothing dropped.
    for (h.nodes) |*nd| {
        try std.testing.expectEqual(@as(u64, 0), nd.hold.dropped_far.load(.acquire));
        try std.testing.expectEqual(@as(u64, 0), nd.hold.dropped_full.load(.acquire));
        try std.testing.expectEqual(@as(u64, 0), nd.hold.dropped_badsig.load(.acquire));
    }
}

// One restarted node. Control: passive for the in-flight slot only (it
// answered maybe_valid for slot 2 and stayed mute there; the network
// tolerates one mute voter at 3-of-4). With the gate it is a full voter for
// slot 2 too.
test "liveness D1-E1-single: 3-of-4 Counter, only node 3 crashes after CONFIRM(1) and restarts -> passive for slot 2 without the gate, a voter with it" {
    const H = Harness(Counter);
    const gpa = std.testing.allocator;
    for ([_]bool{ false, true }) |gate| {
        const h = try H.init(gpa, 4, 3);
        defer h.deinit();
        h.gate = gate;
        for (0..4) |i| try h.propose(@intCast(i), 1);
        const One = struct {
            fn stop(hh: *H) bool {
                return hh.nodes[3].accepted_commit[1] and !hh.nodes[3].ext.contains(1);
            }
        };
        try std.testing.expectEqual(PumpResult.stopped, try h.pump(One.stop, 120_000));
        h.crash(3);
        const Three = struct {
            fn stop(hh: *H) bool {
                return hh.nodes[0].ext.contains(1) and hh.nodes[1].ext.contains(1) and hh.nodes[2].ext.contains(1) and hh.hasNom(0, 2);
            }
        };
        try std.testing.expectEqual(PumpResult.stopped, try h.pump(Three.stop, 120_000));
        try h.restart(3);
        try h.reconnect(3);
        h.prefer_mask = 0b1000;
        h.prefer_from = P;
        const Slot3 = struct {
            fn stop(hh: *H) bool {
                return hh.allExt(3);
            }
        };
        const rc = try h.pump(Slot3.stop, 600_000);
        h.report(if (gate) "E1-single: one restarted node, gate ON" else "E1-single: one restarted node, gate OFF (control)", 2);
        try std.testing.expectEqual(PumpResult.stopped, rc);
        try std.testing.expect(h.nodes[3].ext.contains(2) and h.nodes[3].ext.contains(3)); // followed along either way
        if (!gate) {
            try std.testing.expect(h.nodes[3].validated_before_prev_ext[2]);
            try std.testing.expect(h.nodes[3].tally[2][1] > 0); // it answered maybe_valid for slot 2 ...
            try std.testing.expect(!h.nodes[3].eng.slots.get(2).?.fully_validated); // ... and stayed passive there
        } else {
            try std.testing.expect(!h.nodes[3].validated_before_prev_ext[2]);
            try std.testing.expectEqual(@as(u32, 0), h.nodes[3].tally[2][1]);
            try std.testing.expect(h.nodes[3].eng.slots.get(2).?.fully_validated);
            try std.testing.expect(h.hasNom(3, 2)); // a voter for slot 2
            try std.testing.expect(h.nodes[3].hold.released.load(.acquire) > 0); // the gate did the work
        }
    }
}

// The documented 3-node deployment (2-of-3), both stragglers crash after
// CONFIRM(N) and restart. Crash slots {1, 3, 4, 6} keep the step inside its
// budget; 3, 4 and 6 are the slots the S8 review found halting in map order
// (the pre-fix-1 re-flood order, adversarial for this schedule), 1 is a
// clean one. Map order without the gate MUST still halt somewhere (the
// control); with the gate neither order halts anywhere.
const sweep_slots = [_]u64{ 1, 3, 4, 6 };

fn sweep2of3(gate: bool, hash_order: bool) !u32 {
    var stalls: u32 = 0;
    for (sweep_slots) |n| {
        var label_buf: [128]u8 = undefined;
        const label = try std.fmt.bufPrint(&label_buf, "E1 2-of-3 Counter, crash at slot {d}, {s} order, gate {s}", .{ n, if (hash_order) "map" else "ascending", if (gate) "ON" else "OFF" });
        const r = try runCrashRestartN(Counter, 3, 2, n, label, gate, false, hash_order);
        std.debug.print("  => crash slot {d}: stalled={} validated(N+1)_before_ext(N)={any} maybe_seen={any}\n", .{ n, r.stalled, r.before, r.maybe_seen });
        if (r.stalled) stalls += 1;
        if (gate) try std.testing.expect(r.ext3_all and r.all_voting);
    }
    std.debug.print("\n[2-of-3 sweep, {s} order, gate {s}] {d}/{d} crash slots end in a permanent halt of the 3-node network\n", .{ if (hash_order) "map" else "ascending", if (gate) "ON" else "OFF", stalls, sweep_slots.len });
    return stalls;
}

test "liveness D1-E1-2of3-sweep: 2-of-3 Counter, crash after CONFIRM(N) and restart -- map order halts without the gate; neither order halts with it" {
    const control = try sweep2of3(false, true);
    try std.testing.expect(control > 0); // the finding, on the documented deployment, still reproduced
    try std.testing.expectEqual(@as(u32, 0), try sweep2of3(true, true));
    try std.testing.expectEqual(@as(u32, 0), try sweep2of3(true, false));
}

// ---------------------------------------------------------------------------
// The S8b skeptic's refutation of the first hold buffer: the EXTERNALIZE
// bypass. 3-of-4 {A=0, X=1, Y=2, D=3}. If EXTERNALIZE passes the gate for
// ANY slot ("the catch-up channel"), a single EXTERNALIZE(N+1) from A
// reaching D while D is still one slot behind (it has not externalized N)
// is validated against the stale state -> .maybe_valid -> slot N+1's
// fully_validated is cleared and sticky. D later catches up on N, confirms
// commit on N+1 from {A ext, X conf, Y conf} and externalizes it MUTE. If A
// then dies (the single permanent failure a 3-of-4 tolerates) and X/Y come
// back from a crash-after-CONFIRM(N+1) restart, X and Y hold two
// accept-commits and can never get a third: D never emitted anything for
// N+1 and the re-flood / getSlotState answer carry OWN statements only.
// Halt with three live nodes.
//
// Schedule (every link FIFO; D's restart loses the relayed X/Y history, so
// A's onPeerUp re-flood — OWN statements only, slot-ascending — is all D
// sees for slots 1..3 before X and Y come back):
//   1. all propose 1; D crashes at once (own.log: NOMINATE(1)).
//   2. A, X, Y externalize 1, ballot 2; X and Y crash right after CONFIRM(2).
//   3. A externalizes 2 from the in-flight CONFIRMs, proposes 3.
//   4. D restarts, reconnects to A (the only live peer): A re-floods
//      NOM(1) EXT(1) NOM(2) EXT(2) NOM(3). D: EXT(1) is 1 of 3 -> still
//      behind; NOM(2) held; EXT(2) must be held too (one signer is not
//      v-blocking) — the refuted gate fed it: validate(2) at count 0 ->
//      .maybe_valid -> fully_validated(2) = false, sticky.
//   5. A dies for good.
//   6. X and Y restart (journal: 1; own.log: NOM(2), CONFIRM(2)), reconnect
//      to D and each other. D gets their EXT(1) -> externalizes 1, applies,
//      releases slot 2 (A's NOM + EXT, X/Y's CONFIRMs), validates .valid,
//      confirms commit 2 and puts its own CONFIRM/EXTERNALIZE(2) on the
//      wire -> X and Y externalize 2.
// ---------------------------------------------------------------------------
const BypassResult = struct {
    halted: bool,
    d_fv: ?bool,
    d_ext2: bool,
    x_ext2: bool,
    y_ext2: bool,
    d_wire2: bool,
    d_maybe2: u32,
    d_before2: bool,
};

fn runExtBypass(comptime App: type, label: []const u8, gate: bool, a_dies: bool, trace: bool) !BypassResult {
    const H = Harness(App);
    const gpa = std.testing.allocator;
    const h = try H.init(gpa, 4, 3);
    defer h.deinit();
    h.gate = gate;
    h.trace = trace;
    for (0..4) |i| try h.propose(@intCast(i), 1);
    // 1. D crashes at once: its NOMINATE(1) is on the wire, its own.log has it.
    h.crash(3);
    // 2. A, X, Y externalize slot 1 and ballot slot 2 until X and Y have
    // ACCEPTED commit(2) (CONFIRMs on the wire) but not externalized it.
    const XYAccepted = struct {
        fn stop(hh: *H) bool {
            if (hh.nodes[1].ext.contains(2) or hh.nodes[2].ext.contains(2)) return false;
            return hh.nodes[1].accepted_commit[2] and hh.nodes[2].accepted_commit[2];
        }
    };
    try std.testing.expectEqual(PumpResult.stopped, try h.pump(XYAccepted.stop, 120_000));
    h.crash(1);
    h.crash(2);
    // 3. A finishes slot 2 from the in-flight CONFIRMs and nominates 3.
    const AExt2 = struct {
        fn stop(hh: *H) bool {
            return hh.nodes[0].ext.contains(2) and hh.hasNom(0, 3);
        }
    };
    try std.testing.expectEqual(PumpResult.stopped, try h.pump(AExt2.stop, 120_000));
    // 4. D restarts and reconnects to A, the only live peer.
    try h.restart(3);
    try h.peerUp(3, 0);
    try h.peerUp(0, 3);
    const DDrained = struct {
        fn stop(hh: *H) bool {
            return hh.nodes[3].inbox[0].items.len == 0 and hh.nodes[0].inbox[3].items.len == 0;
        }
    };
    _ = try h.pump(DDrained.stop, 120_000);
    const d_fv_after_a: ?bool = if (h.nodes[3].eng.slots.get(2)) |s| s.fully_validated else null;
    std.debug.print("  [{s}] after A's re-flood: D.state={any} D.ext(1)={} D.slot2.fully_validated={?} D.validate(2)=[inv {d}, maybe {d}, valid {d}] validated(2)_before_ext(1)={} hold[released,far,full,badsig,behind]={any} held_now={d}\n", .{
        label,                                                                                                                                                                                                                                    h.nodes[3].app.state,
        h.nodes[3].ext.contains(1),                                                                                                                                                                                                               d_fv_after_a,
        h.nodes[3].tally[2][0],                                                                                                                                                                                                                   h.nodes[3].tally[2][1],
        h.nodes[3].tally[2][2],                                                                                                                                                                                                                   h.nodes[3].validated_before_prev_ext[2],
        [_]u64{ h.nodes[3].hold.released.load(.acquire), h.nodes[3].hold.dropped_far.load(.acquire), h.nodes[3].hold.dropped_full.load(.acquire), h.nodes[3].hold.dropped_badsig.load(.acquire), h.nodes[3].hold.dropped_behind.load(.acquire) }, h.nodes[3].hold.held_now.load(.acquire),
    });
    // 5. A's permanent failure — the one crash a 3-of-4 tolerates.
    if (a_dies) h.crash(0);
    // 6. X and Y restart on their data_dirs (journal: slot 1; own.log:
    // NOMINATE(2) + CONFIRM(2)) and reconnect to every LIVE peer.
    try h.restart(1);
    try h.restart(2);
    for ([_]u8{ 1, 2 }) |idx| {
        for (0..4) |j_usize| {
            const j: u8 = @intCast(j_usize);
            if (j == idx or !h.nodes[j].live) continue;
            try h.peerUp(idx, j);
            try h.peerUp(j, idx);
        }
    }
    const rd = try h.pump(AllExt2(H).stop, 600_000);
    h.report(label, 2);
    std.debug.print("  phase 6 result: {t}\n", .{rd});
    for (h.nodes, 0..) |*nd, i| {
        if (!nd.live) {
            std.debug.print("  node {d}: DEAD\n", .{i});
            continue;
        }
        const sp = nd.eng.slots.get(2);
        const fv = if (sp) |s| s.fully_validated else false;
        const ol = nd.own_latest.get(2);
        std.debug.print("  node {d} slot 2: ext={} fully_validated={} own nom on wire={} own ballot on wire={}\n", .{ i, nd.ext.contains(2), fv, ol != null and ol.?.nom != null, ol != null and ol.?.ballot != null });
    }
    const ol2 = h.nodes[3].own_latest.get(2);
    return .{
        .halted = rd != .stopped,
        .d_fv = if (h.nodes[3].eng.slots.get(2)) |s| s.fully_validated else null,
        .d_ext2 = h.nodes[3].ext.contains(2),
        .x_ext2 = h.nodes[1].ext.contains(2),
        .y_ext2 = h.nodes[2].ext.contains(2),
        .d_wire2 = ol2 != null and (ol2.?.nom != null or ol2.?.ballot != null),
        .d_maybe2 = h.nodes[3].tally[2][1],
        .d_before2 = h.nodes[3].validated_before_prev_ext[2],
    };
}

// Red with the EXTERNALIZE bypass (the refuted gate; ablation: `.externalize`
// back to `.fed` for any slot in `HoldBuffer.admit`):
//   [ext-bypass Counter, gate ON, A dies] after A's re-flood: D.state=….{ .count = 0 } D.ext(1)=false D.slot2.fully_validated=false D.validate(2)=[inv 0, maybe 1, valid 0] validated(2)_before_ext(1)=true …
//   phase 6 result: time_bound
//   => gate ON: halted=true D.slot2.fully_validated=false D.ext(2)=true X.ext(2)=false Y.ext(2)=false D.wire(2)=false D.maybe(2)=1 …
// With EXTERNALIZE held like every other statement (one signer is not
// v-blocking), apply(1) precedes every validate for 2, no .maybe_valid is
// cached, D votes, X and Y externalize 2 from D's statements.
test "liveness ext-bypass: 3-of-4 Counter, gate ON — a lone EXTERNALIZE(2) reaching a one-slot-behind node is held; with A dead and X/Y restarted the network still converges" {
    const on = try runExtBypass(Counter, "ext-bypass Counter, gate ON, A dies", true, true, false);
    std.debug.print("  => gate ON: halted={} D.slot2.fully_validated={?} D.ext(2)={} X.ext(2)={} Y.ext(2)={} D.wire(2)={} D.maybe(2)={d} D.validated(2)_before_ext(1)={}\n", .{ on.halted, on.d_fv, on.d_ext2, on.x_ext2, on.y_ext2, on.d_wire2, on.d_maybe2, on.d_before2 });
    try std.testing.expect(!on.d_before2); // apply(1) preceded every validate for 2
    try std.testing.expectEqual(@as(u32, 0), on.d_maybe2); // no .maybe_valid verdict was ever cached
    try std.testing.expect(on.d_fv orelse false);
    try std.testing.expect(on.d_wire2); // D's own statement for slot 2 reached the wire
    try std.testing.expect(!on.halted);
    try std.testing.expect(on.x_ext2 and on.y_ext2);
}

// The controls that keep the pin honest: with the gate OFF the same
// schedule still halts (the finding, reproduced through the EXTERNALIZE
// channel); a state-free validate (Loose) converges either way; with A
// alive its re-flood converges the network even though D is mute.
test "liveness ext-bypass controls: gate OFF halts; Loose (state-free validate) converges; A alive converges" {
    const off = try runExtBypass(Counter, "ext-bypass Counter, gate OFF, A dies", false, true, false);
    std.debug.print("  => gate OFF: halted={} D.slot2.fully_validated={?} D.wire(2)={}\n", .{ off.halted, off.d_fv, off.d_wire2 });
    try std.testing.expect(off.halted); // the finding, still reproduced without the gate
    try std.testing.expect(off.d_maybe2 > 0);
    const loose = try runExtBypass(Loose, "ext-bypass Loose, gate ON, A dies", true, true, false);
    std.debug.print("  => Loose gate ON: halted={} D.slot2.fully_validated={?} D.wire(2)={}\n", .{ loose.halted, loose.d_fv, loose.d_wire2 });
    try std.testing.expect(!loose.halted);
    const alive = try runExtBypass(Counter, "ext-bypass Counter, gate ON, A alive", true, false, false);
    std.debug.print("  => A alive gate ON: halted={} D.slot2.fully_validated={?} D.wire(2)={}\n", .{ alive.halted, alive.d_fv, alive.d_wire2 });
    try std.testing.expect(!alive.halted);
    try std.testing.expect(alive.d_wire2); // and D is a voter for slot 2, not merely a follower
}
