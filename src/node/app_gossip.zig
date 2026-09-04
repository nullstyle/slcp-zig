//! Bounded application-message inbox for the native Node.
//!
//! This module owns only in-process admission and delivery. The Node remains
//! the transport adapter: receiving a wire frame calls `receive`, while an
//! explicit application publish first calls `validatePublish` and then sends
//! to every capable peer. In particular, receipt never implies relay.

const std = @import("std");
const builtin = @import("builtin");
const wire = @import("wire.zig");

pub const max_items: usize = 1024;
pub const max_bytes: usize = 16 * 1024 * 1024;

pub const PublishError = error{AppMessageTooLarge};

pub const Stats = struct {
    receiving: bool,
    queued_items: usize,
    queued_bytes: usize,
    dropped_messages: u64,
    duplicate_messages: u64,
};

const WaitTestHook = struct {
    reached: std.atomic.Value(bool) = .init(false),
    release: std.atomic.Value(bool) = .init(false),

    fn park(self: *WaitTestHook) void {
        self.reached.store(true, .release);
        while (!self.release.load(.acquire)) std.Thread.yield() catch {};
    }
};

pub const State = struct {
    const wait_closing_bit: usize = @as(usize, 1) << (@bitSizeOf(usize) - 1);
    const wait_count_mask: usize = wait_closing_bit - 1;
    const max_physical_items = 2 * max_items;
    const Digest = [32]u8;
    const Queued = struct {
        payload: []u8,
        digest: Digest,
    };

    gpa: std.mem.Allocator,
    io: std.Io,
    mu: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    drained: std.Io.Condition = .init,
    queue: std.ArrayList(Queued) = .empty,
    head: usize = 0,
    pending: std.AutoHashMapUnmanaged(Digest, void) = .empty,
    queued_bytes: usize = 0,
    receiving: bool = false,
    closed: bool = false,
    // The high bit closes admission; the remaining bits count wait calls that
    // have crossed the lifetime gate but have not finished State cleanup.
    wait_gate: std.atomic.Value(usize) = .init(0),
    waiters: if (builtin.is_test) usize else void = if (builtin.is_test) 0 else {},
    dropped_messages: u64 = 0,
    duplicate_messages: u64 = 0,
    wait_entry_test_hook: if (builtin.is_test) ?*WaitTestHook else void =
        if (builtin.is_test) null else {},
    wait_exit_test_hook: if (builtin.is_test) ?*WaitTestHook else void =
        if (builtin.is_test) null else {},

    pub fn init(gpa: std.mem.Allocator, io: std.Io) State {
        return .{ .gpa = gpa, .io = io };
    }

    pub fn validatePublish(_: *State, payload: []const u8) PublishError!void {
        if (payload.len > wire.max_app_message_bytes) return error.AppMessageTooLarge;
    }

    pub fn receive(self: *State, payload: []const u8) void {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        if (!self.receiving or self.closed) {
            self.dropped_messages +|= 1;
            return;
        }
        if (payload.len > wire.max_app_message_bytes) {
            self.dropped_messages +|= 1;
            return;
        }
        var digest: Digest = undefined;
        std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
        if (self.pending.contains(digest)) {
            self.duplicate_messages +|= 1;
            return;
        }
        const next_bytes = std.math.add(usize, self.queued_bytes, payload.len) catch {
            self.dropped_messages +|= 1;
            return;
        };
        if (self.queueCount() >= max_items or next_bytes > max_bytes) {
            self.dropped_messages +|= 1;
            return;
        }
        self.compactQueueIfNeeded();
        self.ensureQueueAppendCapacity() catch {
            self.dropped_messages +|= 1;
            return;
        };
        self.pending.ensureUnusedCapacity(self.gpa, 1) catch {
            self.dropped_messages +|= 1;
            return;
        };
        const copy = self.gpa.dupe(u8, payload) catch {
            self.dropped_messages +|= 1;
            return;
        };
        self.queue.appendAssumeCapacity(.{ .payload = copy, .digest = digest });
        self.pending.putAssumeCapacity(digest, {});
        self.queued_bytes = next_bytes;
        self.cond.signal(self.io);
    }

    pub fn wait(self: *State, timeout_ms: ?u64) ?[]u8 {
        if (!self.enterWait()) return null;
        if (comptime builtin.is_test) {
            if (self.wait_entry_test_hook) |hook| hook.park();
        }
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        defer self.leaveWaitLocked();
        self.receiving = true;
        if (comptime builtin.is_test) self.waiters += 1;
        defer {
            if (comptime builtin.is_test) self.waiters -= 1;
        }
        while (self.queueCount() == 0 and !self.closed) {
            if (timeout_ms) |ms| {
                self.cond.waitTimeout(self.io, &self.mu, .{ .duration = .{
                    .raw = std.Io.Duration.fromMilliseconds(@intCast(ms)),
                    .clock = .awake,
                } }) catch return null;
            } else {
                self.cond.waitUncancelable(self.io, &self.mu);
            }
        }
        if (self.closed) return null;
        const item = self.queue.items[self.head];
        self.head += 1;
        if (self.head == self.queue.items.len) {
            self.queue.clearRetainingCapacity();
            self.head = 0;
        }
        const removed = self.pending.remove(item.digest);
        std.debug.assert(removed);
        self.queued_bytes -= item.payload.len;
        return item.payload;
    }

    pub fn closeAndDrain(self: *State) void {
        _ = self.wait_gate.fetchOr(wait_closing_bit, .acq_rel);
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        self.closed = true;
        self.cond.broadcast(self.io);
        while (self.activeWaitCount() > 0) {
            self.drained.waitUncancelable(self.io, &self.mu);
        }
    }

    /// Before `deinit`, the caller must prevent every new State method call and
    /// externally drain non-wait calls. Only `wait` frames which successfully
    /// crossed the atomic gate may overlap teardown; `closeAndDrain` wakes and
    /// drains those frames. A call preempted before gate entry is not covered.
    pub fn deinit(self: *State) void {
        self.closeAndDrain();
        for (self.queue.items[self.head..]) |item| self.gpa.free(item.payload);
        self.queue.deinit(self.gpa);
        self.pending.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn snapshot(self: *State) Stats {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        return .{
            .receiving = self.receiving,
            .queued_items = self.queueCount(),
            .queued_bytes = self.queued_bytes,
            .dropped_messages = self.dropped_messages,
            .duplicate_messages = self.duplicate_messages,
        };
    }

    fn enterWait(self: *State) bool {
        var gate = self.wait_gate.load(.acquire);
        while (gate & wait_closing_bit == 0) {
            std.debug.assert(gate < wait_count_mask);
            if (self.wait_gate.cmpxchgWeak(
                gate,
                gate + 1,
                .acq_rel,
                .acquire,
            )) |actual| {
                gate = actual;
            } else {
                return true;
            }
        }
        return false;
    }

    /// Called by `wait` while holding `mu`. The active count reaches zero only
    /// under the same mutex `closeAndDrain` holds while checking it, so the
    /// closer cannot return while this frame still has State cleanup to do.
    fn leaveWaitLocked(self: *State) void {
        const previous = self.wait_gate.fetchSub(1, .acq_rel);
        const previous_count = previous & wait_count_mask;
        std.debug.assert(previous_count > 0);
        if (previous & wait_closing_bit != 0 and previous_count == 1) {
            self.drained.broadcast(self.io);
        }
        if (comptime builtin.is_test) {
            if (self.wait_exit_test_hook) |hook| hook.park();
        }
    }

    fn activeWaitCount(self: *const State) usize {
        return self.wait_gate.load(.acquire) & wait_count_mask;
    }

    fn queueCount(self: *const State) usize {
        std.debug.assert(self.head <= self.queue.items.len);
        return self.queue.items.len - self.head;
    }

    fn compactQueueIfNeeded(self: *State) void {
        if (self.head < max_items) return;
        const live = self.queue.items[self.head..];
        std.mem.copyForwards(Queued, self.queue.items[0..live.len], live);
        self.queue.shrinkRetainingCapacity(live.len);
        self.head = 0;
    }

    fn ensureQueueAppendCapacity(self: *State) std.mem.Allocator.Error!void {
        const needed = self.queue.items.len + 1;
        if (needed <= self.queue.capacity) return;
        std.debug.assert(needed <= max_physical_items);

        const doubled = if (self.queue.capacity == 0) 8 else 2 * self.queue.capacity;
        const target = @min(max_physical_items, @max(needed, doubled));
        try self.queue.ensureTotalCapacityPrecise(self.gpa, target);
    }
};

test "app gossip: the first wait opts in and later receive yields an owned FIFO payload" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var state = State.init(gpa, io);
    defer state.deinit();

    try std.testing.expect(state.wait(0) == null);
    try std.testing.expect(state.snapshot().receiving);

    var source = [_]u8{ 0x10, 0x20, 0x30 };
    state.receive(&source);
    source = @splat(0xff);

    const got = state.wait(0) orelse return error.MessageMissing;
    defer gpa.free(got);
    try std.testing.expectEqualSlices(u8, &.{ 0x10, 0x20, 0x30 }, got);
}

test "app gossip: an unused inbox retains no inbound payload or digest" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var state = State.init(gpa, io);
    defer state.deinit();

    state.receive("same");
    state.receive("same");

    const stats = state.snapshot();
    try std.testing.expect(!stats.receiving);
    try std.testing.expectEqual(@as(usize, 0), stats.queued_items);
    try std.testing.expectEqual(@as(usize, 0), stats.queued_bytes);
    try std.testing.expectEqual(@as(u64, 2), stats.dropped_messages);
    try std.testing.expectEqual(@as(u64, 0), stats.duplicate_messages);

    // Pre-opt-in traffic must leave no digest behind: once this consumer opts
    // in, the same bytes are admissible immediately.
    try std.testing.expect(state.wait(0) == null);
    state.receive("same");
    const got = state.wait(0) orelse return error.MessageMissing;
    defer gpa.free(got);
    try std.testing.expectEqualStrings("same", got);
}

test "app gossip: duplicates collapse only while queue-resident and FIFO order survives retry" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var state = State.init(gpa, io);
    defer state.deinit();

    try std.testing.expect(state.wait(0) == null);
    state.receive("same");
    state.receive("same");
    state.receive("later");

    var stats = state.snapshot();
    try std.testing.expectEqual(@as(usize, 2), stats.queued_items);
    try std.testing.expectEqual(@as(usize, 9), stats.queued_bytes);
    try std.testing.expectEqual(@as(u64, 1), stats.duplicate_messages);

    const first = state.wait(0) orelse return error.MessageMissing;
    defer gpa.free(first);
    try std.testing.expectEqualStrings("same", first);

    // Once the first copy leaves the inbox, an application-level rejection
    // must not poison a later network retry of those same bytes.
    state.receive("same");
    const second = state.wait(0) orelse return error.MessageMissing;
    defer gpa.free(second);
    const third = state.wait(0) orelse return error.MessageMissing;
    defer gpa.free(third);
    try std.testing.expectEqualStrings("later", second);
    try std.testing.expectEqualStrings("same", third);

    stats = state.snapshot();
    try std.testing.expectEqual(@as(usize, 0), stats.queued_items);
    try std.testing.expectEqual(@as(usize, 0), stats.queued_bytes);
}

test "app gossip: empty and 64 KiB payloads are valid while an oversized inbound payload is dropped" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var state = State.init(gpa, io);
    defer state.deinit();

    const at_cap = try gpa.alloc(u8, wire.max_app_message_bytes);
    defer gpa.free(at_cap);
    @memset(at_cap, 0xa5);
    const over_cap = try gpa.alloc(u8, wire.max_app_message_bytes + 1);
    defer gpa.free(over_cap);
    @memset(over_cap, 0x5a);

    try state.validatePublish("");
    try state.validatePublish(at_cap);
    try state.validatePublish(at_cap); // every explicit publish/retry is valid
    try std.testing.expectError(error.AppMessageTooLarge, state.validatePublish(over_cap));

    try std.testing.expect(state.wait(0) == null);
    state.receive("");
    const empty = state.wait(0) orelse return error.MessageMissing;
    defer gpa.free(empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);

    state.receive(at_cap);
    const exact = state.wait(0) orelse return error.MessageMissing;
    defer gpa.free(exact);
    try std.testing.expectEqualSlices(u8, at_cap, exact);

    state.receive(over_cap);
    const stats = state.snapshot();
    try std.testing.expectEqual(@as(usize, 0), stats.queued_items);
    try std.testing.expectEqual(@as(usize, 0), stats.queued_bytes);
    try std.testing.expectEqual(@as(u64, 1), stats.dropped_messages);
}

test "app gossip: the FIFO admits at most 1024 distinct payloads" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var state = State.init(gpa, io);
    defer state.deinit();
    try std.testing.expect(state.wait(0) == null);

    var buf: [32]u8 = undefined;
    for (0..max_items) |i| {
        const payload = try std.fmt.bufPrint(&buf, "message-{d}", .{i});
        state.receive(payload);
    }
    state.receive("one-too-many");

    const stats = state.snapshot();
    try std.testing.expectEqual(max_items, stats.queued_items);
    try std.testing.expectEqual(@as(u64, 1), stats.dropped_messages);
    try std.testing.expectEqual(@as(u64, 0), stats.duplicate_messages);

    const freed = state.wait(0) orelse return error.MessageMissing;
    gpa.free(freed);
    state.receive("one-too-many");
    try std.testing.expectEqual(max_items, state.snapshot().queued_items);
}

test "app gossip: a saturated FIFO churns in order with bounded physical storage" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var state = State.init(gpa, io);
    defer state.deinit();
    try std.testing.expect(state.wait(0) == null);

    var encoded: [8]u8 = undefined;
    for (0..max_items) |i| {
        std.mem.writeInt(u64, &encoded, @intCast(i), .little);
        state.receive(&encoded);
    }

    const churn_count = 3 * max_items;
    for (0..churn_count) |i| {
        const got = state.wait(0) orelse return error.MessageMissing;
        const actual = std.mem.readInt(u64, got[0..8], .little);
        gpa.free(got);
        try std.testing.expectEqual(@as(u64, @intCast(i)), actual);

        std.mem.writeInt(u64, &encoded, @intCast(max_items + i), .little);
        state.receive(&encoded);

        const stats = state.snapshot();
        try std.testing.expectEqual(max_items, stats.queued_items);
        try std.testing.expect(state.queue.items.len <= 2 * max_items);
        try std.testing.expect(state.queue.capacity <= 2 * max_items);
        if (i == 0) {
            // A head-index FIFO retains the popped slot until amortized
            // compaction; orderedRemove(0) keeps these lengths equal.
            try std.testing.expect(state.queue.items.len > stats.queued_items);
        }
    }

    for (churn_count..churn_count + max_items) |expected| {
        const got = state.wait(0) orelse return error.MessageMissing;
        const actual = std.mem.readInt(u64, got[0..8], .little);
        gpa.free(got);
        try std.testing.expectEqual(@as(u64, @intCast(expected)), actual);
    }
    try std.testing.expectEqual(@as(usize, 0), state.snapshot().queued_items);
}

test "app gossip: queued payload bytes stop exactly at 16 MiB" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var state = State.init(gpa, io);
    defer state.deinit();
    try std.testing.expect(state.wait(0) == null);

    const payload = try gpa.alloc(u8, wire.max_app_message_bytes);
    defer gpa.free(payload);
    @memset(payload, 0);
    const at_byte_cap = max_bytes / wire.max_app_message_bytes;
    for (0..at_byte_cap) |i| {
        payload[0] = @intCast(i);
        payload[1] = @intCast(i >> 8);
        state.receive(payload);
    }
    payload[0] = 0;
    payload[1] = 1;
    state.receive(payload);

    const stats = state.snapshot();
    try std.testing.expectEqual(at_byte_cap, stats.queued_items);
    try std.testing.expectEqual(max_bytes, stats.queued_bytes);
    try std.testing.expectEqual(@as(u64, 1), stats.dropped_messages);
}

test "app gossip: a timed wait blocks until a later receive signals it" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var state = State.init(gpa, io);
    defer state.deinit();
    try std.testing.expect(state.wait(0) == null);

    const DelayedReceive = struct {
        state: *State,
        io: std.Io,

        fn run(self: *@This()) void {
            std.Io.sleep(self.io, std.Io.Duration.fromMilliseconds(20), .awake) catch {};
            self.state.receive("arrived");
        }
    };
    var delayed = DelayedReceive{ .state = &state, .io = io };
    const thread = try std.Thread.spawn(.{}, DelayedReceive.run, .{&delayed});
    defer thread.join();

    const got = state.wait(1_000) orelse return error.MessageMissing;
    defer gpa.free(got);
    try std.testing.expectEqualStrings("arrived", got);
}

test "app gossip: close wakes and drains a parked timed waiter" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var state = State.init(gpa, io);
    defer state.deinit();

    const Waiter = struct {
        state: *State,
        done: std.atomic.Value(bool) = .init(false),
        saw_null: std.atomic.Value(bool) = .init(false),

        fn run(self: *@This()) void {
            const result = self.state.wait(250);
            self.saw_null.store(result == null, .release);
            self.done.store(true, .release);
        }
    };
    var waiter = Waiter{ .state = &state };
    const thread = try std.Thread.spawn(.{}, Waiter.run, .{&waiter});
    defer thread.join();

    var waited_ms: u64 = 0;
    while (!state.snapshot().receiving and waited_ms < 1_000) : (waited_ms += 1) {
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake);
    }
    try std.testing.expect(state.snapshot().receiving);

    state.closeAndDrain();
    try std.testing.expect(waiter.done.load(.acquire));
    try std.testing.expect(waiter.saw_null.load(.acquire));
}

test "app gossip: close drains an untimed waiter and later receives retain nothing" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var state = State.init(gpa, io);
    defer state.deinit();

    const Waiter = struct {
        state: *State,
        done: std.atomic.Value(bool) = .init(false),
        saw_null: std.atomic.Value(bool) = .init(false),

        fn run(self: *@This()) void {
            const result = self.state.wait(null);
            self.saw_null.store(result == null, .release);
            self.done.store(true, .release);
        }
    };
    var waiter = Waiter{ .state = &state };
    const thread = try std.Thread.spawn(.{}, Waiter.run, .{&waiter});

    var waited_ms: u64 = 0;
    while (!state.snapshot().receiving and waited_ms < 1_000) : (waited_ms += 1) {
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake);
    }
    try std.testing.expect(state.snapshot().receiving);
    state.closeAndDrain();
    thread.join();

    try std.testing.expect(waiter.done.load(.acquire));
    try std.testing.expect(waiter.saw_null.load(.acquire));
    state.receive("after-close");
    const stats = state.snapshot();
    try std.testing.expectEqual(@as(usize, 0), stats.queued_items);
    try std.testing.expectEqual(@as(usize, 0), stats.queued_bytes);
    try std.testing.expectEqual(@as(u64, 1), stats.dropped_messages);
}

test "app gossip: shutdown wins over already-queued ephemeral delivery" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var state = State.init(gpa, io);
    defer state.deinit();
    try std.testing.expect(state.wait(0) == null);
    state.receive("queued");

    state.closeAndDrain();
    try std.testing.expect(state.wait(0) == null);
    const stats = state.snapshot();
    try std.testing.expectEqual(@as(usize, 1), stats.queued_items);
    try std.testing.expectEqual(@as(usize, 6), stats.queued_bytes);
}

test "app gossip: allocation failure retains no digest and the same payload can retry" {
    const io = std.testing.io;
    for (0..3) |fail_index| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{
            .fail_index = fail_index,
        });
        const gpa = failing.allocator();
        var state = State.init(gpa, io);
        defer state.deinit();
        try std.testing.expect(state.wait(0) == null);

        state.receive("retry-me");
        var stats = state.snapshot();
        try std.testing.expectEqual(@as(usize, 0), stats.queued_items);
        try std.testing.expectEqual(@as(u64, 1), stats.dropped_messages);
        try std.testing.expectEqual(@as(u64, 0), stats.duplicate_messages);

        failing.fail_index = std.math.maxInt(usize);
        state.receive("retry-me");
        const got = state.wait(0) orelse return error.MessageMissing;
        defer gpa.free(got);
        try std.testing.expectEqualStrings("retry-me", got);
        stats = state.snapshot();
        try std.testing.expectEqual(@as(usize, 0), stats.queued_items);
        try std.testing.expectEqual(@as(u64, 0), stats.duplicate_messages);
    }
}

test "app gossip: close drains a wait call that entered before acquiring the mutex" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var state = State.init(gpa, io);
    defer state.deinit();

    const Waiter = struct {
        state: *State,
        done: std.atomic.Value(bool) = .init(false),
        saw_null: std.atomic.Value(bool) = .init(false),

        fn run(self: *@This()) void {
            const result = self.state.wait(null);
            self.saw_null.store(result == null, .release);
            self.done.store(true, .release);
        }
    };
    const Closer = struct {
        state: *State,
        done: std.atomic.Value(bool) = .init(false),

        fn run(self: *@This()) void {
            self.state.closeAndDrain();
            self.done.store(true, .release);
        }
    };
    const Inspect = struct {
        fn closed(state_: *State, io_: std.Io) bool {
            state_.mu.lockUncancelable(io_);
            defer state_.mu.unlock(io_);
            return state_.closed;
        }
    };

    var hook = WaitTestHook{};
    state.wait_entry_test_hook = &hook;
    var waiter = Waiter{ .state = &state };
    const waiter_thread = try std.Thread.spawn(.{}, Waiter.run, .{&waiter});

    var waited_ms: u64 = 0;
    while (!hook.reached.load(.acquire) and waited_ms < 1_000) : (waited_ms += 1) {
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake);
    }
    const waiter_reached_entry = hook.reached.load(.acquire);

    var closer = Closer{ .state = &state };
    const closer_thread = try std.Thread.spawn(.{}, Closer.run, .{&closer});

    waited_ms = 0;
    while (!Inspect.closed(&state, io) and waited_ms < 1_000) : (waited_ms += 1) {
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake);
    }
    const closer_reached_notification = Inspect.closed(&state, io);

    waited_ms = 0;
    while (!closer.done.load(.acquire) and waited_ms < 250) : (waited_ms += 1) {
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake);
    }
    const close_returned_before_wait_entry_finished = closer.done.load(.acquire);

    hook.release.store(true, .release);
    waiter_thread.join();
    closer_thread.join();

    try std.testing.expect(waiter_reached_entry);
    try std.testing.expect(closer_reached_notification);
    try std.testing.expect(!close_returned_before_wait_entry_finished);
    try std.testing.expect(waiter.done.load(.acquire));
    try std.testing.expect(waiter.saw_null.load(.acquire));
}

test "app gossip: close does not return before the last waiter finishes its exit handshake" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var state = State.init(gpa, io);
    defer state.deinit();

    const Waiter = struct {
        state: *State,

        fn run(self: *@This()) void {
            std.debug.assert(self.state.wait(0) == null);
        }
    };
    const Closer = struct {
        state: *State,
        done: std.atomic.Value(bool) = .init(false),

        fn run(self: *@This()) void {
            self.state.closeAndDrain();
            self.done.store(true, .release);
        }
    };

    var hook = WaitTestHook{};
    state.wait_exit_test_hook = &hook;
    var waiter = Waiter{ .state = &state };
    const waiter_thread = try std.Thread.spawn(.{}, Waiter.run, .{&waiter});

    var waited_ms: u64 = 0;
    while (!hook.reached.load(.acquire) and waited_ms < 1_000) : (waited_ms += 1) {
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake);
    }
    const waiter_reached_exit = hook.reached.load(.acquire);

    var closer = Closer{ .state = &state };
    const closer_thread = try std.Thread.spawn(.{}, Closer.run, .{&closer});
    waited_ms = 0;
    while (state.wait_gate.load(.acquire) & State.wait_closing_bit == 0 and waited_ms < 1_000) : (waited_ms += 1) {
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake);
    }
    const closer_closed_gate = state.wait_gate.load(.acquire) & State.wait_closing_bit != 0;

    waited_ms = 0;
    while (!closer.done.load(.acquire) and waited_ms < 250) : (waited_ms += 1) {
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake);
    }
    const close_returned_before_wait_exit_finished = closer.done.load(.acquire);

    hook.release.store(true, .release);
    waiter_thread.join();
    closer_thread.join();

    try std.testing.expect(waiter_reached_exit);
    try std.testing.expect(closer_closed_gate);
    try std.testing.expect(!close_returned_before_wait_exit_finished);
}

test "app gossip: close broadcasts to every parked waiter" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var state = State.init(gpa, io);
    defer state.deinit();

    const waiter_count = 4;
    const Waiter = struct {
        state: *State,
        done: std.atomic.Value(bool) = .init(false),
        saw_null: std.atomic.Value(bool) = .init(false),

        fn run(self: *@This()) void {
            const result = self.state.wait(null);
            self.saw_null.store(result == null, .release);
            self.done.store(true, .release);
        }
    };
    const Closer = struct {
        state: *State,
        done: std.atomic.Value(bool) = .init(false),

        fn run(self: *@This()) void {
            self.state.closeAndDrain();
            self.done.store(true, .release);
        }
    };
    const Inspect = struct {
        fn parkedWaiters(state_: *State, io_: std.Io) usize {
            state_.mu.lockUncancelable(io_);
            defer state_.mu.unlock(io_);
            return state_.waiters;
        }

        fn closed(state_: *State, io_: std.Io) bool {
            state_.mu.lockUncancelable(io_);
            defer state_.mu.unlock(io_);
            return state_.closed;
        }
    };

    var waiters: [waiter_count]Waiter = undefined;
    var waiter_threads: [waiter_count]std.Thread = undefined;
    for (&waiters, &waiter_threads) |*waiter, *thread| {
        waiter.* = .{ .state = &state };
        thread.* = try std.Thread.spawn(.{}, Waiter.run, .{waiter});
    }

    var waited_ms: u64 = 0;
    while (Inspect.parkedWaiters(&state, io) != waiter_count and waited_ms < 1_000) : (waited_ms += 1) {
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake);
    }
    const all_waiters_parked = Inspect.parkedWaiters(&state, io) == waiter_count;

    var closer = Closer{ .state = &state };
    const closer_thread = try std.Thread.spawn(.{}, Closer.run, .{&closer});

    waited_ms = 0;
    while (!Inspect.closed(&state, io) and waited_ms < 1_000) : (waited_ms += 1) {
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake);
    }
    const closer_reached_notification = Inspect.closed(&state, io);

    waited_ms = 0;
    while (!closer.done.load(.acquire) and waited_ms < 1_000) : (waited_ms += 1) {
        try std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake);
    }
    const needed_rescue_broadcast = !closer.done.load(.acquire);
    if (needed_rescue_broadcast) {
        // Keep a broken signal-only implementation from hanging the test.
        state.mu.lockUncancelable(io);
        state.closed = true;
        state.cond.broadcast(io);
        state.drained.broadcast(io);
        state.mu.unlock(io);
    }

    closer_thread.join();
    for (&waiter_threads) |*thread| thread.join();

    try std.testing.expect(all_waiters_parked);
    try std.testing.expect(closer_reached_notification);
    try std.testing.expect(!needed_rescue_broadcast);
    for (&waiters) |*waiter| {
        try std.testing.expect(waiter.done.load(.acquire));
        try std.testing.expect(waiter.saw_null.load(.acquire));
    }
}
