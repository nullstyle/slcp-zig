//! Bounded application-message inbox for the native Node.
//!
//! This module owns only in-process admission and delivery. The Node remains
//! the transport adapter: receiving a wire frame calls `receive`, while an
//! explicit application publish first calls `validatePublish` and then sends
//! to every capable peer. In particular, receipt never implies relay.

const std = @import("std");
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

pub const State = struct {
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
    pending: std.AutoHashMapUnmanaged(Digest, void) = .empty,
    queued_bytes: usize = 0,
    receiving: bool = false,
    closed: bool = false,
    waiters: usize = 0,
    dropped_messages: u64 = 0,
    duplicate_messages: u64 = 0,

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
        if (self.queue.items.len >= max_items or next_bytes > max_bytes) {
            self.dropped_messages +|= 1;
            return;
        }
        self.queue.ensureUnusedCapacity(self.gpa, 1) catch {
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
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        self.receiving = true;
        self.waiters += 1;
        defer {
            self.waiters -= 1;
            if (self.waiters == 0) self.drained.signal(self.io);
        }
        while (self.queue.items.len == 0 and !self.closed) {
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
        const item = self.queue.orderedRemove(0);
        const removed = self.pending.remove(item.digest);
        std.debug.assert(removed);
        self.queued_bytes -= item.payload.len;
        return item.payload;
    }

    pub fn closeAndDrain(self: *State) void {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        self.closed = true;
        self.cond.broadcast(self.io);
        while (self.waiters > 0) self.drained.waitUncancelable(self.io, &self.mu);
    }

    pub fn deinit(self: *State) void {
        self.closeAndDrain();
        for (self.queue.items) |item| self.gpa.free(item.payload);
        self.queue.deinit(self.gpa);
        self.pending.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn snapshot(self: *State) Stats {
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        return .{
            .receiving = self.receiving,
            .queued_items = self.queue.items.len,
            .queued_bytes = self.queued_bytes,
            .dropped_messages = self.dropped_messages,
            .duplicate_messages = self.duplicate_messages,
        };
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

    state.receive("first");
    state.receive("second");

    const stats = state.snapshot();
    try std.testing.expect(!stats.receiving);
    try std.testing.expectEqual(@as(usize, 0), stats.queued_items);
    try std.testing.expectEqual(@as(usize, 0), stats.queued_bytes);
    try std.testing.expectEqual(@as(u64, 2), stats.dropped_messages);
    try std.testing.expectEqual(@as(u64, 0), stats.duplicate_messages);
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
