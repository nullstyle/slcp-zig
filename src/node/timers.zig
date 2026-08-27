//! Real-clock timer wheel (design §5.4 host side). The engine emits
//! `arm_timer{slot, timer, delay_ms}` and `cancel_timer{slot, timer}`
//! effects; this wheel turns them into `timer_fired{slot, timer}` inputs at
//! the right wall-clock moment.
//!
//! Threading: `arm`/`cancel` are called from the ENGINE THREAD (during effect
//! drain). A single background thread sleeps until the nearest deadline, then
//! invokes `fire(ctx, slot, timer_id)` — which the Node wires to enqueue a
//! `timer_fired` input back onto the engine thread's input queue. `fire` must
//! therefore be cheap and thread-safe; it runs on the wheel thread, NOT the
//! engine thread.
//!
//! ==== IMPLEMENTATION BRIEF (M5 agent) ====================================
//! Public interface below is FROZEN — implement bodies + tests, do not change
//! signatures. `timer_id` is `@intFromEnum(core.engine.TimerId)` (0/1); pass
//! it through opaquely.
//!
//!   * A (slot, timer_id) pair identifies a timer. Arming an already-armed
//!     pair REPLACES its deadline (re-arm). cancel removes it. At most one
//!     live timer per pair.
//!   * Use a mutex + condition variable (std.Thread.Mutex / .Condition, or
//!     the std.Io equivalents) and a deadline-ordered structure (a small
//!     array is fine — timer counts are tiny: ≤ 2 per live slot). The wheel
//!     thread waits with a timed wait until the nearest deadline; a new arm
//!     with an earlier deadline signals it to re-evaluate.
//!   * Monotonic clock: use std.Io's clock (awake/monotonic), NOT wall time,
//!     so a system-clock jump can't stall or stampede timers. delay_ms is
//!     relative.
//!   * On fire: remove the timer from the set, then call `fire`. A cancel
//!     that wins the wheel's lock before the timer is selected must prevent
//!     the fire. (A cancel that loses that race can still observe a stale
//!     delivery — see STALE-FIRE RACE below; accepted for v1.)
//!   * deinit/stop: signal the thread to exit, join it. Idempotent stop.
//!   * Tests: arm 20ms → fires ~once with right (slot,timer) (allow slack);
//!     cancel before deadline → never fires; re-arm extends/replaces; two
//!     timers fire in deadline order; stop() joins cleanly with timers
//!     pending. Count fires via an atomic in the test ctx.
//! ========================================================================
//!
//! Implementation note (this toolchain): `std.Thread` has no `Mutex`/
//! `Condition` here, so the wheel uses the `std.Io` equivalents (`Io.Mutex`,
//! `Io.Condition`) driven from a plain `std.Thread`. The wait deadline is
//! anchored to the monotonic `Io.Clock.awake` clock, so a wall-clock jump
//! can never stall or stampede the wheel. `arm`/`cancel` mutate the live set
//! under the mutex and `signal` the wheel thread to re-evaluate the nearest
//! deadline. Selection and removal of a due timer happen in ONE locked
//! critical section, so a `cancel` (or re-arm) that acquires the lock BEFORE
//! the wheel selects the timer removes (or re-deadlines) it and it does not
//! fire at the old deadline.
//!
//! STALE-FIRE RACE (accepted for v1). The guarantee above is only "cancels
//! that win the lock before selection". Once the wheel thread has selected
//! and removed a due timer and dropped the lock to invoke `fire`, the timer
//! is no longer in the live set — a `cancel` or re-arm arriving in that
//! window finds nothing to remove (cancel is a no-op; re-arm inserts a fresh
//! entry) and CANNOT recall the in-flight callback. The engine thread can
//! therefore observe a `timer_fired{slot, timer}` for a timer it just
//! canceled, or one delivered at the OLD deadline of a pair it just
//! re-armed. Why this is safe: it matches stellar-core's host timer
//! semantics, and the engine treats any `timer_fired` purely as a timeout
//! nudge — a spurious nudge can at worst cause an extra round-timeout
//! evaluation, never a safety (agreement) violation. A v2 fix, if the
//! spurious nudges ever matter, is a generation counter per (slot, timer_id)
//! pair: `arm`/`cancel` bump the generation under the lock, the wheel
//! captures the generation at selection and delivers it with the fire (or
//! re-checks it under the lock immediately before invoking `fire`), and the
//! Node drops any fire whose generation is stale. Do not redesign the wheel
//! for v1.

const std = @import("std");
const core = @import("slcp-core");

pub const FireFn = *const fn (ctx: ?*anyopaque, slot: u64, timer_id: u16) void;

/// One live timer. `deadline_ns` is a monotonic `Io.Clock.awake` timestamp.
const Timer = struct {
    slot: u64,
    timer_id: u16,
    deadline_ns: i96,
};

pub const Wheel = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    fire: FireFn,
    fire_ctx: ?*anyopaque,
    _placeholder: usize = 0,

    // --- private state (guarded by `mu`, except `thread`) ---
    /// Guards `timers` and `stopping`.
    mu: std.Io.Mutex = .init,
    /// Signaled on arm/cancel/stop so the wheel thread re-evaluates.
    cond: std.Io.Condition = .init,
    /// The live set. Tiny (≤ 2 per live slot); a flat list is plenty.
    timers: std.ArrayList(Timer) = .empty,
    /// The background thread; null until `start`, back to null after join.
    thread: ?std.Thread = null,
    /// Latched by `stop` to tell the wheel thread to exit.
    stopping: bool = false,

    pub fn init(gpa: std.mem.Allocator, io: std.Io, fire: FireFn, fire_ctx: ?*anyopaque) Wheel {
        return .{ .gpa = gpa, .io = io, .fire = fire, .fire_ctx = fire_ctx };
    }

    /// Spawn the wheel thread. Idempotent: a second call while running is a
    /// no-op.
    pub fn start(self: *Wheel) !void {
        if (self.thread != null) return;
        self.stopping = false;
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    /// Arm (or re-arm) the (slot, timer_id) timer to fire in `delay_ms`.
    pub fn arm(self: *Wheel, slot: u64, timer_id: u16, delay_ms: u32) !void {
        const io = self.io;
        const now_ns = std.Io.Clock.now(.awake, io).nanoseconds;
        const deadline_ns = now_ns + @as(i96, delay_ms) * std.time.ns_per_ms;

        self.mu.lockUncancelable(io);
        defer self.mu.unlock(io);

        // Re-arm in place if the pair is already live (replace the deadline).
        for (self.timers.items) |*t| {
            if (t.slot == slot and t.timer_id == timer_id) {
                t.deadline_ns = deadline_ns;
                self.cond.signal(io);
                return;
            }
        }
        try self.timers.append(self.gpa, .{
            .slot = slot,
            .timer_id = timer_id,
            .deadline_ns = deadline_ns,
        });
        self.cond.signal(io);
    }

    /// Cancel the (slot, timer_id) timer if live (no-op otherwise).
    pub fn cancel(self: *Wheel, slot: u64, timer_id: u16) void {
        const io = self.io;
        self.mu.lockUncancelable(io);
        defer self.mu.unlock(io);

        var i: usize = 0;
        while (i < self.timers.items.len) : (i += 1) {
            const t = self.timers.items[i];
            if (t.slot == slot and t.timer_id == timer_id) {
                _ = self.timers.swapRemove(i);
                // Wake the wheel: if this was the nearest timer it should stop
                // waiting on a deadline that will never fire.
                self.cond.signal(io);
                return;
            }
        }
    }

    /// Signal the thread to exit and join it. Idempotent.
    pub fn stop(self: *Wheel) void {
        const io = self.io;
        self.mu.lockUncancelable(io);
        self.stopping = true;
        self.cond.broadcast(io);
        self.mu.unlock(io);

        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    pub fn deinit(self: *Wheel) void {
        self.stop();
        self.timers.deinit(self.gpa);
        self.* = undefined;
    }

    /// The wheel thread body: sleep until the nearest deadline, fire, repeat.
    fn run(self: *Wheel) void {
        const io = self.io;
        self.mu.lockUncancelable(io);
        defer self.mu.unlock(io);

        while (!self.stopping) {
            if (self.timers.items.len == 0) {
                // Nothing armed: wait until arm() or stop() wakes us.
                self.cond.waitUncancelable(io, &self.mu);
                continue;
            }

            // Find the nearest deadline (tiny set; a linear scan is fine).
            var idx: usize = 0;
            var min_ns: i96 = self.timers.items[0].deadline_ns;
            for (self.timers.items[1..], 1..) |t, i| {
                if (t.deadline_ns < min_ns) {
                    min_ns = t.deadline_ns;
                    idx = i;
                }
            }

            const now_ns = std.Io.Clock.now(.awake, io).nanoseconds;
            if (now_ns >= min_ns) {
                // Due. Remove it from the live set *while holding the lock* —
                // this is the atomic "selection". A cancel that won the lock
                // before this point already removed the timer, so it is never
                // selected. A cancel (or re-arm) arriving AFTER this point
                // finds the entry gone and cannot recall the callback below —
                // that is the accepted stale-fire race documented in the file
                // header. Only after selection do we drop the lock and invoke
                // the (possibly slow) callback.
                const fired = self.timers.swapRemove(idx);
                self.mu.unlock(io);
                self.fire(self.fire_ctx, fired.slot, fired.timer_id);
                self.mu.lockUncancelable(io);
                continue;
            }

            // Not yet due: wait until the deadline or until arm/cancel/stop
            // signals us. The deadline is a monotonic `awake` timestamp, so a
            // system-clock jump can neither stall nor stampede this wait.
            const deadline: std.Io.Clock.Timestamp = .{
                .raw = .{ .nanoseconds = min_ns },
                .clock = .awake,
            };
            // Timeout/Canceled both just re-evaluate the loop; the mutex is
            // held again on return regardless.
            self.cond.waitTimeout(io, &self.mu, .{ .deadline = deadline }) catch {};
        }
    }
};

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

/// Fire sink for tests. `fire` runs on the wheel thread; the test thread
/// reads these fields, so counters are atomic and `order` is published via a
/// release store of `count`.
const TestCtx = struct {
    count: std.atomic.Value(u32) = .init(0),
    last_slot: std.atomic.Value(u64) = .init(0),
    last_timer: std.atomic.Value(u16) = .init(0),
    /// The slot of each fire, in fire order (up to 8 fires recorded).
    order: [8]u64 = @splat(0),

    fn onFire(ctx_opaque: ?*anyopaque, slot: u64, timer_id: u16) void {
        const ctx: *TestCtx = @ptrCast(@alignCast(ctx_opaque.?));
        // Only the single wheel thread calls this, so `count` has one writer:
        // load the current index, publish the entry, then release-increment.
        const i = ctx.count.load(.monotonic);
        if (i < ctx.order.len) ctx.order[i] = slot;
        ctx.last_slot.store(slot, .monotonic);
        ctx.last_timer.store(timer_id, .monotonic);
        _ = ctx.count.fetchAdd(1, .release);
    }
};

fn sleepMs(io: std.Io, ms: u64) void {
    const ns: i96 = @as(i96, @intCast(ms)) * std.time.ns_per_ms;
    const d: std.Io.Clock.Duration = .{ .raw = .fromNanoseconds(ns), .clock = .awake };
    d.sleep(io) catch {};
}

/// Poll until `ctx.count >= target` or `timeout_ms` elapses (monotonic).
/// Returns true if the target was reached.
fn waitForCount(io: std.Io, ctx: *TestCtx, target: u32, timeout_ms: u64) bool {
    const start_ns = std.Io.Clock.now(.awake, io).nanoseconds;
    const limit_ns: i96 = @as(i96, @intCast(timeout_ms)) * std.time.ns_per_ms;
    while (ctx.count.load(.acquire) < target) {
        if (std.Io.Clock.now(.awake, io).nanoseconds - start_ns > limit_ns) return false;
        sleepMs(io, 3);
    }
    return true;
}

test "arm fires once with correct (slot, timer)" {
    const io = testing.io;
    var ctx: TestCtx = .{};
    var w = Wheel.init(testing.allocator, io, TestCtx.onFire, &ctx);
    defer w.deinit();
    try w.start();

    try w.arm(42, 1, 20);
    try testing.expect(waitForCount(io, &ctx, 1, 2000));

    try testing.expectEqual(@as(u64, 42), ctx.last_slot.load(.monotonic));
    try testing.expectEqual(@as(u16, 1), ctx.last_timer.load(.monotonic));

    // It must fire exactly once — give it room to (wrongly) refire.
    sleepMs(io, 80);
    try testing.expectEqual(@as(u32, 1), ctx.count.load(.acquire));
}

test "cancel before deadline never fires" {
    const io = testing.io;
    var ctx: TestCtx = .{};
    var w = Wheel.init(testing.allocator, io, TestCtx.onFire, &ctx);
    defer w.deinit();
    try w.start();

    try w.arm(7, 0, 120);
    w.cancel(7, 0); // well before the 120ms deadline
    // Cancel of an unknown pair is a harmless no-op.
    w.cancel(999, 1);

    sleepMs(io, 260); // past the original deadline
    try testing.expectEqual(@as(u32, 0), ctx.count.load(.acquire));
}

test "re-arm replaces the deadline" {
    const io = testing.io;
    var ctx: TestCtx = .{};
    var w = Wheel.init(testing.allocator, io, TestCtx.onFire, &ctx);
    defer w.deinit();
    try w.start();

    // Arm far in the future, then re-arm the same pair much SOONER. If the
    // re-arm replaces the deadline, the fire lands ~200ms in; if re-arm were
    // broken (deadline kept), nothing fires before 2000ms and the bounded
    // wait below times out. This direction is timing-robust: preemption
    // between the two arm() calls only delays the test, it cannot let the
    // first deadline slip past before the re-arm the way "arm 20ms then
    // re-arm 300ms" could.
    const start_ns = std.Io.Clock.now(.awake, io).nanoseconds;
    try w.arm(3, 1, 2000);
    try w.arm(3, 1, 200);

    // Fires well before the original 2000ms deadline...
    try testing.expect(waitForCount(io, &ctx, 1, 1200));
    // ...but never before the replacement 200ms deadline (the wheel only
    // fires at now >= deadline, and the deadline was set after `start_ns`).
    const elapsed_ns = std.Io.Clock.now(.awake, io).nanoseconds - start_ns;
    try testing.expect(elapsed_ns >= 200 * std.time.ns_per_ms);
    try testing.expectEqual(@as(u64, 3), ctx.last_slot.load(.monotonic));
    try testing.expectEqual(@as(u16, 1), ctx.last_timer.load(.monotonic));

    // Exactly once: the replaced 2000ms deadline must not fire as a second
    // timer shortly after (give a wrong duplicate some room to appear).
    sleepMs(io, 80);
    try testing.expectEqual(@as(u32, 1), ctx.count.load(.acquire));
}

test "two timers fire in deadline order" {
    const io = testing.io;
    var ctx: TestCtx = .{};
    var w = Wheel.init(testing.allocator, io, TestCtx.onFire, &ctx);
    defer w.deinit();
    try w.start();

    // Arm the later one first to prove ordering is by deadline, not arm order.
    try w.arm(100, 0, 120);
    try w.arm(200, 0, 30);

    try testing.expect(waitForCount(io, &ctx, 2, 2000));
    // 200 (30ms) before 100 (120ms).
    try testing.expectEqual(@as(u64, 200), ctx.order[0]);
    try testing.expectEqual(@as(u64, 100), ctx.order[1]);
}

test "stop joins cleanly with timers pending (idempotent)" {
    const io = testing.io;
    var ctx: TestCtx = .{};
    var w = Wheel.init(testing.allocator, io, TestCtx.onFire, &ctx);
    defer w.deinit();
    try w.start();

    // Long deadlines that will never arrive during the test.
    try w.arm(1, 0, 60_000);
    try w.arm(2, 1, 60_000);
    try w.arm(2, 0, 60_000);

    // Joins promptly despite pending timers, and fires none of them.
    w.stop();
    try testing.expectEqual(@as(u32, 0), ctx.count.load(.acquire));

    // Idempotent: a second stop (and deinit's stop) must be safe.
    w.stop();
}

test "stop with no timers and without start is safe" {
    const io = testing.io;
    var ctx: TestCtx = .{};
    var w = Wheel.init(testing.allocator, io, TestCtx.onFire, &ctx);
    // Never started: stop()/deinit() must still be leak-free no-ops.
    w.stop();
    w.deinit();
    try testing.expectEqual(@as(u32, 0), ctx.count.load(.acquire));
}
