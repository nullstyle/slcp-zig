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
//!   * On fire: remove the timer from the set, then call `fire`. A timer that
//!     was canceled between selection and firing must NOT fire.
//!   * deinit/stop: signal the thread to exit, join it. Idempotent stop.
//!   * Tests: arm 20ms → fires ~once with right (slot,timer) (allow slack);
//!     cancel before deadline → never fires; re-arm extends/replaces; two
//!     timers fire in deadline order; stop() joins cleanly with timers
//!     pending. Count fires via an atomic in the test ctx.
//! ========================================================================

const std = @import("std");
const core = @import("slcp-core");

pub const FireFn = *const fn (ctx: ?*anyopaque, slot: u64, timer_id: u16) void;

pub const Wheel = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    fire: FireFn,
    fire_ctx: ?*anyopaque,
    _placeholder: usize = 0,

    pub fn init(gpa: std.mem.Allocator, io: std.Io, fire: FireFn, fire_ctx: ?*anyopaque) Wheel {
        return .{ .gpa = gpa, .io = io, .fire = fire, .fire_ctx = fire_ctx };
    }

    /// Spawn the wheel thread.
    pub fn start(self: *Wheel) !void {
        _ = self;
        @panic("stub: timers.Wheel.start — M5 agent");
    }

    /// Arm (or re-arm) the (slot, timer_id) timer to fire in `delay_ms`.
    pub fn arm(self: *Wheel, slot: u64, timer_id: u16, delay_ms: u32) !void {
        _ = self;
        _ = slot;
        _ = timer_id;
        _ = delay_ms;
        @panic("stub: timers.Wheel.arm — M5 agent");
    }

    /// Cancel the (slot, timer_id) timer if live (no-op otherwise).
    pub fn cancel(self: *Wheel, slot: u64, timer_id: u16) void {
        _ = self;
        _ = slot;
        _ = timer_id;
        @panic("stub: timers.Wheel.cancel — M5 agent");
    }

    /// Signal the thread to exit and join it. Idempotent.
    pub fn stop(self: *Wheel) void {
        _ = self;
        @panic("stub: timers.Wheel.stop — M5 agent");
    }

    pub fn deinit(self: *Wheel) void {
        _ = self;
        @panic("stub: timers.Wheel.deinit — M5 agent");
    }
};
