//! slcp — the native omakase layer (design §11.2). Wraps the sans-io engine
//! (slcp-core) in a real node: TCP flood overlay, a real-clock timer wheel,
//! crash-safe persistence, and a key file. The typed `AppNode(App)` layer
//! (§8.5) lands at M6 on top of this.
//!
//! Escape hatches stay public: `core` is the whole sans-io engine, so a power
//! user can drive `core.engine.Engine` with their own I/O and skip everything
//! here (the simulator is the reference consumer of that split).

const std = @import("std");

/// The sans-io engine and all its pieces (the M0–M4 core).
pub const core = @import("slcp-core");

/// Overlay frame codec (design §9.1): typed ⇄ overlay.capnp `Frame` bytes.
pub const wire = @import("node/wire.zig");
/// TCP flood overlay: listener + dialer, per-peer reader/writer threads,
/// Hello handshake, relay, per-peer budgets, reconnect backoff (§9.3).
pub const overlay = @import("node/overlay.zig");
/// Real-clock timer wheel: arm/cancel → timer_fired inputs (§5.4).
pub const timers = @import("node/timers.zig");
/// Crash-safe persistence: own.log, externalized.log, qsets/ (§10).
pub const store = @import("node/store.zig");
/// Ed25519 key file: loadOrCreate (§11 keys UX).
pub const keys = @import("node/keys.zig");
/// The omakase Node: engine thread + effect drain + propose/waitExternalized
/// + restart procedure (§11.2 bytes-level surface).
pub const node = @import("node/node.zig");

pub const Node = node.Node;
pub const NodeOptions = node.Options;

// ===== M6:quorum exports =====
// Quorum spec, nodeId helpers, lint_report (M6 quorum stage; insert here only).

// ===== M6:appnode exports =====
// AppNode, Codec, Validity, Driver, DeliveryHook (M6 appnode stage; insert here only).
/// Typed app layer (§8.5): `Codec(T)` auto-codec + the `AppNode(App)` comptime
/// contract. `create` / `propose` / `waitApplied` land in M6 S3.
pub const app_node = @import("node/app_node.zig");
pub const AppNode = app_node.AppNode;
pub const Codec = app_node.Codec;
pub const Validity = core.driver.Validity;
pub const Driver = core.driver.Driver;
pub const DriverError = core.driver.DriverError;

test {
    // Discover every node-layer module's tests under `zig build node-tests`.
    std.testing.refAllDecls(@This());
}
