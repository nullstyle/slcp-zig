//! slcp — the native omakase layer. node/ (overlay, timers, store, keys,
//! Node, AppNode) lands at M5/M6; until then this module re-exports the core.

pub const core = @import("slcp-core");
