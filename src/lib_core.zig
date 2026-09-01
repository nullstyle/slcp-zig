//! slcp-core — the sans-io deterministic SLCP engine module.
//! Zero std.Io, zero clock, zero RNG anywhere in this module graph; the only
//! dependency is capnpc-zig-core (imported as "capnpc-zig").
//! Design of record: ../claude-design.md.

const std = @import("std");

pub const capnpc = @import("capnpc-zig");

pub const gen = struct {
    pub const slcp = @import("gen/slcp.zig");
    pub const overlay = @import("gen/overlay.zig");
    pub const host = @import("gen/host.zig");
};

pub const canonical = @import("canonical.zig");
pub const crypto = @import("crypto.zig");
pub const driver = @import("driver.zig");
pub const limits = @import("engine/limits.zig");
pub const qset = @import("engine/qset.zig");
pub const quorum = @import("quorum.zig");
pub const statement = @import("engine/statement.zig");
pub const stored = @import("engine/stored.zig");
pub const values = @import("engine/values.zig");
pub const local_node = @import("engine/local_node.zig");
pub const slot = @import("engine/slot.zig");
pub const nomination = @import("engine/nomination.zig");
pub const ballot = @import("engine/ballot.zig");
pub const pending = @import("engine/pending.zig");
pub const qset_store = @import("engine/qset_store.zig");
pub const emit = @import("engine/emit.zig");
pub const engine = @import("engine/engine.zig");
pub const host_codec = @import("engine/host_codec.zig");

test {
    std.testing.refAllDecls(@This());
}
