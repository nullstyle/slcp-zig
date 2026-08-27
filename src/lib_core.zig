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
pub const qset = @import("engine/qset.zig");

test {
    std.testing.refAllDecls(@This());
}
