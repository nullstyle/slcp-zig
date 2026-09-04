//! Expected-fail case for `zig build owned-appnode-errors`: no `pub const Command`.
//! Pinned needle (tail of the first error line, build.zig owned_appnode_error_cases):
//!   ): missing `pub const Command` — the value type the network agrees on.
const std = @import("std");
const slcp = @import("slcp");

const Bad = struct {
    pub const State = struct { count: u64 = 0 };
    pub const Obs = struct { count: u64 };
    pub const Context = void;
    pub const InitError = error{ OutOfMemory, SnapshotCorrupt };
    pub fn initState(context: Context, gpa: std.mem.Allocator) InitError!State {
        _ = context;
        _ = gpa;
        return .{};
    }
    pub fn deinitState(state: *State, gpa: std.mem.Allocator) void {
        _ = state;
        _ = gpa;
    }
    pub fn validate(state: *const State, cmd: u64, context: slcp.ValueContext) slcp.Validity {
        _ = state;
        _ = context;
        return if (cmd >= 1) .valid else .invalid;
    }
    pub fn apply(state: *State, cmd: u64, gpa: std.mem.Allocator) std.mem.Allocator.Error!void {
        _ = gpa;
        state.count = cmd;
    }
    pub fn observe(state: *const State, gpa: std.mem.Allocator) std.mem.Allocator.Error!Obs {
        _ = gpa;
        return .{ .count = state.count };
    }
};

comptime {
    _ = slcp.OwnedAppNode(Bad);
}
