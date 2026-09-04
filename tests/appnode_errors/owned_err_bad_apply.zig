//! Expected-fail case for `zig build owned-appnode-errors`: apply takes no allocator and cannot fail.
//! Pinned needle (tail of the first error line, build.zig owned_appnode_error_cases):
//!   ): apply has the wrong signature.
const std = @import("std");
const slcp = @import("slcp");

const Bad = struct {
    pub const State = struct { count: u64 = 0 };
    pub const Command = struct { next: u64 };
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
    pub fn validate(state: *const State, cmd: Command, context: slcp.ValueContext) slcp.Validity {
        _ = state;
        _ = context;
        return if (cmd.next >= 1) .valid else .invalid;
    }
    pub fn apply(state: *State, cmd: Command) void {
        state.count = cmd.next;
    }
    pub fn observe(state: *const State, gpa: std.mem.Allocator) std.mem.Allocator.Error!Obs {
        _ = gpa;
        return .{ .count = state.count };
    }
};

comptime {
    _ = slcp.OwnedAppNode(Bad);
}
