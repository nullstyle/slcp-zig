//! Expected-fail case for `zig build owned-appnode-errors`: no `pub const State` (other decls neutralized to u64 so the contract error is the only one).
//! Pinned needle (tail of the first error line, build.zig owned_appnode_error_cases):
//!   ): missing `pub const State` — the owned replicated state type.
const std = @import("std");
const slcp = @import("slcp");

const Bad = struct {
    pub const Command = struct { next: u64 };
    pub const Obs = struct { count: u64 };
    pub const Context = void;
    pub const InitError = error{ OutOfMemory, SnapshotCorrupt };
    pub fn initState(context: Context, gpa: std.mem.Allocator) InitError!u64 {
        _ = context;
        _ = gpa;
        return 0;
    }
    pub fn deinitState(state: *u64, gpa: std.mem.Allocator) void {
        _ = state;
        _ = gpa;
    }
    pub fn validate(state: u64, cmd: Command, context: slcp.ValueContext) slcp.Validity {
        _ = state;
        _ = context;
        return if (cmd.next >= 1) .valid else .invalid;
    }
    pub fn apply(state: *u64, cmd: Command, gpa: std.mem.Allocator) std.mem.Allocator.Error!void {
        _ = state;
        _ = gpa;
        _ = cmd;
    }
    pub fn observe(state: *const u64, gpa: std.mem.Allocator) std.mem.Allocator.Error!Obs {
        _ = state;
        _ = gpa;
        return .{ .count = 0 };
    }
};

comptime {
    _ = slcp.OwnedAppNode(Bad);
}
