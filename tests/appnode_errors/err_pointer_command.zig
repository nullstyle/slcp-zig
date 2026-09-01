//! Expected-fail case for `zig build appnode-errors`: Command has a `[]const u8` slice field.
//! Pinned needle (tail of the first error line, build.zig appnode_error_cases):
//!    is a pointer/slice ([]const u8).
const slcp = @import("slcp");

const Bad = struct {
    pub const State = struct { n: u64 = 0 };
    pub const Command = struct { name: []const u8 };
    pub fn validate(state: State, cmd: Command) slcp.Validity {
        _ = state;
        _ = cmd;
        return .valid;
    }
    pub fn apply(state: State, cmd: Command) State {
        _ = cmd;
        return state;
    }
};

comptime {
    _ = slcp.AppNode(Bad);
}
