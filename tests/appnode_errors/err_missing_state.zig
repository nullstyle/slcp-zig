//! Expected-fail case for `zig build appnode-errors`: no `pub const State`.
//! Pinned needle (tail of the first error line, build.zig appnode_error_cases):
//!   ): missing `pub const State` — the replicated state type.
const slcp = @import("slcp");

const Bad = struct {
    pub const Command = struct { n: u64 };
    pub fn validate(state: u64, cmd: Command) slcp.Validity {
        _ = state;
        _ = cmd;
        return .valid;
    }
    pub fn apply(state: u64, cmd: Command) u64 {
        _ = cmd;
        return state;
    }
};

comptime {
    _ = slcp.AppNode(Bad);
}
