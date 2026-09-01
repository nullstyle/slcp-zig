//! Expected-fail case for `zig build appnode-errors`: no `pub const Command`.
//! Pinned needle (tail of the first error line, build.zig appnode_error_cases):
//!   ): missing `pub const Command` — the value type the network agrees on.
const slcp = @import("slcp");

const Bad = struct {
    pub const State = struct { n: u64 = 0 };
    pub fn validate(state: State, cmd: u64) slcp.Validity {
        _ = state;
        _ = cmd;
        return .valid;
    }
    pub fn apply(state: State, cmd: u64) State {
        _ = cmd;
        return state;
    }
};

comptime {
    _ = slcp.AppNode(Bad);
}
