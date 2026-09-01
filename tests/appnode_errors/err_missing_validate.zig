//! Expected-fail case for `zig build appnode-errors`: no `pub fn validate`.
//! Pinned needle (tail of the first error line, build.zig appnode_error_cases):
//!   ): missing `pub fn validate(state: State, cmd: Command) slcp.Validity`.
const slcp = @import("slcp");

const Bad = struct {
    pub const State = struct { n: u64 = 0 };
    pub const Command = struct { n: u64 };
    pub fn apply(state: State, cmd: Command) State {
        _ = cmd;
        return state;
    }
};

comptime {
    _ = slcp.AppNode(Bad);
}
