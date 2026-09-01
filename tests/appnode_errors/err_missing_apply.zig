//! Expected-fail case for `zig build appnode-errors`: no `pub fn apply`.
//! Pinned needle (tail of the first error line, build.zig appnode_error_cases):
//!   ): missing `pub fn apply(state: State, cmd: Command) State`.
const slcp = @import("slcp");

const Bad = struct {
    pub const State = struct { n: u64 = 0 };
    pub const Command = struct { n: u64 };
    pub fn validate(state: State, cmd: Command) slcp.Validity {
        _ = state;
        _ = cmd;
        return .valid;
    }
};

comptime {
    _ = slcp.AppNode(Bad);
}
