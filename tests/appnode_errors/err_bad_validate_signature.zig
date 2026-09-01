//! Expected-fail case for `zig build appnode-errors`: validate returns bool instead of slcp.Validity.
//! Pinned needle (tail of the first error line, build.zig appnode_error_cases):
//!   ): validate has the wrong signature.
const slcp = @import("slcp");

const Bad = struct {
    pub const State = struct { n: u64 = 0 };
    pub const Command = struct { n: u64 };
    pub fn validate(state: State, cmd: Command) bool {
        _ = state;
        _ = cmd;
        return true;
    }
    pub fn apply(state: State, cmd: Command) State {
        _ = cmd;
        return state;
    }
};

comptime {
    _ = slcp.AppNode(Bad);
}
