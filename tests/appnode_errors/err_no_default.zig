//! Expected-fail case for `zig build appnode-errors`: State field `owner` has no default and there is no initialState().
//! Pinned needle (tail of the first error line, build.zig appnode_error_cases):
//!   ): State field `owner` has no default value.
const slcp = @import("slcp");

const Bad = struct {
    pub const State = struct { owner: [8]u8, n: u64 = 0 };
    pub const Command = struct { n: u64 };
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
