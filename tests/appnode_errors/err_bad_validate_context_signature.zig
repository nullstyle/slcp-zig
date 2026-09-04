//! Expected-fail case for `zig build appnode-errors`: contextual validate's
//! third parameter is not slcp.ValueContext.
//! Pinned needle (tail of the first error line, build.zig appnode_error_cases):
//!   ): validate context has the wrong signature.
const slcp = @import("slcp");

const Bad = struct {
    pub const State = struct { n: u64 = 0 };
    pub const Command = struct { n: u64 };
    pub fn validate(state: State, cmd: Command, context: u64) slcp.Validity {
        _ = state;
        _ = cmd;
        _ = context;
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
