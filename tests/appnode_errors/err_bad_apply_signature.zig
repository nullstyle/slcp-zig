//! Expected-fail case for `zig build appnode-errors`: apply returns u8 (neither `fn (State, Command) State` nor `fn (*State, Command) void`).
//! Pinned needle (tail of the first error line, build.zig appnode_error_cases):
//!   ): apply has the wrong signature.
const slcp = @import("slcp");

const Bad = struct {
    pub const State = struct { n: u64 = 0 };
    pub const Command = struct { n: u64 };
    pub fn validate(state: State, cmd: Command) slcp.Validity {
        _ = state;
        _ = cmd;
        return .valid;
    }
    pub fn apply(state: State, cmd: Command) u8 {
        _ = state;
        _ = cmd;
        return 0;
    }
};

comptime {
    _ = slcp.AppNode(Bad);
}
