//! Expected-fail case for `zig build appnode-errors`: a `comptime` field in Command (one fixed value, no wire representation; decode cannot store into it).
//! Pinned needle (tail of the first error line, build.zig appnode_error_cases):
//!   ` is a comptime field — it has one fixed value and no wire representation.
const slcp = @import("slcp");

const Bad = struct {
    pub const State = struct { n: u64 = 0 };
    pub const Command = struct { comptime tag: u8 = 1, n: u8 };
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
