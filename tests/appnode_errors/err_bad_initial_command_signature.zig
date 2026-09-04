//! Expected-fail case for `zig build appnode-errors`: initialCommand must
//! return an optional Command.
//! Pinned needle (tail of the first error line, build.zig appnode_error_cases):
//!   ): initialCommand has the wrong signature.
const slcp = @import("slcp");

const Bad = struct {
    pub const State = struct { n: u64 = 0 };
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
    pub fn initialSlot() u64 {
        return 0;
    }
    pub fn initialCommand() Command {
        return .{ .n = 0 };
    }
};

comptime {
    _ = slcp.AppNode(Bad);
}
