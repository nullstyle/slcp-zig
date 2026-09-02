//! Expected-fail case for `zig build appnode-errors`: initialSlot returns u8 instead of u64.
//! Pinned needle (tail of the first error line, build.zig appnode_error_cases):
//!   ): initialSlot has the wrong signature.
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
    pub fn initialSlot() u8 {
        return 0;
    }
};

comptime {
    _ = slcp.AppNode(Bad);
}
