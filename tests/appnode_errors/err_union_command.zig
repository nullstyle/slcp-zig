//! Expected-fail case for `zig build appnode-errors`: Command has a tagged-union field.
//! Pinned needle (tail of the first error line, build.zig appnode_error_cases):
//!   ) — the v1 auto-codec does not encode unions.
const slcp = @import("slcp");

const Bad = struct {
    pub const State = struct { n: u64 = 0 };
    pub const Command = struct { op: union(enum) { deposit: u64, withdraw: u64 } };
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
