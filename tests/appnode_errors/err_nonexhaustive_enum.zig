//! Expected-fail case for `zig build appnode-errors`: Command has a non-exhaustive enum field.
//! Pinned needle (tail of the first error line, build.zig appnode_error_cases):
//!   ) — `_` admits every tag value, so there is no single canonical spelling; make the enum exhaustive.
const slcp = @import("slcp");

const Bad = struct {
    pub const State = struct { n: u64 = 0 };
    pub const Command = struct { kind: enum(u8) { a, b, _ } };
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
