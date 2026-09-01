//! Expected-fail case for `zig build appnode-errors`: Command is an empty struct (encodes to 0 bytes).
//! Pinned needle (tail of the first error line, build.zig appnode_error_cases):
//!    encodes to 0 bytes; the engine rejects empty values (§8.4) — add a field.
const slcp = @import("slcp");

const Bad = struct {
    pub const State = struct { n: u64 = 0 };
    pub const Command = struct {};
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
