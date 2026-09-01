//! Expected-fail case for `zig build appnode-errors`: Command has a function-pointer field (`*const fn () void`).
//! Pinned needle (tail of the first error line, build.zig appnode_error_cases):
//!   , which the auto-codec does not cover. Provide your own encode/decode.
const slcp = @import("slcp");

const Bad = struct {
    pub const State = struct { n: u64 = 0 };
    pub const Command = struct { hook: *const fn () void };
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
