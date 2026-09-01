//! Expected-fail case for `zig build appnode-errors`: Command has an f64 field.
//! Pinned needle (tail of the first error line, build.zig appnode_error_cases):
//!    — floats are NONDETERMINISTIC across nodes (NaN payloads, ±0, platform math differences).
const slcp = @import("slcp");

const Bad = struct {
    pub const State = struct { n: u64 = 0 };
    pub const Command = struct { price: f64 };
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
