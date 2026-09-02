//! Expected-fail case for `zig build appnode-errors`: a Command int wider than 65528 bits (u65535 is a legal Zig width, but `@Int` cannot name its whole-byte rounding, 65536).
//! Pinned needle (tail of the first error line, build.zig appnode_error_cases):
//!   ) is wider than 65528 bits, the widest whole-byte integer the auto-codec can encode.
const slcp = @import("slcp");

const Bad = struct {
    pub const State = struct { n: u64 = 0 };
    pub const Command = struct { n: u65535 };
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
