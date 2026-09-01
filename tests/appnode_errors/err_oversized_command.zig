//! Expected-fail case for `zig build appnode-errors`: Command encodes to 65537 bytes, above the frozen §4.5 cap.
//! Pinned needle (tail of the first error line, build.zig appnode_error_cases):
//!    bytes, above the frozen 65536-byte value cap (§4.5).
const slcp = @import("slcp");

const Bad = struct {
    pub const State = struct { n: u64 = 0 };
    pub const Command = struct { blob: [65537]u8 };
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
