//! Expected-fail case for `zig build appnode-errors`: encode without decode (a lone codec half).
//! Pinned needle (tail of the first error line, build.zig appnode_error_cases):
//!   ): a custom codec needs BOTH `pub fn encode(cmd: Command, buf: []u8) []u8` and `pub fn decode(bytes: []const u8) ?Command`.
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
    pub fn encode(cmd: Command, buf: []u8) []u8 {
        buf[0] = @intCast(cmd.n);
        return buf[0..1];
    }
};

comptime {
    _ = slcp.AppNode(Bad);
}
