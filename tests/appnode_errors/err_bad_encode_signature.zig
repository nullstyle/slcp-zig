//! Expected-fail case for `zig build appnode-errors`: encode returns usize instead of the written `[]u8` prefix.
//! Pinned needle (tail of the first error line, build.zig appnode_error_cases):
//!   ): encode has the wrong signature.
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
    pub fn encode(cmd: Command, buf: []u8) usize {
        buf[0] = @intCast(cmd.n);
        return 1;
    }
    pub fn decode(bytes: []const u8) ?Command {
        if (bytes.len != 1) return null;
        return .{ .n = bytes[0] };
    }
};

comptime {
    _ = slcp.AppNode(Bad);
}
