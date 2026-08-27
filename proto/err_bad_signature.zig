//! PROTOTYPE error demo — this file is EXPECTED TO FAIL compilation.
//! Shows: a wrong signature prints want-vs-got instead of a vtable mystery.
const proto = @import("appnode_proto.zig");

const WrongApp = struct {
    pub const State = struct { n: u64 = 0 };
    pub const Command = struct { n: u64 };

    // wrong: returns bool, not slcp.Validity
    pub fn validate(state: State, cmd: Command) bool {
        _ = state;
        _ = cmd;
        return true;
    }
    pub fn apply(state: State, cmd: Command) State {
        _ = cmd;
        return state;
    }
};

pub fn main() void {
    _ = proto.AppNode(WrongApp);
}
