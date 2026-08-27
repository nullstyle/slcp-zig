//! PROTOTYPE error demo — this file is EXPECTED TO FAIL compilation.
//! Shows: a State field without a default gets a contract error, not a
//! mystery pointing into AppNode internals.
const proto = @import("appnode_proto.zig");

const NoDefaultApp = struct {
    pub const State = struct { n: u64 }; // <- no default, no initialState()
    pub const Command = struct { n: u64 };

    pub fn validate(state: State, cmd: Command) proto.Validity {
        _ = state;
        _ = cmd;
        return .valid;
    }
    pub fn apply(state: State, cmd: Command) State {
        _ = cmd;
        return state;
    }
};

pub fn main() void {
    _ = proto.AppNode(NoDefaultApp);
}
