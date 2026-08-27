//! PROTOTYPE error demo — this file is EXPECTED TO FAIL compilation.
//! Shows: a missing contract method gets a friendly, teaching error.
const proto = @import("appnode_proto.zig");

const HalfApp = struct {
    pub const State = struct { n: u64 = 0 };
    pub const Command = struct { n: u64 };

    pub fn validate(state: State, cmd: Command) proto.Validity {
        _ = state;
        _ = cmd;
        return .valid;
    }
    // apply is missing
};

pub fn main() void {
    _ = proto.AppNode(HalfApp);
}
