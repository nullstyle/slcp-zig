//! PROTOTYPE error demo — this file is EXPECTED TO FAIL compilation.
//! Shows: floats in a Command are rejected at compile time (determinism rule).
const proto = @import("appnode_proto.zig");

const PriceApp = struct {
    pub const State = struct { total: u64 = 0 };
    pub const Command = struct { price: f64 }; // <- the mistake

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
    _ = proto.AppNode(PriceApp);
}
