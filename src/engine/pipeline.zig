//! The envelope/input pipeline (design §5, M2): decode → signature verify →
//! strictCanonical → sanity → relevance filter → qset resolution/parking →
//! slot dispatch → exactly one input_status, always last.
//!
//! PHASE-0 STUB: reports `ignored` for every input so the engine skeleton
//! compiles and the effect discipline is exercised; the M2 pipeline agent
//! replaces this file wholesale.

const std = @import("std");
const engine = @import("engine.zig");

pub fn pushInput(self: *engine.Engine, input: Input) engine.PushError!void {
    if (self.failed) return error.EngineFailed;
    _ = input;
    self.effects.push(.{ .input_status = .{ .code = .ignored } }) catch |err| {
        self.failed = true;
        return err;
    };
}

const Input = engine.Input;
