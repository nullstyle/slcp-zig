//! End-to-end cluster test (design §13.6 / §14-M5 accept). PLACEHOLDER —
//! filled in after the node leaf modules land. The real test stands up four
//! full `slcp.Node`s over loopback TCP (3-of-4 quorum), drives 200 slots, and
//! exercises kill/restart, partition/heal, and an equivocator.

const std = @import("std");
const slcp = @import("slcp");

test "e2e placeholder (real cluster lands after leaf modules)" {
    return error.SkipZigTest;
}
