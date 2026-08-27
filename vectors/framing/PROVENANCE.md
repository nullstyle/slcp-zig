# Framing conformance fixtures — vendored from capnp-zig

`framing_fixtures.json` is a VERBATIM copy of an upstream artifact. Do not
hand-edit it; re-vendor from upstream instead.

| | |
|---|---|
| Upstream repo | https://github.com/nullstyle/capnp-zig |
| Upstream path | `tests/fixtures/framing/framing_fixtures.json` |
| Upstream commit | `453ef8e9db068651035f8a6c3795e868137f17e3` (`453ef8e`, main, 2026-08-27) |
| Commit subject | "rpc/tcp: survive the std.Io net move, add deadline reads, publish framing fixtures" |
| sha256 | `53a4a2f3026ae959d1b01761d6893cb77514345200849571065a2ebd0231caae` |
| Vendored on | 2026-08-27 |

## Why slcp vendors this

`rpc.wire.framing.Framer` is on our consensus wire path — `src/node/overlay.zig`
reassembles every segment frame the flood overlay receives with it (design
§9.1), so a drift in its framing behavior changes what our nodes accept off
the network.

## What replays it

`tests/framing_vectors_test.zig` (`zig build framing-vectors`, also folded
into `zig build test`). It runs the byte streams through a `Framer`
constructed with **slcp's own** options — `overlay.framer_options`, the same
value `Overlay.runConnection` uses — rather than a hardcoded copy, so a change
to our 1 MiB frame cap breaks the replay loudly. It also asserts the
fixtures' recorded `constants` block against the live constants of our pinned
capnp-zig (v0.14.0), so a limit change upstream marks this copy stale instead
of silently passing.

Note the file format: `chunks` are pushed in order and frames are popped after
each push; `expect.error_on` distinguishes a push-time buffered-bytes breach
from a pop-time parse rejection. Upstream's own README documents the schema in
full; the JSON carries a self-describing `semantics` block.

## Cases that carry an `options` override

`buffered_bytes_breach_rejected` pins the buffered-bytes ceiling with a
32-byte cap, which is not slcp's cap. The replay honors the fixture's
override for the recorded verdict (that is the upstream conformance claim),
and then re-runs the same bytes under slcp's real cap to assert they are
accepted there — plus a dedicated slcp case that breaches
`overlay.framer_options.max_buffered_bytes` exactly.

## Re-vendoring

Copy the upstream JSON over this one, update the commit/sha256/date rows
above, and run `zig build framing-vectors`. If a case starts failing, that is
a real behavioral difference between upstream `main` and our pinned
capnp-zig — report it, do not weaken the assertion.
