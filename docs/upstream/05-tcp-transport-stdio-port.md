# M5 upstream ask: port the TCP transport to the new std.Io net surface (+ framing fixtures)

*From: slcp-zig M5 (overlay + node + persistence), 2026-08-27.*
*This is an ask to IMPLEMENT, not just to note. slcp-zig is your downstream
consumer for the non-RPC transport surfaces; M5 is where we tried to reuse
them in anger.*

## Finding 1 (blocking): `tcp.stream.Transport` / `Listener` do not compile on Zig 0.17.0-dev.1786

capnp-zig v0.14.0's TCP I/O path calls `io.vtable.netWrite` / `io.vtable.netRead`.
Those VTable entries no longer exist in current std: socket I/O now goes
through `std.Io.net.Stream.read/write` and `io.operate(.net_write/.net_read)`.
Any downstream that references `rpc.transport.tcp` on a current toolchain
fails to compile.

SLCP's overlay (design §9.3) was specified to reuse your `Transport` as the
per-connection reader/writer shape. We could not; the overlay now drives
`std.Io.net` directly and reuses only the pure `rpc.wire.framing.Framer`
(which compiled and worked flawlessly — zero findings against it).

**Ask:** port `tcp.stream.Transport`, `runtime.Listener/createListenSocket`,
and `client.connect` to the `net.Stream`/`io.operate` surface, and add a CI
job pinned to a current 0.17-dev so the drift is caught at your gate rather
than in downstreams.

## Finding 2: `Io.Threaded` treats EAGAIN as a programmer bug

We arm `SO_RCVTIMEO` on the raw fd for a 10-second Hello-handshake deadline.
A timed-out `recv` returns EAGAIN — which `Io.Threaded`'s read path maps to
`errnoBug` (a debug-build panic), so deadline reads through the Io vtable
crash the process. We had to bypass the vtable with `std.posix.read` while
the deadline is armed.

**Ask:** either surface EAGAIN as `error.WouldBlock` on net reads, or expose
a first-class read-deadline/timeout on `net.Stream` so hosts never need
per-fd sockopt games.

## Finding 3 (repeat of the §15 map row): published framing conformance fixtures

`Framer` is now consensus-adjacent infrastructure for us (every overlay frame
passes through it, capped at 1 MiB via `max_buffered_bytes`). We'd like the
frozen framing behavior pinned by *published fixtures* (byte streams →
expected frames / errors, including the max_segment_count and buffered-bytes
breach cases) that downstreams can vendor into their own suites — the same
pattern as our conformance vectors.

## Context for prioritization

- Finding 1 blocks any non-RPC downstream reuse of your transport layer on
  current Zig; SLCP has a working local substitute, so this is about the
  NEXT downstream, not about unblocking us.
- Finding 2 cost us the subtlest workaround of the milestone and will bite
  anyone implementing read deadlines.
- Finding 3 is cheap and locks in the one surface that survived contact
  fully intact.
