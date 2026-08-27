# Promote the schema-free `canonical` module to the frozen Stable API snapshot

> **Filed 2026-08-26** as https://github.com/nullstyle/capnp-zig/issues/12 (verbatim, citations re-verified at capnp-zig HEAD 1456826).

**Ask:** move `canonical.canonicalize`, `canonical.canonicalizeFlat`,
`canonical.isCanonical`, `CanonicalError`, and `CanonicalizeError` from the
informational experimental snapshot into the CI-gated `docs/api-snapshot.txt`
contract, and add a Stable row for `src/serialization/canonical.zig` to
`docs/stability.md`. No signature or behavior changes requested — freeze as-is.

## Motivation

SLCP (a Federated Byzantine Agreement implementation) defines its consensus
signature preimages as the official Cap'n Proto canonical form and produces
them exclusively through `canonical.canonicalizeFlat`; the receive path gates
on `canonical.isCanonical`. In this downstream, any change to the emitted
bytes is not an API break but a permanent network fork: nodes on different
library versions would compute different signing preimages for the same
statement and reject each other's signatures. SLCP therefore needs the module
under the same freeze discipline as the wire format it walks.

## Current behavior

- The module is public as `capnpc.canonical` (`src/lib.zig:34`) but its
  surface lives only in the experimental snapshot
  (`docs/api-snapshot-experimental.txt:5-10`), whose header states it is
  "informational, NOT frozen" and that "only docs/api-snapshot.txt is a
  contract" (`docs/api-snapshot-experimental.txt:1-4`).
- `docs/stability.md` does not list `src/serialization/canonical.zig` in any
  Module Status table; the Stable serialization tier
  (`docs/stability.md:150-159`) covers `message.zig`, `schema.zig`,
  `request_reader.zig`, `schema_validation.zig`, codegen, and `reader.zig`.
  `docs/supported-surface.md:89` explicitly labels
  `canonical.canonicalize / canonicalizeFlat / isCanonical` "(Experimental)".
- The implementation already meets the bar the Stable tier implies: it is a
  line-cited port of the vendored C++ reference (`layout.c++` /
  `message.c++` citations at each enforcement site,
  `src/serialization/canonical.zig:11-55`), with a spelled-out, closed error
  set (`src/serialization/canonical.zig:72-95`) and differential byte-for-byte
  testing against `capnp convert binary:canonical`
  (`docs/supported-surface.md:89`).

## Proposed API

Exactly the existing declarations, frozen:

```zig
pub const CanonicalError = error{ CannotCanonicalizeCapability, NestingLimitExceeded, MessageTooLarge };
pub const CanonicalizeError = std.mem.Allocator.Error || CanonicalError || error{
    OutOfBounds, InvalidPointer, InvalidFarPointer, InvalidSegmentId,
    InvalidInlineCompositePointer, PointerDepthLimit, InvalidRootPointer,
};
pub fn canonicalize(allocator: std.mem.Allocator, msg: *const message.Message) CanonicalizeError![]u8;
pub fn canonicalizeFlat(allocator: std.mem.Allocator, msg: *const message.Message) CanonicalizeError![]u8;
pub fn isCanonical(msg: *const message.Message) bool;
```

The `check-api` gate (`docs/stability.md:163-168`) then makes any diff a
reviewed breaking change rather than an accident.

## Workaround today

SLCP pins capnp-zig to an exact commit and wraps the module behind one seam
(`slcp-zig/src/canonical.zig:22-24` `canonicalFlat`,
`:47-51` `isCanonicalFlat`), with SLCP-side conformance vectors to detect
byte drift on upgrade. This detects a fork; it cannot prevent one.

## Testing notes

- Snapshot freeze is signature-level; the consensus need is byte-level. A
  checked-in golden corpus (input framed message → expected canonical bytes,
  covering zero-size structs, truncation rules, inline-composite max-sizing,
  upgraded lists, partial-bit-list masking) would pin behavior the way
  `api-snapshot.txt` pins signatures.
- Keep the existing differential suite against `capnp convert
  binary:canonical` as the semantic authority; the golden corpus guards
  against the CLI and the port drifting together.
- `isCanonical` should be asserted `true` on every corpus output
  (round-trip property: `isCanonical(decode(frame(canonicalizeFlat(m))))`).
