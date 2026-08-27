# Direct `MessageBuilder` → canonical-bytes path

> **Filed 2026-08-26** as https://github.com/nullstyle/capnp-zig/issues/13 (verbatim, citations re-verified at capnp-zig HEAD 1456826).

**Ask:** a canonicalization entry point that consumes a `MessageBuilder`
directly, so locally built messages can be canonicalized without a framed
serialize → re-parse → re-validate round trip.

## Motivation

SLCP's hot signing path runs on every own-statement emission (each nomination
and ballot round): build a `Statement` with generated builders, canonicalize
to flat bytes, sign the bytes. Because `canonical.canonicalizeFlat` only
accepts a parsed `Message`, each emission today pays two extra full-message
allocations and a redundant validation walk over bytes the local builder
itself just wrote — pure overhead on the latency-sensitive consensus loop.

## Current behavior

- `canonicalizeFlat` takes `*const message.Message` only
  (`src/serialization/canonical.zig:469`; same for `canonicalize`, `:455`).
- The only route from a `MessageBuilder` (`src/serialization/message.zig:2727`)
  is: `toBytes()` allocates a complete framed copy of all segments
  (`src/serialization/message.zig:3488-3534`); `Message.init` re-parses the
  segment table, allocates the segment index, and runs the full pointer-graph
  validation walk (`src/serialization/message.zig:569-575`, index alloc at
  `:626`); then `canonicalizeFlat` allocates the output.
- The builder already carries the resolver machinery the `Canonicalizer`
  leans on: `MessageBuilder.resolvePointer`
  (`src/serialization/message.zig:2777`) and the resolved list-pointer shapes
  (`:2739-2752`) mirror the `Message` helpers
  (`Message.resolvePointer`/`resolveListPointer`/`resolveInlineCompositeList`,
  `src/serialization/message.zig:753,845,887`) that `canonical.zig` consumes
  (`src/serialization/canonical.zig:197,225,228`).
- Skipping the validation walk is safe for this input: the canonicalizer
  "nonetheless bounds-checks every access and returns errors (never traps) on
  anything malformed" (`src/serialization/canonical.zig:452-454`), and the
  graph is locally produced, not untrusted wire input.

## Proposed API

In `src/serialization/canonical.zig`, mirroring the existing pair:

```zig
/// Canonicalize the builder's current contents into the bare canonical
/// segment. Byte-identical to
/// `canonicalizeFlat(&Message.init(gpa, try b.toBytes(), .{}))`.
pub fn canonicalizeFlatFromBuilder(allocator: std.mem.Allocator, builder: *const message.MessageBuilder) CanonicalizeError![]u8;

/// Framed variant (8-byte single-segment table + canonical segment).
pub fn canonicalizeFromBuilder(allocator: std.mem.Allocator, builder: *const message.MessageBuilder) CanonicalizeError![]u8;
```

Equally acceptable shape: a borrowed read-only segments view on
`MessageBuilder` (e.g. `builder.view() Message`-style, non-owning) that the
existing `canonicalizeFlat` accepts unchanged. SLCP has no preference between
the two; the requirement is one allocation for the output and no re-parse.

## Workaround today

`slcp-zig/src/canonical.zig:56-60` (`canonicalFlatFromFramed`): generated
`MessageBuilder.toBytes()` → validating `Message.init` → `canonicalizeFlat`,
i.e. the exact hop this request removes.

## Testing notes

- Differential property over a built-message corpus:
  `canonicalizeFlatFromBuilder(b)` must equal
  `canonicalizeFlat(Message.init(b.toBytes()))` byte-for-byte. Corpus should
  include multi-segment builders (far pointers in the input graph),
  zero-size structs, deep nesting near the limit, and empty builders.
- Error parity: a builder holding a capability pointer must return
  `CannotCanonicalizeCapability` on both paths.
- An allocation-count assertion (the existing bench harness already gates
  allocation counters) proving the new path performs exactly one
  caller-visible allocation.
