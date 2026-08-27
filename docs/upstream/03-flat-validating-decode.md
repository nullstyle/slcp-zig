# Validating decode entry point for flat (table-less) single-segment bytes

> **Filed 2026-08-26** as https://github.com/nullstyle/capnp-zig/issues/14 (verbatim, citations re-verified at capnp-zig HEAD 1456826).

**Ask:** a `Message.initFlat` that validates and decodes a bare single
segment — the shape `canonical.canonicalizeFlat` emits and `capnp convert
binary:canonical` writes — without requiring the caller to synthesize a
segment table first.

## Motivation

SLCP envelopes carry each statement as its flat canonical bytes: the flat
form is the signature preimage, so those exact bytes are what peers exchange
and verify. Every statement received from an untrusted peer must be
validating-decoded (and checked with `canonical.isCanonical`), which today
forces SLCP to allocate and copy a synthetic framed buffer in front of each
decode — a per-inbound-message tax on the consensus receive path, in the one
library that also defines the flat form.

## Current behavior

- The library itself documents that the reference canonical form is
  table-less: "The reference form itself has NO segment table — `capnp
  convert binary:canonical` writes the bare segment"
  (`src/serialization/canonical.zig:437-444`), and `canonicalizeFlat` returns
  exactly that bare segment (`src/serialization/canonical.zig:469`).
- Yet every validating decode entry point assumes framing: `Message.init`
  delegates to `initUnvalidated` (`src/serialization/message.zig:569-575`),
  which reads a segment count from `data[0..4]` and a size table after it
  (`src/serialization/message.zig:603-657`). Handed flat bytes, it misparses
  the message's first word as a header. `initPacked`/`initCounting` share the
  assumption.
- So flat-form consumers must fabricate the two-u32 single-segment header
  (count − 1 = 0, size in words) before every decode, allocating and copying
  the whole payload to do it.

## Proposed API

On `Message` in `src/serialization/message.zig`, beside `init`:

```zig
/// Deserialize and validate a message from a bare single segment with no
/// segment table — the form `canonical.canonicalizeFlat` and
/// `capnp convert binary:canonical` produce. `flat.len` must be a non-zero
/// multiple of 8. Same validation walk and `ValidationOptions` limits as
/// `init`. The caller retains ownership of `flat`; the message borrows into
/// it (zero-copy: the single segment aliases `flat`).
pub fn initFlat(allocator: std.mem.Allocator, flat: []const u8, options: ValidationOptions) !Message;

/// Header-parse only, no validation walk (parity with initUnvalidated).
pub fn initFlatUnvalidated(allocator: std.mem.Allocator, flat: []const u8) !Message;
```

Zero-copy matters: the workaround's copy exists only to prepend 8 bytes.
A borrowing decode also keeps `canonical.isCanonical` natural, since that
check requires exactly one segment (`src/serialization/canonical.zig:521-532`).

## Workaround today

`slcp-zig/src/canonical.zig:16-43`: `frameFlat` allocates
`8 + flat.len`, writes the synthetic table, and memcpys the payload
(`:28-35`); `decodeFlat` wraps it around `Message.init` (`:39-43`);
`isCanonicalFlat` pays the same copy again on the receive-side canonicality
check (`:47-51`).

## Testing notes

- Equivalence: for a framed-message corpus, `initFlat(canonicalizeFlat(m))`
  must accept, and its readers must observe the same tree as
  `init(canonicalize(m))`; `isCanonical` must return true on the result.
- Rejection: empty input, length not a multiple of 8, out-of-bounds root
  pointer, and inputs exceeding `ValidationOptions` traversal/nesting/size
  limits (`src/serialization/message.zig:533-539`) must error, never trap.
- Interop: decode `capnp convert binary:canonical` CLI output directly
  (the existing differential harness already shells out to the CLI).
- Add `initFlat` to the existing message-decode fuzz entry points, since it
  is a new untrusted-input surface.
