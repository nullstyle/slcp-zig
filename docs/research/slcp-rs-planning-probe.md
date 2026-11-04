# Rust feasibility probe for the SLCP implementation plan

Run 2026-11-02 against SLCP source
`346d3ec67f5917f579e4d7505b3b1abb3194d898` on macOS.
This was a temporary fixture/codec program, not a Rust consensus engine.
Its source/build artifacts were outside the repository; this record captures
the procedure, exact major dependencies and observed output. Recreate it as
a maintained conformance runner in M1 rather than treating this session's
scratch program as release evidence.

## Inputs and procedure

- Toolchain: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`, Cargo `1.99.1`;
  native reference schema compiler `capnp 1.5.0`.
- Dependencies: exact `capnp 0.27.2` with `unaligned`, exact `capnpc 0.27.0`,
  exact `ed25519-dalek 3.0.0`; resolved `sha2 0.10.9`, `hex 0.4.3` and
  `serde_json 1.0.154`.
- Generated `slcp_capnp.rs` and `host_capnp.rs` from the current unmodified
  [schemas](../../schema/host.capnp), using `capnpc::CompilerCommand` with
  an explicit schema import path. This used native `capnp`, not the pinned
  WASM generation path used by SLCP CI.
- Read both statement records in [crypto.json](../../vectors/crypto.json).
  Wrapped each bare statement segment in
  `message::Reader::new(SegmentArray::new(&[bytes]), options)`. Required
  `is_canonical()` and identity of `Word::words_to_bytes(canonicalize())`.
  Recomputed `SHA-256("SLCP-STMT-V1" || networkId || statementBytes)`;
  signed that digest with `SigningKey::sign`, compared the exact 64-byte
  signature, then called `VerifyingKey::verify_strict` on that ordinary case.
- Read all four [SLCPTRC1 files](../../vectors/traces/FORMAT.md), using their
  record kind and little-endian length. For every kind-2 effect, decode the
  framed root, create a fresh default Rust builder, and reconstruct the same
  union arm by setting its fields in `host_codec.zig` order. Do not copy the
  incoming root or canonicalize the frame. Compare
  `serialize::write_message_to_words(&builder)` to the original payload.
- Covered `persistOwnEnvelope`, `broadcastEnvelope`, `forwardEnvelope`,
  `externalized`, `armTimer`, `cancelTimer`, `requestQset` and `inputStatus`
  as encountered. Embedded payload bytes were copied verbatim.

The program built and ran successfully with `cargo run --release --locked`.
An initial compile-only formatting error in an unreachable diagnostic arm was
corrected before this run; generated bindings were not modified.

```text
crypto canonical/digest/signature ordinary fixtures passed: 2
trace single-node-1of1: 14 normative frames reencoded, 0 differ
trace insane-and-stale: 6 normative frames reencoded, 0 differ
trace qset-park-resume: 4 normative frames reencoded, 0 differ
trace timer-bump: 8 normative frames reencoded, 0 differ
total normative frames 32; byte mismatches 0
```

## Interpretation and limits

The existing Rust runtime has the needed canonicalization facilities, and
ordinary crypto plus the small existing host-effect layouts are feasible.
There is no observed framing mismatch in this corpus and no justification
from it for writing a new canonical serializer.

This does not establish engine trace replay: no transitions were computed.
It does not check adversarial verifier equivalence, full eager graph
validation, large/multi-segment encoding, arbitrary pointer presence, network
behavior, persistence, allocation-failure behavior, or Windows/WASM support.
Network ID/key/Gi/qset/framing fixture suites were not fully executed by this
program. `unaligned` avoids borrowing-alignment problems in this scratch
reader; production should choose and measure unaligned reads versus aligned
owned message storage deliberately.

The current Rust generator can also consume a serialized CodeGeneratorRequest
through `capnpc::codegen::CodeGenerationCommand::run(Read)`. Source inspection
supports a future pipeline using SLCP's pinned WASM reference compiler followed
by the Rust generator; that pipeline was not executed here. Ordinary Cargo
consumers should use checked-in bindings and need neither compiler at build
time. CI should regenerate from pinned tools and reject drift.

Primary library references, inspected 2026-11-02:

- [Rust capnp message implementation](https://docs.rs/crate/capnp/0.27.2/source/src/message.rs):
  `Reader::is_canonical`, `canonicalize`, `Builder::set_root_canonical`.
- [Rust capnp serialization implementation](https://docs.rs/crate/capnp/0.27.2/source/src/serialize.rs):
  framed message input/output.
- [Rust capnpc code generation](https://docs.rs/crate/capnpc/0.27.0/source/src/codegen.rs):
  `CodeGenerationCommand::run` consumes a reader.
- [Ed25519 provider's acceptance discussion](https://docs.rs/crate/ed25519-dalek/3.0.0):
  ordinary and strict verification have different rules; the positive probe
  does not choose an SLCP adversarial acceptance policy.
- [Cap'n Proto canonicalization](https://capnproto.org/encoding.html#canonicalization):
  canonical signing bytes omit the segment table.
