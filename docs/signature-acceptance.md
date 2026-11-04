# SLCP v1 signature acceptance

This document records the existing acceptance behavior at SLCP reference
`346d3ec67f5917f579e4d7505b3b1abb3194d898`, Zig 0.17.0 and capnp-zig
v0.21.0. It preserves accepted v1 inputs; it does not select a stricter
verification mode. A provider or toolchain replacement must retain this
behavior, or identify an explicit compatibility/version change.

The owning SLCP paths are [crypto.zig](../src/crypto.zig) and the ordinary
[receive pipeline](../src/engine/pipeline.zig). The toolchain implementation is
`lib/std/crypto/25519/ed25519.zig` and its `edwards25519.zig`/scalar helpers.
The observed Ed25519 source SHA-256 is
`2282a3629c14d498e25116dafc501c183de55fb6aa576764c36c9cb103878c4d`.
The [provider corpus](../vectors/compatibility/ed25519-provider.json) retains
that exact provenance. An algorithm name alone does not specify these rules.

## Signed message and verification equation

SLCP constructs

```text
m = SHA-256("SLCP-STMT-V1" || networkId || receivedStatementBytes)
```

and uses ordinary Ed25519 with the 32 bytes of `m` as its message. This is not
Ed25519ph. The internal verification challenge is
`h = SHA-512(encodedR || encodedA || m) mod L`, where
`L = 2^252 + 27742317777372353535851937790883648493`.
`A` is the public key named by the received statement, `R` is the first 32
signature bytes, and `S` is the little-endian integer in its final 32 bytes.
After the rejection checks below, verification accepts precisely when

```text
[8] ([S] B - [h] A - R) = identity
```

where `B` is the Ed25519 base point. The pinned provider implements this as
`[8S]B - [h]([8]A) - [8]R`. Its ordinary `verify` is cofactored; substituting
a cofactorless or provider-specific strict verifier changes the acceptance
set for some crafted inputs.

## Encoding and point checks

The existing wrapper requires a 32-byte public key, a 64-byte signature and
the 32-byte SLCP message digest. The pinned provider additionally requires:

- `S` is canonical: `0 <= S < L`; noncanonical scalars are rejected.
- The encoded y-coordinates of `A` and `R`, excluding the x-sign bit, are
  canonical field elements less than `p = 2^255 - 19`.
- Both encodings decode to curve points. An encoding with x equal to zero and
  the sign bit set is rejected during decompression.
- Both decoded points have nonzero x. The provider's `rejectIdentity` check
  rejects all zero-x points, including the identity and order-two point.
- `A` cannot be a small-order public key: its cofactor-cleared point must be
  nonidentity. The provider's double-base multiplication enforces this weak-key
  rejection. It does not require `A` itself to lie in the prime-order subgroup.

Mixed-order inputs can therefore be accepted. Small-order `R` values that pass
the preceding encoding and zero-x checks can also be accepted. Do not add a
blanket torsion-free or small-order-R prohibition to this v1 profile.

The underlying provider errors are collapsed to `false` by SLCP's
`crypto.verify`; their individual names are not wire status codes. The finite
provider corpus includes small/mixed-order, cofactored-equation, noncanonical
scalar and noncanonical-point cases. It is regression evidence for these
witnesses, not an exhaustive mathematical proof or a cryptographic audit.

## Ordinary envelope processing

The signed bytes remain exactly the received `statementBytes`. Receivers never
canonicalize or re-encode them before verification. Ordinary receive first
performs bounded validating graph decode and statement sanity, then verifies
the signature, then checks strict canonical form, and then applies relevance
and admission rules. The full order remains in [protocol section 4](protocol.md#4-canonical-form-and-the-statement-preimage).

A sane envelope with a bad signature, tampered signed value, wrong signing key
or wrong network yields `invalid_signature`. Earlier malformed-graph or sanity
failures yield `insane`, even when the signature is also bad. A structurally
valid noncanonical statement with a valid signature is rejected as `insane`
when strict canonical checking is enabled. These statuses describe the ordinary
receive path; startup restore has its own ownership check and ordering.

The [full-envelope corpus](../vectors/compatibility/envelope-signatures.json)
contains complete config, Input and Envelope frames. Its five independent fresh
watcher cases cover valid input, signature tampering, sane statement-value
tampering, wrong network, and wrong key. Each case retains explicit received
statement bytes, public key, signature and expected verification/status result.
Config limit fields are absent and retain existing v1 defaults. The positive
case uses the original nomination/signature in [crypto.json](../vectors/crypto.json).
The [wire corpus](wire-compatibility.md) supplies separate decoder and
multi-fault precedence witnesses.

## Replaying the witnesses

Run `zig build signature-vectors --summary all`. The gate fails when either
corpus file is missing; it checks all twelve provider cases and all five
complete envelope cases. It also independently reconstructs the unsigned
Envelope and Input wrappers while copying their signed payload bytes unchanged.
The suite is included in ordinary tests and the required vector-conformance
gate. Provider witnesses use arbitrary messages directly, so they are kept
separate from full SLCP-envelope witnesses.

Provider acceptance changes need an explicit compatibility decision. Do not
regenerate expected outcomes merely to make a replacement provider pass. Keep
the existing signed schema, domain tags and frozen traces unchanged.
