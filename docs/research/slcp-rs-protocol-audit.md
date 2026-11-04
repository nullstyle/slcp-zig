# SLCP Rust implementation: protocol interoperability audit

Reviewed 2026-11-02 against `slcp-zig` commit
`346d3ec67f5917f579e4d7505b3b1abb3194d898`. Planning evidence only;
no Rust engine or interoperability qualification was performed here.

## Recommended first gate

Before porting nomination or ballot logic, build a small Rust fixture runner
that reads the pinned SLCP schemas and vectors, canonicalizes statements and
normalized quorum sets, signs/verifies the specified digest, and reports the
same malformed-input classification as Zig. Retain discrepancies as fixtures
for both implementations. The largest unresolved primitive is the exact
signature-verification acceptance set, not ordinary signature generation.

## Findings and feedback

| Priority | Observed fact | Rust impedance and proposed SLCP feedback |
|---|---|---|
| P0 | The protocol specifies deterministic RFC 8032 Ed25519 over a 32-byte SHA-256 digest, but implementation verification delegates to Zig `sig.verify`. The pinned installed Zig 0.17.0 implements cofactored verification and distinguishes it from `verifyStrict`. The existing SLCP crypto vectors contain two ordinary valid signatures, with no adversarial verification cases. | Specify point/scalar canonicality, identity/low-order handling, and the verification equation independently of a standard-library function. Add accepted and rejected fixtures for torsion, identity, noncanonical encodings, invalid points, `S >= L`, wrong network, and tampered bytes. Qualify a Rust provider against these before choosing its verification method. Changing acceptance must be a reviewed protocol decision, not a silent Rust library default. |
| P0 | Cap'n Proto graph validation runs before semantic sanity, then signature verification, then canonicality. Zig validates the entire raw pointer graph, including pointer fields the generated SLCP reader does not access. | Rust's ordinary typed reads do not by themselves establish the same eager graph-validation and resource-accounting contract. Test malformed unknown fields, aliases/amplification, cycles, far pointers, huge empty lists, depth, and multi-fault inputs. Publish the intended acceptance/error-precedence rules and an adversarial corpus rather than requiring a second implementation to reproduce incidental parser behavior by inference. |
| P0 | `docs/protocol.md` makes vectors authoritative, but normal Zig packages intentionally exclude documentation, vectors, simulator, and generation tools. Engine traces currently cover four scenarios. | Publish a separately versioned, content-addressed conformance bundle with schemas, vectors, trace format, protocol profile, source identity and a runnable replay entry point. Extend traces to multi-node ballot progression, recovery and adversarial cases; ordinary vectors are a starting point, not a complete protocol specification. |
| P1 | Signed statements and hashed quorum sets use a bare canonical segment, whereas envelope/overlay/host messages use ordinary framing. Generic serialization is not canonical serialization. Null pointers and present-empty/default objects can have distinct canonical bytes. | Keep a private wire module owning these distinctions. Preserve received `statementBytes` for verification and relay; do not decode/rebuild before verifying. Publish explicit emit rules and fixtures for absent `accepted`, optional prepared ballots, empty validator/inner-set lists, and zero/default structs. |
| P1 | Quorum sets are normalized semantically before hashing: child-first singleton flattening, bytewise validator order, inner-set order by normalized hash, and whole-tree duplicate rejection. Wire depth is checked first, with root at depth 1. | Reuse neither a generic canonical serializer nor an unordered Rust collection as normalization. Preserve the pre-normalization depth check: a depth-5 singleton chain is rejected even if normalization could flatten it. Add explicit operation-order documentation and property fixtures for permutations, singleton chains, cross-level duplicates and absent lists. |
| P1 | Configurable value/list/time limits may be lower than frozen protocol maxima; the Hello exchange does not advertise these limits. `Limits` has different zero semantics through `host.capnp` and direct engine construction. | Define a deployable consensus profile separately from local resource policy. Require matching application codec, driver rules and acceptance limits in the profile; decide which values must enter network identity or capability negotiation. Document direct-engine versus wire-default conversion once, with cross-language tests. |
| P1 | Signed schema changes and application codec changes require consensus version events; overlay and host schemas have different evolution rules. Hello's `protocolVersion` only covers incompatible overlay changes. | Publish distinct identifiers for consensus profile, application format, engine trace contract, overlay version and local storage format. A passing TCP handshake must not be presented as proof of consensus/application compatibility. Freeze a Rust target profile while Experimental features continue evolving. |

## Canonicalization feasibility

There is no evidence that Rust needs its own Cap'n Proto canonicalizer.
The primary Rust `capnp` implementation exposes `Reader::is_canonical`,
`Reader::canonicalize`, and `Builder::set_root_canonical`; the latter can
produce a single output segment. Qualify those facilities with the SLCP
corpus before adding a new serialization implementation. Standard
`serialize::write_message_to_words` includes framing, so it is not the
statement-signing output by itself. Cap'n Proto's own specification also
distinguishes canonical signing bytes from framed messages.

For a Rust receive path, a single-segment reader over an appropriately aligned
owned buffer is a reasonable prototype. The outstanding work is validation
parity and ownership lifetime, not a missing canonical-format definition.
Parent planning work may provide executable Rust probes beyond this static
audit.

## Sources and evidence limits

- [Protocol authority and tiers](../protocol.md#0-status-and-scope), lines
  15–30; [receive order](../protocol.md#4-canonical-form-and-the-statement-preimage),
  lines 180–239; [version events](../protocol.md#15-version-events), lines
  1260–1272.
- [Cryptographic implementation](../../src/crypto.zig), lines 16–85:
  `networkIdFromPassphrase`, `statementDigest`, `qsetHash`, `gi`, `sign`,
  `verify`. SLCP uses ordinary Ed25519 on the already-computed digest;
  substituting Ed25519ph would change signatures.
- [Toolchain pin](../../mise.toml), Zig 0.17.0; local `zig env` confirmed
  `/Users/nullstyle/.zvm/0.17.0/lib/std`. That installed
  `crypto/25519/ed25519.zig`, lines 114–115 and 154–235, defines canonical
  key/scalar checks, identity checks and cofactored/cofactorless equations;
  its `cofactored vs cofactorless verification` test at lines 786–808
  contains an input accepted by `verify` and rejected by `verifyStrict`.
  This is evidence that the distinction matters, not a demonstrated
  malformed SLCP-envelope acceptance discrepancy with Rust.
- [Crypto fixture corpus](../../vectors/crypto.json): 3 network IDs,
  3 seeds/public keys, 6 Gi inputs, 2 valid statement digests/signatures.
  [Generator](../../tools/gen_vectors.zig), `makeStatementVector`, derives
  signature answers through the Zig implementation; independently derived
  preimage literals exist in `src/crypto.zig` tests.
- [Pipeline](../../src/engine/pipeline.zig), `frameOptions`, `stmtOptions`,
  `decodeEnvelope`, `handleEnvelope`; [pinned dependency](../../build.zig.zon),
  lines 6–8, capnp-zig v0.21.0. Its cached
  `src/serialization/message.zig`, `Message.init`, `initFlat`,
  `validateCountedInto` and `validateStructPointer`, confirms a schema-free
  eager graph walk and word/element budgets. Resource parity with Rust has
  not been tested by this audit.
- [Qset implementation](../../src/engine/qset.zig), lines 48–88
  (wire depth before normalization), 91–177 (normalization/tree checks),
  179–212 (build rules). [Qset fixtures](../../vectors/qset.json): 4
  accepted normalization cases and 6 rejections, including depth five.
- [Statement schema](../../schema/slcp.capnp), pointer-presence semantics;
  [emitter](../../src/engine/emit.zig), `emit`, only initializes nonempty
  accepted lists and present prepared ballots; [canonical wrapper](../../src/canonical.zig).
- [Package contents](../../build.zig.zon), lines 11–20; [trace inventory](../../vectors/traces/FORMAT.md#scenarios).
- [Limits](../protocol.md#8-frozen-wire-limits), lines 455–507;
  [Hello schema](../../schema/overlay.capnp), `Hello`;
  [driver upgrade rules](../driver-upgrade.md).
- Rust primary documentation consulted 2026-11-02:
  [capnp message implementation](https://docs.rs/crate/capnp/latest/source/src/message.rs),
  [capnp serialization implementation](https://docs.rs/crate/capnp/latest/source/src/serialize.rs),
  [Cap'n Proto canonicalization specification](https://capnproto.org/encoding.html#canonicalization),
  [ed25519-dalek verification methods](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/struct.VerifyingKey.html).
  Dalek documents distinct ordinary/strict acceptance and ZIP-215 key
  decoding. That establishes a provider-selection question, not equivalence
  to Zig or a recommendation to choose a method without testing.
