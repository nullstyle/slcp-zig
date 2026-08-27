# Feedback on `docs/wasm_host_abi.md` from a second downstream

> **DRAFT — not filed.** capnp-zig does not track work in issues; this is written
> to be handed over as a message. Citations are `path:line`, prefixed `capnp/`
> (working copy, `.version = "0.14.0"`) or `slcp/` (slcp-zig at `e306698`).

## 1. Context

SLCP is an independent implementation of the Stellar Consensus Protocol in Zig, driven
from a host runtime as `slcp_core.wasm`. Its WASM ABI (`slcp/src/wasm/slcp_host_abi.zig`,
design §7) was written by cloning the conventions in `capnp/docs/wasm_host_abi.md` +
`capnp/src/wasm/capnp_host_abi.zig` rather than inventing a boundary. That document is
labelled "Language-Neutral", "Draft v1" (`capnp/docs:4`); this is a report from the first
consumer that is not Cap'n Proto. One structural difference shapes everything below:
**capnp-zig's ABI is zero-import, SLCP's is import-bearing** — verified from the
artifacts (capnp's wasm has import count 0, SLCP's 3, from module `slcp_driver`).

## 2. What transferred cleanly

- **All-u32 scalars; `1`/`0` returns; `0`-is-null; byte lengths; `(0,0)` for empty**
  (`capnp/docs:20-23,56-65`) → `slcp/…abi.zig:202-213`. `u64` slot indices cross as
  `(lo, hi)` pairs (`slcp/…abi.zig:420-430`) rather than break the rule.
- **`alloc(0)` returns non-zero** (`capnp/docs:77-78`, `capnp/…abi.zig:464`) →
  `slcp/…abi.zig:124-131`; saves every host a null-vs-empty branch.
- **`buf_free` as a named alias of `free`** (`capnp/docs:81`, `capnp/…abi.zig:512-515`)
  → `slcp/…abi.zig:142-144`: documentation, not mechanism, and it earned its keep.
- **Sticky per-instance error + clear-on-entry + atomic take** (`capnp/docs:98-108`,
  `capnp/…abi.zig:223-263,573-620`) → `slcp/…abi.zig:66-99,179-200`. One place it
  broke; see §3.2.
- **Two-phase borrowed pop** (`capnp/docs:179-186`, `capnp/…abi.zig:708-789`) →
  `slcp/…abi.zig:290-320`. The most valuable convention in the document: zero copies
  inside wasm, no per-item free from the host, and a 1:1 map onto SLCP's own
  `popEffect`/`commitEffect` seam (`slcp/src/engine/engine.zig:327-334`).
- **Copy-everything inbound** (`capnp/docs:83-86`): every host buffer is decoded and
  copied before the call returns (`slcp/…abi.zig:11-16`).
- **Version triple + u64 feature bitset split lo/hi** (`capnp/docs:25-52`) →
  `slcp/…abi.zig:38-45`.
- **Build settings**, which are *not* in the doc — read out of
  `capnp/build/modules.zig:139-143` (`entry = .disabled`, `rdynamic`, `export_memory`,
  4 MiB initial / 64 MiB max), copied to `slcp/build.zig:231-235`.

## 3. Where SLCP diverged

### 3.1 Import-bearing (the structural one)

capnp routes host work through a **polled bridge**: an inbound call is queued and drained
after the export returns (`capnp/docs:220-246`). SCP cannot do that.
`combineCandidates`/`validateValue` are called *inside* envelope processing —
`slcp/src/engine/nomination.zig:889` calls the driver while the slot's candidate set is
borrowed and effects were already pushed at `:882` — and the state machine has no suspend
point. So SLCP declares three synchronous imports (`slcp/…abi.zig:418-426`) instead of
adding pop/respond exports. The §2 conventions are import-agnostic and survive; the ones
below assume a flat call stack.

### 3.2 Re-entrancy — the gap

`capnp/docs/wasm_host_abi.md` has no occurrence of "re-entran" or "recursive" and no
statement about calling exports from inside a callback; the nearest text is a Non-Goal,
"Defining async callback semantics from wasm to host" (`capnp/docs:324`). Zero-import
made the question unnecessary. In SLCP the host calls the export `slcp_alloc` **from
inside an import frame while the engine is mid-mutation** (`slcp/…abi.zig:455-485`):

- **Clear-before-mutate is unsound for memory exports.** `capnp_alloc` clears error state
  on entry (`capnp/…abi.zig:463`), as does `capnp_free` (`:493`), per `capnp/docs:100`.
  Copying that would let the host's next `slcp_alloc` erase a driver fault recorded inside
  the import (`slcp/…abi.zig:444-452`), so SLCP's `slcp_alloc`/`slcp_free` deliberately do
  not clear (`:124-144`).
- **Tracked-allocation pointer validation cannot cover import out-params.** capnp validates
  every host-supplied pointer against the outstanding-allocation table
  (`capnp/…abi.zig:209,269-328,354-369`) — good hardening, and **not documented at all**.
  It does not extend to imports: SLCP's `combine_candidates` out-params are addresses of
  wasm shadow-stack locals (`slcp/…abi.zig:463-472`) and the value pointers it passes out
  are engine-owned interior slices (`:437-439`); both would be rejected as
  `UnknownAllocation`. The model is host→wasm only.
- **No stated re-entrant-safe subset.** SLCP's real contract is "from inside an import,
  call `slcp_alloc`/`slcp_free` and nothing else" — re-entering `slcp_engine_push_input`
  or `slcp_engine_free` would corrupt a half-applied transition. Nothing in the template
  says such a subset must exist.
- **Success with a non-zero error code becomes reachable.** `capnp/docs:57-60` tells hosts
  to consult the error API when a call *fails*; with imports a driver fault can be recorded
  (`slcp/…abi.zig:444-452`) while the outer `slcp_engine_push_input` still returns `1`, and
  a host following that rule never sees it.

### 3.3 Smaller divergences

- **Uncommitted pop**: capnp errors on a second pop without commit (`capnp/…abi.zig:728-731`)
  and exposes `capnp_peer_has_uncommitted_pop` (`:905`); SLCP releases the stale borrow and
  continues (`slcp/…abi.zig:297-301`) because its host loop is pop-until-`0`. Both
  defensible; the doc states neither.
- **Owned vs borrowed is per-export prose**: borrowed at `capnp/docs:179-182`, owned at
  `:227-229`, `:261`, `:302`, with no general rule. SLCP had to invent a house convention
  (every export's doc comment states BORROWED or OWNED, `slcp/…abi.zig:11-16`) after
  mixing the two up once.
- **Out-param arity**: `capnp_error_take` takes three separately-validated out pointers
  (`capnp/…abi.zig:573-620`), `capnp_peer_pop_host_call` five (`capnp/docs:137-144`);
  SLCP collapsed the error variant to one `u32[3]` out array (`slcp/…abi.zig:194-200`)
  — one validation, one host scratch buffer. Error text: capnp copies into a fixed
  1 KiB buffer with a path/stack-trace disclosure scrub (`capnp/…abi.zig:211-263`),
  the better design, and also undocumented.
- **Error code `12` (`ERROR_INVALID_FREE`)** exists (`capnp/…abi.zig:114`) but the
  doc's list stops at `11` (`capnp/docs:109-120`), and it is reachable from a plain
  length mismatch in `capnp_free` (`:497-504`) — a host freeing with a rounded length
  silently leaks.
- **Payload shape**: the template's per-type serde exports (`capnp/docs:275-302`) are
  O(types); SLCP put all boundary payloads in capnp-encoded `host.capnp` frames behind
  a fixed 23-function surface, which also lets those frames double as conformance
  vectors. Worth listing as an alternative.

## 4. Asks for the document

1. Add a **Re-entrancy** section, even for the zero-import case: which exports may be
   called from inside a wasm→host callback, that memory exports must not clear error
   state, and that a borrowed out-buffer must not stay live across a callback.
2. Add an **import-bearing variant** section — ownership rule (result allocated with
   `alloc` inside the import, copied and freed before it returns,
   `slcp/…abi.zig:481-484`), the fault channel, and the `u64`-as-lo/hi convention.
3. Add an **Ownership table** (export → BORROWED-until-commit / OWNED-free-with-
   `buf_free`) plus a naming rule, so downstreams stop re-deriving it per export.
4. Document the **allocation tracking and strict pointer validation** already
   implemented: error code `12`, the exact-length `free` requirement, and the
   outstanding-allocation budgets (`capnp/…abi.zig:116-122`).
5. Label the **capnp-specific** parts: the `peer_*` surface, host-call bridge, serde
   pattern, and feature-flag bit assignments — SLCP reused bits 0-2 with entirely
   different meanings (`slcp/…abi.zig:42-45`), which is fine, but the doc should say
   bit meanings are ABI-local.
6. Move the **build recipe** into the doc and recommend ReleaseSmall for the wasm step:
   `wasm-host` passes the top-level optimize through (`capnp/build/modules.zig:112,119,131`),
   so a default build ships a 4.8 MB debug artifact; SLCP coerces debug→ReleaseSmall
   for the wasm target only (`slcp/build.zig:211`).
7. Normalize the export prefix — `capnp_wasm_abi_version` vs `capnp_alloc` mixes an
   infix; SLCP used one `slcp_` prefix throughout.

## 5. Size report (§14-M4)

`zig build wasm` (wasm32-freestanding, ReleaseSmall); sections read from the artifacts:

| artifact | total | code | data | imports | exports |
|---|---|---|---|---|---|
| `slcp_core.wasm` | **195,794 B** | 188,405 B (96.2%) | 5,970 B (3.0%) | 3 | 23 fn, memory, 1 global |
| `capnp_wasm_host.wasm`, rebuilt ReleaseSmall | 334,991 B | 308,660 B (92.1%) | 24,103 B (7.2%) | 0 | 38 |
| `capnp_wasm_host.wasm`, checked-in default build | 4,809,412 B | 1,574,743 B | 42,735 B | 0 | 38 |

Neither ReleaseSmall build keeps name/debug sections; the checked-in capnp artifact
carries 3.19 MB of DWARF (basis for ask 6). SLCP's 365 function bodies are long-tailed:
top 10 = 36.9% of code, top 50 = 66.8%, median 171 B. Per-symbol attribution is not
recoverable from a stripped build, so it was measured on a named ReleaseSafe build
(448.9 KB code — different absolute sizes, indicative shares): `engine.*` 32.5%,
`crypto.*` 28.4% (Ed25519 `fromBytes` 7.6% and `toBytes` 5.9% alone, plus SHA-2),
`std.sort.block.*` **19.7%**, `slcp_host_abi.*` 5.3%, capnp `serialization.*` 5.3%.
Two things worth passing on: the ABI shim and the capnp encoder are cheap, so
payload-in-capnp-frames costs almost nothing; and two monomorphized `std.sort.block`
instantiations (48.5 KB + 29.4 KB — the largest and third-largest functions in the
module) cost more than the entire boundary. That one hits any Zig wasm downstream.
