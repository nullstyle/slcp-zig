# slcp-zig

> ## ⚠️ This is a vibe-coded project. Do not use it.
>
> All of the code in this repository was written by an AI coding agent under
> the direction of one person, as an experiment. It has **not** been reviewed
> or validated for anyone else's use. The author has not yet confirmed that it
> holds up in their own deployments.
>
> **Do not depend on this code, run it in production, or trust it with anything
> you care about.** No support is offered. APIs, wire formats, and on-disk
> formats may change without notice. This notice will be updated if and when
> that changes.

SLCP (**S**tellar-**L**ike **C**onsensus **P**rotocol) is a clean-room
implementation of SCP-style federated Byzantine agreement, built on Cap'n
Proto. It is **not** wire-compatible with Stellar and does not try to be.

## What is here

- `src/` — a sans-io deterministic consensus engine (`slcp-core`) and a native
  node layer (`slcp`) with a TCP flood overlay, timers, and crash-safe
  persistence.
- `src/wasm/` — a frozen WASM host ABI over the core.
- `sim/` — a deterministic multi-node simulator with Byzantine actors.
- `vectors/` — cross-implementation conformance vectors.
- `tests/` — unit, vector replay, fuzz, ABI, and end-to-end cluster tests.

## Building

The toolchain is pinned in `mise.toml`.

```bash
mise exec -- zig build test
```

## License

No license is granted yet. See the notice at the top of this file.
