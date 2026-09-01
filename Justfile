# Regenerate src/gen/*.zig from schema/*.capnp using the capnpc-zig plugin.
gen:
    capnp compile -ozig:src/gen --src-prefix=schema schema/slcp.capnp schema/overlay.capnp schema/host.capnp

# Run all tests (unit + conformance vectors).
test:
    zig build test

# Regenerate conformance vectors into vectors/.
vectors:
    zig build vectors

# CI drift check: regenerate and fail if checked-in gen/ differs.
gen-check: gen
    git diff --exit-code src/gen

# The §14-M5 gate: 4 nodes over real loopback TCP, 200 slots, kill/restart,
# partition/heal, one equivocator (design §13.6). Minutes-scale.
e2e:
    zig build e2e

# ===== M6:quorum =====
# M6 stage anchor (quorum): cli / lint-quorum / vectors-sweep recipes go here.

# ===== M6:appnode =====
# M6 stage anchor (appnode).

# ===== M6:example =====
# M6 stage anchor (example): example-smoke / example-build recipes go here.

# ===== M6:docs =====
# M6 stage anchor (docs): docs-smoke recipe goes here.

# ===== M6:apisnap_ci =====
# M6 stage anchor (apisnap_ci): fmt / fmt-check / ci-lint / api-snapshot / check-api go here.

# ===== M6:release =====
# M6 stage anchor (release): preflight / package-preflight / release-hash / release-tag / verify-release-hash go here.
