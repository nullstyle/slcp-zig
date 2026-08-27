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
