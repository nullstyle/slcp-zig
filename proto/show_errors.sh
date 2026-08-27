#!/bin/sh
# PROTOTYPE — shows the comptime guardrails. Every case below SHOULD fail.
for f in err_float_command.zig err_missing_apply.zig err_bad_signature.zig err_no_default.zig; do
  echo ""
  echo "================================================================"
  echo "$f  (expected: compile error)"
  echo "================================================================"
  zig build-exe "$f" -fno-emit-bin 2>&1 | sed -n '1,16p'
done
