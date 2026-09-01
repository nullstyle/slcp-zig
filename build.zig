const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const capnpc_dep = b.dependency("capnpc_zig", .{
        .target = target,
        .optimize = optimize,
    });
    // slcp-core depends ONLY on capnpc-zig-core: serialization + codegen,
    // no RPC, no std.Io in the module graph (wasm32-freestanding-safe).
    const capnpc_core = capnpc_dep.module("capnpc-zig-core");
    // The FULL capnpc-zig module carries the RPC surfaces the native node
    // layer reuses (design §9.3): the Stable `rpc.wire.framing` Framer, the
    // TCP `rpc.transport.tcp` sockets, and `io_backend`. Native-only — never
    // in the wasm graph.
    const capnpc_full = capnpc_dep.module("capnpc-zig");

    const slcp_core = b.addModule("slcp-core", .{
        .root_source_file = b.path("src/lib_core.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "capnpc-zig", .module = capnpc_core },
        },
    });

    // "slcp": the native omakase layer (node/, M5): overlay, timers, store,
    // keys, Node. It needs BOTH the engine and the full capnpc-zig transport
    // surfaces in ONE module graph — but `capnpc-zig-core` and the full
    // `capnpc-zig` share source files and cannot coexist in a single
    // compilation. So the node layer gets its OWN slcp-core instance bound to
    // the FULL capnp module (a superset of core); there is exactly one capnp
    // module in this graph. The wasm/sim graphs keep their core-only
    // instances untouched.
    const slcp_core_native = b.createModule(.{
        .root_source_file = b.path("src/lib_core.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "capnpc-zig", .module = capnpc_full },
        },
    });
    const slcp_mod = b.addModule("slcp", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "slcp-core", .module = slcp_core_native },
            .{ .name = "capnpc-zig", .module = capnpc_full },
        },
    });

    // node-tests: the whole native node layer's unit tests (store byte
    // format + restart recovery, timer wheel, key file, overlay framing,
    // Node lifecycle). Runs under `zig build test`.
    const node_tests = b.addTest(.{
        .name = "slcp-node-tests",
        .root_module = slcp_mod,
    });
    const run_node_tests = b.addRunArtifact(node_tests);
    const node_tests_step = b.step("node-tests", "Run the native node-layer unit tests");
    node_tests_step.dependOn(&run_node_tests.step);

    const core_tests = b.addTest(.{
        .name = "slcp-core-tests",
        .root_module = slcp_core,
    });
    const run_core_tests = b.addRunArtifact(core_tests);

    const vector_tests = b.addTest(.{
        .name = "slcp-vector-tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/vectors_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "slcp-core", .module = slcp_core },
            },
        }),
    });
    const run_vector_tests = b.addRunArtifact(vector_tests);
    // Reads vectors/*.json and vectors/traces/*.bin relative to the build
    // root, so cwd is pinned. And since those files are not declared build
    // inputs, a gate reading files the build graph does not declare must
    // never be answered from cache — otherwise a regenerated or hand-edited
    // vector leaves the previous "pass" standing and the replay silently
    // does not re-run.
    run_vector_tests.setCwd(b.path("."));
    run_vector_tests.has_side_effects = true;

    // Vendored framing conformance replay (design §9.1): capnp-zig's published
    // fixtures for the segment framer, checked in under vectors/framing/ and
    // replayed against the Framer AS THE OVERLAY CONFIGURES IT. It therefore
    // lives in the FULL-capnp graph (`slcp_mod` → slcp_core_native →
    // capnpc-zig), not the core-only one: `rpc.wire.framing` exists only
    // there, and capnpc-zig-core cannot coexist with it in one compilation.
    // Reads the checked-in JSON relative to the build root, so cwd is pinned;
    // absent file ⇒ error.SkipZigTest.
    const framing_vector_tests = b.addTest(.{
        .name = "slcp-framing-vector-tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/framing_vectors_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "slcp", .module = slcp_mod },
            },
        }),
    });
    const run_framing_vector_tests = b.addRunArtifact(framing_vector_tests);
    run_framing_vector_tests.setCwd(b.path("."));
    // The fixture JSON is read at runtime, so the build graph cannot see it as
    // an input (and must not declare it, or a missing file would fail the
    // build instead of skipping). Never answer this conformance gate from
    // cache — same reasoning as the wasm differential run steps below.
    run_framing_vector_tests.has_side_effects = true;
    const framing_vectors_step = b.step("framing-vectors", "Replay the vendored capnp-zig framing conformance fixtures");
    framing_vectors_step.dependOn(&run_framing_vector_tests.step);

    const e2e_tests = b.addTest(.{
        .name = "slcp-engine-e2e-tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/engine_e2e_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "slcp-core", .module = slcp_core },
            },
        }),
    });
    const run_e2e_tests = b.addRunArtifact(e2e_tests);

    // Deterministic multi-engine simulator (design §13.1). The smoke matrix
    // is compute-heavy (hundreds of full consensus runs, Ed25519 throughout),
    // so the sim binaries upgrade Debug to ReleaseSafe — safety checks stay
    // on; any explicit -Doptimize choice is respected. The sim gets its own
    // slcp-core module instance at that optimize level (per-module optimize:
    // reusing the Debug instance would keep the hot path slow).
    const sim_optimize: std.builtin.OptimizeMode = if (optimize == .debug) .safe else optimize;
    const capnpc_core_sim = b.dependency("capnpc_zig", .{
        .target = target,
        .optimize = sim_optimize,
    }).module("capnpc-zig-core");
    const slcp_core_sim = b.createModule(.{
        .root_source_file = b.path("src/lib_core.zig"),
        .target = target,
        .optimize = sim_optimize,
        .imports = &.{
            .{ .name = "capnpc-zig", .module = capnpc_core_sim },
        },
    });
    const sim_tests = b.addTest(.{
        .name = "slcp-sim-tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("sim/sim_test.zig"),
            .target = target,
            .optimize = sim_optimize,
            .imports = &.{
                .{ .name = "slcp-core", .module = slcp_core_sim },
            },
        }),
    });
    const run_sim_tests = b.addRunArtifact(sim_tests);

    // Fuzz targets (design §13.5). Two std.testing.fuzz targets — a decode
    // target (arbitrary bytes → typed rejection, never UB/leak) and an
    // input-sequence target (random valid-typed input interleavings against
    // one engine, §13.1 invariants after every input). They compile against
    // the sim-level slcp-core instance (ReleaseSafe by default) and reach the
    // sibling sim/ helpers (adversary.zig, invariants.zig) via relative
    // imports, so all three share one module instance.
    //   `zig build fuzz`        — run both as fuzz targets (add --fuzz to
    //                             actually fuzz; otherwise replays the corpus).
    //   `zig build fuzz-smoke`  — a fixed 5000-iteration deterministic run of
    //                             both, folded into `zig build test` for CI.
    // The sim/ Byzantine toolkit + invariants, as named modules over the same
    // slcp-core instance (module identity ⇒ shared engine types).
    const adversary_mod = b.createModule(.{
        .root_source_file = b.path("sim/adversary.zig"),
        .target = target,
        .optimize = sim_optimize,
        .imports = &.{.{ .name = "slcp-core", .module = slcp_core_sim }},
    });
    const invariants_mod = b.createModule(.{
        .root_source_file = b.path("sim/invariants.zig"),
        .target = target,
        .optimize = sim_optimize,
        .imports = &.{.{ .name = "slcp-core", .module = slcp_core_sim }},
    });
    const fuzz_decode_mod = b.createModule(.{
        .root_source_file = b.path("tests/fuzz/decode_fuzz.zig"),
        .target = target,
        .optimize = sim_optimize,
        .imports = &.{
            .{ .name = "slcp-core", .module = slcp_core_sim },
            .{ .name = "adversary", .module = adversary_mod },
        },
    });
    const fuzz_seq_mod = b.createModule(.{
        .root_source_file = b.path("tests/fuzz/input_seq_fuzz.zig"),
        .target = target,
        .optimize = sim_optimize,
        .imports = &.{
            .{ .name = "slcp-core", .module = slcp_core_sim },
            .{ .name = "adversary", .module = adversary_mod },
            .{ .name = "invariants", .module = invariants_mod },
        },
    });
    const fuzz_decode_tests = b.addTest(.{ .name = "slcp-fuzz-decode", .root_module = fuzz_decode_mod });
    const fuzz_seq_tests = b.addTest(.{ .name = "slcp-fuzz-input-seq", .root_module = fuzz_seq_mod });

    // fuzz-smoke: run the compiled targets' tests deterministically (includes
    // the 5000-iteration smoke tests + the OOM-injection corpus).
    const run_fuzz_decode_smoke = b.addRunArtifact(fuzz_decode_tests);
    const run_fuzz_seq_smoke = b.addRunArtifact(fuzz_seq_tests);
    const fuzz_smoke_step = b.step("fuzz-smoke", "Deterministic bounded run of the fuzz targets (part of `test`)");
    fuzz_smoke_step.dependOn(&run_fuzz_decode_smoke.step);
    fuzz_smoke_step.dependOn(&run_fuzz_seq_smoke.step);

    // fuzz: same artifacts, intended as `zig build fuzz --fuzz` for
    // coverage-guided fuzzing; without --fuzz they replay the seed corpus.
    const run_fuzz_decode = b.addRunArtifact(fuzz_decode_tests);
    const run_fuzz_seq = b.addRunArtifact(fuzz_seq_tests);
    const fuzz_step = b.step("fuzz", "Run the decode + input-seq fuzz targets (add --fuzz to fuzz)");
    fuzz_step.dependOn(&run_fuzz_decode.step);
    fuzz_step.dependOn(&run_fuzz_seq.step);

    // -----------------------------------------------------------------
    // WASM host-ABI conformance suite (design §7.2/§7.3, §14-M4), run
    // WITHOUT a wasm runtime so it is part of plain `zig build test`.
    // tests/abi/ deliberately does NOT import src/wasm/slcp_host_abi.zig:
    // that module pins std.heap.wasm_allocator (a @compileError off wasm) and
    // `export fn` decls are always analyzed — so the ABI source is read as
    // TEXT for its frozen scalar/name surface, and every pure-logic path is
    // re-derived natively. The parts that genuinely need a runtime (linear
    // memory, real imports, handle map) belong to the differential harness.
    // Both files read fixtures relative to the build root, so cwd is pinned.
    // -----------------------------------------------------------------
    const abi_contract_tests = b.addTest(.{
        .name = "slcp-abi-contract-tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/abi/abi_contract_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "slcp-core", .module = slcp_core }},
        }),
    });
    const run_abi_contract_tests = b.addRunArtifact(abi_contract_tests);
    run_abi_contract_tests.setCwd(b.path("."));
    // Reads src/wasm/slcp_host_abi.zig as TEXT (the frozen-surface parse) and
    // vectors/lint.json — neither is a declared build input, so without this
    // a corrupted vector or an edited ABI surface leaves the previous pass
    // standing. Verified: mutating vectors/lint.json kept `zig build abi`
    // green until this line was added.
    run_abi_contract_tests.has_side_effects = true;

    const abi_fake_host_tests = b.addTest(.{
        .name = "slcp-abi-fake-host-tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/abi/fake_host_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "slcp-core", .module = slcp_core }},
        }),
    });
    const run_abi_fake_host_tests = b.addRunArtifact(abi_fake_host_tests);
    run_abi_fake_host_tests.setCwd(b.path("."));

    const abi_step = b.step("abi", "Run the WASM host-ABI conformance suite (no wasm runtime needed)");
    abi_step.dependOn(&run_abi_contract_tests.step);
    abi_step.dependOn(&run_abi_fake_host_tests.step);

    // Differential native-vs-wasm harness (design §13.5, §14-M4 accept). The
    // test binary drives zig-out/bin/slcp_core.wasm through a Node runner
    // (tests/wasm/host.mjs) and byte-compares every effect frame against the
    // native engine AND the recorded trace vectors.
    const wasm_diff_mod = b.createModule(.{
        .root_source_file = b.path("tests/wasm/differential_test.zig"),
        .target = target,
        .optimize = sim_optimize,
        .imports = &.{
            .{ .name = "slcp-core", .module = slcp_core_sim },
            .{ .name = "adversary", .module = adversary_mod },
        },
    });
    const wasm_diff_tests = b.addTest(.{ .name = "slcp-wasm-diff", .root_module = wasm_diff_mod });

    const test_step = b.step("test", "Run unit + vector + framing conformance + e2e + ABI conformance + sim matrix + fuzz smoke + wasm differential (skipped without the wasm artifact)");
    test_step.dependOn(&run_core_tests.step);
    test_step.dependOn(&run_vector_tests.step);
    test_step.dependOn(&run_framing_vector_tests.step);
    test_step.dependOn(&run_e2e_tests.step);
    test_step.dependOn(&run_node_tests.step);
    test_step.dependOn(abi_step);
    test_step.dependOn(&run_sim_tests.step);
    test_step.dependOn(fuzz_smoke_step);

    // Two run steps over the SAME differential binary, differing only in
    // whether the wasm artifact is a build dependency:
    //   `zig build wasm-diff` — depends on the wasm build, so the M4 gate can
    //     never silently pass by skipping.
    //   `zig build test`      — no dependency, so a clean tree (or a machine
    //     without node) reports error.SkipZigTest and stays green.
    // Both are side-effectful: a gate reading files the build graph does not
    // declare must never be answered from cache.
    const run_wasm_diff_soft = b.addRunArtifact(wasm_diff_tests);
    // Opens zig-out/bin/slcp_core.wasm and tests/wasm/host.mjs by RELATIVE
    // path, so cwd is pinned like the other artifact-reading gates.
    run_wasm_diff_soft.setCwd(b.path("."));
    run_wasm_diff_soft.has_side_effects = true;
    test_step.dependOn(&run_wasm_diff_soft.step);

    // One-line repro runner: zig build sim -- --seed=N --nodes=N --scenario=name
    const sim_exe = b.addExecutable(.{
        .name = "slcp-sim",
        .root_module = b.createModule(.{
            .root_source_file = b.path("sim/main.zig"),
            .target = target,
            .optimize = sim_optimize,
            .imports = &.{
                .{ .name = "slcp-core", .module = slcp_core_sim },
            },
        }),
    });
    const run_sim = b.addRunArtifact(sim_exe);
    run_sim.addPassthruArgs(); // forwards everything after `--`
    const sim_step = b.step("sim", "Run one simulator cell: -- --seed=N --nodes=N --scenario=name");
    sim_step.dependOn(&run_sim.step);

    // Full §13.1 matrix (1000 seeds x n 3..7 x 3 scenarios) — manual step.
    const sim_matrix_exe = b.addExecutable(.{
        .name = "slcp-sim-matrix",
        .root_module = b.createModule(.{
            .root_source_file = b.path("sim/matrix_main.zig"),
            .target = target,
            .optimize = sim_optimize,
            .imports = &.{
                .{ .name = "slcp-core", .module = slcp_core_sim },
            },
        }),
    });
    const run_sim_matrix = b.addRunArtifact(sim_matrix_exe);
    run_sim_matrix.addPassthruArgs();
    const sim_matrix_step = b.step("sim-matrix", "Run the FULL 1000-seed simulation matrix (long)");
    sim_matrix_step.dependOn(&run_sim_matrix.step);

    // -----------------------------------------------------------------
    // WASM host ABI (design §7): `zig build wasm` → slcp_core.wasm.
    // Settings copied from capnp-zig's wasm-host build step
    // (build/modules.zig): entry disabled, rdynamic, exported memory,
    // 4 MiB initial / 64 MiB max (§16's memory-ceiling budget).
    // The wasm graph needs a WASM-TARGETED slcp-core instance — mixing the
    // host target into it breaks cross builds.
    // -----------------------------------------------------------------
    const wasm_target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding });
    const wasm_optimize: std.builtin.OptimizeMode = if (optimize == .debug) .small else optimize;
    const capnpc_core_wasm = b.dependency("capnpc_zig", .{
        .target = wasm_target,
        .optimize = wasm_optimize,
    }).module("capnpc-zig-core");
    const slcp_core_wasm = b.createModule(.{
        .root_source_file = b.path("src/lib_core.zig"),
        .target = wasm_target,
        .optimize = wasm_optimize,
        .imports = &.{.{ .name = "capnpc-zig", .module = capnpc_core_wasm }},
    });
    const wasm_exe = b.addExecutable(.{
        .name = "slcp_core",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/wasm/slcp_host_abi.zig"),
            .target = wasm_target,
            .optimize = wasm_optimize,
            .imports = &.{.{ .name = "slcp-core", .module = slcp_core_wasm }},
        }),
    });
    wasm_exe.entry = .disabled;
    wasm_exe.rdynamic = true;
    wasm_exe.export_memory = true;
    wasm_exe.initial_memory = 4 * 1024 * 1024;
    wasm_exe.max_memory = 64 * 1024 * 1024;
    const install_wasm = b.addInstallArtifact(wasm_exe, .{});
    const wasm_step = b.step("wasm", "Build slcp_core.wasm (wasm32-freestanding, ReleaseSmall)");
    wasm_step.dependOn(&install_wasm.step);

    // The M4 gate: `zig build wasm && zig build wasm-diff` — this run step
    // depends on the wasm install, so it always has a real artifact to drive.
    const run_wasm_diff_gate = b.addRunArtifact(wasm_diff_tests);
    run_wasm_diff_gate.setCwd(b.path("."));
    run_wasm_diff_gate.has_side_effects = true;
    run_wasm_diff_gate.step.dependOn(&install_wasm.step);
    const wasm_diff_step = b.step("wasm-diff", "Differential native-vs-wasm replay of the trace vectors + differential fuzz (§13.5)");
    wasm_diff_step.dependOn(&run_wasm_diff_gate.step);

    // Full Byzantine seed matrix (§14-M3 accept: 1000 seeds) — manual step.
    const byz_matrix_mod = b.createModule(.{
        .root_source_file = b.path("sim/byz_matrix_main.zig"),
        .target = target,
        .optimize = sim_optimize,
        .imports = &.{.{ .name = "slcp-core", .module = slcp_core_sim }},
    });
    const byz_matrix_exe = b.addExecutable(.{ .name = "slcp-byz-matrix", .root_module = byz_matrix_mod });
    const run_byz_matrix = b.addRunArtifact(byz_matrix_exe);
    const byz_matrix_step = b.step("byz-matrix", "Run the FULL 1000-seed Byzantine matrix (long)");
    byz_matrix_step.dependOn(&run_byz_matrix.step);

    // Deterministic conformance-vector generator: writes vectors/*.json.
    const gen_vectors = b.addExecutable(.{
        .name = "gen-vectors",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/gen_vectors.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "slcp-core", .module = slcp_core },
            },
        }),
    });
    const run_gen_vectors = b.addRunArtifact(gen_vectors);
    run_gen_vectors.setCwd(b.path("."));
    const vectors_step = b.step("vectors", "Regenerate conformance vectors into vectors/");
    vectors_step.dependOn(&run_gen_vectors.step);

    // `zig build test` COMPILES the vector generator (without running it —
    // running rewrites vectors/ as a side effect). The generator is the
    // frozen protocol definition's source, but nothing in `test` referenced
    // it, so an engine API change silently broke it and `just vectors`
    // stayed dead until the next re-vendor. Compiling it here catches that
    // class of rot at the same gate as everything else.
    test_step.dependOn(&gen_vectors.step);

    // -----------------------------------------------------------------
    // End-to-end (design §13.6 / §14-M5 accept). Four full Zig nodes in
    // ONE process over real loopback TCP, 3-of-4 quorum, 200 slots — plus
    // kill/restart mid-slot, partition/heal, and one equivocator. This is
    // the milestone gate. Kept out of `zig build test` (real sockets, real
    // clocks, minutes-scale) and run explicitly: `zig build e2e`.
    // -----------------------------------------------------------------
    const e2e_optimize: std.builtin.OptimizeMode = if (optimize == .debug) .safe else optimize;
    const capnpc_full_e2e = b.dependency("capnpc_zig", .{
        .target = target,
        .optimize = e2e_optimize,
    }).module("capnpc-zig");
    // One capnp module in the e2e graph: a full-bound slcp-core instance
    // shared by the `slcp` module and the test root (module identity ⇒ shared
    // engine types across both imports).
    const slcp_core_e2e = b.createModule(.{
        .root_source_file = b.path("src/lib_core.zig"),
        .target = target,
        .optimize = e2e_optimize,
        .imports = &.{
            .{ .name = "capnpc-zig", .module = capnpc_full_e2e },
        },
    });
    const slcp_e2e_mod = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = e2e_optimize,
        .imports = &.{
            .{ .name = "slcp-core", .module = slcp_core_e2e },
            .{ .name = "capnpc-zig", .module = capnpc_full_e2e },
        },
    });
    const e2e_node_tests = b.addTest(.{
        .name = "slcp-e2e",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/e2e/cluster_test.zig"),
            .target = target,
            .optimize = e2e_optimize,
            .imports = &.{
                .{ .name = "slcp", .module = slcp_e2e_mod },
                .{ .name = "slcp-core", .module = slcp_core_e2e },
            },
        }),
    });
    const run_e2e = b.addRunArtifact(e2e_node_tests);
    run_e2e.has_side_effects = true; // real sockets/files: never answer from cache
    const e2e_step = b.step("e2e", "Run the 4-node end-to-end cluster (200 slots, kill/restart, partition/heal, equivocator)");
    e2e_step.dependOn(&run_e2e.step);

    // ===== M6:quorum =====
    // M6 stage anchor (quorum): cli exe + cli tests + node_create tests land
    // here and only here. The six M6 anchors stay in this order — later
    // anchors may reference symbols declared under earlier ones.

    // ===== M6:appnode =====
    // M6 stage anchor (appnode): appnode-errors expected-fail compile step,
    // codec fuzz target. Insert under this anchor only; never above it.
    // Keep the blank line between anchors so parallel stages merge cleanly.

    // ===== M6:example =====
    // M6 stage anchor (example): counter-intree compile, example_smoke tool
    // and its run steps. Insert under this anchor only; never above it.
    // Keep the blank line between anchors so parallel stages merge cleanly.

    // ===== M6:docs =====
    // M6 stage anchor (docs): docs_smoke tool + run step, bytes_node example
    // compile, the docs-smoke step. Insert under this anchor only.
    // Keep the blank line between anchors so parallel stages merge cleanly.

    // ===== M6:apisnap_ci =====
    // M6 stage anchor (apisnap_ci): api-snapshot / check-api / api-closure
    // steps and the tool's tests. Insert under this anchor only.
    // Keep the blank line between anchors so parallel stages merge cleanly.
    //
    // Public API snapshot gate (design §13.8 / §14-M6, capnp-zig's check-api
    // pattern). tools/api_snapshot.zig imports `slcp` in a NON-test build, so
    // it sees exactly the surface a consumer sees, and renders it into two
    // files: docs/api-snapshot.txt (STABLE — frozen; drift is red) and
    // docs/api-snapshot-experimental.txt (informational). It also reads
    // src/wasm/slcp_host_abi.zig as TEXT for the `slcp-abi.*` lines (the
    // module cannot be imported natively — see the tests/abi section), and
    // `--check` reads the committed snapshots. None of those files are
    // declared build inputs, so EVERY run step below pins cwd AND is marked
    // side-effectful. Measured on this toolchain (S1c ablations): the TEST
    // step is the one that is actually served from cache without the flag
    // (second run prints `cached`); the exe steps are side-effectful by
    // construction — the runner treats `.infer_from_args` stdio with no
    // output args as never cacheable (lib/compiler/Maker/Step/Run.zig:253-259)
    // — but the flag is kept on them too, because a later `expectExitCode`
    // / `addCheck` flips stdio to `.check`, which IS cached, and the gate
    // would then answer a hand-edited snapshot from the previous pass. See
    // docs/upstream/06-check-api-cache-and-fmt-clean-gen.md.
    //
    // `check-api` / `api-closure` are deliberately NOT folded into `test`
    // yet: the surface is still moving through M6. S6 (the API freeze) adds
    // them; only the tool's unit tests run under `test` today.
    const strict_experimental = b.option(
        bool,
        "strict-experimental",
        "check-api: also fail when docs/api-snapshot-experimental.txt is stale (CI ubuntu job; default false)",
    ) orelse false;
    const api_snapshot_mod = b.createModule(.{
        .root_source_file = b.path("tools/api_snapshot.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "slcp", .module = slcp_mod }},
    });
    const api_snapshot_tool = b.addExecutable(.{
        .name = "api-snapshot",
        .root_module = api_snapshot_mod,
    });

    const run_api_snapshot_write = b.addRunArtifact(api_snapshot_tool);
    run_api_snapshot_write.addArg("--write");
    run_api_snapshot_write.setCwd(b.path("."));
    run_api_snapshot_write.has_side_effects = true;
    const api_snapshot_step = b.step("api-snapshot", "Regenerate docs/api-snapshot.txt + docs/api-snapshot-experimental.txt from the live public API");
    api_snapshot_step.dependOn(&run_api_snapshot_write.step);

    const run_api_snapshot_check = b.addRunArtifact(api_snapshot_tool);
    run_api_snapshot_check.addArg("--check");
    if (strict_experimental) run_api_snapshot_check.addArg("--strict-experimental");
    run_api_snapshot_check.setCwd(b.path("."));
    run_api_snapshot_check.has_side_effects = true;
    const check_api_step = b.step("check-api", "Fail when the STABLE public API drifts from docs/api-snapshot.txt (-Dstrict-experimental=true also gates the experimental file)");
    check_api_step.dependOn(&run_api_snapshot_check.step);

    const run_api_closure = b.addRunArtifact(api_snapshot_tool);
    run_api_closure.addArg("--closure");
    run_api_closure.setCwd(b.path("."));
    run_api_closure.has_side_effects = true;
    const api_closure_step = b.step("api-closure", "Fail when a Stable signature mentions an Experimental type");
    api_closure_step.dependOn(&run_api_closure.step);

    // The tool's own unit tests (error-set sort, line normalization, the ABI
    // text parser on fixtures AND on the real ABI source — hence cwd + side
    // effects). Compiling them also evaluates the rule-liveness assertion, so
    // a stale Stable rule is a compile error at the `test` gate.
    const api_snapshot_tests = b.addTest(.{
        .name = "slcp-api-snapshot-tests",
        .root_module = api_snapshot_mod,
    });
    const run_api_snapshot_tests = b.addRunArtifact(api_snapshot_tests);
    run_api_snapshot_tests.setCwd(b.path("."));
    run_api_snapshot_tests.has_side_effects = true;
    const api_snapshot_tests_step = b.step("api-snapshot-tests", "Run the API-snapshot tool's unit tests (part of `test`)");
    api_snapshot_tests_step.dependOn(&run_api_snapshot_tests.step);
    test_step.dependOn(&run_api_snapshot_tests.step);

    // ===== M6:release =====
    // M6 stage anchor (release): the preflight aggregate step. Insert under
    // this anchor only; it may reference every step declared above.
    // Keep the blank line between anchors so parallel stages merge cleanly.
}
