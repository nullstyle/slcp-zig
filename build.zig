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

    const slcp_core = b.addModule("slcp-core", .{
        .root_source_file = b.path("src/lib_core.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "capnpc-zig", .module = capnpc_core },
        },
    });

    // "slcp": the native omakase layer (node/, M5). For now it re-exports core.
    _ = b.addModule("slcp", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "slcp-core", .module = slcp_core },
        },
    });

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

    const test_step = b.step("test", "Run slcp-core unit tests + vector tests + engine e2e + sim smoke matrix + fuzz smoke");
    test_step.dependOn(&run_core_tests.step);
    test_step.dependOn(&run_vector_tests.step);
    test_step.dependOn(&run_e2e_tests.step);
    test_step.dependOn(&run_sim_tests.step);
    test_step.dependOn(fuzz_smoke_step);

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
}
