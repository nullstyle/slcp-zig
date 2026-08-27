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

    const test_step = b.step("test", "Run slcp-core unit tests + vector tests");
    test_step.dependOn(&run_core_tests.step);
    test_step.dependOn(&run_vector_tests.step);

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
