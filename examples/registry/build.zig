const std = @import("std");
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const slcp_dep = b.dependency("slcp", .{ .target = target, .optimize = optimize });
    const exe = b.addExecutable(.{ .name = "registry", .root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "slcp", .module = slcp_dep.module("slcp") }},
    }) });
    b.installArtifact(exe);
    b.installArtifact(slcp_dep.artifact("slcp")); // the lint/key CLI rides along: zig-out/bin/slcp
    const run = b.addRunArtifact(exe);
    run.addPassthruArgs();
    b.step("run", "Run registry with the arguments after `--`").dependOn(&run.step);
    // `zig build test`: the pure state machine, the RPC, and a live 2-of-2 pair.
    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/app.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "slcp", .module = slcp_dep.module("slcp") }},
    }) });
    b.step("test", "Run the registry's tests").dependOn(&b.addRunArtifact(tests).step);
}
