const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // OpenSSL headers and libraries are located through pkg-config.
    const openssl = b.addTranslateC(.{
        .root_source_file = b.path("src/openssl.h"),
        .target = target,
        .optimize = optimize,
    });
    openssl.linkSystemLibrary("ssl", .{});
    openssl.linkSystemLibrary("crypto", .{});

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "openssl", .module = openssl.createModule() }},
    });

    const exe = b.addExecutable(.{ .name = "raven", .root_module = exe_mod });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    b.step("run", "Run the app").dependOn(&run_cmd.step);

    const unit_tests = b.addTest(.{ .root_module = exe_mod });
    b.step("test", "Run unit tests").dependOn(&b.addRunArtifact(unit_tests).step);

    const smoke_cmd = b.addSystemCommand(&.{ "python3", "scripts/smoke.py" });
    smoke_cmd.step.dependOn(b.getInstallStep());
    b.step("smoke", "Run end-to-end smoke test").dependOn(&smoke_cmd.step);
}
