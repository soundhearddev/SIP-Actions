const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ─────────────────────────────────────────────
    // Dependencies
    // ─────────────────────────────────────────────

    const sip_dep = b.dependency("sip", .{
        .target = target,
        .optimize = optimize,
    });
    const sip_mod = sip_dep.module("sip");

    const siputils_dep = b.dependency("siputils", .{
        .target = target,
        .optimize = optimize,
    });
    const siputils_mod = siputils_dep.module("siputils");

    // ─────────────────────────────────────────────
    // actiond
    // ─────────────────────────────────────────────
    const actiond_mod = b.createModule(.{
        .root_source_file = b.path("src/actiond.zig"),
        .target = target,
        .optimize = optimize,
    });
    actiond_mod.addImport("sip", sip_mod);
    actiond_mod.addImport("siputils", siputils_mod);

    const actiond = b.addExecutable(.{
        .name = "actiond",
        .root_module = actiond_mod,
    });
    b.installArtifact(actiond);

    const run_actiond = b.addRunArtifact(actiond);
    run_actiond.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_actiond.addArgs(args);

    b.step("run-actiond", "Run actiond")
        .dependOn(&run_actiond.step);

    // ─────────────────────────────────────────────
    // actionctl
    // ─────────────────────────────────────────────
    const actionctl_mod = b.createModule(.{
        .root_source_file = b.path("src/actionctl.zig"),
        .target = target,
        .optimize = optimize,
    });
    actionctl_mod.addImport("sip", sip_mod);
    actionctl_mod.addImport("siputils", siputils_mod);

    const actionctl = b.addExecutable(.{
        .name = "actionctl",
        .root_module = actionctl_mod,
    });
    b.installArtifact(actionctl);

    const run_actionctl = b.addRunArtifact(actionctl);
    run_actionctl.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_actionctl.addArgs(args);

    b.step("run-actionctl", "Run actionctl")
        .dependOn(&run_actionctl.step);
}
