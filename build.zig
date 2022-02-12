const std = @import("std");
const Builder = std.build.Builder;

fn baremetal_target(exec: *std.build.LibExeObjStep, arch: std.Target.Cpu.Arch) void {
    var disabled_features = std.Target.Cpu.Feature.Set.empty;
    var enabled_feautres = std.Target.Cpu.Feature.Set.empty;

    switch (arch) {
        .x86_64 => {
            const features = std.Target.x86.Feature;
            disabled_features.addFeature(@enumToInt(features.mmx));
            disabled_features.addFeature(@enumToInt(features.sse));
            disabled_features.addFeature(@enumToInt(features.sse2));
            disabled_features.addFeature(@enumToInt(features.avx));
            disabled_features.addFeature(@enumToInt(features.avx2));

            enabled_feautres.addFeature(@enumToInt(features.soft_float));
            exec.code_model = .kernel;
        },
        .aarch64 => {
            const features = std.Target.aarch64.Feature;
            disabled_features.addFeature(@enumToInt(features.fp_armv8));
            disabled_features.addFeature(@enumToInt(features.crypto));
            disabled_features.addFeature(@enumToInt(features.neon));
            exec.code_model = .small;
        },
        else => unreachable,
    }

    exec.disable_stack_probing = true;
    exec.setTarget(.{
        .cpu_arch = arch,
        .os_tag = std.Target.Os.Tag.freestanding,
        .abi = std.Target.Abi.none,
        .cpu_features_sub = disabled_features,
        .cpu_features_add = enabled_feautres,
    });
}

fn stivale2_kernel(b: *Builder, arch: std.Target.Cpu.Arch) *std.build.LibExeObjStep {
    const kernel_filename = b.fmt("kernel_{s}.elf", .{@tagName(arch)});
    const kernel = b.addExecutable(kernel_filename, "kernel/stivale2.zig");

    kernel.addIncludeDir("extern/stivale/");
    kernel.setMainPkgPath(".");
    kernel.setOutputDir(b.cache_root);
    kernel.setBuildMode(.ReleaseSafe);
    kernel.install();

    baremetal_target(kernel, arch);
    kernel.setLinkerScriptPath(.{ .path = "kernel/linker.ld" });

    b.default_step.dependOn(&kernel.step);

    return kernel;
}

fn run_qemu_with_x86_bios_image(b: *Builder, image_path: []const u8) *std.build.RunStep {
    const cmd = &[_][]const u8{
        // zig fmt: off
        "qemu-system-x86_64",
        "-cdrom", image_path,
        "-debugcon", "stdio",
        "-vga", "std",
        "-m", "4G",
        "-machine", "q35",
        // zig fmt: on
    };

    const run_step = b.addSystemCommand(cmd);

    const run_command = b.step("run-x86_64-bios", "Run on x86_64 with Limine BIOS bootloader");
    run_command.dependOn(&run_step.step);

    return run_step;
}

fn get_ovmf(_: *Builder) ![]const u8
{
    if (std.os.getenv("OVMF_PATH")) |p|
        return p;

    return "OVMF path not found - please set envvar OVMF_PATH";
}

fn run_qemu_with_x86_uefi_image(b: *Builder, image_path: []const u8) *std.build.RunStep
{
    const cmd = &[_][]const u8{
        // zig fmt: off
        "qemu-system-x86_64",
        "-cdrom", image_path,
        "-debugcon", "stdio",
        "-vga", "std",
        "-m", "4G",
        "-machine", "q35,accel=kvm:whpx:tcg",
        "-drive", b.fmt("if=pflash,format=raw,unit=0,file={s},readonly=on", .{get_ovmf(b)}),
        // zig fmt: on
    };

    const run_step = b.addSystemCommand(cmd);

    const run_command = b.step("run-x86_64-uefi", "Run on x86_64 with Limine UEFI bootloader");
    run_command.dependOn(&run_step.step);

    return run_step;
}

fn build_limine_image(b: *Builder, kernel: *std.build.LibExeObjStep, image_path: []const u8) *std.build.RunStep
{
    const img_dir = b.fmt("{s}/img_dir", .{b.cache_root});

    const kernel_path = b.getInstallPath(kernel.install_step.?.dest_dir, kernel.out_filename);

    const cmd = &[_][]const u8{
        "/bin/sh", "-c",
        std.mem.concat(b.allocator, u8, &[_][]const u8{
            // zig fmt: off
            "rm ", image_path, " || true && ",
            "mkdir -p ", img_dir, "/EFI/BOOT && ",
            "make -C extern/limine-bin limine-install && ",
            "cp ",
                "extern/limine-bin/limine-eltorito-efi.bin ",
                "extern/limine-bin/limine-cd.bin ",
                "extern/limine-bin/limine.sys ",
                "limine.cfg ",
                img_dir, " && ",
            "cp extern/limine-bin/BOOTX64.EFI ", img_dir, "/EFI/BOOT/ && ",
            "cp ", kernel_path, " ", img_dir, " && ",
            "xorriso -as mkisofs -quiet -b limine-cd.bin ",
                "-no-emul-boot -boot-load-size 4 -boot-info-table ",
                "--efi-boot limine-eltorito-efi.bin ",
                "-efi-boot-part --efi-boot-image --protective-msdos-label ",
                img_dir, " -o ", image_path, " && ",
            "extern/limine-bin/limine-install ", image_path, " && ",
            "true",
            // zig fmt: on
        }) catch unreachable,
    };

    const image_step = b.addSystemCommand(cmd);
    image_step.step.dependOn(&kernel.install_step.?.step);
    b.default_step.dependOn(&image_step.step);

    const image_command = b.step("x86_64-universal-image", "Build the x86_64 universal (bios and uefi) image");
    image_command.dependOn(&image_step.step);

    return image_step;
}

fn build_x86(b: *Builder) void
{
    const kernel = stivale2_kernel(b, .x86_64);
    const image_path = b.fmt("{s}/universal.iso", .{b.cache_root});
    const image = build_limine_image(b, kernel, image_path);

    const uefi_step = run_qemu_with_x86_uefi_image(b, image_path);
    uefi_step.step.dependOn(&image.step);

    const bios_step = run_qemu_with_x86_bios_image(b, image_path);
    bios_step.step.dependOn(&image.step);

    const run_step = b.step("run", "Run step. Default is BIOS");
    run_step.dependOn(&bios_step.step);
}

pub fn build(b: *Builder) void
{
    build_x86(b);

    // Just boots your kernel using sabaton, without a filesystem.
    //_ = run_qemu_with_sabaton(b, stivale2_kernel(b, .aarch64));
}
