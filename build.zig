const std = @import("std");
const Builder = std.build.Builder;
const limine_installer = @import("limine/installer.zig");

fn kernel_exe(kernel: *std.build.LibExeObjStep, arch: std.Target.Cpu.Arch) void
{
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
            kernel.code_model = .kernel;
        },
        //.aarch64 => {
            //@compi
            //const features = std.Target.aarch64.Feature;
            //disabled_features.addFeature(@enumToInt(features.fp_armv8));
            //disabled_features.addFeature(@enumToInt(features.crypto));
            //disabled_features.addFeature(@enumToInt(features.neon));
            //kernel.code_model = .small;
        //},
        else => unreachable,
    }

    // kernel.pie = true;
    kernel.force_pic = true;
    kernel.disable_stack_probing = true;
    kernel.strip = false;
    kernel.setTarget(.{
        .cpu_arch = arch,
        .os_tag = std.Target.Os.Tag.freestanding,
        .abi = std.Target.Abi.none,
        .cpu_features_sub = disabled_features,
        .cpu_features_add = enabled_feautres,
    });
}

fn stivale2_kernel(b: *Builder, arch: std.Target.Cpu.Arch) *std.build.LibExeObjStep
{
    const kernel_filename = b.fmt("kernel_{s}.elf", .{@tagName(arch)});
    const kernel = b.addExecutable(kernel_filename, "src/kernel/kernel.zig");
    kernel.addIncludeDir("stivale");
    kernel.setOutputDir(b.cache_root);
    kernel.setBuildMode(b.standardReleaseOptions());
    kernel.setMainPkgPath("src/kernel");
    kernel.addPackagePath("stivale", "stivale/stivale2.zig");
    kernel.addPackagePath("kernel", "src/kernel/kernel.zig");
    kernel.install();

    kernel_exe(kernel, arch);
    kernel.setLinkerScriptPath(.{ .path = "src/kernel/linker.ld" });

    b.default_step.dependOn(&kernel.step);

    return kernel;
}

fn run_qemu_with_x86_bios_image(b: *Builder, image_path: []const u8) *std.build.RunStep
{
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

const LimineImage = struct
{
    step: std.build.Step,
    b: *Builder,
    image_path: []const u8,
    kernel_path: []const u8,

    fn build(step: *std.build.Step) !void
    {
        const self = @fieldParentPtr(@This(), "step", step);
        const img_dir_path = self.b.fmt("{s}/img_dir", .{self.b.cache_root});
        const cwd = std.fs.cwd();
        cwd.deleteFile(self.image_path) catch {};
        const img_dir = try cwd.makeOpenPath(img_dir_path, .{});
        const img_efi_dir = try img_dir.makeOpenPath("EFI/BOOT", .{});
        const limine_dir = try cwd.openDir("limine", .{});

        const files_to_copy_from_limine_dir = [_][]const u8
        { 
            "limine-eltorito-efi.bin", 
            "limine-cd.bin",
            "limine.sys",
        };

        for (files_to_copy_from_limine_dir) |filename|
        {
            try std.fs.Dir.copyFile(limine_dir, filename, img_dir, filename, .{});
        }
        try std.fs.Dir.copyFile(cwd, "limine.cfg", img_dir, "limine.cfg", .{});
        try std.fs.Dir.copyFile(limine_dir, "BOOTX64.EFI", img_efi_dir, "BOOTX64.EFI", .{});
        try std.fs.Dir.copyFile(cwd, self.kernel_path, img_dir, std.fs.path.basename(self.kernel_path), .{});

        const xorriso_process = try std.ChildProcess.init(
            & .{
                "xorriso", "-as", "mkisofs", "-quiet", "-b", "limine-cd.bin",
                "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table",
                "--efi-boot", "limine-eltorito-efi.bin",
                "-efi-boot-part", "--efi-boot-image", "--protective-msdos-label",
                img_dir_path, "-o", self.image_path
            },
            self.b.allocator);
        // Ignore stderr and stdout
        xorriso_process.stdin_behavior = std.ChildProcess.StdIo.Ignore;
        xorriso_process.stdout_behavior = std.ChildProcess.StdIo.Ignore;
        xorriso_process.stderr_behavior = std.ChildProcess.StdIo.Ignore;
        _ = try xorriso_process.spawnAndWait();

        try limine_installer.install(self.image_path, false, null);
    }
    
    fn create(b: *Builder, kernel: *std.build.LibExeObjStep, image_path: []const u8) *std.build.Step
    {
        const kernel_path = b.getInstallPath(kernel.install_step.?.dest_dir, kernel.out_filename);
        var self = b.allocator.create(@This()) catch @panic("out of memory");

        self.* = @This()
        {
            .step = std.build.Step.init(.custom, "_limine_image_", b.allocator, @This().build),
            .b = b,
            .image_path = image_path,
            .kernel_path = kernel_path,
        };

        self.step.dependOn(&kernel.install_step.?.step);

        const image_step = b.step("x86_64-universal-image", "Build the x86_64 universal (bios and uefi) image");
        image_step.dependOn(&self.step);

        return image_step;
    }

};

fn build_x86(b: *Builder) void
{
    const kernel = stivale2_kernel(b, .x86_64);
    const image_path = b.fmt("{s}/universal.iso", .{b.cache_root});
    const image_step = LimineImage.create(b, kernel, image_path);

    const uefi_step = run_qemu_with_x86_uefi_image(b, image_path);
    uefi_step.step.dependOn(image_step);

    const bios_step = run_qemu_with_x86_bios_image(b, image_path);
    bios_step.step.dependOn(image_step);

    const run_step = b.step("run", "Run step. Default is BIOS");
    run_step.dependOn(&bios_step.step);
}

pub fn build(b: *Builder) void
{
    build_x86(b);

    // Just boots your kernel using sabaton, without a filesystem.
    //_ = run_qemu_with_sabaton(b, stivale2_kernel(b, .aarch64));
}
