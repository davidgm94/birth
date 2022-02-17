const std = @import("std");
const Builder = std.build.Builder;
const limine_installer = @import("limine/installer.zig");
const Autogenerator = @import("autogenerator.zig");

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
    const kernel = b.addExecutable(kernel_filename, "src/kernel/main.zig");
    kernel_exe(kernel, arch);
    kernel.addIncludeDir("stivale");
    kernel.setOutputDir(b.cache_root);
    //kernel.setBuildMode(.ReleaseSafe);
    kernel.setBuildMode(b.standardReleaseOptions());

    const stivale_package = std.build.Pkg
    {
        .name = "stivale",
        .path = std.build.FileSource.relative("stivale/stivale2.zig"),
    };

    kernel.setMainPkgPath("src/kernel");
    kernel.addPackage(stivale_package);
    kernel.install();

    kernel.setLinkerScriptPath(.{ .path = "src/kernel/linker.ld" });

    b.default_step.dependOn(&kernel.step);

    return kernel;
}
const Loader = enum
{
    uefi,
    bios,
};

fn get_qemu_command(arch: std.Target.Cpu.Arch, loader: Loader, debug: bool) []const []const u8
{
    switch (arch)
    {
        .x86_64 =>
        {
            switch (loader)
            {
                .bios =>
                {
                    const x86_bios_qemu_cmd = [_][]const u8
                    {
                        // zig fmt: off
                        "qemu-system-x86_64",
                        "-cdrom", image_path,
                        "-debugcon", "stdio",
                        "-vga", "std",
                        "-m", "4G",
                        "-machine", "q35",
                        // zig fmt: on
                    };

                    if (debug)
                    {
                        const debug_flags = [_][]const u8 { "-S", "-s" };
                        const result = x86_bios_qemu_cmd ++ debug_flags;
                        return &result;
                    }
                    else
                    {

                        return &x86_bios_qemu_cmd;
                    }
                },
                .uefi => unreachable,
            }
        },
        else => unreachable,
    }
}


fn run_qemu_with_x86_bios_image(b: *Builder) *std.build.RunStep
{
    const run_step = b.addSystemCommand(get_qemu_command(.x86_64, .bios, false));

    const run_command = b.step("run-x86_64-bios", "Run on x86_64 with Limine BIOS bootloader");
    run_command.dependOn(&run_step.step);

    return run_step;
}

const Debug = struct
{
    step: std.build.Step,
    b: *Builder,

    fn create(b: *Builder) *@This()
    {
        var self = b.allocator.create(@This()) catch @panic("out of memory\n");
        self.* =
        .{
            .step = std.build.Step.init(.custom, "_debug_", b.allocator, @This().build),
            .b = b,
        };

        return self;
    }

    fn build(step: *std.build.Step) !void
    {
        const self = @fieldParentPtr(@This(), "step", step);
        const gdb_script_path = "zig-cache/.gdb_script";
        // @TODO: stop hardcoding the kernel path
        const gdb_script =
            \\set disassembly-flavor intel
            \\symbol-file zig-cache/kernel_x86_64.elf
            \\b _start
            \\target remote localhost:1234
            \\c
            ;
        try std.fs.cwd().writeFile(gdb_script_path, gdb_script);
        const first_pid = try std.os.fork();
        if (first_pid == 0)
        {
            const debugger = try std.ChildProcess.init( &.{ "gf2", "-x", gdb_script_path }, self.b.allocator);
            _ = try debugger.spawnAndWait();
        }
        else
        {
            const qemu_debug_command = get_qemu_command(.x86_64, .bios, true);
            const qemu = try std.ChildProcess.init(qemu_debug_command, self.b.allocator);
            try qemu.spawn();

            _ = std.os.waitpid(first_pid, 0);
            _ = try qemu.kill();
        }
    }
};

fn get_ovmf(_: *Builder) ![]const u8
{
    if (std.os.getenv("OVMF_PATH")) |p|
        return p;

    return "OVMF path not found - please set envvar OVMF_PATH";
}

const image_path = "zig-cache/universal.iso";
fn run_qemu_with_x86_uefi_image(b: *Builder) *std.build.RunStep
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
    kernel_path: []const u8,

    fn build(step: *std.build.Step) !void
    {
        const self = @fieldParentPtr(@This(), "step", step);
        const img_dir_path = self.b.fmt("{s}/img_dir", .{self.b.cache_root});
        const cwd = std.fs.cwd();
        cwd.deleteFile(image_path) catch {};
        const img_dir = try cwd.makeOpenPath(img_dir_path, .{});
        const img_efi_dir = try img_dir.makeOpenPath("EFI/BOOT", .{});
        const limine_dir = try cwd.openDir("limine", .{});

        const files_to_copy_from_limine_dir = [_][]const u8
        { 
            "limine-eltorito-efi.bin", 
            "limine-cd.bin",
            "limine.sys",
            "limine.cfg",
        };

        for (files_to_copy_from_limine_dir) |filename|
        {
            try std.fs.Dir.copyFile(limine_dir, filename, img_dir, filename, .{});
        }
        try std.fs.Dir.copyFile(limine_dir, "BOOTX64.EFI", img_efi_dir, "BOOTX64.EFI", .{});
        try std.fs.Dir.copyFile(cwd, self.kernel_path, img_dir, std.fs.path.basename(self.kernel_path), .{});

        const xorriso_process = try std.ChildProcess.init(
            & .{
                "xorriso", "-as", "mkisofs", "-quiet", "-b", "limine-cd.bin",
                "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table",
                "--efi-boot", "limine-eltorito-efi.bin",
                "-efi-boot-part", "--efi-boot-image", "--protective-msdos-label",
                img_dir_path, "-o", image_path
            },
            self.b.allocator);
        // Ignore stderr and stdout
        xorriso_process.stdin_behavior = std.ChildProcess.StdIo.Ignore;
        xorriso_process.stdout_behavior = std.ChildProcess.StdIo.Ignore;
        xorriso_process.stderr_behavior = std.ChildProcess.StdIo.Ignore;
        _ = try xorriso_process.spawnAndWait();

        try limine_installer.install(image_path, false, null);
    }
    
    fn create(b: *Builder, kernel: *std.build.LibExeObjStep) *std.build.Step
    {
        const kernel_path = b.getInstallPath(kernel.install_step.?.dest_dir, kernel.out_filename);
        var self = b.allocator.create(@This()) catch @panic("out of memory");

        self.* = @This()
        {
            .step = std.build.Step.init(.custom, "_limine_image_", b.allocator, @This().build),
            .b = b,
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
    const interrupts_file = Autogenerator.generate_interrupts(b.allocator) catch @panic("unable to generate interrupts file string\n");
    const interrupt_file_step = b.addWriteFile("interrupts.zig", interrupts_file);
    var interrupt_file_step_install = Autogenerator.InstallInSourceStep.init(b, interrupt_file_step.getFileSource("interrupts.zig").?, "src/kernel/arch/x86_64/interrupts.zig");
    interrupt_file_step_install.step.dependOn(&interrupt_file_step.step);
    const kernel = stivale2_kernel(b, .x86_64);
    kernel.step.dependOn(&interrupt_file_step_install.step);
    const image_step = LimineImage.create(b, kernel);

    const uefi_step = run_qemu_with_x86_uefi_image(b);
    uefi_step.step.dependOn(image_step);

    const bios_step = run_qemu_with_x86_bios_image(b);
    bios_step.step.dependOn(image_step);

    const run_step = b.step("run", "Run step. Default is BIOS");
    run_step.dependOn(&bios_step.step);

    const debug_step = b.step("debug", "Debug step. Launch QEMU and GF (GDB frontend)");
    const debug_custom = Debug.create(b);
    debug_custom.step.dependOn(image_step);
    debug_step.dependOn(&debug_custom.step);
}

pub fn build(b: *Builder) void
{
    build_x86(b);

    // Just boots your kernel using sabaton, without a filesystem.
    //_ = run_qemu_with_sabaton(b, stivale2_kernel(b, .aarch64));
}
