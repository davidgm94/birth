const std = @import("std");
const builtin = @import("builtin");
const log = std.log;

const fs = @import("src/build/fs.zig");
const Builder = std.build.Builder;

const building_os = builtin.target.os.tag;
const current_arch = std.Target.Cpu.Arch.x86_64;

const cache_dir = "zig-cache";
const kernel_name = "kernel.elf";
const kernel_path = cache_dir ++ "/" ++ kernel_name;
const arch_source_dir = "src/kernel/arch/" ++ @tagName(current_arch) ++ "/";

const CPUFeatures = struct {
    enabled: std.Target.Cpu.Feature.Set,
    disabled: std.Target.Cpu.Feature.Set,
};

fn get_riscv_base_features() CPUFeatures {
    var features = CPUFeatures{
        .enabled = std.Target.Cpu.Feature.Set.empty,
        .disabled = std.Target.Cpu.Feature.Set.empty,
    };
    const Feature = std.Target.riscv.Feature;
    features.enabled.addFeature(@enumToInt(Feature.a));

    return features;
}

fn get_x86_base_features() CPUFeatures {
    var features = CPUFeatures{
        .enabled = std.Target.Cpu.Feature.Set.empty,
        .disabled = std.Target.Cpu.Feature.Set.empty,
    };

    const Feature = std.Target.x86.Feature;
    features.disabled.addFeature(@enumToInt(Feature.mmx));
    features.disabled.addFeature(@enumToInt(Feature.sse));
    features.disabled.addFeature(@enumToInt(Feature.sse2));
    features.disabled.addFeature(@enumToInt(Feature.avx));
    features.disabled.addFeature(@enumToInt(Feature.avx2));

    features.enabled.addFeature(@enumToInt(Feature.soft_float));

    return features;
}

fn get_target_base(arch: std.Target.Cpu.Arch) std.zig.CrossTarget {
    const cpu_features = switch (current_arch) {
        .riscv64 => blk: {
            break :blk get_riscv_base_features();
        },
        .x86_64 => blk: {
            break :blk get_x86_base_features();
        },
        else => @compileError("CPU architecture notFeatureed\n"),
    };
    const target = std.zig.CrossTarget{
        .cpu_arch = arch,
        .os_tag = .freestanding,
        .abi = .none,
        .cpu_features_add = cpu_features.enabled,
        .cpu_features_sub = cpu_features.disabled,
    };

    return target;
}

fn set_target_specific_parameters_for_kernel(kernel_exe: *std.build.LibExeObjStep) void {
    var target = get_target_base(current_arch);

    var linker_path = arch_source_dir ++ "linker.ld";

    switch (current_arch) {
        .riscv64 => {
            target.cpu_features_sub.addFeature(@enumToInt(std.Target.riscv.Feature.d));
            kernel_exe.code_model = .medium;

            const asssembly_files = [_][]const u8{
                arch_source_dir ++ "start.S",
                arch_source_dir ++ "interrupt.S",
            };

            for (asssembly_files) |asm_file| {
                kernel_exe.addAssemblyFile(asm_file);
            }
        },
        .x86_64 => {
            kernel_exe.code_model = .kernel;
            //kernel_exe.pie = true;
            //kernel_exe.force_pic = true;
            kernel_exe.disable_stack_probing = true;
            kernel_exe.strip = false;
            kernel_exe.code_model = .kernel;
            kernel_exe.red_zone = false;
            kernel_exe.omit_frame_pointer = false;
            if (LimineImage.version == 3) {
                linker_path = arch_source_dir ++ "linker_limine3.ld";
            }
        },
        else => @compileError("CPU architecture not supported"),
    }
    kernel_exe.setTarget(target);
    kernel_exe.entry_symbol_name = "_start";
    kernel_exe.setLinkerScriptPath(std.build.FileSource.relative(linker_path));
}

pub fn build(b: *Builder) void {
    var kernel = b.addExecutable(kernel_name, "src/kernel/root.zig");
    set_target_specific_parameters_for_kernel(kernel);
    kernel.setMainPkgPath("src");
    kernel.setBuildMode(b.standardReleaseOptions());
    kernel.setOutputDir(cache_dir);
    b.default_step.dependOn(&kernel.step);

    const minimal = b.addExecutable("minimal.elf", "src/user/minimal/main.zig");
    minimal.setTarget(get_target_base(current_arch));
    minimal.setOutputDir(cache_dir);
    b.default_step.dependOn(&minimal.step);

    const disk = HDD.create(b);
    disk.step.dependOn(&minimal.step);
    const qemu = qemu_command(b);
    switch (current_arch) {
        .x86_64 => {
            const image_step = LimineImage.create(b, kernel);
            qemu.step.dependOn(image_step);
        },
        else => {
            qemu.step.dependOn(&kernel.step);
        },
    }
    // TODO: as disk is not written, this dependency doesn't need to be executed for every time the run step is executed
    //qemu.step.dependOn(&disk.step);

    const debug = Debug.create(b);
    debug.step.dependOn(&kernel.step);
    debug.step.dependOn(&disk.step);
}

const HDD = struct {
    const block_size = 0x400;
    const block_count = 32;
    var buffer: [block_size * block_count]u8 align(0x1000) = undefined;
    const path = "zig-cache/hdd.bin";

    step: std.build.Step,
    b: *std.build.Builder,

    fn create(b: *Builder) *HDD {
        const self = b.allocator.create(HDD) catch @panic("out of memory\n");
        self.* = .{
            .step = std.build.Step.init(.custom, "hdd_create", b.allocator, make),
            .b = b,
        };

        const named_step = b.step("disk", "Create a disk blob to use with QEMU");
        named_step.dependOn(&self.step);
        return self;
    }

    fn make(step: *std.build.Step) !void {
        const parent = @fieldParentPtr(HDD, "step", step);
        const allocator = parent.b.allocator;
        const font_file = try std.fs.cwd().readFileAlloc(allocator, "resources/zap-light16.psf", std.math.maxInt(usize));
        std.debug.print("Font file size: {} bytes\n", .{font_file.len});
        var disk = fs.MemoryDisk{
            .bytes = buffer[0..],
        };
        fs.add_file(disk, "font.psf", font_file);
        fs.read(disk);
        //std.mem.copy(u8, &buffer, font_file);

        try std.fs.cwd().writeFile(HDD.path, &HDD.buffer);
    }
};

fn qemu_command(b: *Builder) *std.build.RunStep {
    const run_step = b.addSystemCommand(get_qemu_command(current_arch));
    const step = b.step("run", "run step");
    step.dependOn(&run_step.step);
    return run_step;
}

fn get_qemu_command(arch: std.Target.Cpu.Arch) []const []const u8 {
    log.debug("Arch: {}", .{arch});
    return switch (arch) {
        .riscv64 => &riscv_qemu_command_str,
        .x86_64 => &x86_bios_qemu_cmd,
        else => unreachable,
    };
}

const x86_bios_qemu_cmd = [_][]const u8{
    // zig fmt: off
    "qemu-system-x86_64",
    "-cdrom", image_path,
    "-debugcon", "stdio",
    "-vga", "std",
    "-m", "4G",
    "-machine", "q35",
    "-S", "-s",
    // zig fmt: on
};

const Debug = struct {
    step: std.build.Step,
    b: *std.build.Builder,

    fn create(b: *std.build.Builder) *Debug {
        const self = b.allocator.create(@This()) catch @panic("out of memory\n");
        self.* = Debug{
            .step = std.build.Step.init(.custom, "_debug_", b.allocator, make),
            .b = b,
        };

        const named_step = b.step("debug", "Debug the program with QEMU and GDB");
        named_step.dependOn(&self.step);
        return self;
    }

    fn make(step: *std.build.Step) !void {
        const self = @fieldParentPtr(Debug, "step", step);
        const b = self.b;
        const terminal_thread = try std.Thread.spawn(.{}, terminal_and_gdb_thread, .{b});
        const process = std.ChildProcess.init(&riscv_qemu_command_str ++ [_][]const u8{ "-S", "-s" }, b.allocator) catch unreachable;
        _ = process.spawnAndWait() catch unreachable;

        terminal_thread.join();
    }

    fn terminal_and_gdb_thread(b: *std.build.Builder) void {
        switch (building_os) {
            .linux, .macos => {
                // zig fmt: off
                const process = std.ChildProcess.init(&.{
                    "kitty", "--start-as=maximized",
                    "riscv64-elf-gdb",
                    "-tui",
                    "-ex", "symbol-file zig-cache/kernel.elf",
                    "-ex", "target remote :1234",
                    "-ex", "b riscv_start",
                    "-ex", "b kernel.panic.panic",
                    "-ex", "c",
                }, b.allocator) catch unreachable;
                // zig fmt: on
                _ = process.spawnAndWait() catch unreachable;
            },
            else => unreachable,
        }
    }

    fn get_terminal_name() []const []const u8 {
        if (builtin.target.os.tag == .linux) {
            return "kitty";
        } else unreachable;
    }
};

// zig fmt: off
const riscv_qemu_command_str = [_][]const u8 {
    "qemu-system-riscv64",
    "-no-reboot", "-no-shutdown",
    "-machine", "virt",
    "-cpu", "rv64",
    "-m", "4G",
    "-bios", "default",
    "-kernel", kernel_path,
    "-serial", "mon:stdio",
    "-drive", "if=none,format=raw,file=zig-cache/hdd.bin,id=foo",
    "-global", "virtio-mmio.force-legacy=false",
    "-device", "virtio-blk-device,drive=foo",
    "-device", "virtio-gpu-device",
    "-d", "guest_errors,int",
    //"-D", "logfile",

    //"-trace", "virtio*",
    //"-S", "-s",
};
// zig fmt: on

const image_path = "zig-cache/universal.iso";
const limine_installer = @import("src/kernel/arch/x86_64/limine3/installer.zig");

const LimineImage = struct {
    step: std.build.Step,
    b: *Builder,

    const version = 2;

    fn build(step: *std.build.Step) !void {
        const self = @fieldParentPtr(@This(), "step", step);
        const img_dir_path = self.b.fmt("{s}/img_dir", .{self.b.cache_root});
        const cwd = std.fs.cwd();
        cwd.deleteFile(image_path) catch {};
        const img_dir = try cwd.makeOpenPath(img_dir_path, .{});
        const img_efi_dir = try img_dir.makeOpenPath("EFI/BOOT", .{});
        const limine_dir_path = switch (version) {
            2 => "src/kernel/arch/x86_64/limine",
            3 => "src/kernel/arch/x86_64/limine3",
            else => unreachable,
        };
        const limine_dir = try cwd.openDir(limine_dir_path, .{});

        const limine_efi_bin_file = switch (version) {
            2 => "limine-eltorito-efi.bin",
            3 => "limine-cd-efi.bin",
            else => unreachable,
        };

        const files_to_copy_from_limine_dir = [_][]const u8{
            "limine.cfg",
            "limine.sys",
            "limine-cd.bin",
            limine_efi_bin_file,
        };

        for (files_to_copy_from_limine_dir) |filename| {
            log.debug("Trying to copy {s}", .{filename});
            try std.fs.Dir.copyFile(limine_dir, filename, img_dir, filename, .{});
        }
        try std.fs.Dir.copyFile(limine_dir, "BOOTX64.EFI", img_efi_dir, "BOOTX64.EFI", .{});
        try std.fs.Dir.copyFile(cwd, kernel_path, img_dir, std.fs.path.basename(kernel_path), .{});

        const xorriso_process = try std.ChildProcess.init(&.{ "xorriso", "-as", "mkisofs", "-quiet", "-b", "limine-cd.bin", "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table", "--efi-boot", limine_efi_bin_file, "-efi-boot-part", "--efi-boot-image", "--protective-msdos-label", img_dir_path, "-o", image_path }, self.b.allocator);
        // Ignore stderr and stdout
        xorriso_process.stdin_behavior = std.ChildProcess.StdIo.Ignore;
        xorriso_process.stdout_behavior = std.ChildProcess.StdIo.Ignore;
        xorriso_process.stderr_behavior = std.ChildProcess.StdIo.Ignore;
        _ = try xorriso_process.spawnAndWait();

        try limine_installer.install(image_path, false, null);
    }

    fn create(b: *Builder, kernel: *std.build.LibExeObjStep) *std.build.Step {
        var self = b.allocator.create(@This()) catch @panic("out of memory");

        self.* = @This(){
            .step = std.build.Step.init(.custom, "_limine_image_", b.allocator, @This().build),
            .b = b,
        };

        self.step.dependOn(&kernel.step);

        const image_step = b.step("x86_64-universal-image", "Build the x86_64 universal (bios and uefi) image");
        image_step.dependOn(&self.step);

        return image_step;
    }
};
