const std = @import("std");
const builtin = @import("builtin");
const log = std.log;

const fs = @import("src/build/fs.zig");
const Builder = std.build.Builder;
const LibExeObjStep = std.build.LibExeObjStep;

const building_os = builtin.target.os.tag;
const building_arch = builtin.target.cpu.arch;
const Arch = std.Target.Cpu.Arch;

const cache_dir = "zig-cache";
const kernel_name = "kernel.elf";
const kernel_path = cache_dir ++ "/" ++ kernel_name;

pub fn build(b: *Builder) void {
    create_kernel_for_arch(b, .x86_64);
}

fn create_kernel_for_arch(b: *Builder, arch: Arch) void {
    var kernel = b.addExecutable(kernel_name, "src/kernel/root.zig");
    set_target_specific_parameters_for_kernel(b, kernel, arch);
    kernel.setMainPkgPath("src");
    kernel.setBuildMode(b.standardReleaseOptions());
    kernel.setOutputDir(cache_dir);
    b.default_step.dependOn(&kernel.step);

    create_disassembly_step(b, kernel);

    //const userspace_programs = create_userspace_programs(b, arch);

    //const disk = Disk.create(b, userspace_programs);
    //create_run_and_debug_steps(b, .{
    //});

    //switch (arch) {
    //.x86_64 => {
    //const image_step = Limine.create_image_step(b, kernel);
    //qemu.step.dependOn(image_step);
    //},
    //else => {
    //unreachable;
    ////qemu.step.dependOn(&kernel.step);
    //},
    //}

    // TODO: as disk is not written, this dependency doesn't need to be executed for every time the run step is executed
    //qemu.step.dependOn(&disk.step);

    //const debug = Debug.create(b, arch);
    //debug.step.dependOn(&kernel.step);
    //debug.step.dependOn(&disk.step);
}

const x86_bios_qemu_cmd = [_][]const u8{
    // zig fmt: off
    "qemu-system-x86_64",
    "-no-reboot", "-no-shutdown",
    "-cdrom", image_path,
    "-debugcon", "stdio",
    "-vga", "std",
    "-m", "4G",
    //"-machine", "q35,accel=kvm:whpx:tcg",
    "-machine", "q35",
    //"-smp", "4",
    "-d", "guest_errors,int,in_asm",
    "-D", "logfile",
    "-device", "virtio-gpu-pci",
    // zig fmt: on
};

fn create_run_and_debug_steps(b: *Builder, options: RunOptions) void {
    var run_argument_list = std.ArrayList(u8).init(b.allocator);
    var debug_argument_list: std.ArrayList(u8) = undefined;

    switch (options.emulator) {
        .QEMU => {
            const qemu_name = std.mem.concat(b.allocator, u8, &.{"qemu-system-", @tagName(options.arch)}) catch unreachable;
            run_argument_list.append(qemu_name) catch unreachable;
            run_argument_list.append("-no-reboot") catch unreachable;
            run_argument_list.append("-no-shutdown") catch unreachable;

            const memory_arg = b.fmt("{}{s}", .{options.memory.get_bytes(), @tagName(options.unit)});
            run_argument_list.append("-m");
            run_argument_list.append(memory_arg);

            if (options.emulator.qemu.vga) |vga_option| {
                run_argument_list.append("-vga");
                run_argument_list.append(@tagName(vga_option));
            } else {
                run_argument_list.append("-nographic");
            }

            if (options.arch == .x86_64) {
                run_argument_list.append("-debugcon");
                run_argument_list.append("stdio");
            }

            debug_argument_list = run_argument_list.clone();
            if (options.arch == building_arch and !options.emulator.qemu.run_for_debug) {

            } else {
            }
        },
    }
}

const RunOptions = struct {
    arch: Arch,
    disk_interface: DiskInterface,
    filesystem: Filesystem,
    memory: Memory,
    emulator: union(enum) {
        qemu: QEMU,
    },

    const Memory = struct {
        amount: u64,
        unit: Unit,

        const Unit = enum(u3) {
            K = 1,
            M = 2,
            G = 3,
            T = 4,
        };

        fn get_bytes(memory: Memory) u64 {
            var result = memory.amount;
            var i: u3 = 0;
            while (i <= memory.unit) : (i += 1) {
                result <<= 10;
            }

            return result;
        }
    };

const QEMU = struct {
    vga: ?VGA,
    log: ?LogOptions,
    run_for_debug: bool,
const VGA = enum {
    std,
    virtio,
};
};

const LogOptions = packed struct {
    file: ?[]const u8,
    guest_errors: bool,
    cpu: bool,
    interrupts: bool,
    assembly: bool,
};
};


const DiskInterface = enum {
    virtio,
    ahci,
    nvme,
};

const Filesystem = enum {
    custom
};

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

fn get_target_base(arch: Arch) std.zig.CrossTarget {
    const cpu_features = switch (arch) {
        .riscv64 => get_riscv_base_features(),
        .x86_64 => get_x86_base_features(),
        else => unreachable,
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

fn set_target_specific_parameters_for_kernel(b: *Builder, kernel_exe: *std.build.LibExeObjStep, arch: Arch) void {
    var target = get_target_base(arch);

    switch (arch) {
        .riscv64 => {
            target.cpu_features_sub.addFeature(@enumToInt(std.Target.riscv.Feature.d));
            kernel_exe.code_model = .medium;

            const asssembly_files = [_][]const u8{
                "start.S",
                "interrupt.S",
            };

            const arch_source_dir = b.fmt("src/kernel/arch/{s}/", .{@tagName(arch)});

            for (asssembly_files) |asm_file| {
                const asm_file_path = std.mem.concat(b.allocator, u8, &.{ arch_source_dir, asm_file }) catch unreachable;
                kernel_exe.addAssemblyFile(asm_file_path);
            }

            const linker_path = std.mem.concat(b.allocator, u8, &.{ arch_source_dir, "linker.ld" }) catch unreachable;
            kernel_exe.setLinkerScriptPath(std.build.FileSource.relative(linker_path));
        },
        .x86_64 => {
            kernel_exe.code_model = .kernel;
            //kernel_exe.pie = true;
            kernel_exe.force_pic = true;
            kernel_exe.disable_stack_probing = true;
            kernel_exe.strip = false;
            kernel_exe.code_model = .kernel;
            kernel_exe.red_zone = false;
            kernel_exe.omit_frame_pointer = false;
            const linker_script_file = @tagName(Limine.protocol) ++ ".ld";
            const linker_script_path = Limine.base_path ++ linker_script_file;
            kernel_exe.setLinkerScriptPath(std.build.FileSource.relative(linker_script_path));
        },
        else => unreachable,
    }

    kernel_exe.setTarget(target);
}

fn create_disassembly_step(b: *Builder, kernel: *LibExeObjStep) void {
    var arg_list = std.ArrayList([]const u8).init(b.allocator);
    const main_args = &.{ "llvm-objdump", kernel_path };
    const common_flags = &.{ "-d", "-S" };
    arg_list.appendSlice(main_args) catch unreachable;
    arg_list.appendSlice(common_flags) catch unreachable;
    switch (kernel.target.getCpu().arch) {
        .x86_64 => arg_list.append("-Mintel") catch unreachable,
        else => {},
    }
    const disassembly_kernel = b.addSystemCommand(arg_list.items);
    disassembly_kernel.step.dependOn(&kernel.step);
    const disassembly_kernel_step = b.step("disasm", "Disassembly the kernel ELF");
    disassembly_kernel_step.dependOn(&disassembly_kernel.step);
}

const ZigProgramDescriptor = struct {
    out_filename: []const u8,
    main_source_file: []const u8,
};

fn create_userspace_programs(b: *Builder, arch: Arch) []*LibExeObjStep {
    var userspace_programs = std.ArrayList(*LibExeObjStep).init(b.allocator);
    const userspace_program_descriptors = [_]ZigProgramDescriptor{.{
        .out_filename = "minimal.elf",
        .main_source_file = "src/user/minimal/main.zig",
    }};

    for (userspace_program_descriptors) |descriptor| {
        const program = user_program_from_zig_descriptor(b, descriptor, arch);
        userspace_programs.append(program) catch unreachable;
    }

    return userspace_programs.items;
}

fn user_program_from_zig_descriptor(b: *Builder, zig_descriptor: ZigProgramDescriptor, arch: Arch) *LibExeObjStep {
    const program = b.addExecutable(zig_descriptor.out_filename, zig_descriptor.main_source_file);
    program.setTarget(get_target_base(arch));
    program.setOutputDir(cache_dir);
    b.default_step.dependOn(&program.step);

    return program;
}

const Disk = struct {
    const block_size = 0x400;
    const block_count = 32;
    var buffer: [block_size * block_count]u8 align(0x1000) = undefined;
    const path = "zig-cache/disk.bin";

    step: std.build.Step,
    b: *std.build.Builder,

    fn create(b: *Builder, userspace_programs: []*LibExeObjStep) *Disk {
        const disk = b.allocator.create(Disk) catch @panic("out of memory\n");
        disk.* = .{
            .step = std.build.Step.init(.custom, "disk_create", b.allocator, make),
            .b = b,
        };

        const named_step = b.step("disk", "Create a disk blob to use with QEMU");
        named_step.dependOn(&disk.step);

        for (userspace_programs) |program| {
            disk.step.dependOn(&program.step);
        }
        return disk;
    }

    fn make(step: *std.build.Step) !void {
        const parent = @fieldParentPtr(Disk, "step", step);
        const allocator = parent.b.allocator;
        const font_file = try std.fs.cwd().readFileAlloc(allocator, "resources/zap-light16.psf", std.math.maxInt(usize));
        std.debug.print("Font file size: {} bytes\n", .{font_file.len});
        var disk = fs.MemoryDisk{
            .bytes = buffer[0..],
        };
        fs.add_file(disk, "font.psf", font_file);
        fs.read_debug(disk);
        //std.mem.copy(u8, &buffer, font_file);

        try std.fs.cwd().writeFile(Disk.path, &Disk.buffer);
    }
};

fn qemu_command(b: *Builder, arch: Arch) *std.build.RunStep {
    const run_step = b.addSystemCommand(get_qemu_command(arch));
    const step = b.step("run", "run step");
    step.dependOn(&run_step.step);
    return run_step;
}

fn get_qemu_command(arch: std.Target.Cpu.Arch) []const []const u8 {
    return switch (arch) {
        .riscv64 => &riscv_qemu_command_str,
        .x86_64 => &x86_bios_qemu_cmd,
        else => unreachable,
    };
}


const Debug = struct {
    step: std.build.Step,
    b: *std.build.Builder,
    arch: Arch,

    fn create(b: *std.build.Builder, arch: Arch) *Debug {
        const self = b.allocator.create(@This()) catch @panic("out of memory\n");
        self.* = Debug{
            .step = std.build.Step.init(.custom, "_debug_", b.allocator, make),
            .b = b,
            .arch = arch,
        };

        const named_step = b.step("debug", "Debug the program with QEMU and GDB");
        named_step.dependOn(&self.step);
        return self;
    }

    fn make(step: *std.build.Step) !void {
        const self = @fieldParentPtr(Debug, "step", step);
        const b = self.b;
        const qemu = get_qemu_command(self.arch) ++ [_][]const u8{ "-S", "-s" };
        if (building_os == .windows) {
            unreachable;
        } else {
            const terminal_thread = try std.Thread.spawn(.{}, terminal_and_gdb_thread, .{b});
            var process = std.ChildProcess.init(qemu, b.allocator);
            _ = try process.spawnAndWait();

            terminal_thread.join();
            _ = try process.kill();
        }
    }

    fn terminal_and_gdb_thread(b: *std.build.Builder) void {
        _ = b;
        //zig fmt: off
        //var kernel_elf = std.fs.realpathAlloc(b.allocator, "zig-cache/kernel.elf") catch unreachable;
        //if (builtin.os.tag == .windows) {
            //const buffer = b.allocator.create([512]u8) catch unreachable;
            //var counter: u64 = 0;
            //for (kernel_elf) |ch| {
                //const is_separator = ch == '\\';
                //buffer[counter] = ch;
                //buffer[counter + @boolToInt(is_separator)] = ch;
                //counter += @as(u64, 1) + @boolToInt(is_separator);
            //}
            //kernel_elf = buffer[0..counter];
        //}
        //const symbol_file = b.fmt("symbol-file {s}", .{kernel_elf});
        //const process_name = [_][]const u8{
            //"wezterm", "start", "--",
            //get_gdb_name(arch),
            //"-tui",
            //"-ex", symbol_file,
            //"-ex", "target remote :1234",
            //"-ex", "b start",
            //"-ex", "c",
        //};

        //for (process_name) |arg, arg_i| {
            //log.debug("Process[{}]: {s}", .{arg_i, arg});
        //}
        //var process = std.ChildProcess.init(&process_name, b.allocator);
        // zig fmt: on
        //_ = process.spawnAndWait() catch unreachable;
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
    "-drive", "if=none,format=raw,file=zig-cache/disk.bin,id=foo",
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

const Limine = struct {
    step: std.build.Step,
    b: *Builder,

    const Protocol = enum(u32) {
        stivale2,
        limine,
    };
    const installer = @import("src/kernel/arch/x86_64/limine/installer.zig");

    const protocol = Protocol.stivale2;
    const base_path = "src/kernel/arch/x86_64/limine/";
    const to_install_path = base_path ++ "to_install/";

    fn build(step: *std.build.Step) !void {
        const self = @fieldParentPtr(@This(), "step", step);
        const img_dir_path = self.b.fmt("{s}/img_dir", .{self.b.cache_root});
        const cwd = std.fs.cwd();
        cwd.deleteFile(image_path) catch {};
        const img_dir = try cwd.makeOpenPath(img_dir_path, .{});
        const img_efi_dir = try img_dir.makeOpenPath("EFI/BOOT", .{});
        const limine_dir = try cwd.openDir(to_install_path, .{});

        const limine_efi_bin_file = "limine-cd-efi.bin";
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

        var xorriso_process = std.ChildProcess.init(&.{ "xorriso", "-as", "mkisofs", "-quiet", "-b", "limine-cd.bin", "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table", "--efi-boot", limine_efi_bin_file, "-efi-boot-part", "--efi-boot-image", "--protective-msdos-label", img_dir_path, "-o", image_path }, self.b.allocator);
        // Ignore stderr and stdout
        xorriso_process.stdin_behavior = std.ChildProcess.StdIo.Ignore;
        xorriso_process.stdout_behavior = std.ChildProcess.StdIo.Ignore;
        xorriso_process.stderr_behavior = std.ChildProcess.StdIo.Ignore;
        _ = try xorriso_process.spawnAndWait();

        try Limine.installer.install(image_path, false, null);
    }

    fn create_image_step(b: *Builder, kernel: *std.build.LibExeObjStep) *std.build.Step {
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

fn get_gdb_name(comptime arch: std.Target.Cpu.Arch) []const u8 {
    return switch (arch) {
        .riscv64 => "riscv64-elf-gdb",
        .x86_64 => blk: {
            switch (building_os) {
                .windows => break :blk "C:\\Users\\David\\programs\\gdb\\bin\\gdb",
                .macos => break :blk "x86_64-elf-gdb",
                else => break :blk "gdb",
            }
        },
        else => @compileError("CPU architecture not supported"),
    };
}
