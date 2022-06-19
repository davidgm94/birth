const std = @import("std");
const builtin = @import("builtin");
const log = std.log;
const assert = std.debug.assert;

const fs = @import("src/build/fs.zig");
const Builder = std.build.Builder;
const LibExeObjStep = std.build.LibExeObjStep;
const Step = std.build.Step;
const RunStep = std.build.RunStep;
const FileSource = std.build.FileSource;

const building_os = builtin.target.os.tag;
const building_arch = builtin.target.cpu.arch;
const Arch = std.Target.Cpu.Arch;

const cache_dir = "zig-cache";
const kernel_name = "kernel.elf";
const kernel_path = cache_dir ++ "/" ++ kernel_name;

pub fn build(b: *Builder) void {
    const kernel = b.allocator.create(Kernel) catch unreachable;
    // zig fmt: off
    kernel.* = Kernel {
        .builder = b,
        .options = .{
            .arch = Kernel.Options.x86_64.new(.{ .bootloader = .limine, .protocol = .stivale2 }),
            .run = .{
                .disk_interface = null,// .nvme,
                .filesystem = .custom,
                .memory = .{ .amount = 4, .unit = .G, },
                .emulator = .{
                    .qemu = .{
                        .vga = .std,
                        .log = .{ .file = "logfile", .guest_errors = true, .cpu = false, .assembly = false, .interrupts = true, },
                        .run_for_debug = true,
                    },
                },
            },
        }
    };
    // zig fmt: on
    kernel.create();
}

const Kernel = struct {
    builder: *Builder,
    executable: *LibExeObjStep = undefined,
    userspace_programs: []*LibExeObjStep = &.{},
    options: Options,
    boot_image: BootImage = undefined,

    fn create(kernel: *Kernel) void {
        kernel.create_executable();
        kernel.create_disassembly_step();
        kernel.create_userspace_programs();
        kernel.create_boot_image();
        kernel.create_disk();
        kernel.create_run_and_debug_steps();
    }

    fn create_executable(kernel: *Kernel) void {
        kernel.executable = kernel.builder.addExecutable(kernel_name, "src/kernel/root.zig");
        var target = get_target_base(kernel.options.arch);

        switch (kernel.options.arch) {
            .riscv64 => {
                target.cpu_features_sub.addFeature(@enumToInt(std.Target.riscv.Feature.d));
                kernel.executable.code_model = .medium;

                const assembly_files = [_][]const u8{
                    "start.S",
                    "interrupt.S",
                };

                const arch_source_dir = kernel.builder.fmt("src/kernel/arch/{s}/", .{@tagName(kernel.options.arch)});

                for (assembly_files) |asm_file| {
                    const asm_file_path = std.mem.concat(kernel.builder.allocator, u8, &.{ arch_source_dir, asm_file }) catch unreachable;
                    kernel.executable.addAssemblyFile(asm_file_path);
                }

                const linker_path = std.mem.concat(kernel.builder.allocator, u8, &.{ arch_source_dir, "linker.ld" }) catch unreachable;
                kernel.executable.setLinkerScriptPath(FileSource.relative(linker_path));
            },
            .x86_64 => {
                kernel.executable.code_model = .kernel;
                //kernel.executable.pie = true;
                kernel.executable.force_pic = true;
                kernel.executable.disable_stack_probing = true;
                kernel.executable.strip = false;
                kernel.executable.code_model = .kernel;
                kernel.executable.red_zone = false;
                kernel.executable.omit_frame_pointer = false;
                const linker_script_path = std.mem.concat(kernel.builder.allocator, u8, &.{ BootImage.x86_64.Limine.base_path, @tagName(kernel.options.arch.x86_64.bootloader.limine.protocol), ".ld" }) catch unreachable;
                kernel.executable.setLinkerScriptPath(FileSource.relative(linker_script_path));
            },
            else => unreachable,
        }

        kernel.executable.setTarget(target);
        kernel.executable.setMainPkgPath("src");
        kernel.executable.setBuildMode(kernel.builder.standardReleaseOptions());
        kernel.executable.setOutputDir(cache_dir);
        kernel.builder.default_step.dependOn(&kernel.executable.step);
    }

    fn create_disassembly_step(kernel: *Kernel) void {
        var arg_list = std.ArrayList([]const u8).init(kernel.builder.allocator);
        const main_args = &.{ "llvm-objdump", kernel_path };
        const common_flags = &.{ "-d", "-S" };
        arg_list.appendSlice(main_args) catch unreachable;
        arg_list.appendSlice(common_flags) catch unreachable;
        switch (kernel.options.arch) {
            .x86_64 => arg_list.append("-Mintel") catch unreachable,
            else => {},
        }
        const disassembly_kernel = kernel.builder.addSystemCommand(arg_list.items);
        disassembly_kernel.step.dependOn(&kernel.executable.step);
        const disassembly_kernel_step = kernel.builder.step("disasm", "Disassembly the kernel ELF");
        disassembly_kernel_step.dependOn(&disassembly_kernel.step);
    }

    fn create_userspace_programs(kernel: *Kernel) void {
        var userspace_programs = std.ArrayList(*LibExeObjStep).init(kernel.builder.allocator);
        const userspace_program_descriptors = [_]ZigProgramDescriptor{.{
            .out_filename = "minimal.elf",
            .main_source_file = "src/user/minimal/main.zig",
        }};

        for (userspace_program_descriptors) |descriptor| {
            const program = kernel.builder.addExecutable(descriptor.out_filename, descriptor.main_source_file);
            program.setTarget(get_target_base(kernel.options.arch));
            program.setOutputDir(cache_dir);
            kernel.builder.default_step.dependOn(&program.step);

            userspace_programs.append(program) catch unreachable;
        }

        kernel.userspace_programs = userspace_programs.items;
    }

    fn create_boot_image(kernel: *Kernel) void {
        kernel.boot_image = .{ .arch = switch (kernel.options.arch) {
            .x86_64 => .{
                .x86_64 = switch (kernel.options.arch.x86_64.bootloader) {
                    .limine => BootImage.x86_64.Limine.new(kernel),
                },
            },
            else => unreachable,
        } };
    }

    fn create_disk(kernel: *Kernel) void {
        if (kernel.options.run.disk_interface) |_| {
            log.debug("TODO: disk", .{});
        }
    }

    fn create_run_and_debug_steps(kernel: *Kernel) void {
        var run_argument_list = std.ArrayList([]const u8).init(kernel.builder.allocator);
        var debug_argument_list: std.ArrayList([]const u8) = undefined;

        switch (kernel.options.run.emulator) {
            .qemu => {
                const qemu_name = std.mem.concat(kernel.builder.allocator, u8, &.{ "qemu-system-", @tagName(kernel.options.arch) }) catch unreachable;
                run_argument_list.append(qemu_name) catch unreachable;
                run_argument_list.append("-no-reboot") catch unreachable;
                run_argument_list.append("-no-shutdown") catch unreachable;

                const memory_arg = kernel.builder.fmt("{}{s}", .{ kernel.options.run.memory.amount, @tagName(kernel.options.run.memory.unit) });
                run_argument_list.append("-m") catch unreachable;
                run_argument_list.append(memory_arg) catch unreachable;

                if (kernel.options.run.emulator.qemu.vga) |vga_option| {
                    run_argument_list.append("-vga") catch unreachable;
                    run_argument_list.append(@tagName(vga_option)) catch unreachable;
                } else {
                    run_argument_list.append("-nographic") catch unreachable;
                }

                if (kernel.options.arch == .x86_64) {
                    run_argument_list.append("-debugcon") catch unreachable;
                    run_argument_list.append("stdio") catch unreachable;
                }

                switch (kernel.options.arch) {
                    .x86_64 => {
                        const image_flag = "-cdrom";
                        const image_path = Kernel.BootImage.x86_64.Limine.image_path;
                        run_argument_list.append(image_flag) catch unreachable;
                        run_argument_list.append(image_path) catch unreachable;
                    },
                    else => unreachable,
                }

                // Here the arch-specific stuff start and that's why the lists are split. For debug builds virtualization is pointless since it gives you no debug information
                run_argument_list.append("-machine") catch unreachable;
                debug_argument_list = run_argument_list.clone() catch unreachable;
                if (kernel.options.arch == building_arch and !kernel.options.run.emulator.qemu.run_for_debug) {
                    switch (kernel.options.arch) {
                        .x86_64 => run_argument_list.append("q35,accel=kvm:whpx:tcg") catch unreachable,
                        else => unreachable,
                    }
                } else {
                    switch (kernel.options.arch) {
                        .x86_64 => {
                            const machine = "q35";
                            run_argument_list.append(machine) catch unreachable;
                            debug_argument_list.append(machine) catch unreachable;
                        },
                        else => unreachable,
                    }

                    if (kernel.options.run.emulator.qemu.log) |log_options| {
                        const log_flag = "-d";
                        run_argument_list.append(log_flag) catch unreachable;
                        debug_argument_list.append(log_flag) catch unreachable;

                        var log_what = std.ArrayList(u8).init(kernel.builder.allocator);
                        if (log_options.guest_errors) log_what.appendSlice("guest_errors,") catch unreachable;
                        if (log_options.cpu) log_what.appendSlice("cpu,") catch unreachable;
                        if (log_options.interrupts) log_what.appendSlice("int,") catch unreachable;
                        if (log_options.assembly) log_what.appendSlice("in_asm,") catch unreachable;
                        // Delete the last comma
                        _ = log_what.pop();
                        run_argument_list.append(log_what.items) catch unreachable;
                        debug_argument_list.append(log_what.items) catch unreachable;

                        if (log_options.file) |log_file| {
                            const log_file_flag = "-D";
                            run_argument_list.append(log_file_flag) catch unreachable;
                            debug_argument_list.append(log_file_flag) catch unreachable;
                            run_argument_list.append(log_file) catch unreachable;
                            debug_argument_list.append(log_file) catch unreachable;
                        }
                    }
                }
            },
        }

        log.debug("run arg list:", .{});
        for (run_argument_list.items) |arg| {
            log.debug("{s}", .{arg});
        }
        log.debug("debug arg list:", .{});
        for (debug_argument_list.items) |arg| {
            log.debug("{s}", .{arg});
        }

        const run_command = kernel.builder.addSystemCommand(run_argument_list.items);
        const run_step = kernel.builder.step("run", "run step");
        run_step.dependOn(&run_command.step);

        switch (kernel.options.arch) {
            .x86_64 => {
                const boot_image_step = kernel.boot_image.get_step() orelse unreachable;
                run_command.step.dependOn(boot_image_step);
            },
            else => unreachable,
        }
    }

    const BootImage = struct {
        arch: ArchSpecific,

        fn get_step(boot_image: *BootImage) ?*Step {
            return switch (boot_image.arch) {
                .x86_64 => &boot_image.arch.x86_64.step,
                else => null,
            };
        }

        const ArchSpecific = union(Arch) {
            arm,
            armeb,
            aarch64,
            aarch64_be,
            aarch64_32,
            arc,
            avr,
            bpfel,
            bpfeb,
            csky,
            hexagon,
            m68k,
            mips,
            mipsel,
            mips64,
            mips64el,
            msp430,
            powerpc,
            powerpcle,
            powerpc64,
            powerpc64le,
            r600,
            amdgcn,
            riscv32,
            riscv64: void,
            sparc,
            sparc64,
            sparcel,
            s390x,
            tce,
            tcele,
            thumb,
            thumbeb,
            i386,
            x86_64: x86_64,
            xcore,
            nvptx,
            nvptx64,
            le32,
            le64,
            amdil,
            amdil64,
            hsail,
            hsail64,
            spir,
            spir64,
            kalimba,
            shave,
            lanai,
            wasm32,
            wasm64,
            renderscript32,
            renderscript64,
            ve,
            // Stage1 currently assumes that architectures above this comment
            // map one-to-one with the ZigLLVM_ArchType enum.
            spu_2,
            spirv32,
            spirv64,
        };

        const x86_64 = struct {
            step: Step,

            const Limine = struct {
                const installer = @import("src/kernel/arch/x86_64/limine/installer.zig");
                const base_path = "src/kernel/arch/x86_64/limine/";
                const to_install_path = base_path ++ "to_install/";
                const image_path = "zig-cache/universal.iso";

                fn new(kernel: *Kernel) x86_64 {
                    var result = x86_64{
                        .step = Step.init(.custom, "_limine_image_", kernel.builder.allocator, Limine.build),
                    };
                    result.step.dependOn(&kernel.executable.step);
                    return result;
                }

                fn build(step: *Step) !void {
                    const kernel = @fieldParentPtr(Kernel, "boot_image", @fieldParentPtr(BootImage, "arch", @ptrCast(*ArchSpecific, @fieldParentPtr(x86_64, "step", step))));
                    assert(kernel.options.arch == .x86_64);
                    const img_dir_path = kernel.builder.fmt("{s}/img_dir", .{kernel.builder.cache_root});
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

                    var xorriso_process = std.ChildProcess.init(&.{ "xorriso", "-as", "mkisofs", "-quiet", "-b", "limine-cd.bin", "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table", "--efi-boot", limine_efi_bin_file, "-efi-boot-part", "--efi-boot-image", "--protective-msdos-label", img_dir_path, "-o", image_path }, kernel.builder.allocator);
                    // Ignore stderr and stdout
                    xorriso_process.stdin_behavior = std.ChildProcess.StdIo.Ignore;
                    xorriso_process.stdout_behavior = std.ChildProcess.StdIo.Ignore;
                    xorriso_process.stderr_behavior = std.ChildProcess.StdIo.Ignore;
                    _ = try xorriso_process.spawnAndWait();

                    try Limine.installer.install(image_path, false, null);
                }
            };
        };
    };

    const Disk = struct {
        const block_size = 0x400;
        const block_count = 32;
        var buffer: [block_size * block_count]u8 align(0x1000) = undefined;
        const path = "zig-cache/disk.bin";

        step: Step,

        fn create(kernel: *Kernel) *Disk {
            const disk = kernel.builder.allocator.create(Disk) catch @panic("out of memory\n");
            disk.* = .{
                .step = Step.init(.custom, "disk_create", kernel.builder.allocator, make),
            };

            const named_step = kernel.builder.step("disk", "Create a disk blob to use with QEMU");
            named_step.dependOn(&disk.step);

            for (kernel.userspace_programs) |program| {
                disk.step.dependOn(&program.step);
            }
            return disk;
        }

        fn make(step: *Step) !void {
            const parent = @fieldParentPtr(Disk, "step", step);
            const allocator = parent.kernel.builder.allocator;
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

    const Options = struct {
        arch: Options.ArchSpecific,
        run: RunOptions,

        const x86_64 = struct {
            bootloader: union(Bootloader) {
                limine: Limine,
            },

            const Bootloader = enum {
                limine,
            };

            fn new(context: anytype) Options.ArchSpecific {
                return switch (context.bootloader) {
                    .limine => .{
                        .x86_64 = .{
                            .bootloader = .{
                                .limine = .{
                                    .protocol = context.protocol,
                                },
                            },
                        },
                    },
                    else => unreachable,
                };
            }

            const Limine = struct {
                protocol: Protocol,

                const Protocol = enum(u32) {
                    stivale2,
                    limine,
                };
            };
        };

        const ArchSpecific = union(Arch) {
            arm,
            armeb,
            aarch64,
            aarch64_be,
            aarch64_32,
            arc,
            avr,
            bpfel,
            bpfeb,
            csky,
            hexagon,
            m68k,
            mips,
            mipsel,
            mips64,
            mips64el,
            msp430,
            powerpc,
            powerpcle,
            powerpc64,
            powerpc64le,
            r600,
            amdgcn,
            riscv32,
            riscv64: void,
            sparc,
            sparc64,
            sparcel,
            s390x,
            tce,
            tcele,
            thumb,
            thumbeb,
            i386,
            x86_64: x86_64,
            xcore,
            nvptx,
            nvptx64,
            le32,
            le64,
            amdil,
            amdil64,
            hsail,
            hsail64,
            spir,
            spir64,
            kalimba,
            shave,
            lanai,
            wasm32,
            wasm64,
            renderscript32,
            renderscript64,
            ve,
            // Stage1 currently assumes that architectures above this comment
            // map one-to-one with the ZigLLVM_ArchType enum.
            spu_2,
            spirv32,
            spirv64,
        };

        const RunOptions = struct {
            disk_interface: ?DiskInterface,
            filesystem: ?Filesystem,
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

                //fn get_bytes(memory: Memory) u64 {
                //var result = memory.amount;
                //var i: u3 = 0;
                //while (i <= @enumToInt(memory.unit)) : (i += 1) {
                //result <<= 10;
                //}

                //return result;
                //}
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

            const LogOptions = struct {
                file: ?[]const u8,
                guest_errors: bool,
                cpu: bool,
                interrupts: bool,
                assembly: bool,
            };

            const DiskInterface = enum {
                virtio,
                ahci,
                nvme,
            };

            const Filesystem = enum { custom };
        };
    };
};

//const x86_bios_qemu_cmd = [_][]const u8{
//// zig fmt: off
//"qemu-system-x86_64",
//"-no-reboot", "-no-shutdown",
//"-cdrom", image_path,
//"-debugcon", "stdio",
//"-vga", "std",
//"-m", "4G",
////"-machine", "q35,accel=kvm:whpx:tcg",
//"-machine", "q35",
////"-smp", "4",
//"-d", "guest_errors,int,in_asm",
//"-D", "logfile",
//"-device", "virtio-gpu-pci",
//// zig fmt: on
//};

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

const ZigProgramDescriptor = struct {
    out_filename: []const u8,
    main_source_file: []const u8,
};

//fn get_qemu_command(arch: std.Target.Cpu.Arch) []const []const u8 {
//return switch (arch) {
//.riscv64 => &riscv_qemu_command_str,
//.x86_64 => &x86_bios_qemu_cmd,
//else => unreachable,
//};
//}

//const Debug = struct {
//step: Step,
//b: *Builder,
//arch: Arch,

//fn create(b: *Builder, arch: Arch) *Debug {
//const self = kernel.builder.allocator.create(@This()) catch @panic("out of memory\n");
//self.* = Debug{
//.step = Step.init(.custom, "_debug_", kernel.builder.allocator, make),
//.b = b,
//.arch = arch,
//};

//const named_step = kernel.builder.step("debug", "Debug the program with QEMU and GDB");
//named_step.dependOn(&self.step);
//return self;
//}

//fn make(step: *Step) !void {
//const self = @fieldParentPtr(Debug, "step", step);
//const b = self.b;
//const qemu = get_qemu_command(self.arch) ++ [_][]const u8{ "-S", "-s" };
//if (building_os == .windows) {
//unreachable;
//} else {
//const terminal_thread = try std.Thread.spawn(.{}, terminal_and_gdb_thread, .{b});
//var process = std.ChildProcess.init(qemu, kernel.builder.allocator);
//_ = try process.spawnAndWait();

//terminal_thread.join();
//_ = try process.kill();
//}
//}

//fn terminal_and_gdb_thread(b: *Builder) void {
//_ = b;
////zig fmt: off
////var kernel_elf = std.fs.realpathAlloc(kernel.builder.allocator, "zig-cache/kernel.elf") catch unreachable;
////if (builtin.os.tag == .windows) {
////const buffer = kernel.builder.allocator.create([512]u8) catch unreachable;
////var counter: u64 = 0;
////for (kernel_elf) |ch| {
////const is_separator = ch == '\\';
////buffer[counter] = ch;
////buffer[counter + @boolToInt(is_separator)] = ch;
////counter += @as(u64, 1) + @boolToInt(is_separator);
////}
////kernel_elf = buffer[0..counter];
////}
////const symbol_file = kernel.builder.fmt("symbol-file {s}", .{kernel_elf});
////const process_name = [_][]const u8{
////"wezterm", "start", "--",
////get_gdb_name(arch),
////"-tui",
////"-ex", symbol_file,
////"-ex", "target remote :1234",
////"-ex", "b start",
////"-ex", "c",
////};

////for (process_name) |arg, arg_i| {
////log.debug("Process[{}]: {s}", .{arg_i, arg});
////}
////var process = std.ChildProcess.init(&process_name, kernel.builder.allocator);
//// zig fmt: on
////_ = process.spawnAndWait() catch unreachable;
//}
//};

// zig fmt: off
//const riscv_qemu_command_str = [_][]const u8 {
    //"qemu-system-riscv64",
    //"-no-reboot", "-no-shutdown",
    //"-machine", "virt",
    //"-cpu", "rv64",
    //"-m", "4G",
    //"-bios", "default",
    //"-kernel", kernel_path,
    //"-serial", "mon:stdio",
    //"-drive", "if=none,format=raw,file=zig-cache/disk.bin,id=foo",
    //"-global", "virtio-mmio.force-legacy=false",
    //"-device", "virtio-blk-device,drive=foo",
    //"-device", "virtio-gpu-device",
    //"-d", "guest_errors,int",
    ////"-D", "logfile",

    ////"-trace", "virtio*",
    ////"-S", "-s",
//};
// zig fmt: on

