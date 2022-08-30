const std = @import("src/common/std.zig");
const Build = @import("src/build/lib.zig");
const drivers = @import("src/drivers/common.zig");
const DiskDriverType = drivers.DiskDriverType;
const FilesystemDriverType = drivers.FilesystemDriverType;
const WriteOnlyRNUFS = @import("src/drivers/rnufs/write_only.zig");

const Arch = Build.Arch;

pub const sector_size = 0x200;

const cache_dir = "zig-cache";
const kernel_name = "kernel.elf";
const kernel_path = cache_dir ++ "/" ++ kernel_name;

pub fn build(b: *Build.Builder) void {
    std.test_comptime_hack();
    const kernel = b.allocator.create(Kernel) catch unreachable;
    // zig fmt: off
    kernel.* = Kernel {
        .builder = b,
        .options = .{
            .arch = Kernel.Options.x86_64.new(.{ .bootloader = .limine, .protocol = .stivale2 }),
            .run = .{
                .disks = &.{
                    .{ .interface = .ahci, .filesystem = .RNU, .userspace_programs = &.{ "minimal" }, .resource_files = &.{ "zap-light16.psf", "FiraSans-Regular.otf", } },
                },
                .memory = .{ .amount = 4, .unit = .G, },
                .emulator = .{
                    .qemu = .{
                        .vga = .std,
                        .smp = null,
                        .log = .{ .file = "logfile", .guest_errors = true, .cpu = false, .assembly = false, .interrupts = true, },
                        .run_for_debug = true,
                        .print_command = false,
                    },
                },
            },
        }
    };
    // zig fmt: on
    kernel.create();
}

const Kernel = struct {
    builder: *Build.Builder,
    executable: *Build.LibExeObjStep = undefined,
    userspace_programs: []*Build.LibExeObjStep = &.{},
    options: Options,
    boot_image_step: Build.Step = undefined,
    disk_count: u64 = 0,
    disk_step: Build.Step = undefined,
    debug_step: Build.Step = undefined,
    run_argument_list: Build.ArrayList([]const u8) = undefined,
    debug_argument_list: Build.ArrayList([]const u8) = undefined,
    gdb_script: *Build.WriteFileStep = undefined,

    fn create(kernel: *Kernel) void {
        kernel.create_executable();
        kernel.create_disassembly_step();
        kernel.create_userspace_programs();
        kernel.create_boot_image();
        kernel.create_disk();
        kernel.create_run_and_debug_steps();
    }

    fn create_executable(kernel: *Kernel) void {
        var target = get_target(kernel.options.arch, false);

        switch (kernel.options.arch) {
            .x86_64 => {
                const limine_entry_point = Build.concatenate(kernel.builder.allocator, u8, &.{ BootImage.x86_64.Limine.base_path, @tagName(kernel.options.arch.x86_64.bootloader.limine.protocol), ".zig" }) catch unreachable;
                const linker_script_path = Build.concatenate(kernel.builder.allocator, u8, &.{ BootImage.x86_64.Limine.base_path, @tagName(kernel.options.arch.x86_64.bootloader.limine.protocol), ".ld" }) catch unreachable;
                kernel.executable = kernel.builder.addExecutable(kernel_name, limine_entry_point);
                kernel.executable.code_model = .kernel;
                //kernel.executable.pie = true;
                kernel.executable.force_pic = true;
                kernel.executable.disable_stack_probing = true;
                kernel.executable.strip = false;
                kernel.executable.code_model = .kernel;
                kernel.executable.red_zone = false;
                kernel.executable.omit_frame_pointer = false;
                kernel.executable.entry_symbol_name = "kernel_entry_point";
                kernel.executable.setLinkerScriptPath(Build.FileSource.relative(linker_script_path));
            },
            else => unreachable,
        }

        kernel.executable.setMainPkgPath("src");
        kernel.executable.setTarget(target);
        kernel.executable.setBuildMode(kernel.builder.standardReleaseOptions());
        kernel.executable.setOutputDir(cache_dir);
        kernel.executable.emit_llvm_ir = .{ .emit_to = "zig-cache/kernel_llvm.ir" };

        kernel.executable.addCSourceFile("./src/dependencies/stb_truetype/stb_truetype.c", &.{});

        kernel.builder.default_step.dependOn(&kernel.executable.step);
    }

    fn create_disassembly_step(kernel: *Kernel) void {
        var arg_list = Build.ArrayList([]const u8).init(kernel.builder.allocator);
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
        const linker_script_path = kernel.builder.fmt("src/user/arch/{s}/linker.ld", .{@tagName(kernel.options.arch)});

        var unique_programs = Build.ArrayList([]const u8).init(kernel.builder.allocator);
        {
            for (kernel.options.run.disks) |disk| {
                next_program: for (disk.userspace_programs) |program| {
                    for (unique_programs.items) |unique_program| {
                        if (Build.memory_equal(u8, unique_program, program)) continue :next_program;
                    }

                    unique_programs.append(program) catch unreachable;
                }
            }
        }
        var userspace_programs = Build.ArrayList(*Build.LibExeObjStep).initCapacity(kernel.builder.allocator, unique_programs.items.len) catch unreachable;

        for (unique_programs.items) |userspace_program_name| {
            const out_filename = kernel.builder.fmt("{s}.elf", .{userspace_program_name});
            const main_source_file = kernel.builder.fmt("src/user/programs/{s}/main.zig", .{userspace_program_name});
            const program = kernel.builder.addExecutable(out_filename, main_source_file);
            program.setMainPkgPath("src");
            program.setTarget(get_target(kernel.options.arch, true));
            program.setOutputDir(cache_dir);
            program.setBuildMode(kernel.builder.standardReleaseOptions());
            //program.setBuildMode(.ReleaseSafe);
            program.setLinkerScriptPath(Build.FileSource.relative(linker_script_path));
            program.entry_symbol_name = "user_entry_point";

            kernel.builder.default_step.dependOn(&program.step);

            userspace_programs.appendAssumeCapacity(program);
        }

        kernel.userspace_programs = userspace_programs.items;
    }

    fn create_boot_image(kernel: *Kernel) void {
        kernel.boot_image_step = switch (kernel.options.arch) {
            .x86_64 => switch (kernel.options.arch.x86_64.bootloader) {
                .limine => BootImage.x86_64.Limine.new(kernel),
            },
            else => unreachable,
        };
    }

    fn create_disk(kernel: *Kernel) void {
        Disk.create(kernel);
    }

    fn create_run_and_debug_steps(kernel: *Kernel) void {
        kernel.run_argument_list = Build.ArrayList([]const u8).init(kernel.builder.allocator);
        switch (kernel.options.run.emulator) {
            .qemu => {
                const qemu_name = Build.concatenate(kernel.builder.allocator, u8, &.{ "qemu-system-", @tagName(kernel.options.arch) }) catch unreachable;
                kernel.run_argument_list.append(qemu_name) catch unreachable;

                kernel.run_argument_list.append("-trace") catch unreachable;
                kernel.run_argument_list.append("-nvme*") catch unreachable;
                kernel.run_argument_list.append("-trace") catch unreachable;
                kernel.run_argument_list.append("-pci*") catch unreachable;
                kernel.run_argument_list.append("-trace") catch unreachable;
                kernel.run_argument_list.append("-ide*") catch unreachable;
                kernel.run_argument_list.append("-trace") catch unreachable;
                kernel.run_argument_list.append("-ata*") catch unreachable;
                kernel.run_argument_list.append("-trace") catch unreachable;
                kernel.run_argument_list.append("-ahci*") catch unreachable;
                kernel.run_argument_list.append("-trace") catch unreachable;
                kernel.run_argument_list.append("-sata*") catch unreachable;

                switch (kernel.options.arch) {
                    .x86_64 => {
                        const image_flag = "-cdrom";
                        const image_path = switch (kernel.options.arch.x86_64.bootloader) {
                            .limine => Kernel.BootImage.x86_64.Limine.image_path,
                        };
                        kernel.run_argument_list.append(image_flag) catch unreachable;
                        kernel.run_argument_list.append(image_path) catch unreachable;
                    },
                    .riscv64 => {
                        kernel.run_argument_list.append("-bios") catch unreachable;
                        kernel.run_argument_list.append("default") catch unreachable;
                        kernel.run_argument_list.append("-kernel") catch unreachable;
                        kernel.run_argument_list.append(kernel_path) catch unreachable;
                    },
                    else => unreachable,
                }

                {
                    kernel.run_argument_list.append("-no-reboot") catch unreachable;
                    kernel.run_argument_list.append("-no-shutdown") catch unreachable;
                }

                {
                    const memory_arg = kernel.builder.fmt("{}{s}", .{ kernel.options.run.memory.amount, @tagName(kernel.options.run.memory.unit) });
                    kernel.run_argument_list.append("-m") catch unreachable;
                    kernel.run_argument_list.append(memory_arg) catch unreachable;
                }

                if (kernel.options.run.emulator.qemu.smp) |smp_count| {
                    kernel.run_argument_list.append("-smp") catch unreachable;
                    kernel.run_argument_list.append(kernel.builder.fmt("{}", .{smp_count})) catch unreachable;
                }

                if (kernel.options.run.emulator.qemu.vga) |vga_option| {
                    kernel.run_argument_list.append("-vga") catch unreachable;
                    kernel.run_argument_list.append(@tagName(vga_option)) catch unreachable;
                } else {
                    kernel.run_argument_list.append("-nographic") catch unreachable;
                }

                if (kernel.options.arch == .x86_64) {
                    kernel.run_argument_list.append("-debugcon") catch unreachable;
                    kernel.run_argument_list.append("stdio") catch unreachable;
                }

                kernel.run_argument_list.append("-global") catch unreachable;
                kernel.run_argument_list.append("virtio-mmio.force-legacy=false") catch unreachable;

                for (kernel.options.run.disks) |disk, disk_i| {
                    const disk_id = kernel.builder.fmt("disk{}", .{disk_i});
                    const disk_path = kernel.builder.fmt("zig-cache/{s}.bin", .{disk_id});

                    switch (disk.interface) {
                        .nvme => {
                            kernel.run_argument_list.append("-device") catch unreachable;
                            const device_options = kernel.builder.fmt("nvme,drive={s},serial=1234", .{disk_id});
                            kernel.run_argument_list.append(device_options) catch unreachable;
                            kernel.run_argument_list.append("-drive") catch unreachable;
                            const drive_options = kernel.builder.fmt("file={s},if=none,id={s},format=raw", .{ disk_path, disk_id });
                            kernel.run_argument_list.append(drive_options) catch unreachable;
                        },
                        .virtio => {
                            kernel.run_argument_list.append("-device") catch unreachable;
                            const device_type = switch (kernel.options.arch) {
                                .x86_64 => "pci",
                                .riscv64 => "device",
                                else => unreachable,
                            };
                            const device_options = kernel.builder.fmt("virtio-blk-{s},drive={s}", .{ device_type, disk_id });
                            kernel.run_argument_list.append(device_options) catch unreachable;
                            kernel.run_argument_list.append("-drive") catch unreachable;
                            const drive_options = kernel.builder.fmt("file={s},if=none,id={s},format=raw", .{ disk_path, disk_id });
                            kernel.run_argument_list.append(drive_options) catch unreachable;
                        },
                        .ide => {
                            kernel.run_argument_list.append("-device") catch unreachable;
                            Build.assert(kernel.options.arch == .x86_64);
                            kernel.run_argument_list.append("piix3-ide,id=ide") catch unreachable;

                            kernel.run_argument_list.append("-drive") catch unreachable;
                            kernel.run_argument_list.append(kernel.builder.fmt("id={s},file={s},format=raw,if=none", .{ disk_id, disk_path })) catch unreachable;
                            kernel.run_argument_list.append("-device") catch unreachable;
                            // ide bus port is hardcoded to avoid errors
                            kernel.run_argument_list.append(kernel.builder.fmt("ide-hd,drive={s},bus=ide.0", .{disk_id})) catch unreachable;
                        },
                        .ahci => {
                            kernel.run_argument_list.append("-device") catch unreachable;
                            kernel.run_argument_list.append("ahci,id=ahci") catch unreachable;

                            kernel.run_argument_list.append("-drive") catch unreachable;
                            kernel.run_argument_list.append(kernel.builder.fmt("id={s},file={s},format=raw,if=none", .{ disk_id, disk_path })) catch unreachable;
                            kernel.run_argument_list.append("-device") catch unreachable;
                            // ide bus port is hardcoded to avoid errors
                            kernel.run_argument_list.append(kernel.builder.fmt("ide-hd,drive={s},bus=ahci.0", .{disk_id})) catch unreachable;
                        },

                        else => unreachable,
                    }
                }

                // Here the arch-specific stuff start and that's why the lists are split. For debug builds virtualization is pointless since it gives you no debug information
                kernel.run_argument_list.append("-machine") catch unreachable;
                kernel.debug_argument_list = kernel.run_argument_list.clone() catch unreachable;
                const machine = switch (kernel.options.arch) {
                    .x86_64 => "q35",
                    .riscv64 => "virt",
                    else => unreachable,
                };
                kernel.debug_argument_list.append(machine) catch unreachable;
                if (kernel.options.arch == Build.arch and !kernel.options.run.emulator.qemu.run_for_debug) {
                    kernel.run_argument_list.append(kernel.builder.fmt("{s},accel=kvm:whpx:tcg", .{machine})) catch unreachable;
                } else {
                    kernel.run_argument_list.append(machine) catch unreachable;

                    if (kernel.options.run.emulator.qemu.log) |log_options| {
                        var log_what = Build.ArrayList(u8).init(kernel.builder.allocator);
                        if (log_options.guest_errors) log_what.appendSlice("guest_errors,") catch unreachable;
                        if (log_options.cpu) log_what.appendSlice("cpu,") catch unreachable;
                        if (log_options.interrupts) log_what.appendSlice("int,") catch unreachable;
                        if (log_options.assembly) log_what.appendSlice("in_asm,") catch unreachable;

                        if (log_what.items.len > 0) {
                            // Delete the last comma
                            _ = log_what.pop();

                            const log_flag = "-d";
                            kernel.run_argument_list.append(log_flag) catch unreachable;
                            kernel.debug_argument_list.append(log_flag) catch unreachable;
                            kernel.run_argument_list.append(log_what.items) catch unreachable;
                            kernel.debug_argument_list.append(log_what.items) catch unreachable;
                        }

                        if (log_options.file) |log_file| {
                            const log_file_flag = "-D";
                            kernel.run_argument_list.append(log_file_flag) catch unreachable;
                            kernel.debug_argument_list.append(log_file_flag) catch unreachable;
                            kernel.run_argument_list.append(log_file) catch unreachable;
                            kernel.debug_argument_list.append(log_file) catch unreachable;
                        }
                    }
                }

                Build.add_qemu_debug_isa_exit(kernel.builder, &kernel.run_argument_list, switch (kernel.options.arch) {
                    .x86_64 => Build.QEMU.x86_64_debug_exit,
                    else => unreachable,
                }) catch unreachable;

                kernel.debug_argument_list.append("-S") catch unreachable;
                kernel.debug_argument_list.append("-s") catch unreachable;
            },
        }

        if (kernel.options.run.emulator.qemu.print_command) {
            for (kernel.run_argument_list.items) |arg| {
                Build.print("{s} ", .{arg});
            }
            Build.print("\n\n", .{});
        }

        const run_command = kernel.builder.addSystemCommand(kernel.run_argument_list.items);
        run_command.step.dependOn(kernel.builder.default_step);
        run_command.step.dependOn(&kernel.disk_step);
        const run_step = kernel.builder.step("run", "run step");
        run_step.dependOn(&run_command.step);

        switch (kernel.options.arch) {
            .x86_64 => run_command.step.dependOn(&kernel.boot_image_step),
            else => unreachable,
        }

        var gdb_script_buffer = Build.ArrayList(u8).init(kernel.builder.allocator);
        switch (kernel.options.arch) {
            .x86_64 => gdb_script_buffer.appendSlice("set disassembly-flavor intel\n") catch unreachable,
            else => {},
        }
        gdb_script_buffer.appendSlice(
            \\symbol-file zig-cache/kernel.elf
            \\target remote localhost:1234
            \\b kernel_entry_point
            \\c
        ) catch unreachable;

        kernel.gdb_script = kernel.builder.addWriteFile("gdb_script", gdb_script_buffer.items);
        kernel.builder.default_step.dependOn(&kernel.gdb_script.step);

        // We need a member variable because we need consistent memory around it to do @fieldParentPtr
        kernel.debug_step = Build.Step.init(.custom, "_debug_", kernel.builder.allocator, do_debug_step);
        kernel.debug_step.dependOn(&kernel.boot_image_step);
        kernel.debug_step.dependOn(&kernel.gdb_script.step);
        kernel.debug_step.dependOn(&kernel.disk_step);

        const debug_step = kernel.builder.step("debug", "Debug the program with QEMU and GDB");
        debug_step.dependOn(&kernel.debug_step);
    }

    const BootImage = struct {
        const x86_64 = struct {
            const Limine = struct {
                const build_installer_path = "src/build/arch/x86_64/limine/";
                const installer = @import("src/build/arch/x86_64/limine/installer.zig");
                const base_path = "src/kernel/arch/x86_64/limine/";
                const to_install_path = build_installer_path ++ "to_install/";
                const image_path = "zig-cache/universal.iso";

                fn new(kernel: *Kernel) Build.Step {
                    var step = Build.Step.init(.custom, "_limine_image_", kernel.builder.allocator, Limine.build);
                    step.dependOn(&kernel.executable.step);
                    return step;
                }

                fn build(step: *Build.Step) !void {
                    const kernel = @fieldParentPtr(Kernel, "boot_image_step", step);
                    Build.assert(kernel.options.arch == .x86_64);
                    const img_dir_path = kernel.builder.fmt("{s}/img_dir", .{kernel.builder.cache_root});
                    const cwd = Build.cwd();
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
                        Build.log.debug("Trying to copy {s}", .{filename});
                        try Build.Dir.copyFile(limine_dir, filename, img_dir, filename, .{});
                    }
                    try Build.Dir.copyFile(limine_dir, "BOOTX64.EFI", img_efi_dir, "BOOTX64.EFI", .{});
                    try Build.Dir.copyFile(cwd, kernel_path, img_dir, Build.path.basename(kernel_path), .{});

                    const xorriso_executable = switch (std.os) {
                        .windows => "tools/xorriso-windows/xorriso.exe",
                        else => "xorriso",
                    };
                    var xorriso_process = Build.ChildProcess.init(&.{ xorriso_executable, "-as", "mkisofs", "-quiet", "-b", "limine-cd.bin", "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table", "--efi-boot", limine_efi_bin_file, "-efi-boot-part", "--efi-boot-image", "--protective-msdos-label", img_dir_path, "-o", image_path }, kernel.builder.allocator);
                    // Ignore stderr and stdout
                    xorriso_process.stdin_behavior = Build.ChildProcess.StdIo.Ignore;
                    xorriso_process.stdout_behavior = Build.ChildProcess.StdIo.Ignore;
                    xorriso_process.stderr_behavior = Build.ChildProcess.StdIo.Ignore;
                    _ = try xorriso_process.spawnAndWait();

                    try Limine.installer.install(image_path, false, null);
                }
            };
        };
    };

    const Disk = struct {
        fn create(kernel: *Kernel) void {
            kernel.disk_step = Build.Step.init(.custom, "disk_create", kernel.builder.allocator, make);

            const named_step = kernel.builder.step("disk", "Create a disk blob to use with QEMU");
            named_step.dependOn(&kernel.disk_step);

            for (kernel.userspace_programs) |program| {
                kernel.disk_step.dependOn(&program.step);
            }
        }

        fn make(step: *Build.Step) !void {
            const kernel = @fieldParentPtr(Kernel, "disk_step", step);
            const max_file_length = Build.maxInt(usize);

            for (kernel.options.run.disks) |disk, disk_i| {
                const disk_memory = Build.allocate_zero_memory(1024 * 1024 * 1024) catch unreachable;
                var build_disk_buffer = Build.ArrayListAlignedUnmanaged(u8, 0x1000){
                    .items = disk_memory,
                    .capacity = disk_memory.len,
                };
                build_disk_buffer.items.len = 0;
                var build_disk = Build.Disk.new(build_disk_buffer);
                var build_fs = WriteOnlyRNUFS.new(&build_disk.disk);
                const rnufs_signature = WriteOnlyRNUFS.get_signature();
                build_disk.buffer.items.len = WriteOnlyRNUFS.get_superblock_size();
                for (rnufs_signature) |signature_byte, byte_i| {
                    const dst_byte = &build_disk.buffer.items[byte_i];
                    dst_byte.* = signature_byte;
                }

                for (disk.resource_files) |resource_file| {
                    const file = try Build.cwd().readFileAlloc(kernel.builder.allocator, kernel.builder.fmt("resources/{s}", .{resource_file}), max_file_length);
                    build_fs.fs.write_file(kernel.builder.allocator, resource_file, file, null) catch unreachable;
                }

                for (disk.userspace_programs) |userspace_program_name| {
                    const userspace_program = find_userspace_program(kernel, userspace_program_name) orelse @panic("wtf");
                    const exe_name = userspace_program.out_filename;
                    const exe_path = userspace_program.output_path_source.getPath();
                    const exe_file_content = try Build.cwd().readFileAlloc(kernel.builder.allocator, exe_path, Build.maxInt(usize));
                    build_fs.fs.write_file(kernel.builder.allocator, exe_name, exe_file_content, null) catch unreachable;
                }

                const disk_size = build_disk.buffer.items.len;
                const disk_sector_count = std.bytes_to_sector(disk_size, build_disk.disk.sector_size, .must_be_exact);
                Build.log.debug("Disk size: {}. Disk sector count: {}", .{ disk_size, disk_sector_count });

                try Build.cwd().writeFile(kernel.builder.fmt("zig-cache/disk{}.bin", .{disk_i}), build_disk.buffer.items);
            }
        }

        fn find_userspace_program(kernel: *Kernel, userspace_program_name: []const u8) ?*Build.LibExeObjStep {
            for (kernel.userspace_programs) |userspace_program| {
                const ending = ".elf";
                std.assert(std.ends_with(u8, userspace_program.out_filename, ending));
                const name = userspace_program.out_filename[0 .. userspace_program.out_filename.len - ending.len];
                if (Build.memory_equal(u8, name, userspace_program_name)) {
                    return userspace_program;
                }
            }

            return null;
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
            disks: []const DiskOptions,
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
            };

            const QEMU = struct {
                vga: ?VGA,
                log: ?LogOptions,
                smp: ?u64,
                run_for_debug: bool,
                print_command: bool,
                const VGA = enum {
                    std,
                    virtio,
                };
            };

            const DiskOptions = struct {
                interface: DiskDriverType,
                filesystem: FilesystemDriverType,
                userspace_programs: []const []const u8,
                resource_files: []const []const u8,
            };

            const LogOptions = struct {
                file: ?[]const u8,
                guest_errors: bool,
                cpu: bool,
                interrupts: bool,
                assembly: bool,
            };
        };
    };
};

const CPUFeatures = struct {
    enabled: Build.Target.Cpu.Feature.Set,
    disabled: Build.Target.Cpu.Feature.Set,

    fn disable_fpu(features: *CPUFeatures) void {
        const Feature = Build.Target.x86.Feature;
        features.disabled.addFeature(@enumToInt(Feature.x87));
        features.disabled.addFeature(@enumToInt(Feature.mmx));
        features.disabled.addFeature(@enumToInt(Feature.sse));
        features.disabled.addFeature(@enumToInt(Feature.sse2));
        features.disabled.addFeature(@enumToInt(Feature.avx));
        features.disabled.addFeature(@enumToInt(Feature.avx2));

        features.enabled.addFeature(@enumToInt(Feature.soft_float));
    }
};

//fn get_riscv_base_features() CPUFeatures {
//var features = CPUFeatures{
//.enabled = Build.Target.Cpu.Feature.Set.empty,
//.disabled = Build.Target.Cpu.Feature.Set.empty,
//};
//const Feature = Build.Target.riscv.Feature;
//features.enabled.addFeature(@enumToInt(Feature.a));

//return features;
//}

fn get_x86_base_features() CPUFeatures {
    var features = CPUFeatures{
        .enabled = Build.Target.Cpu.Feature.Set.empty,
        .disabled = Build.Target.Cpu.Feature.Set.empty,
    };

    return features;
}
//
//fn CPUFeatures

fn get_target(arch: Arch, user: bool) Build.CrossTarget {
    var cpu_features = CPUFeatures{
        .enabled = Build.Target.Cpu.Feature.Set.empty,
        .disabled = Build.Target.Cpu.Feature.Set.empty,
    };

    if (!user) {
        cpu_features.disable_fpu();
    }

    const target = Build.CrossTarget{
        .cpu_arch = arch,
        .os_tag = .freestanding,
        .abi = .none,
        .cpu_features_add = cpu_features.enabled,
        .cpu_features_sub = cpu_features.disabled,
    };

    return target;
}

fn do_debug_step(step: *Build.Step) !void {
    const kernel = @fieldParentPtr(Kernel, "debug_step", step);
    switch (Build.os) {
        .linux => {
            const gdb_script_path = kernel.gdb_script.getFileSource(kernel.gdb_script.files.first.?.data.basename).?.getPath(kernel.builder);
            const first_pid = try Build.fork();
            if (first_pid == 0) {
                var debugger_process = Build.ChildProcess.init(&[_][]const u8{ "gf2", "-x", gdb_script_path }, kernel.builder.allocator);
                _ = try debugger_process.spawnAndWait();
            } else {
                var qemu_process = Build.ChildProcess.init(kernel.debug_argument_list.items, kernel.builder.allocator);
                try qemu_process.spawn();

                _ = Build.waitpid(first_pid, 0);
                _ = try qemu_process.kill();
            }
        },
        else => unreachable,
    }
}
