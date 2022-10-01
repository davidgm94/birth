const common = @import("src/common.zig");
const Build = @import("src/build/lib.zig");
const Arch = Build.Arch;

const cache_dir = "zig-cache/";
const kernel_name = "kernel.elf";
const kernel_path = cache_dir ++ kernel_name;

const user_programs = .{@import("src/user/programs/minimal/dependency.zig")};
const resource_files = [_][]const u8{ "zap-light16.psf", "FiraSans-Regular.otf" };

const common_package = Build.Package{
    .name = "common",
    .source = Build.FileSource.relative("src/common.zig"),
    .dependencies = &.{common_package_dummy},
};

const common_package_dummy = Build.Package{
    .name = "common",
    .source = Build.FileSource.relative("src/common.zig"),
};

const ExecutionEnvironment = enum {
    os,
    software_renderer,
};
const execution_environment = ExecutionEnvironment.software_renderer;

pub fn build(b: *Build.Builder) void {
    switch (execution_environment) {
        .os => {
            const kernel = b.allocator.create(Kernel) catch unreachable;
            kernel.* = Kernel{
                .builder = b,
                .options = .{
                    .arch = Kernel.Options.x86_64.new(.{
                        .bootloader = .limine,
                        .protocol = .limine,
                    }),
                    .run = .{
                        .disks = &.{
                            .{
                                .interface = .ahci,
                                .filesystem = .RNU,
                            },
                        },
                        .memory = .{
                            .amount = 4,
                            .unit = .G,
                        },
                        .emulator = .{
                            .qemu = .{
                                .vga = .std,
                                .smp = null,
                                .log = .{
                                    .file = null,
                                    .guest_errors = true,
                                    .cpu = false,
                                    .assembly = false,
                                    .interrupts = true,
                                },
                                .run_for_debug = true,
                                .print_command = false,
                            },
                        },
                    },
                },
            };

            kernel.create();
        },
        .software_renderer => {
            const SDL = @import("./src/software_renderer/dependencies/sdl/Sdk.zig");
            const sdl = SDL.init(b);
            const software_renderer_root_dir = "src/software_renderer/";
            const exe_source_path = software_renderer_root_dir ++ "main.zig";
            const exe_name = "software-renderer";
            const exe = b.addExecutable(exe_name, exe_source_path);
            const target = b.standardTargetOptions(.{});
            const build_mode = b.standardReleaseOptions();

            sdl.link(exe, .dynamic);
            exe.addPackage(sdl.getWrapperPackage("sdl"));
            //exe.defineCMacroRaw("USE_WAYLAND_API=OFF");
            exe.setTarget(target);
            exe.setBuildMode(build_mode);
            exe.setMainPkgPath("src");
            exe.setOutputDir(cache_dir);

            b.default_step.dependOn(&exe.step);

            const run_cmd = exe.run();
            run_cmd.step.dependOn(b.getInstallStep());
            if (b.args) |args| {
                run_cmd.addArgs(args);
            }

            const run_step = b.step("run", "Run the app");
            run_step.dependOn(&run_cmd.step);

            const exe_tests = b.addTest(exe_source_path);
            exe_tests.setMainPkgPath("src");
            exe_tests.setTarget(target);
            exe_tests.setBuildMode(build_mode);

            const test_step = b.step("test", "Run unit tests");
            test_step.dependOn(&exe_tests.step);

            const debug_cmd = b.addSystemCommand(&.{ "gf2", cache_dir ++ exe_name });
            debug_cmd.step.dependOn(&exe.step);

            const debug_step = b.step("debug", "Debug the app");
            debug_step.dependOn(&debug_cmd.step);
        },
    }
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
    run_argument_list: common.ArrayListManaged([]const u8) = undefined,
    debug_argument_list: common.ArrayListManaged([]const u8) = undefined,
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
                kernel.executable = kernel.builder.addExecutable(kernel_name, "src/kernel/arch/x86_64/limine.zig");
                kernel.executable.code_model = .kernel;
                //kernel.executable.pie = true;
                kernel.executable.force_pic = true;
                kernel.executable.disable_stack_probing = true;
                kernel.executable.strip = false;
                kernel.executable.code_model = .kernel;
                kernel.executable.red_zone = false;
                kernel.executable.omit_frame_pointer = false;
                kernel.executable.entry_symbol_name = "kernel_entry_point";
                kernel.executable.setLinkerScriptPath(Build.FileSource.relative("src/kernel/arch/x86_64/linker.ld"));
            },
            else => unreachable,
        }

        var bootloader_package = Build.Package{
            .name = "bootloader",
            .source = Build.FileSource.relative("src/bootloader.zig"),
        };

        var arch_package = Build.Package{
            .name = "arch",
            .source = Build.FileSource.relative("src/arch.zig"),
        };

        var rnu_package = Build.Package{
            .name = "RNU",
            .source = Build.FileSource.relative("src/rnu.zig"),
        };

        var kernel_package = Build.Package{
            .name = "kernel",
            .source = Build.FileSource.relative("src/kernel.zig"),
        };

        arch_package.dependencies = &.{ common_package, rnu_package, arch_package, kernel_package, bootloader_package };
        rnu_package.dependencies = &.{ common_package, arch_package, rnu_package, kernel_package };
        kernel_package.dependencies = &.{ common_package, rnu_package, arch_package };

        kernel.executable.addPackage(common_package);
        kernel.executable.addPackage(bootloader_package);
        kernel.executable.addPackage(kernel_package);
        kernel.executable.addPackage(rnu_package);
        kernel.executable.addPackage(arch_package);

        kernel.executable.setMainPkgPath("src");
        kernel.executable.setTarget(target);
        kernel.executable.setBuildMode(kernel.builder.standardReleaseOptions());
        kernel.executable.setOutputDir(cache_dir);
        kernel.executable.emit_llvm_ir = .{ .emit_to = cache_dir ++ "kernel_llvm.ir" };

        kernel.builder.default_step.dependOn(&kernel.executable.step);
    }

    fn create_disassembly_step(kernel: *Kernel) void {
        var arg_list = common.ArrayListManaged([]const u8).init(kernel.builder.allocator);
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

        var libexeobj_steps = common.ArrayListManaged(*Build.LibExeObjStep).initCapacity(kernel.builder.allocator, user_programs.len) catch unreachable;
        inline for (user_programs) |user_program| {
            const unique_program = Build.UserProgram.make(kernel.builder.allocator, user_program);
            const out_filename = kernel.builder.fmt("{s}.elf", .{unique_program.name});
            const main_source_file = unique_program.path;
            const program = kernel.builder.addExecutable(out_filename, main_source_file);

            for (unique_program.dependency.dependencies) |dependency| {
                switch (dependency.type) {
                    .c_objects => {
                        const cobjects = @ptrCast(*const Build.CObject, dependency);
                        for (cobjects.objects) |object_name| {
                            const path_to_cobject = cobjects.dependency.get_path_to_file(kernel.builder.allocator, object_name);
                            program.addObjectFile(path_to_cobject);
                        }
                        common.assert(cobjects.dependency.dependencies.len == 0);
                    },
                    else => unreachable,
                }
            }

            program.setMainPkgPath("src");
            program.setTarget(get_target(kernel.options.arch, true));
            program.setOutputDir(cache_dir);
            program.setBuildMode(kernel.builder.standardReleaseOptions());
            //program.setBuildMode(.ReleaseSafe);
            program.setLinkerScriptPath(Build.FileSource.relative(linker_script_path));
            program.entry_symbol_name = "user_entry_point";

            const user_package = Build.Package{
                .name = "user",
                .source = Build.FileSource.relative("src/user.zig"),
                .dependencies = &.{common_package},
            };
            program.addPackage(common_package);
            program.addPackage(user_package);

            kernel.builder.default_step.dependOn(&program.step);

            libexeobj_steps.appendAssumeCapacity(program);
        }

        kernel.userspace_programs = libexeobj_steps.items;
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
        kernel.run_argument_list = common.ArrayListManaged([]const u8).init(kernel.builder.allocator);
        switch (kernel.options.run.emulator) {
            .qemu => {
                const qemu_name = common.concatenate(kernel.builder.allocator, u8, &.{ "qemu-system-", @tagName(kernel.options.arch) }) catch unreachable;
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
                    kernel.run_argument_list.append("-vga") catch unreachable;
                    kernel.run_argument_list.append("none") catch unreachable;
                    kernel.run_argument_list.append("-display") catch unreachable;
                    kernel.run_argument_list.append("none") catch unreachable;
                    //kernel.run_argument_list.append("-nographic") catch unreachable;
                }

                if (kernel.options.arch == .x86_64) {
                    kernel.run_argument_list.append("-debugcon") catch unreachable;
                    kernel.run_argument_list.append("stdio") catch unreachable;
                }

                kernel.run_argument_list.append("-global") catch unreachable;
                kernel.run_argument_list.append("virtio-mmio.force-legacy=false") catch unreachable;

                for (kernel.options.run.disks) |disk, disk_i| {
                    const disk_id = kernel.builder.fmt("disk{}", .{disk_i});
                    const disk_path = kernel.builder.fmt("{s}{s}.bin", .{ cache_dir, disk_id });

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
                            common.assert(kernel.options.arch == .x86_64);
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
                        var log_what = common.ArrayListManaged(u8).init(kernel.builder.allocator);
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

        var gdb_script_buffer = common.ArrayListManaged(u8).init(kernel.builder.allocator);
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
                const installer = @import("src/bootloader/limine/installer.zig");
                const base_path = "src/bootloader/limine";
                const installables_path = base_path ++ "/installables";
                const image_path = cache_dir ++ "universal.iso";

                fn new(kernel: *Kernel) Build.Step {
                    var step = Build.Step.init(.custom, "_limine_image_", kernel.builder.allocator, Limine.build);
                    step.dependOn(&kernel.executable.step);
                    return step;
                }

                fn build(step: *Build.Step) !void {
                    const kernel = @fieldParentPtr(Kernel, "boot_image_step", step);
                    common.assert(kernel.options.arch == .x86_64);
                    const img_dir_path = kernel.builder.fmt("{s}/img_dir", .{kernel.builder.cache_root});
                    const cwd = Build.cwd();
                    cwd.deleteFile(image_path) catch {};
                    const img_dir = try cwd.makeOpenPath(img_dir_path, .{});
                    const img_efi_dir = try img_dir.makeOpenPath("EFI/BOOT", .{});

                    const limine_dir = try cwd.openDir(installables_path, .{});

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

                    const xorriso_executable = switch (common.os) {
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
            const max_file_length = common.max_int(usize);

            // TODO:
            for (kernel.options.run.disks) |_, disk_i| {
                var disk = Build.Disk.new(Build.zero_allocator, 1024 * 1024 * 1024);
                var filesystem = Build.Filesystem.new(&disk);

                common.assert(resource_files.len > 0);

                for (resource_files) |filename| {
                    const file_content = try Build.cwd().readFileAlloc(kernel.builder.allocator, kernel.builder.fmt("resources/{s}", .{filename}), max_file_length);
                    filesystem.write_file(Build.get_allocator(kernel.builder), filename, file_content) catch unreachable;
                }

                common.assert(kernel.userspace_programs.len > 0);

                for (kernel.userspace_programs) |program| {
                    const filename = program.out_filename;
                    common.log.debug("Exe name: {s}", .{filename});
                    const file_path = program.output_path_source.getPath();
                    common.log.debug("Exe path: {s}", .{file_path});
                    const file_content = try Build.cwd().readFileAlloc(kernel.builder.allocator, file_path, common.max_int(usize));
                    filesystem.write_file(Build.get_allocator(kernel.builder), filename, file_content) catch unreachable;
                }

                //const disk_size = build_disk.buffer.items.len;
                //const disk_sector_count = @divFloor(disk_size, build_disk.disk.sector_size);
                //Build.log.debug("Disk size: {}. Disk sector count: {}", .{ disk_size, disk_sector_count });

                try Build.cwd().writeFile(kernel.builder.fmt("{s}disk{}.bin", .{ cache_dir, disk_i }), filesystem.disk.buffer.items);
            }
        }

        fn find_userspace_program(kernel: *Kernel, userspace_program_name: []const u8) ?*Build.LibExeObjStep {
            for (kernel.userspace_programs) |userspace_program| {
                const ending = ".elf";
                common.assert(common.ends_with(u8, userspace_program.out_filename, ending));
                const name = userspace_program.out_filename[0 .. userspace_program.out_filename.len - ending.len];
                if (common.equal(u8, name, userspace_program_name)) {
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
                limine: void,
            },

            const Bootloader = enum {
                limine,
            };

            fn new(context: anytype) Options.ArchSpecific {
                return switch (context.bootloader) {
                    .limine => .{
                        .x86_64 = .{
                            .bootloader = .{
                                .limine = {},
                            },
                        },
                    },
                    else => unreachable,
                };
            }
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
            dxil,
            loongarch32,
            loongarch64,
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
                interface: common.Disk.Type,
                filesystem: common.Filesystem.Type,
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
    const gdb_script_path = kernel.gdb_script.getFileSource(kernel.gdb_script.files.first.?.data.basename).?.getPath(kernel.builder);
    switch (Build.os) {
        .linux, .macos => {
            const first_pid = try Build.fork();
            if (first_pid == 0) {
                switch (Build.os) {
                    .linux => {
                        var debugger_process = Build.ChildProcess.init(&[_][]const u8{ "gf2", "-x", gdb_script_path }, kernel.builder.allocator);
                        _ = try debugger_process.spawnAndWait();
                    },
                    .macos => {
                        var debugger_process = Build.ChildProcess.init(&[_][]const u8{ "wezterm", "start", "--cwd", kernel.builder.build_root, "--", "x86_64-elf-gdb", "-x", gdb_script_path }, kernel.builder.allocator);
                        _ = try debugger_process.spawnAndWait();
                    },
                    else => unreachable,
                }
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
