const host = @import("src/host.zig");

const assert = host.assert;
const Cpu = host.Cpu;
const CrossTarget = host.CrossTarget;
const DiskType = host.DiskType;
const FilesystemType = host.FilesystemType;
const Target = host.Target;

const cache_dir = "zig-cache/";
const kernel_name = "kernel.elf";
const kernel_path = cache_dir ++ kernel_name;

pub fn build(b: *host.build.Builder) void {
    const kernel = b.allocator.create(Kernel) catch @panic("unable to allocate memory for kernel builder");
    const emulator = Kernel.Options.RunOptions.Emulator.qemu;
    kernel.* = Kernel{
        .builder = b,
        .options = .{
            .arch = .{
                .x86_64 = .{
                    .bootloader = .rise,
                    .boot_protocol = .bios,
                },
            },
            .run = .{
                .memory = .{
                    .amount = 4,
                    .unit = .G,
                },
                .emulator = blk: {
                    switch (emulator) {
                        .qemu => {
                            break :blk .{
                                .qemu = .{
                                    .vga = .std,
                                    .smp = null,
                                    .log = .{
                                        .file = null,
                                        .guest_errors = true,
                                        .cpu = false,
                                        .assembly = false,
                                        .interrupts = true,
                                        .pmode_exceptions = true,
                                    },
                                    .virtualize = false,
                                    .print_command = true,
                                },
                            };
                        },
                        .bochs => break :blk .{ .bochs = {} },
                    }
                },
            },
        },
    };

    kernel.create() catch |err| {
        host.getStdOut().writeAll("error: ") catch unreachable;
        host.getStdOut().writeAll(@errorName(err)) catch unreachable;
        host.getStdOut().writer().writeByte('\n') catch unreachable;
        @panic("building the kernel failed");
    };

    const test_step = b.step("test", "Run unit tests");

    const native_tests = [_]struct { name: []const u8, zig_source_file: []const u8 }{
        .{ .name = lib_package.name, .zig_source_file = lib_package.source.path },
    };

    for (native_tests) |native_test| {
        const test_exe = b.addTestExe(native_test.name, native_test.zig_source_file);
        test_exe.setTarget(b.standardTargetOptions(.{}));
        test_exe.setBuildMode(b.standardReleaseOptions());
        test_exe.setOutputDir("zig-cache");
        const run_test_step = test_exe.run();
        test_step.dependOn(&run_test_step.step);
    }
}

var lib_package = host.build.Pkg{
    .name = "lib",
    .source = host.build.FileSource.relative("src/lib.zig"),
};

var bootloader_package = host.build.Pkg{
    .name = "bootloader",
    .source = host.build.FileSource.relative("src/bootloader.zig"),
};

var rise_package = host.build.Pkg{
    .name = "rise",
    .source = host.build.FileSource.relative("src/rise.zig"),
};

var privileged_package = host.build.Pkg{
    .name = "privileged",
    .source = host.build.FileSource.relative("src/privileged.zig"),
};

var user_package = host.build.Pkg{
    .name = "user",
    .source = host.build.FileSource.relative("src/user.zig"),
};

const Kernel = struct {
    builder: *host.build.Builder,
    bootloader: ?*host.build.LibExeObjStep = null,
    executable: *host.build.LibExeObjStep = undefined,
    //userspace_programs: []*host.build.LibExeObjStep = &.{},
    options: Options,
    boot_image_step: host.build.Step = undefined,
    disk_count: u64 = 0,
    disk_step: host.build.Step = undefined,
    debug_step: host.build.Step = undefined,
    disk_image_builder_run_step: *host.build.RunStep = undefined,
    run_argument_list: host.ArrayList([]const u8) = undefined,
    debug_argument_list: host.ArrayList([]const u8) = undefined,
    gdb_script: *host.build.WriteFileStep = undefined,

    fn create(kernel: *Kernel) !void {
        // Initialize package dependencies here
        lib_package.dependencies = &.{lib_package};
        rise_package.dependencies = &.{ lib_package, rise_package, privileged_package };
        user_package.dependencies = &.{lib_package};
        privileged_package.dependencies = &.{ lib_package, privileged_package };

        kernel.create_bootloader();
        kernel.create_executable();
        try kernel.create_disassembly_step();
        kernel.create_disk();
        try kernel.create_run_and_debug_steps();
    }

    fn create_bootloader(kernel: *Kernel) void {
        switch (kernel.options.arch) {
            .x86_64 => {
                switch (kernel.options.arch.x86_64.bootloader) {
                    .rise => {
                        switch (kernel.options.arch.x86_64.boot_protocol) {
                            .uefi => {
                                const bootloader_exe = kernel.builder.addExecutable("BOOTX64", "src/bootloader/rise/uefi.zig");
                                bootloader_exe.setTarget(.{
                                    .cpu_arch = .x86_64,
                                    .os_tag = .uefi,
                                    .abi = .msvc,
                                });
                                bootloader_exe.setOutputDir(cache_dir);
                                bootloader_exe.addPackage(lib_package);
                                bootloader_exe.addPackage(privileged_package);
                                bootloader_exe.strip = true;
                                bootloader_exe.setBuildMode(.ReleaseSafe);

                                kernel.builder.default_step.dependOn(&bootloader_exe.step);
                                kernel.bootloader = bootloader_exe;
                            },
                            .bios => {
                                const bootloader_exe = kernel.builder.addExecutable("rise.elf", "src/bootloader/rise/bios/main.zig");
                                bootloader_exe.addAssemblyFile("src/bootloader/rise/bios/bios.S");
                                bootloader_exe.setTarget(get_target(.x86, false));
                                bootloader_exe.setOutputDir(cache_dir);
                                bootloader_exe.addPackage(lib_package);
                                bootloader_exe.addPackage(privileged_package);
                                bootloader_exe.setLinkerScriptPath(host.build.FileSource.relative("src/bootloader/rise/bios.ld"));
                                bootloader_exe.link_gc_sections = true;
                                bootloader_exe.want_lto = true;
                                bootloader_exe.strip = true;
                                bootloader_exe.setBuildMode(.ReleaseSmall);

                                kernel.builder.default_step.dependOn(&bootloader_exe.step);
                                kernel.bootloader = bootloader_exe;
                            },
                        }
                    },
                    .limine => {
                        const bootloader_exe = kernel.builder.addExecutable("limine.elf", "src/bootloader/limine/limine.zig");
                        bootloader_exe.setTarget(get_target(.x86_64, false));
                        bootloader_exe.setOutputDir(cache_dir);
                        bootloader_exe.addPackage(lib_package);
                        bootloader_exe.addPackage(privileged_package);
                        bootloader_exe.strip = true;
                        bootloader_exe.setBuildMode(.ReleaseSafe);

                        kernel.builder.default_step.dependOn(&bootloader_exe.step);
                        kernel.bootloader = bootloader_exe;
                    },
                }
            },
            else => unreachable,
        }
    }

    fn create_executable(kernel: *Kernel) void {
        const target = get_target(kernel.options.arch, false);

        const kernel_source_path = "src/rise/";
        switch (kernel.options.arch) {
            .x86_64 => {
                kernel.executable = kernel.builder.addExecutable(kernel_name, "src/rise/arch/x86_64/entry_point.zig");
                kernel.executable.code_model = .kernel;
                kernel.executable.setLinkerScriptPath(host.build.FileSource.relative(kernel_source_path ++ "arch/x86_64/linker.ld"));
            },
            else => unreachable,
        }

        kernel.executable.force_pic = true;
        kernel.executable.disable_stack_probing = true;
        kernel.executable.stack_protector = false;
        kernel.executable.strip = false;
        kernel.executable.red_zone = false;
        kernel.executable.omit_frame_pointer = false;
        kernel.executable.entry_symbol_name = "kernel_entry_point";
        kernel.executable.setTarget(target);
        kernel.executable.setBuildMode(kernel.builder.standardReleaseOptions());
        kernel.executable.setOutputDir(cache_dir);

        kernel.executable.addPackage(lib_package);
        kernel.executable.addPackage(bootloader_package);
        kernel.executable.addPackage(rise_package);
        kernel.executable.addPackage(privileged_package);

        kernel.executable.setMainPkgPath("src");

        kernel.builder.default_step.dependOn(&kernel.executable.step);
    }

    fn create_disassembly_step(kernel: *Kernel) !void {
        var arg_list = host.ArrayList([]const u8).init(kernel.builder.allocator);
        const main_args = &.{ "llvm-objdump", kernel_path };
        const common_flags = &.{ "-d", "-S" };
        try arg_list.appendSlice(main_args);
        try arg_list.appendSlice(common_flags);
        switch (kernel.options.arch) {
            .x86_64 => try arg_list.append("-Mintel"),
            else => {},
        }
        const disassembly_kernel = kernel.builder.addSystemCommand(arg_list.items);
        disassembly_kernel.step.dependOn(&kernel.executable.step);
        const disassembly_kernel_step = kernel.builder.step("disasm", "Disassembly the kernel ELF");
        disassembly_kernel_step.dependOn(&disassembly_kernel.step);
    }

    fn create_disk(kernel: *Kernel) void {
        const disk_image_builder = kernel.builder.addExecutable("disk_image_builder", "src/disk_image_builder.zig");
        disk_image_builder.setOutputDir(cache_dir);
        disk_image_builder.setBuildMode(kernel.builder.standardReleaseOptions());
        disk_image_builder.step.dependOn(&(kernel.bootloader orelse unreachable).step);
        disk_image_builder.step.dependOn(&kernel.executable.step);

        kernel.disk_image_builder_run_step = disk_image_builder.run();
        kernel.disk_image_builder_run_step.step.dependOn(kernel.builder.default_step);
    }

    const Error = error{
        not_implemented,
        module_file_not_found,
    };

    fn create_run_and_debug_steps(kernel: *Kernel) !void {
        kernel.run_argument_list = host.ArrayList([]const u8).init(kernel.builder.allocator);
        switch (kernel.options.run.emulator) {
            .qemu => {
                const qemu_name = try host.concat(kernel.builder.allocator, u8, &.{ "qemu-system-", @tagName(kernel.options.arch) });
                try kernel.run_argument_list.append(qemu_name);

                if (!kernel.options.is_virtualizing()) {
                    try kernel.run_argument_list.append("-trace");
                    try kernel.run_argument_list.append("-nvme*");
                    try kernel.run_argument_list.append("-trace");
                    try kernel.run_argument_list.append("-pci*");
                    try kernel.run_argument_list.append("-trace");
                    try kernel.run_argument_list.append("-ide*");
                    try kernel.run_argument_list.append("-trace");
                    try kernel.run_argument_list.append("-ata*");
                    try kernel.run_argument_list.append("-trace");
                    try kernel.run_argument_list.append("-ahci*");
                    try kernel.run_argument_list.append("-trace");
                    try kernel.run_argument_list.append("-sata*");
                }

                // Boot device
                switch (kernel.options.arch) {
                    .x86_64 => {
                        if (kernel.options.arch.x86_64.boot_protocol == .uefi) {
                            try kernel.run_argument_list.appendSlice(&.{ "-bios", "tools/OVMF_CODE-pure-efi.fd" });
                        }
                    },
                    else => return Error.not_implemented,
                }

                {
                    try kernel.run_argument_list.append("-no-reboot");
                    try kernel.run_argument_list.append("-no-shutdown");
                }

                {
                    const memory_arg = kernel.builder.fmt("{}{s}", .{ kernel.options.run.memory.amount, @tagName(kernel.options.run.memory.unit) });
                    try kernel.run_argument_list.append("-m");
                    try kernel.run_argument_list.append(memory_arg);
                }

                if (kernel.options.run.emulator.qemu.smp) |smp_count| {
                    try kernel.run_argument_list.append("-smp");
                    try kernel.run_argument_list.append(kernel.builder.fmt("{}", .{smp_count}));
                }

                if (kernel.options.run.emulator.qemu.vga) |vga_option| {
                    try kernel.run_argument_list.append("-vga");
                    try kernel.run_argument_list.append(@tagName(vga_option));
                } else {
                    try kernel.run_argument_list.append("-vga");
                    try kernel.run_argument_list.append("none");
                    try kernel.run_argument_list.append("-display");
                    try kernel.run_argument_list.append("none");
                    //kernel.run_argument_list.append("-nographic") ;
                }

                if (kernel.options.arch == .x86_64) {
                    try kernel.run_argument_list.append("-debugcon");
                    try kernel.run_argument_list.append("stdio");
                }

                try kernel.run_argument_list.append("-global");
                try kernel.run_argument_list.append("virtio-mmio.force-legacy=false");

                const image_config = try host.ImageConfig.get(kernel.builder.allocator, host.ImageConfig.default_path);
                const disk_path = try host.concat(kernel.builder.allocator, u8, &.{ cache_dir, image_config.image_name });
                // TODO: don't ignore system interface
                try kernel.run_argument_list.appendSlice(
                //&.{ "-hda", disk_path });
                &.{ "-drive", kernel.builder.fmt("file={s},index=0,media=disk,format=raw", .{disk_path}) });

                kernel.debug_argument_list = try kernel.run_argument_list.clone();
                if (kernel.options.is_virtualizing()) {
                    const args = &.{
                        "-accel",
                        switch (host.os) {
                            .windows => "whpx",
                            .linux => "kvm",
                            .macos => "hvf",
                            else => @compileError("OS not supported"),
                        },
                        "-cpu",
                        "host",
                    };
                    try kernel.run_argument_list.appendSlice(args);
                    try kernel.debug_argument_list.appendSlice(args);
                } else {
                    if (kernel.options.run.emulator.qemu.log) |log_options| {
                        var log_what = host.ArrayList(u8).init(kernel.builder.allocator);
                        if (log_options.guest_errors) try log_what.appendSlice("guest_errors,");
                        if (log_options.cpu) try log_what.appendSlice("cpu,");
                        if (log_options.interrupts) try log_what.appendSlice("int,");
                        if (log_options.assembly) try log_what.appendSlice("in_asm,");
                        if (log_options.pmode_exceptions) try log_what.appendSlice("pcall,");

                        if (log_what.items.len > 0) {
                            // Delete the last comma
                            _ = log_what.pop();

                            const log_flag = "-d";
                            try kernel.run_argument_list.append(log_flag);
                            try kernel.debug_argument_list.append(log_flag);
                            try kernel.run_argument_list.append(log_what.items);
                            try kernel.debug_argument_list.append(log_what.items);
                        }

                        if (log_options.file) |log_file| {
                            const log_file_flag = "-D";
                            try kernel.run_argument_list.append(log_file_flag);
                            try kernel.debug_argument_list.append(log_file_flag);
                            try kernel.run_argument_list.append(log_file);
                            try kernel.debug_argument_list.append(log_file);
                        }
                    }
                }

                if (!kernel.options.is_virtualizing()) {
                    try kernel.debug_argument_list.append("-S");
                }

                try kernel.debug_argument_list.append("-s");
            },
            .bochs => {
                try kernel.run_argument_list.append("bochs");
            },
        }

        const run_command = kernel.builder.addSystemCommand(kernel.run_argument_list.items);
        run_command.step.dependOn(kernel.builder.default_step);
        run_command.step.dependOn(&kernel.disk_image_builder_run_step.step);

        const run_step = kernel.builder.step("run", "run step");
        run_step.dependOn(&run_command.step);

        var gdb_script_buffer = host.ArrayList(u8).init(kernel.builder.allocator);
        switch (kernel.options.arch) {
            .x86, .x86_64 => try gdb_script_buffer.appendSlice("set disassembly-flavor intel\n"),
            else => return Error.not_implemented,
        }

        const gdb_script_chunk = if (kernel.options.is_virtualizing())
            \\symbol-file zig-cache/kernel.elf
            \\target remote localhost:1234
            \\c
        else
            \\symbol-file zig-cache/kernel.elf
            \\target remote localhost:1234
            \\b *0xa3b9
            \\c
            ;

        try gdb_script_buffer.appendSlice(gdb_script_chunk);

        kernel.gdb_script = kernel.builder.addWriteFile("gdb_script", gdb_script_buffer.items);
        kernel.builder.default_step.dependOn(&kernel.gdb_script.step);

        // We need a member variable because we need consistent memory around it to do @fieldParentPtr
        kernel.debug_step = host.build.Step.init(.custom, "_debug_", kernel.builder.allocator, do_debug_step);
        //kernel.debug_step.dependOn(&kernel.boot_image_step);
        kernel.debug_step.dependOn(&kernel.gdb_script.step);
        //kernel.debug_step.dependOn(&kernel.disk_step);
        kernel.debug_step.dependOn(&kernel.disk_image_builder_run_step.step);

        const debug_step = kernel.builder.step("debug", "Debug the program with QEMU and GDB");
        debug_step.dependOn(&kernel.debug_step);
    }

    const Options = struct {
        arch: Options.ArchSpecific,
        run: RunOptions,

        const x86_64 = struct {
            bootloader: Bootloader,
            boot_protocol: BootProtocol,

            const BootProtocol = enum {
                bios,
                uefi,
            };

            const Bootloader = enum {
                rise,
                limine,
            };
        };

        const ArchSpecific = union(Cpu.Arch) {
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
            riscv64,
            sparc,
            sparc64,
            sparcel,
            s390x,
            tce,
            tcele,
            thumb,
            thumbeb,
            x86,
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
            spu_2,
            spirv32,
            spirv64,
            dxil,
            loongarch32,
            loongarch64,
        };

        const RunOptions = struct {
            memory: Memory,
            emulator: union(Emulator) {
                qemu: QEMU,
                bochs: Bochs,
            },

            const Emulator = enum {
                qemu,
                bochs,
            };

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
                virtualize: bool,
                print_command: bool,
                const VGA = enum {
                    std,
                    virtio,
                };
            };

            const Bochs = struct {};

            const DiskOptions = struct {
                interface: host.DiskType,
                filesystem: host.FilesystemType,
            };

            const LogOptions = struct {
                file: ?[]const u8,
                guest_errors: bool,
                cpu: bool,
                interrupts: bool,
                assembly: bool,
                pmode_exceptions: bool,
            };
        };

        fn is_virtualizing(options: Options) bool {
            return switch (options.run.emulator) {
                .qemu => options.run.emulator.qemu.virtualize and host.cpu.arch == options.arch,
                .bochs => false,
            };
        }
    };

    fn get_target(asked_arch: Cpu.Arch, user: bool) CrossTarget {
        var enabled_features = Cpu.Feature.Set.empty;
        var disabled_features = Cpu.Feature.Set.empty;

        if (!user) {
            assert(asked_arch == .x86_64 or asked_arch == .x86);
            // disable FPU
            const Feature = Target.x86.Feature;
            disabled_features.addFeature(@enumToInt(Feature.x87));
            disabled_features.addFeature(@enumToInt(Feature.mmx));
            disabled_features.addFeature(@enumToInt(Feature.sse));
            disabled_features.addFeature(@enumToInt(Feature.sse2));
            disabled_features.addFeature(@enumToInt(Feature.avx));
            disabled_features.addFeature(@enumToInt(Feature.avx2));

            enabled_features.addFeature(@enumToInt(Feature.soft_float));
        }

        const target = CrossTarget{
            .cpu_arch = asked_arch,
            .os_tag = .freestanding,
            .abi = .none,
            .cpu_features_add = enabled_features,
            .cpu_features_sub = disabled_features,
        };

        return target;
    }
};

fn do_debug_step(step: *host.build.Step) !void {
    const kernel = @fieldParentPtr(Kernel, "debug_step", step);
    const gdb_script_path = kernel.gdb_script.getFileSource(kernel.gdb_script.files.first.?.data.basename).?.getPath(kernel.builder);
    switch (host.os) {
        .linux, .macos => {
            const first_pid = try host.posix.fork();
            if (first_pid == 0) {
                switch (host.os) {
                    .linux => {
                        var debugger_process = host.ChildProcess.init(&[_][]const u8{ "gf2", "-x", gdb_script_path }, kernel.builder.allocator);
                        _ = try debugger_process.spawnAndWait();
                    },
                    .macos => {
                        var debugger_process = host.ChildProcess.init(&[_][]const u8{ "wezterm", "start", "--cwd", kernel.builder.build_root, "--", "x86_64-elf-gdb", "-x", gdb_script_path }, kernel.builder.allocator);
                        _ = try debugger_process.spawnAndWait();
                    },
                    else => @compileError("OS not supported"),
                }
            } else {
                var qemu_process = host.ChildProcess.init(kernel.debug_argument_list.items, kernel.builder.allocator);
                try qemu_process.spawn();

                _ = host.posix.waitpid(first_pid, 0);
                _ = try qemu_process.kill();
            }
        },
        else => @panic("todo implement"),
    }
}

const Limine = struct {
    const base_path = "src/bootloader/limine";
    const installables_path = base_path ++ "/installables";
    const image_path = cache_dir ++ "universal.iso";
    const installer = @import("src/bootloader/limine/installer.zig");
};
