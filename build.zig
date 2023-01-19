const host = @import("src/host.zig");

// Build types
const Builder = host.build.Builder;
const FileSource = host.build.FileSource;
const LibExeObjStep = host.build.LibExeObjStep;
const RunStep = host.build.RunStep;
const Step = host.build.Step;

const assert = host.assert;
const Bootloader = host.Bootloader;
const Cpu = host.Cpu;
const CrossTarget = host.CrossTarget;
const DiskType = host.DiskType;
const Emulator = host.Emulator;
const FilesystemType = host.FilesystemType;
const Target = host.Target;

const source_root_dir = "src";
const cache_dir = "zig-cache/";
// const kernel_path = cache_dir ++ kernel_name;

const Configuration = struct {
    bootloader: Bootloader.ID,
    architecture: Cpu.Arch,
    boot_protocol: Bootloader.Protocol,
};

const default_configuration = Configuration{
    .bootloader = .rise,
    .architecture = .x86_64,
    .boot_protocol = .bios,
};

const default_emulator = Emulator.qemu;

pub fn build(builder: *host.build.Builder) !void {
    const ci = builder.option(bool, "ci", "CI mode") orelse false;
    _ = ci;

    lib_package.dependencies = &.{lib_package};
    rise_package.dependencies = &.{ lib_package, rise_package, privileged_package };
    user_package.dependencies = &.{lib_package};
    privileged_package.dependencies = &.{ lib_package, privileged_package };

    const disk_image_builder = createDiskImageBuilder(builder);

    const build_steps = blk: {
    var bootloader_steps = host.ArrayList(BootloaderSteps).init(builder.allocator);

    inline for (host.bootloaders) |bootloader, bootloader_index| {
        const bootloader_id = @intToEnum(host.Bootloader.ID, bootloader_index);

        var architecture_steps = host.ArrayList(ArchitectureSteps).init(builder.allocator);

        inline for (bootloader.supported_architectures) |architecture| {
            var boot_protocol_steps = host.ArrayList(BootProtocolSteps).init(builder.allocator);
            inline for (architecture.supported_protocols) |boot_protocol| {
                var emulator_steps = host.ArrayList(EmulatorSteps).init(builder.allocator);
                const configuration = .{
                    .bootloader = bootloader_id,
                    .architecture = architecture.id,
                    .boot_protocol = boot_protocol,
                };

                const prefix = @tagName(configuration.bootloader) ++ "_" ++ @tagName(configuration.architecture) ++ "_" ++ @tagName(configuration.boot_protocol) ++ "_";
                const bootloader_build = try createBootloader(builder, configuration, prefix);
                _ = bootloader_build;

                const cpu_driver = try createCPUDriver(builder, configuration, prefix);
                _ = cpu_driver;

                const disk_image_builder_run_step = disk_image_builder.run();
                disk_image_builder_run_step.addArg(prefix);

                const emulators = comptime getEmulators(configuration);

                inline for (emulators) |emulator| {
                    const step_prefix = prefix ++ "_" ++ @tagName(emulator);
                    const emulator_step = try EmulatorSteps.Interface(configuration, emulator, step_prefix).create(builder, &emulator_steps);
                    emulator_step.run.dependOn(&disk_image_builder_run_step.step);
                    emulator_step.debug.dependOn(&disk_image_builder_run_step.step);

                    if (emulator == default_emulator and default_configuration.bootloader == bootloader_id and default_configuration.architecture == architecture.id and default_configuration.boot_protocol == boot_protocol) {
                        const default_run_step = builder.step("run", "Run " ++ step_prefix);
                        const default_debug_step = builder.step("debug", "Debug " ++ step_prefix);
                        default_run_step.dependOn(&emulator_step.run);
                        default_debug_step.dependOn(&emulator_step.debug);
                    }
                }

                try boot_protocol_steps.append(.{ .emulator_steps = emulator_steps.items });
            }

            try architecture_steps.append(.{ .boot_protocol_steps = boot_protocol_steps.items });
        }

        try bootloader_steps.append( .{ .architecture_steps = architecture_steps.items });
    }

    break :blk BuildSteps{ .bootloader_steps = bootloader_steps.items };
    };
    _ = build_steps;

    const test_step = builder.step("test", "Run unit tests");

    const native_tests = [_]struct { name: []const u8, zig_source_file: []const u8 }{
       .{ .name = lib_package.name, .zig_source_file = lib_package.source.path },
    };

    for (native_tests) |native_test| {
       const test_exe = builder.addTestExe(native_test.name, native_test.zig_source_file);
       test_exe.setTarget(builder.standardTargetOptions(.{}));
       test_exe.setBuildMode(builder.standardReleaseOptions());
       test_exe.setOutputDir("zig-cache");
       const run_test_step = test_exe.run();
       test_step.dependOn(&run_test_step.step);
    }
}

pub fn getEmulators(comptime configuration: Configuration) []const Emulator{
    return switch (configuration.bootloader) {
        .rise, .limine => switch (configuration.architecture) {
            .x86_64 => switch (configuration.boot_protocol) {
                .bios => &.{ .qemu },
                .uefi => &.{ .qemu },
            },
            else => @compileError("Architecture not supported"),
        },
    };
}

const BuildSteps = struct {
    bootloader_steps: []const BootloaderSteps,
};

const BootloaderSteps = struct {
    architecture_steps: []const ArchitectureSteps,
};

const ArchitectureSteps = struct {
    boot_protocol_steps: []const BootProtocolSteps,
};

const BootProtocolSteps = struct {
    emulator_steps: []const EmulatorSteps,
};

const EmulatorSteps = struct {
    builder: *Builder,
    run: Step,
    debug: Step,

    fn Interface(comptime configuration: Configuration, comptime emulator: Emulator, comptime step_prefix: []const u8) type {
        return switch (emulator) {
            .qemu => struct {
                const qemu_executable = "qemu-system-" ++ switch (configuration.architecture) {
                    else => @tagName(configuration.architecture),
                };


                fn create(builder: *Builder, list: *host.ArrayList(EmulatorSteps)) !*EmulatorSteps {
                    const new_one = try list.addOne();
                    new_one.* = .{
                        .builder = builder,
                            .run = Step.init(.custom, step_prefix ++ "_run_", builder.allocator, run),
                            .debug = Step.init(.custom, step_prefix ++ "_debug_", builder.allocator, debug),
                    };

                    const run_step = builder.step(step_prefix ++ "_run", "Run " ++ step_prefix);
                    const debug_step = builder.step(step_prefix ++ "_debug", "Debug " ++ step_prefix);
                    run_step.dependOn(&new_one.run);
                    debug_step.dependOn(&new_one.debug);

                    return new_one;
                }

                fn run(step: *Step) !void {
                    const emulator_steps = @fieldParentPtr(EmulatorSteps, "run", step);
                    const arguments = try qemuCommon(emulator_steps);
                    for (arguments.list.items) |argument| {
                        host.log.debug("{s}", .{argument});
                    }
                    var process = host.ChildProcess.init(arguments.list.items, emulator_steps.builder.allocator);
                    _ = try process.spawnAndWait();
                }

                fn debug(step: *Step) !void {
                    const emulator_steps = @fieldParentPtr(EmulatorSteps, "debug", step);
                    var arguments = try qemuCommon(emulator_steps);
                    
                    if (!arguments.config.isVirtualizing()) {
                        try arguments.list.append("-S");
                    }

                    try arguments.list.append("-s");

                    return Error.not_implemented;
                }

                fn qemuCommon(emulator_steps: *EmulatorSteps) !struct {config: Arguments, list: host.ArrayList([]const u8) } {
                    const builder = emulator_steps.builder;
                    const config_file = try readConfig(builder, emulator);
                    var token_stream = host.json.TokenStream.init(config_file);
                    const arguments = try host.json.parse(Arguments, &token_stream, .{ .allocator = builder.allocator });

                    var argument_list = host.ArrayList([]const u8).init(builder.allocator);

                    try argument_list.append(qemu_executable);

                    switch (configuration.boot_protocol) {
                        .uefi => try argument_list.appendSlice(&.{ "-bios", "tools/OVMF_CODE-pure-efi.fd" }),
                        else => {},
                    }

                    const image_config = try host.ImageConfig.get(builder.allocator, host.ImageConfig.default_path);
                    const disk_path = try host.concat(builder.allocator, u8, &.{ cache_dir, image_config.image_name });
                    try argument_list.appendSlice( &.{ "-drive", builder.fmt("file={s},index=0,media=disk,format=raw", .{disk_path}) });

                    if (!arguments.reboot) {
                        try argument_list.append("-no-reboot");
                    }

                    if (!arguments.shutdown) {
                        try argument_list.append("-no-shutdown");
                    }

                    if (arguments.vga) |vga| {
                        try argument_list.append("-vga");
                        try argument_list.append(@tagName(vga));
                    }

                    if (arguments.smp) |smp| {
                        try argument_list.append("-smp");
                        const smp_string = builder.fmt("{}", .{smp});
                        try argument_list.append(smp_string);
                    }

                    if (arguments.debugcon) |debugcon| {
                        try argument_list.append("-debugcon");
                        try argument_list.append(@tagName(debugcon));
                    }

                    if (arguments.memory) |memory| {
                        try argument_list.append("-m");
                        const memory_argument = builder.fmt("{}{c}", .{memory.amount, @as(u8, switch (memory.unit) {
                            .kilobyte => 'K',
                            .megabyte => 'M',
                            .gigabyte => 'G',
                            else => unreachable,
                        })});
                        try argument_list.append(memory_argument);
                    }

                    if (arguments.isVirtualizing()) {
                        try argument_list.appendSlice(&.{
                                "-accel",
                                switch (host.os) {
                                .windows => "whpx",
                                .linux => "kvm",
                                .macos => "hvf",
                                else => @compileError("OS not supported"),
                                },
                                "-cpu",
                                "host",
                                });
                    } else {
                        if (arguments.log) |log_configuration| {
                            var log_what = host.ArrayList(u8).init(builder.allocator);

                            if (log_configuration.guest_errors) try log_what.appendSlice("guest_errors,");
                            if (log_configuration.interrupts) try log_what.appendSlice("int,");
                            if (log_configuration.assembly) try log_what.appendSlice("in_asm,");

                            if (log_what.items.len > 0) {
                                // Delete the last comma
                                _ = log_what.pop();

                                try argument_list.append("-d");
                                try argument_list.append(log_what.items);
                            }

                            if (log_configuration.file) |log_file| {
                                try argument_list.append("-D");
                                try argument_list.append(log_file);
                            }
                        }

                        if (arguments.trace) |tracees| {
                            for (tracees) |tracee| {
                                const tracee_slice = builder.fmt("-{s}*", .{tracee});
                                try argument_list.append("-trace");
                                try argument_list.append(tracee_slice);
                            }
                        }
                    }

                    return .{ .config = arguments, .list = argument_list };
                }
               
                const Arguments = struct {
                    memory: ?struct {
                        amount: u64,
                        unit: host.SizeUnit,
                    },
                    virtualize: ?bool,
                    vga: ?enum {
                        std,
                    },
                    smp: ?usize,
                    reboot: bool,
                    shutdown: bool,
                    debugcon: ?enum {
                        stdio,
                    },
                    log: ?struct {
                        file: ?[]const u8,
                        guest_errors: bool,
                        assembly: bool,
                        interrupts: bool,
                    },
                    trace: ?[]const []const u8,

                    pub fn isVirtualizing(arguments: Arguments) bool {
                        return (arguments.virtualize orelse false) and host.cpu.arch == configuration.architecture;
                    }
                };

            },
        };
    }
};


fn readConfig(builder: *Builder, comptime emulator: Emulator) ![]const u8 {
    const config_file = switch (emulator) {
        else => try host.cwd().readFileAlloc(builder.allocator, "config/" ++ @tagName(emulator) ++ ".json", host.maxInt(usize)),
    };

    return config_file;
}


const BootloaderBuild = struct {
    executables: []const *LibExeObjStep,
};

const Error = error {
    not_implemented,
};

fn createBootloader(builder: *Builder, comptime configuration: Configuration, comptime prefix: []const u8) !BootloaderBuild{
    var bootloader_executables = host.ArrayList(*LibExeObjStep).init(builder.allocator);

    switch (configuration.bootloader) {
        .rise => {
            const rise_loader_path = "src/bootloader/rise/";
            switch (configuration.architecture) {
                .x86_64 => {
                    switch (configuration.boot_protocol) {
                        .bios => {
                            const stages = [_]comptime_int{1, 2};

                            inline for (stages) |stage| {
                                const stage_ascii = [1]u8{'0' + @intCast(u8, stage)};
                                const stage_string = "stage" ++ &stage_ascii;
                                const stage_path = rise_loader_path ++ "bios/" ++ stage_string ++ "/";

                                const executable = builder.addExecutable(prefix ++ stage_string, stage_path ++ "main.zig");
                                executable.addAssemblyFile(stage_path ++ "assembly.S");
                                executable.setTarget(get_target(if (stage == 1) .x86 else .x86_64, .privileged));
                                executable.setOutputDir(cache_dir);
                                executable.addPackage(lib_package);
                                executable.addPackage(privileged_package);
                                executable.setLinkerScriptPath(host.build.FileSource.relative(stage_path ++ "linker_script.ld"));
                                executable.red_zone = false;
                                executable.link_gc_sections = true;
                                executable.want_lto = true;
                                executable.strip = true;
                                executable.entry_symbol_name = "entry_point";
                                executable.setBuildMode(.ReleaseSmall);

                                try bootloader_executables.append(executable);
                            }
                        },
                            .uefi => {
                                const executable = builder.addExecutable("BOOTX64", rise_loader_path ++ "uefi/main.zig");
                                executable.setTarget(.{
                                        .cpu_arch = .x86_64,
                                        .os_tag = .uefi,
                                        .abi = .msvc,
                                        });
                                                            
                                executable.setOutputDir(cache_dir);
                                executable.addPackage(lib_package);
                                executable.addPackage(privileged_package);
                                executable.strip = true;
                                executable.setBuildMode(.ReleaseSafe);
                                try bootloader_executables.append(executable);
                            },
                    }
                },
                else => @compileError("Architecture not supported"),
            }
        },
            .limine => {
                const executable = builder.addExecutable("limine", "src/bootloader/limine/limine.zig");
                executable.setTarget(get_target(.x86_64, .privileged));
                executable.setOutputDir(cache_dir);
                executable.addPackage(lib_package);
                executable.addPackage(privileged_package);
                
                try bootloader_executables.append(executable);
            },
    }

    const bootloader_build = .{
        .executables = bootloader_executables.items,
    };

    for (bootloader_build.executables) |executable| {
        builder.default_step.dependOn(&executable.step);
    }

    return bootloader_build;
}

fn createCPUDriver(builder: *Builder, comptime configuration: Configuration, comptime prefix: []const u8) !*LibExeObjStep {
    const path = "src/cpu_driver/arch/" ++ @tagName(configuration.architecture) ++ "/";
    const cpu_driver = builder.addExecutable(prefix ++ "cpu_driver", path ++ "entry_point.zig");
    const target = get_target(configuration.architecture, .privileged);
    cpu_driver.setTarget(target);
    cpu_driver.setBuildMode(cpu_driver.builder.standardReleaseOptions());
    cpu_driver.setOutputDir(cache_dir);
    cpu_driver.force_pic = true;
    cpu_driver.disable_stack_probing = true;
    cpu_driver.stack_protector = false;
    cpu_driver.strip = false;
    cpu_driver.red_zone = false;
    cpu_driver.omit_frame_pointer = false;
    cpu_driver.entry_symbol_name = "kernel_entry_point";

    cpu_driver.addPackage(lib_package);
    cpu_driver.addPackage(bootloader_package);
    cpu_driver.addPackage(rise_package);
    cpu_driver.addPackage(privileged_package);

    cpu_driver.setMainPkgPath(source_root_dir);
    cpu_driver.setLinkerScriptPath(FileSource.relative(path ++ "linker_script.ld"));

    switch (configuration.architecture) {
        .x86_64 => {
            cpu_driver.code_model = .kernel;
        },
        else => @compileError("Architecture not supported"),
    }

    builder.default_step.dependOn(&cpu_driver.step);
    
    return cpu_driver;
}

fn createDiskImageBuilder(builder: *Builder) *LibExeObjStep {
    const disk_image_builder = builder.addExecutable("disk_image_builder", "src/disk_image_builder.zig");
    disk_image_builder.setOutputDir(cache_dir);
    disk_image_builder.setBuildMode(builder.standardReleaseOptions());
    builder.default_step.dependOn(&disk_image_builder.step);

    return disk_image_builder;
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

//     fn create_run_and_debug_steps(kernel: *Kernel) !void {
//         var gdb_script_buffer = host.ArrayList(u8).init(kernel.builder.allocator);
//         switch (kernel.options.arch) {
//             .x86, .x86_64 => try gdb_script_buffer.appendSlice("set disassembly-flavor intel\n"),
//             else => return Error.not_implemented,
//         }
//
//         const gdb_script_chunk = if (kernel.options.is_virtualizing())
//             \\symbol-file zig-cache/kernel.elf
//             \\target remote localhost:1234
//             \\c
//         else
//             \\symbol-file zig-cache/kernel.elf
//             \\target remote localhost:1234
//             \\b *0xa3b9
//             \\c
//             ;
//
//         try gdb_script_buffer.appendSlice(gdb_script_chunk);
//
//         kernel.gdb_script = kernel.builder.addWriteFile("gdb_script", gdb_script_buffer.items);
//         kernel.builder.default_step.dependOn(&kernel.gdb_script.step);
//
//         // We need a member variable because we need consistent memory around it to do @fieldParentPtr
//         kernel.debug_step = host.build.Step.init(.custom, "_debug_", kernel.builder.allocator, do_debug_step);
//         //kernel.debug_step.dependOn(&kernel.boot_image_step);
//         kernel.debug_step.dependOn(&kernel.gdb_script.step);
//         //kernel.debug_step.dependOn(&kernel.disk_step);
//         kernel.debug_step.dependOn(&kernel.disk_image_builder_run_step.step);
//
//         const debug_step = kernel.builder.step("debug", "Debug the program with QEMU and GDB");
//         debug_step.dependOn(&kernel.debug_step);
//     }
//
// fn do_debug_step(step: *host.build.Step) !void {
//     const kernel = @fieldParentPtr(Kernel, "debug_step", step);
//     const gdb_script_path = kernel.gdb_script.getFileSource(kernel.gdb_script.files.first.?.data.basename).?.getPath(kernel.builder);
//     switch (host.os) {
//         .linux, .macos => {
//             const first_pid = try host.posix.fork();
//             if (first_pid == 0) {
//                 switch (host.os) {
//                     .linux => {
//                         var debugger_process = host.ChildProcess.init(&[_][]const u8{ "gf2", "-x", gdb_script_path }, kernel.builder.allocator);
//                         _ = try debugger_process.spawnAndWait();
//                     },
//                     .macos => {
//                         var debugger_process = host.ChildProcess.init(&[_][]const u8{ "wezterm", "start", "--cwd", kernel.builder.build_root, "--", "x86_64-elf-gdb", "-x", gdb_script_path }, kernel.builder.allocator);
//                         _ = try debugger_process.spawnAndWait();
//                     },
//                     else => @compileError("OS not supported"),
//                 }
//             } else {
//                 var qemu_process = host.ChildProcess.init(kernel.debug_argument_list.items, kernel.builder.allocator);
//                 try qemu_process.spawn();
//
//                 _ = host.posix.waitpid(first_pid, 0);
//                 _ = try qemu_process.kill();
//             }
//         },
//         else => @panic("todo implement"),
//     }
// }
//
// const Limine = struct {
//     const base_path = "src/bootloader/limine";
//     const installables_path = base_path ++ "/installables";
//     const image_path = cache_dir ++ "universal.iso";
//     const installer = @import("src/bootloader/limine/installer.zig");
// };

fn get_target(comptime asked_arch: Cpu.Arch, comptime execution_mode: host.TraditionalExecutionMode) CrossTarget {
    var enabled_features = Cpu.Feature.Set.empty;
    var disabled_features = Cpu.Feature.Set.empty;

    if (execution_mode == .privileged) {
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
