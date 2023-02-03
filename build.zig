const std = @import("std");
const common = @import("src/common.zig");

// Build types
const Builder = std.build.Builder;
const FileSource = std.build.FileSource;
const LibExeObjStep = std.build.LibExeObjStep;
const RunStep = std.build.RunStep;
const Step = std.build.Step;

const assert = std.debug.assert;
const Bootloader = common.Bootloader;
const Cpu = common.Cpu;
const CrossTarget = common.CrossTarget;
const DiskType = common.DiskType;
const Emulator = common.Emulator;
const FilesystemType = common.FilesystemType;
const Target = common.Target;

const source_root_dir = "src";
const cache_dir = "zig-cache/";
// const kernel_path = cache_dir ++ kernel_name;

const Configuration = struct {
    bootloader: Bootloader,
    architecture: Cpu.Arch,
    boot_protocol: Bootloader.Protocol,
};

const default_configuration = Configuration{
    .bootloader = .limine,
    .architecture = .x86_64,
    .boot_protocol = .bios,
};

const default_emulator = .qemu;
const entry_point_name = "entryPoint";

pub fn build(builder: *Builder) !void {
    const ci = builder.option(bool, "ci", "CI mode") orelse false;
    _ = ci;

    lib_package.dependencies = &.{ lib_package, host_package };
    rise_package.dependencies = &.{ lib_package, rise_package, privileged_package };
    user_package.dependencies = &.{lib_package};
    privileged_package.dependencies = &.{ lib_package, privileged_package, bootloader_package };
    bootloader_package.dependencies = &.{ bootloader_package, lib_package, privileged_package };
    host_package.dependencies = &.{ host_package, lib_package };

    const disk_image_builder = createDiskImageBuilder(builder);

    const build_steps = blk: {
        var architecture_steps = std.ArrayList(ArchitectureSteps).init(builder.allocator);

        inline for (common.supported_architectures) |architecture, architecture_index| {
            const cpu_driver = try createCPUDriver(builder, architecture);
            _ = cpu_driver;
            const bootloaders = common.architecture_bootloader_map[architecture_index];
            var bootloader_steps = std.ArrayList(BootloaderSteps).init(builder.allocator);

            inline for (bootloaders) |bootloader| {
                const bootloader_id = bootloader.id;
                var protocol_steps = std.ArrayList(BootProtocolSteps).init(builder.allocator);

                inline for (bootloader.protocols) |protocol| {
                    var emulator_steps = std.ArrayList(EmulatorSteps).init(builder.allocator);
                    const configuration = .{
                        .bootloader = bootloader_id,
                        .architecture = architecture,
                        .boot_protocol = protocol,
                    };
                    const suffix = "_" ++ @tagName(configuration.bootloader) ++ "_" ++ @tagName(configuration.architecture) ++ "_" ++ @tagName(configuration.boot_protocol);
                    const bootloader_build = try createBootloader(builder, configuration, suffix);
                    _ = bootloader_build;

                    const disk_image_builder_run_step = disk_image_builder.run();
                    disk_image_builder_run_step.addArgs(&.{ @tagName(configuration.bootloader), @tagName(configuration.architecture), @tagName(configuration.boot_protocol) });

                    const emulators = comptime getEmulators(configuration);

                    inline for (emulators) |emulator| {
                        const step_suffix = suffix ++ @tagName(emulator);
                        const emulator_step = try EmulatorSteps.Interface(configuration, emulator, suffix, step_suffix).create(builder, &emulator_steps);
                        emulator_step.run.dependOn(builder.default_step);
                        emulator_step.debug.dependOn(builder.default_step);
                        emulator_step.run.dependOn(&disk_image_builder_run_step.step);
                        emulator_step.debug.dependOn(&disk_image_builder_run_step.step);

                        if (emulator == default_emulator and default_configuration.bootloader == bootloader_id and default_configuration.architecture == architecture and default_configuration.boot_protocol == protocol) {
                            const default_run_step = builder.step("run", "Run " ++ step_suffix);
                            const default_debug_step = builder.step("debug", "Debug " ++ step_suffix);
                            default_run_step.dependOn(&emulator_step.run);
                            default_debug_step.dependOn(&emulator_step.debug);
                        }
                    }

                    try protocol_steps.append(.{ .emulator_steps = emulator_steps.items });
                }

                try bootloader_steps.append(.{ .protocol_steps = protocol_steps.items });
            }

            try architecture_steps.append(.{ .bootloader_steps = bootloader_steps.items });
        }

        break :blk BuildSteps{ .architecture_steps = architecture_steps.items };
    };

    _ = build_steps;

    const test_step = builder.step("test", "Run unit tests");

    const native_tests = [_]struct { name: []const u8, zig_source_file: []const u8 }{
        .{ .name = lib_package.name, .zig_source_file = lib_package.source.path },
    };

    for (native_tests) |native_test| {
        const test_exe = builder.addTest(.{
            .name = native_test.name,
            .root_source_file = FileSource.relative(native_test.zig_source_file),
            .kind = .test_exe,
        });
        test_exe.setOutputDir("zig-cache");
        test_exe.addPackage(lib_package);
        test_exe.addPackage(host_package);
        const run_test_step = test_exe.run();
        test_step.dependOn(&run_test_step.step);
    }
}

pub fn getEmulators(comptime configuration: Configuration) []const Emulator {
    return switch (configuration.bootloader) {
        .rise, .limine => switch (configuration.architecture) {
            .x86_64 => switch (configuration.boot_protocol) {
                .bios => &.{.qemu},
                .uefi => &.{.qemu},
            },
            else => @compileError("Architecture not supported"),
        },
    };
}

const BuildSteps = struct {
    architecture_steps: []const ArchitectureSteps,
};
const ArchitectureSteps = struct {
    bootloader_steps: []const BootloaderSteps,
};

const BootloaderSteps = struct {
    protocol_steps: []const BootProtocolSteps,
};

const BootProtocolSteps = struct {
    emulator_steps: []const EmulatorSteps,
};

const EmulatorSteps = struct {
    builder: *Builder,
    run: Step,
    debug: Step,
    gdb_script: Step,

    fn Interface(comptime configuration: Configuration, comptime emulator: Emulator, comptime suffix: []const u8, comptime step_suffix: []const u8) type {
        const gdb_script_path = "zig-cache/" ++ "gdb_script_" ++ suffix;
        return switch (emulator) {
            .qemu => struct {
                const qemu_executable = "qemu-system-" ++ switch (configuration.architecture) {
                    else => @tagName(configuration.architecture),
                };

                fn create(builder: *Builder, list: *std.ArrayList(EmulatorSteps)) !*EmulatorSteps {
                    const new_one = try list.addOne();
                    new_one.* = .{
                        .builder = builder,
                        .run = Step.init(.custom, "_run_" ++ step_suffix, builder.allocator, run),
                        .debug = Step.init(.custom, "_debug_" ++ step_suffix, builder.allocator, debug),
                        .gdb_script = Step.init(.custom, "_gdb_script_" ++ step_suffix, builder.allocator, gdbScript),
                    };

                    new_one.debug.dependOn(&new_one.gdb_script);

                    const run_step = builder.step("run" ++ step_suffix, "Run the operating system through an emulator");
                    const debug_step = builder.step("debug" ++ step_suffix, "Debug the operating system through an emulator");
                    run_step.dependOn(&new_one.run);
                    debug_step.dependOn(&new_one.debug);

                    return new_one;
                }

                fn run(step: *Step) !void {
                    const emulator_steps = @fieldParentPtr(EmulatorSteps, "run", step);
                    const arguments = try qemuCommon(emulator_steps);
                    for (arguments.list.items) |argument| {
                        std.log.debug("{s}", .{argument});
                    }
                    var process = std.ChildProcess.init(arguments.list.items, emulator_steps.builder.allocator);
                    _ = try process.spawnAndWait();
                }

                fn debug(step: *Step) !void {
                    const emulator_steps = @fieldParentPtr(EmulatorSteps, "debug", step);
                    const builder = emulator_steps.builder;

                    var arguments = try qemuCommon(emulator_steps);

                    if (!arguments.config.isVirtualizing()) {
                        try arguments.list.append("-S");
                    }

                    try arguments.list.append("-s");

                    var qemu_process = std.ChildProcess.init(arguments.list.items, emulator_steps.builder.allocator);
                    _ = try qemu_process.spawn();

                    const debugger_process_arguments = switch (common.os) {
                        .linux => .{ "gf2", "-x", gdb_script_path },
                        else => return Error.not_implemented,
                    };

                    var debugger_process = std.ChildProcess.init(&debugger_process_arguments, builder.allocator);
                    _ = try debugger_process.spawnAndWait();
                }

                fn gdbScript(step: *Step) !void {
                    const emulator_steps = @fieldParentPtr(EmulatorSteps, "gdb_script", step);
                    const builder = emulator_steps.builder;

                    var gdb_script_buffer = std.ArrayList(u8).init(builder.allocator);
                    switch (configuration.architecture) {
                        .x86_64 => try gdb_script_buffer.appendSlice("set disassembly-flavor intel\n"),
                        else => @compileError("Architecture not supported"),
                    }

                    try gdb_script_buffer.appendSlice("symbol-file zig-cache/cpu_driver_" ++ @tagName(configuration.architecture) ++ "\n");
                    try gdb_script_buffer.appendSlice("target remote localhost:1234\n");

                    const base_gdb_script = try std.fs.cwd().readFileAlloc(builder.allocator, "config/gdb_script", common.maxInt(usize));
                    try gdb_script_buffer.appendSlice(base_gdb_script);

                    try std.fs.cwd().writeFile(gdb_script_path, gdb_script_buffer.items);
                }

                fn qemuCommon(emulator_steps: *EmulatorSteps) !struct { config: Arguments, list: std.ArrayList([]const u8) } {
                    const builder = emulator_steps.builder;
                    const config_file = try readConfig(builder, emulator);
                    var token_stream = std.json.TokenStream.init(config_file);
                    const arguments = try std.json.parse(Arguments, &token_stream, .{ .allocator = builder.allocator });

                    var argument_list = std.ArrayList([]const u8).init(builder.allocator);

                    try argument_list.append(qemu_executable);

                    switch (configuration.boot_protocol) {
                        .uefi => try argument_list.appendSlice(&.{ "-bios", "tools/OVMF_CODE-pure-efi.fd" }),
                        else => {},
                    }

                    const image_config = try common.ImageConfig.get(builder.allocator, common.ImageConfig.default_path);
                    const disk_path = try common.concat(builder.allocator, u8, &.{ cache_dir, image_config.image_name });
                    try argument_list.appendSlice(&.{ "-drive", builder.fmt("file={s},index=0,media=disk,format=raw", .{disk_path}) });

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
                        const memory_argument = builder.fmt("{}{c}", .{ memory.amount, @as(u8, switch (memory.unit) {
                            .kilobyte => 'K',
                            .megabyte => 'M',
                            .gigabyte => 'G',
                            else => @panic("Unit too big"),
                        }) });
                        try argument_list.append(memory_argument);
                    }

                    if (arguments.isVirtualizing()) {
                        try argument_list.appendSlice(&.{
                            "-accel",
                            switch (common.os) {
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
                            var log_what = std.ArrayList(u8).init(builder.allocator);

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
                        unit: common.SizeUnit,
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
                        return (arguments.virtualize orelse false) and common.cpu.arch == configuration.architecture;
                    }
                };
            },
        };
    }
};

fn readConfig(builder: *Builder, comptime emulator: Emulator) ![]const u8 {
    const config_file = switch (emulator) {
        else => try std.fs.cwd().readFileAlloc(builder.allocator, "config/" ++ @tagName(emulator) ++ ".json", common.maxInt(usize)),
    };

    return config_file;
}

const BootloaderBuild = struct {
    executables: []const *LibExeObjStep,
};

const Error = error{
    not_implemented,
};

fn createBootloader(builder: *Builder, comptime configuration: Configuration, comptime suffix: []const u8) !BootloaderBuild {
    var bootloader_executables = std.ArrayList(*LibExeObjStep).init(builder.allocator);

    switch (configuration.bootloader) {
        .rise => {
            const rise_loader_path = "src/bootloader/rise/";
            switch (configuration.architecture) {
                .x86_64 => {
                    switch (configuration.boot_protocol) {
                        .bios => {
                            const bootloader_path = rise_loader_path ++ "bios/";

                            const executable = builder.addExecutable(.{
                                .name = "loader" ++ suffix,
                                .root_source_file = FileSource.relative(bootloader_path ++ "main.zig"),
                                .target = getTarget(.x86, .privileged),
                                .optimize = .ReleaseSmall,
                            });
                            executable.addAssemblyFile(bootloader_path ++ "assembly.S");
                            executable.setOutputDir(cache_dir);
                            executable.addPackage(lib_package);
                            executable.addPackage(privileged_package);
                            executable.addPackage(bootloader_package);
                            executable.setLinkerScriptPath(std.build.FileSource.relative(bootloader_path ++ "linker_script.ld"));
                            executable.red_zone = false;
                            executable.link_gc_sections = true;
                            executable.want_lto = true;
                            executable.strip = true;
                            executable.entry_symbol_name = entry_point_name;

                            try bootloader_executables.append(executable);
                        },
                        .uefi => {
                            const executable = builder.addExecutable(.{
                                .name = "BOOTX64",
                                .root_source_file = FileSource.relative(rise_loader_path ++ "uefi/main.zig"),
                                .target = .{
                                    .cpu_arch = .x86_64,
                                    .os_tag = .uefi,
                                    .abi = .msvc,
                                },
                                .optimize = .ReleaseSafe,
                            });
                            executable.setOutputDir(cache_dir);
                            executable.addPackage(lib_package);
                            executable.addPackage(privileged_package);
                            executable.addPackage(bootloader_package);
                            executable.strip = true;
                            try bootloader_executables.append(executable);
                        },
                    }
                },
                else => @compileError("Architecture not supported"),
            }
        },
        .limine => {},
        //     const executable = builder.addExecutable(.{
        //         .name = "loader" ++ suffix,
        //         .root_source_file = FileSource.relative("src/bootloader/limine/limine.zig"),
        //         .target = getTarget(.x86_64, .privileged),
        //     });
        //     executable.setOutputDir(cache_dir);
        //     executable.addPackage(lib_package);
        //     executable.addPackage(privileged_package);
        //
        //     try bootloader_executables.append(executable);
        // },
    }

    const bootloader_build = .{
        .executables = bootloader_executables.items,
    };

    for (bootloader_build.executables) |executable| {
        builder.default_step.dependOn(&executable.step);
    }

    return bootloader_build;
}

fn createCPUDriver(builder: *Builder, comptime architecture: Target.Cpu.Arch) !*LibExeObjStep {
    const cpu_driver_path = "src/cpu_driver/";
    const cpu_driver = builder.addExecutable(.{
        .name = "cpu_driver_" ++ @tagName(architecture),
        .root_source_file = FileSource.relative(cpu_driver_path ++ "entry_point.zig"),
        .target = getTarget(architecture, .privileged),
        .linkage = .static,
    });
    cpu_driver.setOutputDir(cache_dir);
    cpu_driver.force_pic = true;
    cpu_driver.disable_stack_probing = true;
    cpu_driver.stack_protector = false;
    cpu_driver.strip = false;
    cpu_driver.red_zone = false;
    cpu_driver.omit_frame_pointer = false;
    cpu_driver.entry_symbol_name = entry_point_name;

    cpu_driver.addPackage(lib_package);
    cpu_driver.addPackage(bootloader_package);
    cpu_driver.addPackage(rise_package);
    cpu_driver.addPackage(privileged_package);

    cpu_driver.setMainPkgPath(source_root_dir);
    cpu_driver.setLinkerScriptPath(FileSource.relative(cpu_driver_path ++ "arch/" ++ switch (architecture) {
        .x86_64 => "x86/64/",
        .x86 => "x86/32/",
        else => @compileError("Architecture not supported"),
    } ++ "linker_script.ld"));

    switch (architecture) {
        .x86_64 => {
            cpu_driver.code_model = .kernel;
        },
        else => @compileError("Architecture not supported"),
    }

    builder.default_step.dependOn(&cpu_driver.step);

    return cpu_driver;
}

fn createDiskImageBuilder(builder: *Builder) *LibExeObjStep {
    const disk_image_builder = builder.addExecutable(.{
        .name = "disk_image_builder",
        .root_source_file = FileSource.relative("src/disk_image_builder.zig"),
    });
    disk_image_builder.setOutputDir(cache_dir);
    disk_image_builder.addPackage(bootloader_package);
    disk_image_builder.addPackage(lib_package);
    builder.default_step.dependOn(&disk_image_builder.step);

    disk_image_builder.addPackage(host_package);

    return disk_image_builder;
}

var bootloader_package = std.build.Pkg{
    .name = "bootloader",
    .source = std.build.FileSource.relative("src/bootloader.zig"),
};

var host_package = std.build.Pkg{
    .name = "host",
    .source = std.build.FileSource.relative("src/host.zig"),
};

var lib_package = std.build.Pkg{
    .name = "lib",
    .source = std.build.FileSource.relative("src/lib.zig"),
};

var privileged_package = std.build.Pkg{
    .name = "privileged",
    .source = std.build.FileSource.relative("src/privileged.zig"),
};

var rise_package = std.build.Pkg{
    .name = "rise",
    .source = std.build.FileSource.relative("src/rise.zig"),
};

var user_package = std.build.Pkg{
    .name = "user",
    .source = std.build.FileSource.relative("src/user.zig"),
};

fn getTarget(comptime asked_arch: Cpu.Arch, comptime execution_mode: common.TraditionalExecutionMode) CrossTarget {
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
