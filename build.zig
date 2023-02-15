const std = @import("std");
const common = @import("src/common.zig");

// Build types
const Builder = std.Build.Builder;
const CompileStep = std.build.CompileStep;
const FileSource = std.Build.FileSource;
const RunStep = std.Build.RunStep;
const Step = std.Build.Step;

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

const Configuration = struct {
    bootloader: Bootloader,
    architecture: Cpu.Arch,
    boot_protocol: Bootloader.Protocol,

    pub fn getSuffix(configuration: Configuration, builder: *Builder) ![]const u8 {
        return try std.mem.concat(builder.allocator, u8, &.{ "_", @tagName(configuration.bootloader), "_", @tagName(configuration.architecture), "_", @tagName(configuration.boot_protocol) });
    }
};

const default_configuration = Configuration{
    .bootloader = .limine,
    .architecture = .x86_64,
    .boot_protocol = .uefi,
};

const default_emulator = .qemu;
const entry_point_name = "entryPoint";

pub fn build(builder: *Builder) !void {
    const ci = builder.option(bool, "ci", "CI mode") orelse false;
    _ = ci;

    const disk_image_builder = createDiskImageBuilder(builder);

    const build_steps = blk: {
        var architecture_steps = std.ArrayList(ArchitectureSteps).init(builder.allocator);

        for (common.supported_architectures) |architecture, architecture_index| {
            const cpu_driver = try createCPUDriver(builder, architecture, false);
            // const cpu_driver_test = try createCPUDriver(builder, architecture, true);
            _ = cpu_driver;
            const bootloaders = common.architecture_bootloader_map[architecture_index];
            var bootloader_steps = std.ArrayList(BootloaderSteps).init(builder.allocator);

            for (bootloaders) |bootloader| {
                const bootloader_id = bootloader.id;
                var protocol_steps = std.ArrayList(BootProtocolSteps).init(builder.allocator);

                for (bootloader.protocols) |protocol| {
                    var emulator_steps = std.ArrayList(EmulatorSteps).init(builder.allocator);
                    const configuration = .{
                        .bootloader = bootloader_id,
                        .architecture = architecture,
                        .boot_protocol = protocol,
                    };
                    const bootloader_build = try createBootloader(builder, configuration);
                    _ = bootloader_build;

                    const emulators = try getEmulators(configuration);

                    for (emulators) |emulator| {
                        const emulator_step = try EmulatorSteps.create(builder, &emulator_steps, configuration, emulator);
                        emulator_step.run.dependOn(builder.default_step);
                        emulator_step.debug.dependOn(builder.default_step);
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

    const default_step = try DefaultStep.create(builder);
    default_step.run.dependOn(builder.default_step);
    default_step.debug.dependOn(builder.default_step);

    const test_step = builder.step("test", "Run unit tests");

    const native_tests = [_]struct { name: []const u8, zig_source_file: []const u8 }{
        .{ .name = "lib", .zig_source_file = "src/lib.zig" },
        .{ .name = disk_image_builder.name, .zig_source_file = "src/disk_image_builder.zig" },
    };

    for (native_tests) |native_test| {
        const test_exe = builder.addTest(.{
            .name = native_test.name,
            .root_source_file = FileSource.relative(native_test.zig_source_file),
            .kind = .test_exe,
        });
        test_exe.setOutputDir("zig-cache");
        // TODO: do this properly
        if (std.mem.eql(u8, native_test.name, disk_image_builder.name)) {
            test_exe.addIncludePath("src/bootloader/limine/installables");
            test_exe.addCSourceFile("src/bootloader/limine/installables/limine-deploy.c", &.{});
            test_exe.linkLibC();
        }
        const run_test_step = test_exe.run();
        test_step.dependOn(&run_test_step.step);
    }
}

pub const DefaultStep = struct {
    configuration: Configuration,
    emulator: Emulator,
    fn create(builder: *Builder) !*EmulatorSteps {
        const step = try builder.allocator.create(EmulatorSteps);
        step.* = .{
            .builder = builder,
            .run = Step.init(.custom, "_run_", builder.allocator, run),
            .debug = Step.init(.custom, "_debug_", builder.allocator, debug),
            .gdb_script = Step.init(.custom, "_gdb_script_", builder.allocator, gdbScript),
            .configuration = undefined,
            .emulator = undefined,
        };

        step.debug.dependOn(&step.gdb_script);

        const run_step = builder.step("run", "Run the operating system through an emulator");
        const debug_step = builder.step("debug", "Debug the operating system through an emulator");
        run_step.dependOn(&step.run);
        debug_step.dependOn(&step.debug);

        return step;
    }

    fn run(step: *Step) !void {
        const default_step = @fieldParentPtr(EmulatorSteps, "run", step);
        const default = try readConfigFromFile(default_step.builder);
        default_step.configuration = default.configuration;
        default_step.emulator = default.emulator;
        try EmulatorSteps.run(step);
    }

    fn debug(step: *Step) !void {
        const default_step = @fieldParentPtr(EmulatorSteps, "debug", step);
        const default = try readConfigFromFile(default_step.builder);
        default_step.configuration = default.configuration;
        default_step.emulator = default.emulator;
        try EmulatorSteps.debug(step);
    }

    fn gdbScript(step: *Step) !void {
        const default_step = @fieldParentPtr(EmulatorSteps, "gdb_script", step);
        const default = try readConfigFromFile(default_step.builder);
        default_step.configuration = default.configuration;
        default_step.emulator = default.emulator;
        try EmulatorSteps.gdbScript(step);
    }

    fn readConfigFromFile(builder: *Builder) !DefaultStep {
        const config_file = try std.fs.cwd().readFileAlloc(builder.allocator, "config/default.json", std.math.maxInt(usize));
        var token_stream = std.json.TokenStream.init(config_file);
        return try std.json.parse(DefaultStep, &token_stream, .{ .allocator = builder.allocator });
    }
};

pub fn getEmulators(configuration: Configuration) ![]const Emulator {
    return switch (configuration.bootloader) {
        .rise, .limine => switch (configuration.architecture) {
            .x86_64 => switch (configuration.boot_protocol) {
                .bios => &.{.qemu},
                .uefi => &.{.qemu},
            },
            else => return Error.architecture_not_supported,
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
    configuration: Configuration,
    emulator: Emulator,
    run: Step,
    debug: Step,
    gdb_script: Step,

    fn getGDBScriptPath(builder: *Builder, configuration: Configuration) ![]const u8 {
        return try std.mem.concat(builder.allocator, u8, &.{ "zig-cache/gdb_script_", @tagName(configuration.bootloader), "_", @tagName(configuration.architecture), "_", @tagName(configuration.boot_protocol) });
    }

    fn create(builder: *Builder, list: *std.ArrayList(EmulatorSteps), configuration: Configuration, emulator: Emulator) !*EmulatorSteps {
        const new_one = try list.addOne();
        new_one.* = .{
            .builder = builder,
            .configuration = configuration,
            .emulator = emulator,
            .run = Step.init(.custom, "_run_", builder.allocator, run),
            .debug = Step.init(.custom, "_debug_", builder.allocator, debug),
            .gdb_script = Step.init(.custom, "_gdb_script_", builder.allocator, gdbScript),
        };

        new_one.debug.dependOn(&new_one.gdb_script);

        const suffix = try std.mem.concat(builder.allocator, u8, &.{ try configuration.getSuffix(builder), "_", @tagName(emulator) });

        const run_step = builder.step(try std.mem.concat(builder.allocator, u8, &.{ "run", suffix }), "Run the operating system through an emulator");
        const debug_step = builder.step(try std.mem.concat(builder.allocator, u8, &.{ "debug", suffix }), "Debug the operating system through an emulator");
        run_step.dependOn(&new_one.run);
        debug_step.dependOn(&new_one.debug);

        return new_one;
    }

    fn run(step: *Step) !void {
        const emulator_steps = @fieldParentPtr(EmulatorSteps, "run", step);
        try runDiskImageBuilder(emulator_steps.builder, emulator_steps.configuration);
        const arguments = try qemuCommon(emulator_steps);
        for (arguments.list.items) |argument| {
            std.log.debug("{s}", .{argument});
        }
        var process = std.ChildProcess.init(arguments.list.items, emulator_steps.builder.allocator);
        _ = try process.spawnAndWait();
    }

    fn debug(step: *Step) !void {
        const emulator_steps = @fieldParentPtr(EmulatorSteps, "debug", step);
        try runDiskImageBuilder(emulator_steps.builder, emulator_steps.configuration);
        const builder = emulator_steps.builder;

        var arguments = try qemuCommon(emulator_steps);

        if (!arguments.config.isVirtualizing(emulator_steps.configuration)) {
            try arguments.list.append("-S");
        }

        try arguments.list.append("-s");

        var qemu_process = std.ChildProcess.init(arguments.list.items, emulator_steps.builder.allocator);
        _ = try qemu_process.spawn();

        const debugger_process_arguments = switch (common.os) {
            .linux => .{ "gf2", "-x", try getGDBScriptPath(builder, emulator_steps.configuration) },
            else => return Error.not_implemented,
        };

        var debugger_process = std.ChildProcess.init(&debugger_process_arguments, builder.allocator);
        _ = try debugger_process.spawnAndWait();
    }

    fn gdbScript(step: *Step) !void {
        const emulator_steps = @fieldParentPtr(EmulatorSteps, "gdb_script", step);
        const builder = emulator_steps.builder;

        var gdb_script_buffer = std.ArrayList(u8).init(builder.allocator);
        switch (emulator_steps.configuration.architecture) {
            .x86_64 => try gdb_script_buffer.appendSlice("set disassembly-flavor intel\n"),
            else => return Error.architecture_not_supported,
        }

        try gdb_script_buffer.appendSlice(try std.mem.concat(builder.allocator, u8, &.{ "symbol-file zig-cache/cpu_driver_", @tagName(emulator_steps.configuration.architecture), "\n" }));
        try gdb_script_buffer.appendSlice("target remote localhost:1234\n");

        const base_gdb_script = try std.fs.cwd().readFileAlloc(builder.allocator, "config/gdb_script", common.maxInt(usize));
        try gdb_script_buffer.appendSlice(base_gdb_script);

        try std.fs.cwd().writeFile(try getGDBScriptPath(builder, emulator_steps.configuration), gdb_script_buffer.items);
    }

    fn qemuCommon(emulator_steps: *EmulatorSteps) !struct { config: Arguments, list: std.ArrayList([]const u8) } {
        const builder = emulator_steps.builder;
        const config_file = try readConfig(builder, emulator_steps.emulator);
        var token_stream = std.json.TokenStream.init(config_file);
        const arguments = try std.json.parse(Arguments, &token_stream, .{ .allocator = builder.allocator });

        var argument_list = std.ArrayList([]const u8).init(builder.allocator);

        // const qemu_executable =  ++ switch (configuration.architecture) {
        //     else => @tagName(configuration.architecture),
        // };
        try argument_list.append(try std.mem.concat(builder.allocator, u8, &.{ "qemu-system-", @tagName(emulator_steps.configuration.architecture) }));

        switch (emulator_steps.configuration.boot_protocol) {
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

        //if (arguments.vga) |vga| {
        //try argument_list.append("-vga");
        //try argument_list.append(@tagName(vga));
        //}

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

        if (arguments.isVirtualizing(emulator_steps.configuration)) {
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

    fn runDiskImageBuilder(builder: *Builder, configuration: Configuration) !void {
        var process = std.ChildProcess.init(&.{ "zig-cache/disk_image_builder", @tagName(configuration.bootloader), @tagName(configuration.architecture), @tagName(configuration.boot_protocol) }, builder.allocator);
        const termination = try process.spawnAndWait();
        switch (termination) {
            .Exited => |exited| if (exited != 0) return Error.failed_to_run,
            else => return Error.failed_to_run,
        }
    }

    const Arguments = struct {
        const VGA = enum {
            std,
            cirrus,
            vmware,
            qxl,
            xenfb,
            tcx,
            cg3,
            virtio,
            none,
        };
        memory: ?struct {
            amount: u64,
            unit: common.SizeUnit,
        },
        virtualize: ?bool,
        vga: ?VGA,
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

        pub fn isVirtualizing(arguments: Arguments, configuration: Configuration) bool {
            return (arguments.virtualize orelse false) and common.cpu.arch == configuration.architecture;
        }
    };
};

fn readConfig(builder: *Builder, emulator: Emulator) ![]const u8 {
    return try std.fs.cwd().readFileAlloc(builder.allocator, try std.mem.concat(builder.allocator, u8, &.{"config/" ++ @tagName(emulator) ++ ".json"}), common.maxInt(usize));
}

const BootloaderBuild = struct {
    executables: []const *CompileStep,
};

const Error = error{
    not_implemented,
    architecture_not_supported,
    failed_to_run,
};

fn createBootloader(builder: *Builder, configuration: Configuration) !BootloaderBuild {
    var bootloader_executables = std.ArrayList(*CompileStep).init(builder.allocator);

    switch (configuration.bootloader) {
        .rise => {
            const rise_loader_path = "src/bootloader/rise/";
            switch (configuration.architecture) {
                .x86_64 => {
                    switch (configuration.boot_protocol) {
                        .bios => {
                            const bootloader_path = rise_loader_path ++ "bios/";

                            const executable = builder.addExecutable(.{
                                .name = try std.mem.concat(builder.allocator, u8, &.{ "loader", try configuration.getSuffix(builder) }),
                                .root_source_file = FileSource.relative(bootloader_path ++ "main.zig"),
                                .target = getTarget(.x86, .privileged),
                                .optimize = .ReleaseSmall,
                            });
                            executable.addAssemblyFile(bootloader_path ++ "assembly.S");
                            executable.setOutputDir(cache_dir);
                            executable.setMainPkgPath("src");
                            executable.setLinkerScriptPath(std.Build.FileSource.relative(bootloader_path ++ "linker_script.ld"));
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
                            executable.setMainPkgPath("src");
                            executable.strip = true;
                            try bootloader_executables.append(executable);
                        },
                    }
                },
                else => return Error.architecture_not_supported,
            }
        },
        .limine => {},
    }

    const bootloader_build = .{
        .executables = bootloader_executables.items,
    };

    for (bootloader_build.executables) |executable| {
        builder.default_step.dependOn(&executable.step);
    }

    return bootloader_build;
}

fn createCPUDriver(builder: *Builder, architecture: Target.Cpu.Arch, is_test: bool) !*CompileStep {
    const cpu_driver_path = "src/cpu_driver/";
    const cpu_driver_source_file = "src/cpu_driver.zig";
    const exe_prefix = if (is_test) "cpu_driver_test_" else "cpu_driver_";
    const exe_name = try std.mem.concat(builder.allocator, u8, &.{ exe_prefix, @tagName(architecture) });

    const cpu_driver_file = FileSource.relative(cpu_driver_source_file);
    const target = getTarget(architecture, .privileged);
    const cpu_driver = if (is_test) builder.addTest(.{
        .name = exe_name,
        .root_source_file = cpu_driver_file,
        .target = target,
        .kind = .test_exe,
    }) else builder.addExecutable(.{
        .name = exe_name,
        .root_source_file = cpu_driver_file,
        .target = target,
        .linkage = .static,
    });
    cpu_driver.setOutputDir(cache_dir);
    cpu_driver.setMainPkgPath(source_root_dir);

    cpu_driver.force_pic = true;
    cpu_driver.disable_stack_probing = true;
    cpu_driver.stack_protector = false;
    cpu_driver.strip = false;
    cpu_driver.red_zone = false;
    cpu_driver.omit_frame_pointer = false;
    cpu_driver.entry_symbol_name = entry_point_name;

    if (is_test) cpu_driver.setTestRunner(cpu_driver_source_file);

    cpu_driver.setLinkerScriptPath(FileSource.relative(cpu_driver_path ++ "arch/" ++ switch (architecture) {
        .x86_64 => "x86/64/",
        .x86 => "x86/32/",
        else => return Error.architecture_not_supported,
    } ++ "linker_script.ld"));

    switch (architecture) {
        .x86_64 => {
            cpu_driver.code_model = .kernel;
        },
        else => return Error.architecture_not_supported,
    }

    builder.default_step.dependOn(&cpu_driver.step);

    return cpu_driver;
}

fn createDiskImageBuilder(builder: *Builder) *CompileStep {
    const disk_image_builder = builder.addExecutable(.{
        .name = "disk_image_builder",
        .root_source_file = FileSource.relative("src/disk_image_builder.zig"),
    });
    disk_image_builder.setOutputDir(cache_dir);
    builder.default_step.dependOn(&disk_image_builder.step);

    return disk_image_builder;
}

fn getTarget(asked_arch: Cpu.Arch, execution_mode: common.TraditionalExecutionMode) CrossTarget {
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
