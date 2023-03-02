const std = @import("std");
const common = @import("src/common.zig");

// Build types
const Build = std.Build;
const CompileStep = std.Build.CompileStep;
const FileSource = std.Build.FileSource;
const Module = std.Build.Module;
const ModuleDependency = std.Build.ModuleDependency;
const RunStep = std.Build.RunStep;
const Step = std.Build.Step;

const assert = std.debug.assert;
const Bootloader = common.Bootloader;
const Configuration = common.Configuration;
const Cpu = common.Cpu;
const CrossTarget = common.CrossTarget;
const DiskType = common.DiskType;
const ExecutionType = common.ExecutionType;
const ExecutableKind = common.ExecutableKind;
const ExecutionEnvironment = common.ExecutionEnvironment;
const FilesystemType = common.FilesystemType;
const OptimizeMode = common.OptimizeMode;
const Suffix = common.Suffix;
const Target = common.Target;

const BuildSteps = struct {
    build_all: *Step,
    build_all_tests: *Step,
    debug: *Step,
    run: *Step,
    test_step: *Step,
    test_debug: *Step,
    test_all: *Step,
};

var ci = false;
var modules = Modules{};
var b: *Build = undefined;
var build_steps: *BuildSteps = undefined;
var default_configuration: Configuration = undefined;

pub fn build(b_arg: *Build) !void {
    b = b_arg;
    ci = b.option(bool, "ci", "CI mode") orelse false;
    const default_cfg_override = b.option([]const u8, "default", "Default configuration JSON file") orelse "config/default.json";
    modules = try Modules.new();

    default_configuration = blk: {
        const default_json_file = try std.fs.cwd().readFileAlloc(b.allocator, default_cfg_override, common.maxInt(usize));
        var token_stream = std.json.TokenStream.init(default_json_file);
        const cfg = try std.json.parse(Configuration, &token_stream, .{ .allocator = b.allocator });

        break :blk Configuration{
            .architecture = b.standardTargetOptions(.{ .default_target = .{ .cpu_arch = cfg.architecture } }).getCpuArch(),
            .bootloader = cfg.bootloader,
            .boot_protocol = cfg.boot_protocol,
            .execution_environment = cfg.execution_environment,
            .optimize_mode = b.standardOptimizeOption(.{ .preferred_optimize_mode = cfg.optimize_mode }),
            .execution_type = cfg.execution_type,
            .executable_kind = .normal_exe,
        };
    };

    build_steps = try b.allocator.create(BuildSteps);
    build_steps.* = .{
        .build_all = b.step("all", "Build all the artifacts"),
        .build_all_tests = b.step("all_tests", "Build all the artifacts related to tests"),
        .run = b.step("run", "Run the operating system through an emulator"),
        .debug = b.step("debug", "Debug the operating system through an emulator"),
        .test_step = b.step("test", "Run unit tests"),
        .test_debug = b.step("test_debug", "Debug unit tests"),
        .test_all = b.step("test_all", "Run all unit tests"),
    };

    const disk_image_builder = blk: {
        const exe = b.addExecutable(.{
            .name = "disk_image_builder",
            .root_source_file = FileSource.relative("src/disk_image_builder.zig"),
        });
        exe.setOutputDir(cache_dir);

        modules.addModule(exe, .lib);
        modules.addModule(exe, .host);
        modules.addModule(exe, .bootloader);

        b.default_step.dependOn(&exe.step);

        break :blk exe;
    };
    build_steps.build_all.dependOn(&disk_image_builder.step);

    const native_tests = [_]struct { name: []const u8, zig_source_file: []const u8, modules: []const ModuleID }{
        .{ .name = "host_test", .zig_source_file = "src/host_test.zig", .modules = &.{ .lib, .host } },
        .{ .name = "disk_image_builder_test", .zig_source_file = "src/disk_image_builder.zig", .modules = &.{ .lib, .host } },
    };

    for (common.enumValues(OptimizeMode)) |optimize_mode| {
        for (native_tests) |native_test| {
            const test_exe = b.addTest(.{
                .name = try std.mem.concat(b.allocator, u8, &.{ native_test.name, "_", @tagName(optimize_mode) }),
                .root_source_file = FileSource.relative(native_test.zig_source_file),
                .kind = .test_exe,
                .optimize = optimize_mode,
            });
            test_exe.setOutputDir("zig-cache");
            // TODO: do this properly
            if (std.mem.eql(u8, native_test.name, "disk_image_builder_test")) {
                test_exe.addIncludePath("src/bootloader/limine/installables");
                test_exe.addCSourceFile("src/bootloader/limine/installables/limine-deploy.c", &.{});
                test_exe.linkLibC();
            }

            for (native_test.modules) |module_id| {
                modules.addModule(test_exe, module_id);
            }

            const run_test_step = test_exe.run();
            run_test_step.condition = .always;
            build_steps.test_all.dependOn(&run_test_step.step);
            build_steps.build_all_tests.dependOn(&test_exe.step);
        }
    }

    for (common.enumValues(OptimizeMode)) |optimize_mode| {
        for (common.supported_architectures, 0..) |architecture, architecture_index| {
            try prepareArchitectureCompilation(architecture_index, .emulated, optimize_mode, disk_image_builder);
            if (architecture == common.cpu.arch) {
                if (canVirtualizeWithQEMU(architecture)) {
                    try prepareArchitectureCompilation(architecture_index, .accelerated, optimize_mode, disk_image_builder);
                }
            }
        }
    }
}

fn prepareArchitectureCompilation(architecture_index: usize, execution_type: ExecutionType, optimize_mode: OptimizeMode, disk_image_builder: *CompileStep) !void {
    const architecture = common.supported_architectures[architecture_index];

    const cpu_driver = try createCPUDriver(architecture, optimize_mode, .normal_exe);
    build_steps.build_all.dependOn(&cpu_driver.step);
    const cpu_driver_test = try createCPUDriver(architecture, optimize_mode, .test_exe);
    build_steps.build_all_tests.dependOn(&cpu_driver_test.step);

    const bootloaders = common.architecture_bootloader_map[architecture_index];
    for (bootloaders) |bootloader_struct| {
        const bootloader = bootloader_struct.id;
        for (bootloader_struct.protocols) |protocol| {
            const rise_loader_path = "src/bootloader/rise/";
            const bootloader_name = try Suffix.bootloader.fromConfiguration(b.allocator, .{
                .architecture = architecture,
                .bootloader = bootloader,
                .boot_protocol = protocol,
                // dummy fields
                .execution_environment = undefined,
                .optimize_mode = undefined,
                .execution_type = undefined,
                .executable_kind = undefined,
            }, "bootloader_");

            const maybe_bootloader_compile_step: ?*CompileStep = switch (bootloader) {
                .rise => switch (protocol) {
                    .bios => switch (architecture) {
                        .x86_64 => blk: {
                            const bootloader_path = rise_loader_path ++ "bios/";
                            const executable = b.addExecutable(.{
                                .name = bootloader_name,
                                .root_source_file = FileSource.relative(bootloader_path ++ "main.zig"),
                                .target = try getTarget(.x86, .privileged),
                                .optimize = .ReleaseSmall,
                            });
                            executable.addAssemblyFile("src/bootloader/arch/x86/64/smp_trampoline.S");
                            executable.addAssemblyFile(bootloader_path ++ "unreal_mode.S");
                            executable.setLinkerScriptPath(FileSource.relative(bootloader_path ++ "linker_script.ld"));
                            executable.entry_symbol_name = entry_point_name;
                            executable.code_model = .small;

                            break :blk executable;
                        },
                        else => return Error.architecture_not_supported,
                    },
                    .uefi => blk: {
                        const executable = b.addExecutable(.{
                            .name = bootloader_name,
                            .root_source_file = FileSource.relative(rise_loader_path ++ "uefi/main.zig"),
                            .target = .{
                                .cpu_arch = architecture,
                                .os_tag = .uefi,
                                .abi = .msvc,
                            },
                            .optimize = .ReleaseSafe,
                        });

                        switch (architecture) {
                            .x86_64 => executable.addAssemblyFile("src/bootloader/arch/x86/64/smp_trampoline.S"),
                            else => {},
                        }

                        break :blk executable;
                    },
                },
                .limine => null,
            };

            if (maybe_bootloader_compile_step) |bootloader_compile_step| {
                bootloader_compile_step.setOutputDir(cache_dir);
                bootloader_compile_step.setMainPkgPath("src");

                bootloader_compile_step.red_zone = false;
                bootloader_compile_step.link_gc_sections = true;
                bootloader_compile_step.want_lto = true;
                bootloader_compile_step.strip = true;

                modules.addModule(bootloader_compile_step, .lib);
                modules.addModule(bootloader_compile_step, .bootloader);
                modules.addModule(bootloader_compile_step, .privileged);

                if (default_configuration.architecture == architecture and default_configuration.optimize_mode == optimize_mode and default_configuration.bootloader == bootloader and default_configuration.boot_protocol == protocol) {
                    b.default_step.dependOn(&bootloader_compile_step.step);
                }

                build_steps.build_all.dependOn(&bootloader_compile_step.step);
            }

            const execution_environments: []const ExecutionEnvironment = switch (bootloader) {
                .rise, .limine => switch (protocol) {
                    .bios => switch (architecture) {
                        .x86_64 => &.{.qemu},
                        else => return Error.architecture_not_supported,
                    },
                    .uefi => &.{.qemu},
                },
            };

            for (execution_environments) |execution_environment| {
                const configuration = Configuration{
                    .architecture = architecture,
                    .bootloader = bootloader,
                    .boot_protocol = protocol,
                    .optimize_mode = optimize_mode,
                    .execution_environment = execution_environment,
                    .execution_type = execution_type,
                    .executable_kind = .normal_exe,
                };

                const run_steps = try b.allocator.create(RunSteps);
                const suffix = try Suffix.complete.fromConfiguration(b.allocator, configuration, null);
                var test_configuration = configuration;
                test_configuration.executable_kind = .test_exe;
                const test_suffix = try Suffix.complete.fromConfiguration(b.allocator, test_configuration, null);

                run_steps.* = .{
                    .configuration = configuration,
                    .run = Step.init(.custom, "_run_", b.allocator, RunSteps.run),
                    .debug = Step.init(.custom, "_debug_", b.allocator, RunSteps.debug),
                    .gdb_script = Step.init(.custom, "_gdb_script_", b.allocator, RunSteps.gdbScript),
                    .disk_image_builder = disk_image_builder.run(),
                    .test_run = Step.init(.custom, "_test_run_", b.allocator, RunSteps.run),
                    .test_debug = Step.init(.custom, "_test_debug_", b.allocator, RunSteps.debug),
                    .test_gdb_script = Step.init(.custom, "_test_gdb_script_", b.allocator, RunSteps.gdbScript),
                    .test_disk_image_builder = disk_image_builder.run(),
                };

                const normal_setup = .{ .cpu_driver = cpu_driver, .bootloader_step = maybe_bootloader_compile_step, .disk_image_builder = disk_image_builder, .disk_image_builder_run = run_steps.disk_image_builder };
                const test_setup = .{ .cpu_driver = cpu_driver_test, .bootloader_step = maybe_bootloader_compile_step, .disk_image_builder = disk_image_builder, .disk_image_builder_run = run_steps.test_disk_image_builder };
                try run_steps.createStep("run", normal_setup, suffix);
                try run_steps.createStep("debug", normal_setup, suffix);

                inline for (common.fields(Configuration)) |field| {
                    run_steps.disk_image_builder.addArg(@tagName(@field(configuration, field.name)));
                }

                try run_steps.createStep("test_run", test_setup, test_suffix);
                try run_steps.createStep("test_debug", test_setup, test_suffix);

                inline for (common.fields(Configuration)) |field| {
                    run_steps.test_disk_image_builder.addArg(@tagName(@field(test_configuration, field.name)));
                }

                run_steps.debug.dependOn(&run_steps.gdb_script);
                run_steps.test_debug.dependOn(&run_steps.test_gdb_script);

                if (architecture == .x86_64) build_steps.test_all.dependOn(&run_steps.test_run);

                if (std.meta.eql(configuration, default_configuration)) {
                    build_steps.run.dependOn(&run_steps.run);
                    build_steps.debug.dependOn(&run_steps.debug);
                    build_steps.test_step.dependOn(&run_steps.test_run);
                    build_steps.test_debug.dependOn(&run_steps.test_debug);
                }
            }
        }
    }
}

fn canVirtualizeWithQEMU(architecture: Cpu.Arch) bool {
    if (architecture != common.cpu.arch) return false;
    if (ci) return false;

    return switch (common.os) {
        .linux => true,
        .macos, .windows => false,
        else => @compileError("Operating system not supported"),
    };
}

const ModuleID = enum {
    lib,
    host,
    bootloader,
    privileged,
    cpu,
};

pub const Modules = struct {
    modules: std.EnumArray(ModuleID, *Module) = std.EnumArray(ModuleID, *Module).initUndefined(),
    dependencies: std.EnumArray(ModuleID, []const ModuleDependency) = std.EnumArray(ModuleID, []const ModuleDependency).initUndefined(),

    fn new() !Modules {
        var mods = Modules{};
        inline for (comptime common.enumValues(ModuleID)) |module_id| {
            mods.modules.set(module_id, b.createModule(.{ .source_file = FileSource.relative("src/" ++ @tagName(module_id) ++ ".zig") }));
        }

        try mods.setDependencies(.lib, &.{});
        try mods.setDependencies(.host, &.{.lib});
        try mods.setDependencies(.bootloader, &.{ .lib, .privileged });
        try mods.setDependencies(.privileged, &.{ .lib, .bootloader });
        try mods.setDependencies(.cpu, &.{ .privileged, .lib, .bootloader });

        return mods;
    }

    fn addModule(mods: Modules, compile_step: *CompileStep, module_id: ModuleID) void {
        compile_step.addModule(@tagName(module_id), mods.modules.get(module_id));
    }

    fn setDependencies(mods: Modules, module_id: ModuleID, dependencies: []const ModuleID) !void {
        const module = mods.modules.get(module_id);
        try module.dependencies.put(@tagName(module_id), module);

        for (dependencies) |dependency_id| {
            const dependency_module = mods.modules.get(dependency_id);
            try module.dependencies.put(@tagName(dependency_id), dependency_module);
        }
    }
};

const source_root_dir = "src";
const cache_dir = "zig-cache/";
const entry_point_name = "entryPoint";

const RunSteps = struct {
    configuration: Configuration,
    run: Step,
    debug: Step,
    gdb_script: Step,
    disk_image_builder: *RunStep,
    test_run: Step,
    test_debug: Step,
    test_gdb_script: Step,
    test_disk_image_builder: *RunStep,

    fn getGDBScriptPath(configuration: Configuration) ![]const u8 {
        return try std.mem.concat(b.allocator, u8, &.{ "zig-cache/gdb_script_", @tagName(configuration.bootloader), "_", @tagName(configuration.architecture), "_", @tagName(configuration.boot_protocol) });
    }

    const RunStepsSetup = struct {
        cpu_driver: *CompileStep,
        bootloader_step: ?*CompileStep,
        disk_image_builder: *CompileStep,
        disk_image_builder_run: *RunStep,
    };

    fn createStep(run_steps: *RunSteps, comptime step: []const u8, setup: RunStepsSetup, suffix: []const u8) !void {
        if (setup.bootloader_step) |bs| {
            @field(run_steps, step).dependOn(&bs.step);
        }
        @field(run_steps, step).dependOn(&setup.cpu_driver.step);
        @field(run_steps, step).dependOn(&setup.disk_image_builder.step);
        @field(run_steps, step).dependOn(&setup.disk_image_builder_run.step);
        const final_step = b.step(try std.mem.concat(b.allocator, u8, &.{ step, "_", suffix }), "Run the operating system through an emulator");
        final_step.dependOn(&@field(run_steps, step));
    }

    const RunError = error{
        failure,
    };

    fn run(step: *Step) !void {
        const is_test = std.mem.containsAtLeast(u8, step.name, 1, "test");
        const run_steps = switch (is_test) {
            true => @fieldParentPtr(RunSteps, "test_run", step),
            false => @fieldParentPtr(RunSteps, "run", step),
        };

        for (step.dependencies.items) |dependency| {
            common.log.debug("Dep: {s}", .{dependency.name});
        }
        const is_debug = false;
        const arguments = try qemuCommon(run_steps, .{ .is_debug = is_debug, .is_test = is_test });
        for (arguments.list.items) |argument| {
            std.log.debug("{s}", .{argument});
        }

        var process = std.ChildProcess.init(arguments.list.items, b.allocator);

        switch (try process.spawnAndWait()) {
            .Exited => |exit_code| {
                std.log.debug("Exit code: 0x{x}", .{exit_code});
                if (exit_code & 1 == 0) {
                    return RunError.failure;
                }

                const mask = common.maxInt(@TypeOf(exit_code)) - 1;
                const masked_exit_code = exit_code & mask;

                if (masked_exit_code == 0) {
                    return RunError.failure;
                }

                const qemu_exit_code = @intToEnum(common.QEMU.ExitCode, masked_exit_code >> 1);

                if (qemu_exit_code != .success) {
                    common.log.err("QEMU exit code: {s}", .{@tagName(qemu_exit_code)});
                    return RunError.failure;
                }
            },
            else => return RunError.failure,
        }
    }

    fn debug(step: *Step) !void {
        const is_test = std.mem.containsAtLeast(u8, step.name, 1, "test");
        const run_steps = switch (is_test) {
            true => @fieldParentPtr(RunSteps, "test_debug", step),
            false => @fieldParentPtr(RunSteps, "debug", step),
        };

        const is_debug = true;
        var arguments = try qemuCommon(run_steps, .{ .is_debug = is_debug, .is_test = is_test });

        if (!(run_steps.configuration.execution_type == .accelerated or (arguments.config.virtualize orelse false))) {
            try arguments.list.append("-S");
        }

        try arguments.list.append("-s");

        const debugger_process_arguments = switch (common.os) {
            .linux => .{ "kitty", "gdb", "-x", try getGDBScriptPath(run_steps.configuration) },
            else => return Error.not_implemented,
        };

        var debugger_process = std.ChildProcess.init(&debugger_process_arguments, b.allocator);
        _ = try debugger_process.spawn();

        var qemu_process = std.ChildProcess.init(arguments.list.items, b.allocator);
        _ = try qemu_process.spawnAndWait();
    }

    fn gdbScript(step: *Step) !void {
        const is_test = std.mem.containsAtLeast(u8, step.name, 1, "test");
        const run_steps = switch (is_test) {
            true => @fieldParentPtr(RunSteps, "test_gdb_script", step),
            false => @fieldParentPtr(RunSteps, "gdb_script", step),
        };

        var gdb_script_buffer = std.ArrayList(u8).init(b.allocator);
        const architecture = run_steps.configuration.architecture;
        common.log.debug("Architecture: {}", .{architecture});
        switch (architecture) {
            .x86_64 => try gdb_script_buffer.appendSlice("set disassembly-flavor intel\n"),
            else => return Error.architecture_not_supported,
        }

        var test_configuration = run_steps.configuration;
        test_configuration.executable_kind = .test_exe;

        try gdb_script_buffer.appendSlice(try std.mem.concat(b.allocator, u8, &.{ "symbol-file zig-cache/cpu_driver_", try Suffix.cpu_driver.fromConfiguration(b.allocator, if (is_test) test_configuration else run_steps.configuration, null), "\n" }));
        try gdb_script_buffer.appendSlice("target remote localhost:1234\n");

        const base_gdb_script = try std.fs.cwd().readFileAlloc(b.allocator, "config/gdb_script", common.maxInt(usize));
        try gdb_script_buffer.appendSlice(base_gdb_script);

        try std.fs.cwd().writeFile(try getGDBScriptPath(run_steps.configuration), gdb_script_buffer.items);
    }

    const QEMUOptions = packed struct {
        is_test: bool,
        is_debug: bool,
    };

    fn qemuCommon(run_steps: *RunSteps, options: QEMUOptions) !struct { config: Arguments, list: std.ArrayList([]const u8) } {
        const config_file = try std.fs.cwd().readFileAlloc(b.allocator, try std.mem.concat(b.allocator, u8, &.{"config/" ++ @tagName(run_steps.configuration.execution_environment) ++ ".json"}), common.maxInt(usize));
        var token_stream = std.json.TokenStream.init(config_file);
        const arguments = try std.json.parse(Arguments, &token_stream, .{ .allocator = b.allocator });

        var argument_list = std.ArrayList([]const u8).init(b.allocator);

        try argument_list.append(try std.mem.concat(b.allocator, u8, &.{ "qemu-system-", @tagName(run_steps.configuration.architecture) }));

        if (options.is_test and !options.is_debug) {
            try argument_list.appendSlice(&.{ "-device", b.fmt("isa-debug-exit,iobase=0x{x:0>2},iosize=0x{x:0>2}", .{ common.QEMU.isa_debug_exit.io_base, common.QEMU.isa_debug_exit.io_size }) });
        }

        switch (run_steps.configuration.boot_protocol) {
            .uefi => try argument_list.appendSlice(&.{ "-bios", "tools/OVMF_CODE-pure-efi.fd" }),
            else => {},
        }

        var test_configuration = run_steps.configuration;
        test_configuration.executable_kind = .test_exe;

        const image_config = try common.ImageConfig.get(b.allocator, common.ImageConfig.default_path);
        const disk_image_path = try std.mem.concat(b.allocator, u8, &.{ "zig-cache/", image_config.image_name, try Suffix.image.fromConfiguration(b.allocator, if (options.is_test) test_configuration else run_steps.configuration, "_"), ".hdd" });
        try argument_list.appendSlice(&.{ "-drive", b.fmt("file={s},index=0,media=disk,format=raw", .{disk_image_path}) });

        try argument_list.append("-no-reboot");

        if (!options.is_test) {
            try argument_list.append("-no-shutdown");
        }

        if (ci) {
            try argument_list.appendSlice(&.{ "-display", "none" });
        }

        //if (arguments.vga) |vga| {
        //try argument_list.append("-vga");
        //try argument_list.append(@tagName(vga));
        //}

        if (arguments.smp) |smp| {
            try argument_list.append("-smp");
            const smp_string = b.fmt("{}", .{smp});
            try argument_list.append(smp_string);
        }

        if (arguments.debugcon) |debugcon| {
            try argument_list.append("-debugcon");
            try argument_list.append(@tagName(debugcon));
        }

        if (arguments.memory) |memory| {
            try argument_list.append("-m");
            const memory_argument = b.fmt("{}{c}", .{ memory.amount, @as(u8, switch (memory.unit) {
                .kilobyte => 'K',
                .megabyte => 'M',
                .gigabyte => 'G',
                else => @panic("Unit too big"),
            }) });
            try argument_list.append(memory_argument);
        }

        if (canVirtualizeWithQEMU(run_steps.configuration.architecture) and (run_steps.configuration.execution_type == .accelerated or (arguments.virtualize orelse false))) {
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
            if (arguments.trace) |tracees| {
                for (tracees) |tracee| {
                    const tracee_slice = b.fmt("-{s}*", .{tracee});
                    try argument_list.append("-trace");
                    try argument_list.append(tracee_slice);
                }
            }

            if (arguments.log) |log_configuration| {
                var log_what = std.ArrayList(u8).init(b.allocator);

                if (log_configuration.guest_errors) try log_what.appendSlice("guest_errors,");
                if (log_configuration.interrupts) try log_what.appendSlice("int,");
                if (!ci and log_configuration.assembly) try log_what.appendSlice("in_asm,");

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
        }

        return .{ .config = arguments, .list = argument_list };
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
    };
};

const Error = error{
    not_implemented,
    architecture_not_supported,
    failed_to_run,
};

fn createCPUDriver(architecture: Target.Cpu.Arch, optimize_mode: OptimizeMode, executable_kind: ExecutableKind) !*CompileStep {
    const cpu_driver_path = "src/cpu/";
    const cpu_driver_main_source_file = "src/cpu/entry_point.zig";
    const exe_name = try Suffix.cpu_driver.fromConfiguration(b.allocator, .{
        .architecture = architecture,
        .optimize_mode = optimize_mode,
        .executable_kind = executable_kind,
        // dummy fields
        .bootloader = .rise,
        .boot_protocol = .bios,
        .execution_environment = .qemu,
        .execution_type = .emulated,
    }, "cpu_driver_");

    const cpu_driver_file = FileSource.relative(cpu_driver_main_source_file);
    const target = try getTarget(architecture, .privileged);
    const cpu_driver = switch (executable_kind) {
        .normal_exe => b.addExecutable(.{
            .name = exe_name,
            .root_source_file = cpu_driver_file,
            .target = target,
            .optimize = optimize_mode,
            .linkage = .static,
        }),
        .test_exe => b.addTest(.{
            .name = exe_name,
            .root_source_file = FileSource.relative(cpu_driver_path ++ "test.zig"),
            .target = target,
            .kind = .test_exe,
            .optimize = optimize_mode,
        }),
    };
    cpu_driver.setOutputDir(cache_dir);
    cpu_driver.setMainPkgPath(source_root_dir);

    cpu_driver.force_pic = true;
    cpu_driver.disable_stack_probing = true;
    cpu_driver.stack_protector = false;
    cpu_driver.strip = false;
    cpu_driver.red_zone = false;
    cpu_driver.omit_frame_pointer = false;
    cpu_driver.entry_symbol_name = entry_point_name;

    if (executable_kind == .test_exe) {
        cpu_driver.setTestRunner(cpu_driver_main_source_file);
    }

    cpu_driver.setLinkerScriptPath(FileSource.relative(try std.mem.concat(b.allocator, u8, &.{ cpu_driver_path, "arch/", switch (architecture) {
        .x86_64 => "x86/64",
        .x86 => "x86/32",
        else => @tagName(architecture),
    }, "/linker_script.ld" })));

    cpu_driver.code_model = switch (architecture) {
        .x86_64 => .kernel,
        .riscv64 => .medium,
        .aarch64 => .small,
        else => return Error.architecture_not_supported,
    };

    modules.addModule(cpu_driver, .lib);
    modules.addModule(cpu_driver, .bootloader);
    modules.addModule(cpu_driver, .privileged);
    modules.addModule(cpu_driver, .cpu);

    if (default_configuration.optimize_mode == optimize_mode and default_configuration.architecture == architecture and executable_kind == .normal_exe) {
        b.default_step.dependOn(&cpu_driver.step);
    }

    return cpu_driver;
}

fn getTarget(asked_arch: Cpu.Arch, execution_mode: common.TraditionalExecutionMode) Error!CrossTarget {
    var enabled_features = Cpu.Feature.Set.empty;
    var disabled_features = Cpu.Feature.Set.empty;

    if (execution_mode == .privileged) {
        switch (common.cpu.arch) {
            .x86, .x86_64 => {
                // disable FPU
                const Feature = Target.x86.Feature;
                disabled_features.addFeature(@enumToInt(Feature.x87));
                disabled_features.addFeature(@enumToInt(Feature.mmx));
                disabled_features.addFeature(@enumToInt(Feature.sse));
                disabled_features.addFeature(@enumToInt(Feature.sse2));
                disabled_features.addFeature(@enumToInt(Feature.avx));
                disabled_features.addFeature(@enumToInt(Feature.avx2));
                disabled_features.addFeature(@enumToInt(Feature.avx512f));

                enabled_features.addFeature(@enumToInt(Feature.soft_float));
            },
            else => return Error.architecture_not_supported,
        }
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
