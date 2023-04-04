const std = @import("std");
const common = @import("src/common.zig");

// Build types
const Build = std.Build;
const CompileStep = std.Build.CompileStep;
const FileSource = std.Build.FileSource;
const Module = std.Build.Module;
const ModuleDependency = std.Build.ModuleDependency;
const OptionsStep = std.Build.OptionsStep;
const RunStep = std.Build.RunStep;
const Step = std.Build.Step;

const assert = std.debug.assert;
const Bootloader = common.Bootloader;
const Configuration = common.Configuration;
const Cpu = common.Cpu;
const CrossTarget = common.CrossTarget;
const DiskType = common.DiskType;
const ExecutionType = common.ExecutionType;
const ExecutionEnvironment = common.ExecutionEnvironment;
const FilesystemType = common.FilesystemType;
const OptimizeMode = common.OptimizeMode;
const RiseProgram = common.RiseProgram;
const Suffix = common.Suffix;
const Target = common.Target;

const BuildSteps = struct {
    build_all: *Step,
    build_all_tests: *Step,
    debug: *Step,
    run: *Step,
    test_run: *Step,
    test_debug: *Step,
    test_all: *Step,
};

var ci = false;
var modules = Modules{};
var b: *Build = undefined;
var build_steps: *BuildSteps = undefined;
var default_configuration: Configuration = undefined;
var user_modules: []const common.Module = undefined;
var options = Options{};

var qemu_mutex = std.Thread.Mutex{};

const Options = struct {
    arr: std.EnumArray(RiseProgram, *OptionsStep) = std.EnumArray(RiseProgram, *OptionsStep).initUndefined(),

    pub fn createOption(options_struct: *Options, rise_program: RiseProgram) void {
        const new_options = b.addOptions();
        new_options.addOption(RiseProgram, "program_type", rise_program);
        options_struct.arr.set(rise_program, new_options);
    }
};

pub fn build(b_arg: *Build) !void {
    b = b_arg;
    ci = b.option(bool, "ci", "CI mode") orelse false;
    const default_cfg_override = b.option([]const u8, "default", "Default configuration JSON file") orelse "config/default.json";
    modules = blk: {
        var mods = Modules{};
        inline for (comptime common.enumValues(ModuleID)) |module_id| {
            mods.modules.set(module_id, b.createModule(.{ .source_file = FileSource.relative("src/" ++ @tagName(module_id) ++ ".zig") }));
        }

        try mods.setDependencies(.lib, &.{});
        try mods.setDependencies(.host, &.{.lib});
        try mods.setDependencies(.bootloader, &.{ .lib, .privileged });
        try mods.setDependencies(.privileged, &.{ .lib, .bootloader });
        try mods.setDependencies(.cpu, &.{ .privileged, .lib, .bootloader });
        try mods.setDependencies(.disk_image_builder, &.{ .lib, .host });
        try mods.setDependencies(.user, &.{.lib});

        break :blk mods;
    };

    options = blk: {
        var opts = Options{};
        opts.createOption(.bootloader);
        opts.createOption(.cpu);
        opts.createOption(.user);
        opts.createOption(.host);
        break :blk opts;
    };

    default_configuration = blk: {
        const default_json_file = try std.fs.cwd().readFileAlloc(b.allocator, default_cfg_override, common.maxInt(usize));
        var token_stream = std.json.TokenStream.init(default_json_file);
        const cfg = try std.json.parse(Configuration, &token_stream, .{ .allocator = b.allocator });

        break :blk Configuration{
            .architecture = b.standardTargetOptions(.{ .default_target = .{ .cpu_arch = cfg.architecture } }).getCpuArch(),
            .bootloader = cfg.bootloader,
            .boot_protocol = cfg.boot_protocol,
            .execution_environment = cfg.execution_environment,
            .optimize_mode = cfg.optimize_mode,
            .execution_type = cfg.execution_type,
            .executable_kind = .exe,
        };
    };

    build_steps = try b.allocator.create(BuildSteps);
    build_steps.* = .{
        .build_all = b.step("all", "Build all the artifacts"),
        .build_all_tests = b.step("all_tests", "Build all the artifacts related to tests"),
        .run = b.step("run", "Run the operating system through an emulator"),
        .debug = b.step("debug", "Debug the operating system through an emulator"),
        .test_run = b.step("test", "Run unit tests"),
        .test_debug = b.step("test_debug", "Debug unit tests"),
        .test_all = b.step("test_all", "Run all unit tests"),
    };

    const disk_image_builder_modules = &.{ .lib, .host, .bootloader, .disk_image_builder };
    const disk_image_builder = blk: {
        const exe = try addCompileStep(.host, .{
            .kind = .exe,
            .name = "disk_image_builder",
            .root_project_path = "src/disk_image_builder",
            .modules = disk_image_builder_modules,
        });

        b.default_step.dependOn(&exe.step);

        break :blk exe;
    };

    const native_tests = [_]struct { name: []const u8, root_project_path: []const u8, modules: []const ModuleID }{
        .{ .name = "host_native_test", .root_project_path = "src/host", .modules = &.{ .lib, .host } },
        .{ .name = "disk_image_builder_native_test", .root_project_path = "src/disk_image_builder", .modules = disk_image_builder_modules },
    };

    const native_test_optimize_mode = .ReleaseFast;
    for (native_tests) |native_test| {
        const test_name = try std.mem.concat(b.allocator, u8, &.{ native_test.name, "_", @tagName(native_test_optimize_mode) });
        const test_exe = try addCompileStep(.host, .{
            .name = test_name,
            .root_project_path = native_test.root_project_path,
            .optimize_mode = native_test_optimize_mode,
            .modules = native_test.modules,
            .kind = .@"test",
        });

        // TODO: do this properly
        if (std.mem.containsAtLeast(u8, native_test.name, 1, "disk_image_builder")) {
            test_exe.addIncludePath("src/bootloader/limine/installables");
            test_exe.addCSourceFile("src/bootloader/limine/installables/limine-deploy.c", &.{});
            test_exe.linkLibC();
        }

        const run_test_step = test_exe.run();
        //run_test_step.condition = .always;
        build_steps.test_all.dependOn(&run_test_step.step);
    }

    {
        var user_module_list = std.ArrayList(common.Module).init(b.allocator);
        var user_program_dir = try std.fs.cwd().openIterableDir(user_program_dir_path, .{ .access_sub_paths = true });
        defer user_program_dir.close();

        var user_program_iterator = user_program_dir.iterate();

        while (try user_program_iterator.next()) |entry| {
            const dir_name = entry.name;
            const file_path = try std.mem.concat(b.allocator, u8, &.{ dir_name, "/module.json" });
            const file = try user_program_dir.dir.readFileAlloc(b.allocator, file_path, common.maxInt(usize));
            var token_stream = std.json.TokenStream.init(file);
            const user_program = try std.json.parse(common.UserProgram, &token_stream, .{ .allocator = b.allocator });
            try user_module_list.append(.{
                .program = user_program,
                .name = dir_name,
            });
        }

        user_modules = user_module_list.items;
    }

    const executable_kinds = [2]CompileStep.Kind{ .exe, .@"test" };

    for (common.enumValues(OptimizeMode)) |optimize_mode| {
        for (common.supported_architectures, 0..) |architecture, architecture_index| {
            const user_target = try getTarget(architecture, .user);

            for (executable_kinds) |executable_kind| {
                const cpu_driver_path = "src/cpu";
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

                const target = try getTarget(architecture, .privileged);
                const cpu_driver = try addCompileStep(.cpu, .{
                    .kind = executable_kind,
                    .name = exe_name,
                    .root_project_path = cpu_driver_path,
                    .target = target,
                    .optimize_mode = optimize_mode,
                    .modules = &.{ .lib, .bootloader, .privileged, .cpu },
                });

                cpu_driver.force_pic = true;
                cpu_driver.disable_stack_probing = true;
                cpu_driver.stack_protector = false;
                cpu_driver.strip = false;
                cpu_driver.red_zone = false;
                cpu_driver.omit_frame_pointer = false;
                cpu_driver.entry_symbol_name = entry_point_name;

                cpu_driver.code_model = switch (architecture) {
                    .x86_64 => .kernel,
                    .riscv64 => .medium,
                    .aarch64 => .small,
                    else => return Error.architecture_not_supported,
                };

                cpu_driver.setLinkerScriptPath(FileSource.relative(try std.mem.concat(b.allocator, u8, &.{ cpu_driver_path, "/arch/", switch (architecture) {
                    .x86_64 => "x86/64",
                    .x86 => "x86/32",
                    else => @tagName(architecture),
                }, "/linker_script.ld" })));

                var user_module_list = try std.ArrayList(*CompileStep).initCapacity(b.allocator, user_modules.len);
                const user_linker_script_path = FileSource.relative(try std.mem.concat(b.allocator, u8, &.{ "src/user/arch/", @tagName(architecture), "/linker_script.ld" }));
                for (user_modules) |module| {
                    const user_module_name = try Suffix.cpu_driver.fromConfiguration(b.allocator, .{
                        .architecture = architecture,
                        .optimize_mode = optimize_mode,
                        .executable_kind = executable_kind,
                        // dummy fields
                        .bootloader = .rise,
                        .boot_protocol = .bios,
                        .execution_environment = .qemu,
                        .execution_type = .emulated,
                    }, try std.mem.concat(b.allocator, u8, &.{ module.name, "_" }));

                    const user_module = try addCompileStep(.user, .{
                        .kind = executable_kind,
                        .name = user_module_name,
                        .root_project_path = try std.mem.concat(b.allocator, u8, &.{ user_program_dir_path, "/", module.name }),
                        .target = user_target,
                        .optimize_mode = optimize_mode,
                        .modules = &.{ .lib, .user },
                    });
                    user_module.strip = false;

                    user_module.setLinkerScriptPath(user_linker_script_path);

                    user_module_list.appendAssumeCapacity(user_module);
                }

                const bootloaders = common.architecture_bootloader_map[architecture_index];
                for (bootloaders) |bootloader_struct| {
                    const bootloader = bootloader_struct.id;
                    for (bootloader_struct.protocols) |boot_protocol| {
                        const rise_loader_path = "src/bootloader/rise/";
                        const bootloader_name = try Suffix.bootloader.fromConfiguration(b.allocator, .{
                            .architecture = architecture,
                            .bootloader = bootloader,
                            .boot_protocol = boot_protocol,
                            // dummy fields
                            .execution_environment = .qemu,
                            .optimize_mode = .Debug,
                            .execution_type = .emulated,
                            .executable_kind = .exe,
                        }, "bootloader_");

                        const bootloader_modules = &.{ .lib, .bootloader, .privileged };

                        const maybe_bootloader_compile_step: ?*CompileStep = switch (bootloader) {
                            .rise => switch (boot_protocol) {
                                .bios => switch (architecture) {
                                    .x86_64 => blk: {
                                        const bootloader_path = rise_loader_path ++ "bios";
                                        const executable = try addCompileStep(.bootloader, .{
                                            .kind = executable_kind,
                                            .name = bootloader_name,
                                            .root_project_path = bootloader_path,
                                            .target = try getTarget(.x86, .privileged),
                                            .optimize_mode = .ReleaseSmall,
                                            .modules = bootloader_modules,
                                        });

                                        executable.disable_stack_probing = true;
                                        executable.stack_protector = false;

                                        executable.addAssemblyFile("src/bootloader/arch/x86/64/smp_trampoline.S");
                                        executable.addAssemblyFile(bootloader_path ++ "/unreal_mode.S");
                                        executable.setLinkerScriptPath(FileSource.relative(bootloader_path ++ "/linker_script.ld"));
                                        executable.code_model = .small;

                                        break :blk executable;
                                    },
                                    else => return Error.architecture_not_supported,
                                },
                                .uefi => blk: {
                                    const bootloader_path = rise_loader_path ++ "uefi";
                                    const executable = try addCompileStep(.bootloader, .{
                                        .kind = executable_kind,
                                        .name = bootloader_name,
                                        .root_project_path = bootloader_path,
                                        .target = .{
                                            .cpu_arch = architecture,
                                            .os_tag = .uefi,
                                            .abi = .msvc,
                                        },
                                        .optimize_mode = .ReleaseSafe,
                                        .modules = bootloader_modules,
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
                            bootloader_compile_step.red_zone = false;
                            bootloader_compile_step.link_gc_sections = true;
                            bootloader_compile_step.want_lto = true;
                            bootloader_compile_step.strip = true;
                        }

                        const execution_environments: []const ExecutionEnvironment = switch (bootloader) {
                            .rise, .limine => switch (boot_protocol) {
                                .bios => switch (architecture) {
                                    .x86_64 => &.{.qemu},
                                    else => return Error.architecture_not_supported,
                                },
                                .uefi => &.{.qemu},
                            },
                        };

                        const execution_types: []const ExecutionType = if (canVirtualizeWithQEMU(architecture)) &.{ .emulated, .accelerated } else &.{.emulated};
                        for (execution_types) |execution_type| {
                            for (execution_environments) |execution_environment| {
                                const configuration = Configuration{
                                    .architecture = architecture,
                                    .bootloader = bootloader,
                                    .boot_protocol = boot_protocol,
                                    .optimize_mode = optimize_mode,
                                    .execution_environment = execution_environment,
                                    .execution_type = execution_type,
                                    .executable_kind = executable_kind,
                                };

                                const run_steps = try b.allocator.create(RunSteps);
                                const suffix = try Suffix.complete.fromConfiguration(b.allocator, configuration, null);

                                run_steps.* = .{
                                    .configuration = configuration,
                                    .run = Step.init(.{ .id = .custom, .name = try std.mem.concat(b.allocator, u8, &.{ "_run_", suffix }), .owner = b, .makeFn = RunSteps.run }),
                                    .debug = Step.init(.{ .id = .custom, .name = try std.mem.concat(b.allocator, u8, &.{ "_debug_", suffix }), .owner = b, .makeFn = RunSteps.debug }),
                                    .gdb_script = Step.init(.{ .id = .custom, .name = try std.mem.concat(b.allocator, u8, &.{ "_gdb_script_", suffix }), .owner = b, .makeFn = RunSteps.gdbScript }),
                                    .disk_image_builder = disk_image_builder.run(),
                                };

                                inline for (common.fields(Configuration)) |field| {
                                    run_steps.disk_image_builder.addArg(@tagName(@field(configuration, field.name)));
                                }

                                const setup = .{ .cpu_driver = cpu_driver, .bootloader_step = maybe_bootloader_compile_step, .disk_image_builder = disk_image_builder, .disk_image_builder_run = run_steps.disk_image_builder, .user_modules = user_module_list.items };
                                try run_steps.createStep("run", setup, suffix);
                                try run_steps.createStep("debug", setup, suffix);

                                run_steps.debug.dependOn(&run_steps.gdb_script);

                                if (configuration.executable_kind == .@"test") {
                                    build_steps.test_all.dependOn(&run_steps.run);
                                }

                                if (architecture == default_configuration.architecture and bootloader == default_configuration.bootloader and boot_protocol == default_configuration.boot_protocol and optimize_mode == default_configuration.optimize_mode and execution_environment == default_configuration.execution_environment and execution_type == default_configuration.execution_type) {
                                    switch (executable_kind) {
                                        .exe => {
                                            build_steps.run.dependOn(&run_steps.run);
                                            build_steps.debug.dependOn(&run_steps.debug);
                                            b.default_step.dependOn(&cpu_driver.step);
                                            if (maybe_bootloader_compile_step) |bootloader_compile_step| {
                                                b.default_step.dependOn(&bootloader_compile_step.step);
                                            }

                                            for (setup.user_modules) |user_module| {
                                                b.default_step.dependOn(&user_module.step);
                                            }
                                        },
                                        .@"test" => {
                                            build_steps.test_run.dependOn(&run_steps.run);
                                            build_steps.test_debug.dependOn(&run_steps.debug);
                                        },
                                        else => return Error.not_implemented,
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

const Executable = struct {
    kind: CompileStep.Kind,
    name: []const u8,
    root_project_path: []const u8,
    target: CrossTarget = .{},
    optimize_mode: OptimizeMode = .Debug,
    modules: []const ModuleID,
};

fn addCompileStep(program_type: RiseProgram, executable_options: Executable) !*CompileStep {
    _ = program_type;
    const main_file = try std.mem.concat(b.allocator, u8, &.{ executable_options.root_project_path, "/main.zig" });
    const compile_step = switch (executable_options.kind) {
        .exe => blk: {
            const executable = b.addExecutable(.{
                .name = executable_options.name,
                .root_source_file = FileSource.relative(main_file),
                .target = executable_options.target,
                .optimize = executable_options.optimize_mode,
            });

            build_steps.build_all.dependOn(&executable.step);

            break :blk executable;
        },
        .@"test" => blk: {
            const test_file = FileSource.relative(try std.mem.concat(b.allocator, u8, &.{ executable_options.root_project_path, "/test.zig" }));
            const test_exe = b.addTest(.{
                .name = executable_options.name,
                .root_source_file = test_file,
                .target = executable_options.target,
                .optimize = executable_options.optimize_mode,
            });

            build_steps.build_all_tests.dependOn(&test_exe.step);

            break :blk test_exe;
        },
        else => return Error.not_implemented,
    };

    compile_step.setMainPkgPath(source_root_dir);
    compile_step.setOutputDir(cache_dir);

    if (executable_options.target.os_tag) |os| {
        switch (os) {
            .freestanding, .uefi => {
                if (executable_options.kind == .@"test") {
                    compile_step.setTestRunner(main_file);
                }

                if (os == .freestanding) {
                    compile_step.entry_symbol_name = "entryPoint";
                }
            },
            else => {},
        }
    }

    for (executable_options.modules) |module| {
        modules.addModule(compile_step, module);
    }

    return compile_step;
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
    user,
    disk_image_builder,
};

pub const Modules = struct {
    modules: std.EnumArray(ModuleID, *Module) = std.EnumArray(ModuleID, *Module).initUndefined(),
    dependencies: std.EnumArray(ModuleID, []const ModuleDependency) = std.EnumArray(ModuleID, []const ModuleDependency).initUndefined(),

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
const user_program_dir_path = "src/user/programs";

const RunSteps = struct {
    configuration: Configuration,
    run: Step,
    debug: Step,
    gdb_script: Step,
    disk_image_builder: *RunStep,

    fn getGDBScriptPath(configuration: Configuration) ![]const u8 {
        return try std.mem.concat(b.allocator, u8, &.{ "zig-cache/gdb_script_", @tagName(configuration.bootloader), "_", @tagName(configuration.architecture), "_", @tagName(configuration.boot_protocol) });
    }

    const RunStepsSetup = struct {
        cpu_driver: *CompileStep,
        bootloader_step: ?*CompileStep,
        disk_image_builder: *CompileStep,
        user_modules: []const *CompileStep,
        disk_image_builder_run: *RunStep,
    };

    fn createStep(run_steps: *RunSteps, comptime step: []const u8, setup: RunStepsSetup, suffix: []const u8) !void {
        if (setup.bootloader_step) |bs| {
            @field(run_steps, step).dependOn(&bs.step);
            setup.disk_image_builder_run.step.dependOn(&bs.step);
        }

        for (setup.user_modules) |user_module| {
            @field(run_steps, step).dependOn(&user_module.step);
            setup.disk_image_builder_run.step.dependOn(&user_module.step);
        }

        @field(run_steps, step).dependOn(&setup.cpu_driver.step);
        setup.disk_image_builder_run.step.dependOn(&setup.cpu_driver.step);

        @field(run_steps, step).dependOn(&setup.disk_image_builder.step);
        @field(run_steps, step).dependOn(&setup.disk_image_builder_run.step);

        const final_step = b.step(try std.mem.concat(b.allocator, u8, &.{ @tagName(setup.cpu_driver.kind), "_", suffix }), "Run the operating system through an emulator");
        final_step.dependOn(&@field(run_steps, step));
    }

    const RunError = error{
        failure,
    };

    fn run(step: *Step, progress_node: *std.Progress.Node) !void {
        qemu_mutex.lock();
        defer qemu_mutex.unlock();
        _ = progress_node;
        const run_steps = @fieldParentPtr(RunSteps, "run", step);

        const is_debug = false;
        const is_test = run_steps.configuration.executable_kind == .@"test";
        const arguments = try qemuCommon(run_steps, .{ .is_debug = is_debug, .is_test = is_test });

        var process = std.ChildProcess.init(arguments.list.items, b.allocator);

        switch (try process.spawnAndWait()) {
            .Exited => |exit_code| {
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
                    return RunError.failure;
                }
            },
            else => return RunError.failure,
        }
    }

    fn debug(step: *Step, progress_node: *std.Progress.Node) !void {
        _ = progress_node;
        const run_steps = @fieldParentPtr(RunSteps, "debug", step);
        const is_debug = true;
        const is_test = run_steps.configuration.executable_kind == .@"test";
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

    fn gdbScript(step: *Step, progress_node: *std.Progress.Node) !void {
        _ = progress_node;
        const run_steps = @fieldParentPtr(RunSteps, "gdb_script", step);

        var gdb_script_buffer = std.ArrayList(u8).init(b.allocator);
        const architecture = run_steps.configuration.architecture;
        common.log.debug("Architecture: {}", .{architecture});
        switch (architecture) {
            .x86_64 => try gdb_script_buffer.appendSlice("set disassembly-flavor intel\n"),
            else => return Error.architecture_not_supported,
        }

        try gdb_script_buffer.appendSlice(try std.mem.concat(b.allocator, u8, &.{ "symbol-file zig-cache/cpu_driver_", try Suffix.cpu_driver.fromConfiguration(b.allocator, run_steps.configuration, null), "\n" }));
        try gdb_script_buffer.appendSlice("target remote localhost:1234\n");
        try gdb_script_buffer.appendSlice("layout split\n");

        const base_gdb_script = try std.fs.cwd().readFileAlloc(b.allocator, "config/gdb_script", common.maxInt(usize));
        try gdb_script_buffer.appendSlice(base_gdb_script);

        try std.fs.cwd().writeFile(try getGDBScriptPath(run_steps.configuration), gdb_script_buffer.items);
    }

    const QEMUOptions = packed struct {
        is_test: bool,
        is_debug: bool,
    };

    fn qemuCommon(run_steps: *RunSteps, qemu_options: QEMUOptions) !struct { config: Arguments, list: std.ArrayList([]const u8) } {
        const config_file = try std.fs.cwd().readFileAlloc(b.allocator, try std.mem.concat(b.allocator, u8, &.{"config/" ++ @tagName(run_steps.configuration.execution_environment) ++ ".json"}), common.maxInt(usize));
        var token_stream = std.json.TokenStream.init(config_file);
        const arguments = try std.json.parse(Arguments, &token_stream, .{ .allocator = b.allocator });

        var argument_list = std.ArrayList([]const u8).init(b.allocator);

        try argument_list.append(try std.mem.concat(b.allocator, u8, &.{ "qemu-system-", @tagName(run_steps.configuration.architecture) }));

        if (qemu_options.is_test and !qemu_options.is_debug) {
            try argument_list.appendSlice(&.{ "-device", b.fmt("isa-debug-exit,iobase=0x{x:0>2},iosize=0x{x:0>2}", .{ common.QEMU.isa_debug_exit.io_base, common.QEMU.isa_debug_exit.io_size }) });
        }

        switch (run_steps.configuration.boot_protocol) {
            .uefi => try argument_list.appendSlice(&.{ "-bios", "tools/OVMF_CODE-pure-efi.fd" }),
            else => {},
        }

        var test_configuration = run_steps.configuration;
        test_configuration.executable_kind = .@"test";

        const image_config = try common.ImageConfig.get(b.allocator, common.ImageConfig.default_path);
        const disk_image_path = try std.mem.concat(b.allocator, u8, &.{ "zig-cache/", image_config.image_name, try Suffix.image.fromConfiguration(b.allocator, if (qemu_options.is_test) test_configuration else run_steps.configuration, "_"), ".hdd" });
        try argument_list.appendSlice(&.{ "-drive", b.fmt("file={s},index=0,media=disk,format=raw", .{disk_image_path}) });

        try argument_list.append("-no-reboot");

        if (!qemu_options.is_test) {
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
            // switch (common.cpu.arch) {
            //     .x86_64 => try argument_list.appendSlice(&.{ "-cpu", "qemu64,level=11,+x2apic" }),
            //     else => return Error.architecture_not_supported,
            // }

            if (arguments.trace) |tracees| {
                for (tracees) |tracee| {
                    const tracee_slice = b.fmt("-{s}*", .{tracee});
                    try argument_list.append("-trace");
                    try argument_list.append(tracee_slice);
                }
            }

            if (arguments.log) |log_configuration| {
                var log_what = std.ArrayList(u8).init(b.allocator);

                if (log_configuration.guest_errors) {
                    // In CI, only log guest_errors for Linux
                    if (!ci or common.os == .linux) {
                        try log_what.appendSlice("guest_errors,");
                    }
                }

                if (log_configuration.interrupts) {
                    // In CI, only log interrupts for Linux
                    if (!ci or common.os == .linux) {
                        try log_what.appendSlice("int,");
                    }
                }

                if (!ci and log_configuration.assembly) try log_what.appendSlice("in_asm,");

                if (log_what.items.len > 0) {
                    // Delete the last comma
                    _ = log_what.pop();

                    try argument_list.append("-d");
                    try argument_list.append(log_what.items);

                    if (log_configuration.interrupts) {
                        try argument_list.appendSlice(&.{ "-machine", "smm=off" });
                    }
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
