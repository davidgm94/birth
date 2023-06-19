const std = @import("std");
const common = @import("src/common.zig");
const os = common.os;

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
const QEMUOptions = common.QEMUOptions;
const RiseProgram = common.RiseProgram;
const Suffix = common.Suffix;
const Target = common.Target;

const Error = error{
    not_implemented,
    architecture_not_supported,
    failed_to_run,
};

const source_root_dir = "src";
const user_program_dir_path = "src/user/programs";

var ci = false;
var debug_user = false;
var debug_loader = false;
var modules = Modules{};
var b: *Build = undefined;
var build_steps: *BuildSteps = undefined;
var default_configuration: Configuration = undefined;
var user_modules: []const common.Module = undefined;
var options = Options{};

pub fn build(b_arg: *Build) !void {
    b = b_arg;
    ci = b.option(bool, "ci", "CI mode") orelse false;
    debug_user = b.option(bool, "debug_user", "Debug user program") orelse false;
    debug_loader = b.option(bool, "debug_loader", "Debug loader program") orelse false;
    const default_cfg_override = b.option([]const u8, "default", "Default configuration JSON file") orelse "config/default.json";
    modules = blk: {
        var mods = Modules{};
        inline for (comptime common.enumValues(ModuleID)) |module_id| {
            mods.modules.set(module_id, b.createModule(.{
                .source_file = FileSource.relative(switch (module_id) {
                    .limine_installer => "src/bootloader/limine/installer.zig",
                    else => switch (module_id) {
                        .bios, .uefi, .limine => "src/bootloader",
                        else => "src",
                    } ++ "/" ++ @tagName(module_id) ++ ".zig",
                }),
            }));
        }

        try mods.setDependencies(.lib, &.{});
        try mods.setDependencies(.host, &.{.lib});
        try mods.setDependencies(.bootloader, &.{ .lib, .privileged });
        try mods.setDependencies(.bios, &.{ .lib, .privileged });
        try mods.setDependencies(.limine, &.{ .lib, .privileged });
        try mods.setDependencies(.uefi, &.{ .lib, .privileged });
        try mods.setDependencies(.limine_installer, &.{ .lib, .privileged });
        try mods.setDependencies(.privileged, &.{ .lib, .bootloader });
        try mods.setDependencies(.cpu, &.{ .privileged, .lib, .bootloader, .rise });
        try mods.setDependencies(.rise, &.{.lib});
        try mods.setDependencies(.user, &.{ .lib, .rise });

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
        const parsed_cfg = try std.json.parseFromSlice(Configuration, b.allocator, default_json_file, .{});
        const cfg = parsed_cfg.value;

        const optimize_mode = b.option(
            std.builtin.Mode,
            "optimize",
            "Prioritize performance, safety, or binary size (-O flag)",
        ) orelse cfg.optimize_mode;

        break :blk Configuration{
            .architecture = b.standardTargetOptions(.{ .default_target = .{ .cpu_arch = cfg.architecture } }).getCpuArch(),
            .bootloader = cfg.bootloader,
            .boot_protocol = cfg.boot_protocol,
            .execution_environment = cfg.execution_environment,
            .optimize_mode = optimize_mode,
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
        .test_host = b.step("test_host", "Run host unit tests"),
    };

    const disk_image_builder_modules = &.{ .lib, .host, .bootloader, .limine_installer, .bios };
    const disk_image_root_path = "src/host/disk_image_builder";
    const disk_image_builder = blk: {
        const exe = try addCompileStep(.{
            .kind = .exe,
            .name = "disk_image_builder",
            .root_project_path = disk_image_root_path,
            .modules = disk_image_builder_modules,
        });

        b.default_step.dependOn(&exe.step);

        break :blk exe;
    };

    const runner = blk: {
        const exe = try addCompileStep(.{
            .kind = .exe,
            .name = "runner",
            .root_project_path = "src/host/runner",
            .modules = &.{ .lib, .host },
        });

        b.default_step.dependOn(&exe.step);

        break :blk exe;
    };

    const native_tests = [_]struct {
        name: []const u8,
        root_project_path: []const u8,
        modules: []const ModuleID,
        c: ?C = null,

        const C = struct {
            include_paths: []const []const u8,
            source_files: []const SourceFile,
            link_libc: bool,
            link_libcpp: bool,

            const SourceFile = struct {
                path: []const u8,
                flags: []const []const u8,
            };
        };
    }{
        .{
            .name = "host_native_test",
            .root_project_path = "src/host",
            .modules = &.{ .lib, .host },
        },
        .{
            .name = "disk_image_builder_native_test",
            .root_project_path = disk_image_root_path,
            .modules = disk_image_builder_modules,
            .c = .{
                .include_paths = &.{"src/bootloader/limine/installables"},
                .source_files = &.{
                    .{
                        .path = "src/bootloader/limine/installables/limine-deploy.c",
                        .flags = &.{},
                    },
                },
                .link_libc = true,
                .link_libcpp = false,
            },
        },
    };

    const native_test_optimize_mode = .ReleaseFast;
    for (native_tests) |native_test| {
        const test_name = try std.mem.concat(b.allocator, u8, &.{ native_test.name, "_", @tagName(native_test_optimize_mode) });
        const test_exe = try addCompileStep(.{
            .name = test_name,
            .root_project_path = native_test.root_project_path,
            .optimize_mode = native_test_optimize_mode,
            .modules = native_test.modules,
            .kind = .@"test",
        });

        if (native_test.c) |c| {
            for (c.include_paths) |include_path| {
                test_exe.addIncludePath(include_path);
            }

            for (c.source_files) |source_file| {
                test_exe.addCSourceFile(source_file.path, source_file.flags);
            }

            if (c.link_libc) {
                test_exe.linkLibC();
            }

            if (c.link_libcpp) {
                test_exe.linkLibCpp();
            }
        }

        const run_test_step = b.addRunArtifact(test_exe);
        //run_test_step.condition = .always;
        build_steps.test_all.dependOn(&run_test_step.step);
        build_steps.test_host.dependOn(&run_test_step.step);
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
            const parsed_user_program = try std.json.parseFromSlice(common.UserProgram, b.allocator, file, .{});
            const user_program = parsed_user_program.value;
            try user_module_list.append(.{
                .program = user_program,
                .name = b.dupe(dir_name), // we have to dupe here otherwise Windows CI fails
            });
        }

        user_modules = user_module_list.items;
    }

    const executable_kinds = [2]CompileStep.Kind{ .exe, .@"test" };

    for (common.enumValues(OptimizeMode)) |optimize_mode| {
        for (common.supported_architectures, 0..) |architecture, architecture_index| {
            const user_target = try getTarget(architecture, .user);

            for (executable_kinds) |executable_kind| {
                const is_test = executable_kind == .@"test";
                const cpu_driver_path = "src/cpu";
                const target = try getTarget(architecture, .privileged);
                const cpu_driver = try addCompileStep(.{
                    .kind = executable_kind,
                    .name = "cpu_driver",
                    .root_project_path = cpu_driver_path,
                    .target = target,
                    .optimize_mode = optimize_mode,
                    .modules = &.{ .lib, .bootloader, .privileged, .cpu, .rise },
                });

                cpu_driver.force_pic = true;
                cpu_driver.disable_stack_probing = true;
                cpu_driver.stack_protector = false;
                cpu_driver.strip = false;
                cpu_driver.red_zone = false;
                cpu_driver.omit_frame_pointer = false;

                cpu_driver.code_model = switch (architecture) {
                    .x86_64 => .kernel,
                    .riscv64 => .medium,
                    .aarch64 => .small,
                    else => return Error.architecture_not_supported,
                };

                const cpu_driver_linker_script_path = FileSource.relative(try std.mem.concat(b.allocator, u8, &.{ cpu_driver_path, "/arch/", switch (architecture) {
                    .x86_64 => "x86/64",
                    .x86 => "x86/32",
                    else => @tagName(architecture),
                }, "/linker_script.ld" }));

                cpu_driver.setLinkerScriptPath(cpu_driver_linker_script_path);

                var user_module_list = try std.ArrayList(*CompileStep).initCapacity(b.allocator, user_modules.len);
                const user_architecture_source_path = try std.mem.concat(b.allocator, u8, &.{ "src/user/arch/", @tagName(architecture), "/" });
                const user_linker_script_path = FileSource.relative(try std.mem.concat(b.allocator, u8, &.{ user_architecture_source_path, "linker_script.ld" }));
                for (user_modules) |module| {
                    const user_module = try addCompileStep(.{
                        .kind = executable_kind,
                        .name = module.name,
                        .root_project_path = try std.mem.concat(b.allocator, u8, &.{ user_program_dir_path, "/", module.name }),
                        .target = user_target,
                        .optimize_mode = optimize_mode,
                        .modules = &.{ .lib, .user, .rise },
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
                        const limine_loader_path = "src/bootloader/limine/";
                        const bootloader_name = "loader";
                        const bootloader_modules = [_]ModuleID{ .lib, .bootloader, .privileged };

                        const bootloader_compile_step = switch (bootloader) {
                            .rise => switch (boot_protocol) {
                                .bios => switch (architecture) {
                                    .x86_64 => blk: {
                                        const bootloader_path = rise_loader_path ++ "bios";
                                        const executable = try addCompileStep(.{
                                            .kind = executable_kind,
                                            .name = bootloader_name,
                                            .root_project_path = bootloader_path,
                                            .target = try getTarget(.x86, .privileged),
                                            .optimize_mode = .ReleaseSmall,
                                            .modules = &(bootloader_modules ++ .{.bios}),
                                        });

                                        executable.strip = true;

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
                                    const executable = try addCompileStep(.{
                                        .kind = executable_kind,
                                        .name = bootloader_name,
                                        .root_project_path = bootloader_path,
                                        .target = .{
                                            .cpu_arch = architecture,
                                            .os_tag = .uefi,
                                            .abi = .msvc,
                                        },
                                        .optimize_mode = .ReleaseSafe,
                                        .modules = &(bootloader_modules ++ .{.uefi}),
                                    });

                                    executable.strip = true;

                                    switch (architecture) {
                                        .x86_64 => executable.addAssemblyFile("src/bootloader/arch/x86/64/smp_trampoline.S"),
                                        else => {},
                                    }

                                    break :blk executable;
                                },
                            },
                            .limine => blk: {
                                const bootloader_path = limine_loader_path;
                                const executable = try addCompileStep(.{
                                    .kind = executable_kind,
                                    .name = bootloader_name,
                                    .root_project_path = bootloader_path,
                                    .target = target,
                                    .optimize_mode = .ReleaseSafe,
                                    .modules = &(bootloader_modules ++ .{.limine}),
                                });

                                executable.force_pic = true;
                                executable.omit_frame_pointer = false;
                                executable.want_lto = false;
                                executable.strip = false;

                                executable.code_model = cpu_driver.code_model;

                                executable.setLinkerScriptPath(FileSource.relative(try common.concat(b.allocator, u8, &.{ limine_loader_path ++ "arch/", @tagName(architecture), "/linker_script.ld" })));

                                break :blk executable;
                            },
                        };

                        bootloader_compile_step.disable_stack_probing = true;
                        bootloader_compile_step.stack_protector = false;
                        bootloader_compile_step.red_zone = false;

                        if (architecture == default_configuration.architecture and bootloader == default_configuration.bootloader and boot_protocol == default_configuration.boot_protocol and optimize_mode == default_configuration.optimize_mode and !is_test) {
                            addObjdump(bootloader_compile_step, bootloader_name);
                            addFileSize(bootloader_compile_step, bootloader_name);
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

                        const execution_types: []const ExecutionType =
                            switch (common.canVirtualizeWithQEMU(architecture, ci)) {
                            true => &.{ .emulated, .accelerated },
                            false => &.{.emulated},
                        };

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

                                var disk_argument_parser = common.ArgumentParser.DiskImageBuilder{};
                                const disk_image_builder_run = b.addRunArtifact(disk_image_builder);
                                const disk_image_path = disk_image_builder_run.addOutputFileArg("disk.hdd");

                                while (disk_argument_parser.next()) |argument_type| switch (argument_type) {
                                    .configuration => inline for (common.fields(Configuration)) |field| disk_image_builder_run.addArg(@tagName(@field(configuration, field.name))),
                                    .image_configuration_path => disk_image_builder_run.addArg(common.ImageConfig.default_path),
                                    .disk_image_path => {
                                        // Must be first
                                        assert(@intFromEnum(argument_type) == 0);
                                    },
                                    .bootloader => {
                                        disk_image_builder_run.addArtifactArg(bootloader_compile_step);
                                    },
                                    .cpu => disk_image_builder_run.addArtifactArg(cpu_driver),
                                    .user_programs => for (user_module_list.items) |user_module| disk_image_builder_run.addArtifactArg(user_module),
                                };

                                const user_init = user_module_list.items[0];

                                const runner_run = try newRunnerRunArtifact(.{
                                    .configuration = configuration,
                                    .disk_image_path = disk_image_path,
                                    .cpu_driver = cpu_driver,
                                    .loader = bootloader_compile_step,
                                    .user_init = user_init,
                                    .runner = runner,
                                    .qemu_options = .{
                                        .is_debug = false,
                                        .is_test = is_test,
                                    },
                                });
                                const runner_debug = try newRunnerRunArtifact(.{
                                    .configuration = configuration,
                                    .disk_image_path = disk_image_path,
                                    .cpu_driver = cpu_driver,
                                    .loader = bootloader_compile_step,
                                    .user_init = user_init,
                                    .runner = runner,
                                    .qemu_options = .{
                                        .is_debug = true,
                                        .is_test = is_test,
                                    },
                                });

                                if (is_test) {
                                    build_steps.test_all.dependOn(&runner_run.step);
                                }

                                if (architecture == default_configuration.architecture and bootloader == default_configuration.bootloader and boot_protocol == default_configuration.boot_protocol and optimize_mode == default_configuration.optimize_mode and execution_environment == default_configuration.execution_environment and execution_type == default_configuration.execution_type) {
                                    if (is_test) {
                                        build_steps.test_run.dependOn(&runner_run.step);
                                        build_steps.test_debug.dependOn(&runner_debug.step);
                                    } else {
                                        build_steps.run.dependOn(&runner_run.step);
                                        build_steps.debug.dependOn(&runner_debug.step);

                                        b.default_step.dependOn(&bootloader_compile_step.step);

                                        b.default_step.dependOn(&cpu_driver.step);

                                        for (user_module_list.items) |user_module| {
                                            b.default_step.dependOn(&user_module.step);
                                        }

                                        const artifacts: []const *CompileStep = &.{ cpu_driver, user_init };
                                        const artifact_names: []const []const u8 = &.{ "cpu", "init" };

                                        inline for (artifact_names, 0..) |artifact_name, index| {
                                            const artifact = artifacts[index];
                                            addObjdump(artifact, artifact_name);
                                            addFileSize(artifact, artifact_name);
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

    if (os == .linux) {
        const generate_command = b.addSystemCommand(&.{ "dot", "-Tpng" });
        generate_command.addFileSourceArg(FileSource.relative("capabilities.dot"));
        generate_command.addArg("-o");
        const png = generate_command.addOutputFileArg("capabilities.png");

        const visualize_command = b.addSystemCommand(&.{"xdg-open"});
        visualize_command.addFileSourceArg(png);

        const dot_command = b.step("dot", "TEMPORARY: (developers only) Generate a graph and visualize it");
        dot_command.dependOn(&visualize_command.step);
    }
}

const Options = struct {
    arr: std.EnumArray(RiseProgram, *OptionsStep) = std.EnumArray(RiseProgram, *OptionsStep).initUndefined(),

    pub fn createOption(options_struct: *Options, rise_program: RiseProgram) void {
        const new_options = b.addOptions();
        new_options.addOption(RiseProgram, "program_type", rise_program);
        options_struct.arr.set(rise_program, new_options);
    }
};

const BuildSteps = struct {
    build_all: *Step,
    build_all_tests: *Step,
    debug: *Step,
    run: *Step,
    test_run: *Step,
    test_debug: *Step,
    test_all: *Step,
    test_host: *Step,
};

fn addObjdump(artifact: *CompileStep, comptime name: []const u8) void {
    switch (os) {
        .linux, .macos => {
            const objdump = b.addSystemCommand(&.{ "objdump", "-dxS", "-Mintel" });
            objdump.addArtifactArg(artifact);
            const objdump_step = b.step("objdump_" ++ name, "Objdump " ++ name);
            objdump_step.dependOn(&objdump.step);
        },
        else => {},
    }
}

fn addFileSize(artifact: *CompileStep, comptime name: []const u8) void {
    switch (os) {
        .linux, .macos => {
            const file_size = b.addSystemCommand(switch (os) {
                .linux => &.{ "stat", "-c", "%s" },
                .macos => &.{ "wc", "-c" },
                else => unreachable,
            });
            file_size.addArtifactArg(artifact);

            const file_size_step = b.step("file_size_" ++ name, "Get the file size of " ++ name);
            file_size_step.dependOn(&file_size.step);
        },
        else => {},
    }
}

fn newRunnerRunArtifact(arguments: struct {
    configuration: Configuration,
    disk_image_path: FileSource,
    loader: *CompileStep,
    runner: *CompileStep,
    cpu_driver: *CompileStep,
    user_init: *CompileStep,
    qemu_options: QEMUOptions,
}) !*RunStep {
    const runner = b.addRunArtifact(arguments.runner);
    var argument_parser = common.ArgumentParser.Runner{};
    while (argument_parser.next()) |argument_type| switch (argument_type) {
        .configuration => inline for (common.fields(Configuration)) |field| runner.addArg(@tagName(@field(arguments.configuration, field.name))),
        .image_configuration_path => runner.addArg(common.ImageConfig.default_path),
        .cpu_driver => runner.addArtifactArg(arguments.cpu_driver),
        .loader_path => runner.addArtifactArg(arguments.loader),
        .init => runner.addArtifactArg(arguments.user_init),
        .disk_image_path => runner.addFileSourceArg(arguments.disk_image_path),
        .qemu_options => inline for (common.fields(QEMUOptions)) |field| runner.addArg(if (@field(arguments.qemu_options, field.name)) "true" else "false"),
        .ci => runner.addArg(if (ci) "true" else "false"),
        .debug_user => runner.addArg(if (debug_user) "true" else "false"),
        .debug_loader => runner.addArg(if (debug_loader) "true" else "false"),
    };

    return runner;
}

const ExecutableDescriptor = struct {
    kind: CompileStep.Kind,
    name: []const u8,
    root_project_path: []const u8,
    target: CrossTarget = .{},
    optimize_mode: OptimizeMode = .Debug,
    modules: []const ModuleID,
};

fn addCompileStep(executable_descriptor: ExecutableDescriptor) !*CompileStep {
    const main_file = try std.mem.concat(b.allocator, u8, &.{ executable_descriptor.root_project_path, "/main.zig" });
    const compile_step = switch (executable_descriptor.kind) {
        .exe => blk: {
            const executable = b.addExecutable(.{
                .name = executable_descriptor.name,
                .root_source_file = FileSource.relative(main_file),
                .target = executable_descriptor.target,
                .optimize = executable_descriptor.optimize_mode,
            });

            build_steps.build_all.dependOn(&executable.step);

            break :blk executable;
        },
        .@"test" => blk: {
            const test_file = FileSource.relative(try std.mem.concat(b.allocator, u8, &.{ executable_descriptor.root_project_path, "/test.zig" }));
            const test_exe = b.addTest(.{
                .name = executable_descriptor.name,
                .root_source_file = test_file,
                .target = executable_descriptor.target,
                .optimize = executable_descriptor.optimize_mode,
                .test_runner = if (executable_descriptor.target.os_tag) |_| main_file else null,
            });

            build_steps.build_all_tests.dependOn(&test_exe.step);

            break :blk test_exe;
        },
        else => return Error.not_implemented,
    };

    compile_step.link_gc_sections = true;

    if (executable_descriptor.target.getOs().tag == .freestanding) {
        compile_step.entry_symbol_name = "_start";
    }

    compile_step.setMainPkgPath(source_root_dir);

    for (executable_descriptor.modules) |module| {
        modules.addModule(compile_step, module);
    }

    return compile_step;
}

const ModuleID = enum {
    /// This module has typical common stuff used everywhere
    lib,
    /// This module contains code that is used by host programs when building and trying to run the OS
    host,
    /// This module contains code related to the bootloaders
    bootloader,
    bios,
    uefi,
    limine,
    limine_installer,
    /// This module contains code that is used by Rise privileged programs
    privileged,
    /// This module contains code that is unique to Rise CPU drivers
    cpu,
    /// This module contains code that is used by userspace programs
    user,
    /// This module contains code that is interacting between userspace and cpu in Rise
    rise,
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

fn getTarget(asked_arch: Cpu.Arch, execution_mode: common.TraditionalExecutionMode) Error!CrossTarget {
    var enabled_features = Cpu.Feature.Set.empty;
    var disabled_features = Cpu.Feature.Set.empty;

    if (execution_mode == .privileged) {
        switch (asked_arch) {
            .x86, .x86_64 => {
                // disable FPU
                const Feature = Target.x86.Feature;
                disabled_features.addFeature(@intFromEnum(Feature.x87));
                disabled_features.addFeature(@intFromEnum(Feature.mmx));
                disabled_features.addFeature(@intFromEnum(Feature.sse));
                disabled_features.addFeature(@intFromEnum(Feature.sse2));
                disabled_features.addFeature(@intFromEnum(Feature.avx));
                disabled_features.addFeature(@intFromEnum(Feature.avx2));
                disabled_features.addFeature(@intFromEnum(Feature.avx512f));

                enabled_features.addFeature(@intFromEnum(Feature.soft_float));
            },
            else => return Error.architecture_not_supported,
        }
    }

    return CrossTarget{
        .cpu_arch = asked_arch,
        .cpu_model = switch (common.cpu.arch) {
            .x86 => .determined_by_cpu_arch,
            .x86_64 => if (execution_mode == .privileged) .determined_by_cpu_arch else
            // zig fmt off
            .determined_by_cpu_arch,
            // .determined_by_cpu_arch,
            // TODO: this causes some problems: https://github.com/ziglang/zig/issues/15524
            //.{ .explicit = &common.Target.x86.cpu.x86_64_v3 },
            else => .determined_by_cpu_arch,
        },
        .os_tag = .freestanding,
        .abi = .none,
        .cpu_features_add = enabled_features,
        .cpu_features_sub = disabled_features,
    };
}
