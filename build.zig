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
const Cpu = common.Cpu;
const CrossTarget = common.CrossTarget;
const DiskType = common.DiskType;
const Emulator = common.Emulator;
const FilesystemType = common.FilesystemType;
const Target = common.Target;

var ci = false;

var modules = Modules{};
var b: *Build = undefined;

pub fn build(b_arg: *Build) !void {
    b = b_arg;
    ci = b.option(bool, "ci", "CI mode") orelse false;

    modules = try Modules.new();

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

    const test_step = b.step("test", "Run unit tests");
    const test_debug_step = b.step("test_debug", "Debug unit tests");
    const test_all_step = b.step("test_all", "Run all unit tests");

    const native_tests = [_]struct { name: []const u8, zig_source_file: []const u8, modules: []const ModuleID }{
        .{ .name = "host_test", .zig_source_file = "src/host_test.zig", .modules = &.{ .lib, .host } },
        .{ .name = disk_image_builder.name, .zig_source_file = "src/disk_image_builder.zig", .modules = &.{ .lib, .host } },
    };

    for (native_tests) |native_test| {
        const test_exe = b.addTest(.{
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

        for (native_test.modules) |module_id| {
            modules.addModule(test_exe, module_id);
        }

        const run_test_step = test_exe.run();
        run_test_step.condition = .always;
        test_step.dependOn(&run_test_step.step);
    }

    for (common.supported_architectures) |architecture, architecture_index| {
        try prepareArchitectureCompilation(architecture_index, false, test_all_step);
        if (architecture == common.cpu.arch) {
            if (canVirtualizeWithQEMU(architecture)) {
                try prepareArchitectureCompilation(architecture_index, true, test_all_step);
            }
        }
    }

    const default_step = try DefaultStep.create();
    default_step.run.dependOn(b.default_step);
    default_step.debug.dependOn(b.default_step);
    default_step.test_run.dependOn(b.default_step);
    default_step.test_debug.dependOn(b.default_step);

    test_step.dependOn(&default_step.test_run);
    test_debug_step.dependOn(&default_step.test_debug);
}

fn prepareArchitectureCompilation(architecture_index: usize, override_virtualize: bool, test_step: *Step) !void {
    const architecture = common.supported_architectures[architecture_index];
    const cpu_driver = try createCPUDriver(architecture, false);
    const cpu_driver_test = try createCPUDriver(architecture, true);
    _ = cpu_driver_test;
    _ = cpu_driver;
    // try all_tests.append(cpu_driver_test);
    const bootloaders = common.architecture_bootloader_map[architecture_index];
    for (bootloaders) |bootloader| {
        const bootloader_id = bootloader.id;
        for (bootloader.protocols) |protocol| {
            var emulator_steps = std.ArrayList(EmulatorSteps).init(b.allocator);
            const configuration = Configuration{
                .bootloader = bootloader_id,
                .architecture = architecture,
                .boot_protocol = protocol,
            };

            switch (configuration.bootloader) {
                .rise => {
                    const rise_loader_path = "src/bootloader/rise/";
                    switch (configuration.architecture) {
                        .x86_64 => {
                            switch (configuration.boot_protocol) {
                                .bios => {
                                    const bootloader_path = rise_loader_path ++ "bios/";

                                    const executable = b.addExecutable(.{
                                        .name = try std.mem.concat(b.allocator, u8, &.{ "loader", try configuration.getSuffix() }),
                                        .root_source_file = FileSource.relative(bootloader_path ++ "main.zig"),
                                        .target = getTarget(.x86, .privileged),
                                        .optimize = .ReleaseSmall,
                                    });
                                    executable.addAssemblyFile(bootloader_path ++ "assembly.S");
                                    executable.setOutputDir(cache_dir);
                                    executable.setMainPkgPath("src");
                                    executable.setLinkerScriptPath(FileSource.relative(bootloader_path ++ "linker_script.ld"));
                                    executable.red_zone = false;
                                    executable.link_gc_sections = true;
                                    executable.want_lto = true;
                                    executable.strip = true;
                                    executable.entry_symbol_name = entry_point_name;

                                    modules.addModule(executable, .lib);
                                    modules.addModule(executable, .bootloader);
                                    modules.addModule(executable, .privileged);

                                    b.default_step.dependOn(&executable.step);
                                },
                                .uefi => {
                                    const executable = b.addExecutable(.{
                                        .name = "BOOTX64",
                                        .root_source_file = FileSource.relative(rise_loader_path ++ "uefi/main.zig"),
                                        .target = .{
                                            .cpu_arch = .x86_64,
                                            .os_tag = .uefi,
                                            .abi = .msvc,
                                        },
                                        .optimize = .Debug,
                                    });
                                    executable.setOutputDir(cache_dir);
                                    executable.setMainPkgPath("src");
                                    executable.strip = true;

                                    modules.addModule(executable, .lib);
                                    modules.addModule(executable, .bootloader);
                                    modules.addModule(executable, .privileged);

                                    b.default_step.dependOn(&executable.step);
                                },
                            }
                        },
                        else => return Error.architecture_not_supported,
                    }
                },
                .limine => {},
            }

            const emulators: []const Emulator = switch (configuration.bootloader) {
                .rise, .limine => switch (configuration.architecture) {
                    .x86_64 => switch (configuration.boot_protocol) {
                        .bios => &.{.qemu},
                        .uefi => &.{.qemu},
                    },
                    else => return Error.architecture_not_supported,
                },
            };

            for (emulators) |emulator| {
                const emulator_step = try EmulatorSteps.create(&emulator_steps, configuration, emulator, override_virtualize);
                emulator_step.run.dependOn(b.default_step);
                emulator_step.debug.dependOn(b.default_step);
                emulator_step.test_run.dependOn(b.default_step);
                emulator_step.test_debug.dependOn(b.default_step);

                test_step.dependOn(&emulator_step.test_run);
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

const Configuration = struct {
    bootloader: Bootloader,
    architecture: Cpu.Arch,
    boot_protocol: Bootloader.Protocol,

    pub fn getSuffix(configuration: Configuration) ![]const u8 {
        return try std.mem.concat(b.allocator, u8, &.{ "_", @tagName(configuration.bootloader), "_", @tagName(configuration.architecture), "_", @tagName(configuration.boot_protocol) });
    }
};

pub const DefaultStep = struct {
    configuration: Configuration,
    emulator: Emulator,

    fn create() !*EmulatorSteps {
        const step = try b.allocator.create(EmulatorSteps);
        step.* = .{
            .run = Step.init(.custom, "_run_", b.allocator, Interface(false).run),
            .debug = Step.init(.custom, "_debug_", b.allocator, Interface(false).debug),
            .gdb_script = Step.init(.custom, "_gdb_script_", b.allocator, Interface(false).gdbScript),
            .test_run = Step.init(.custom, "_test_run_", b.allocator, Interface(true).run),
            .test_debug = Step.init(.custom, "_test_debug_", b.allocator, Interface(true).debug),
            .test_gdb_script = Step.init(.custom, "_test_gdb_script_", b.allocator, Interface(true).gdbScript),
            .configuration = undefined,
            .emulator = undefined,
            .override_virtualize = false,
        };

        step.debug.dependOn(&step.gdb_script);
        step.test_debug.dependOn(&step.test_gdb_script);

        const run_step = b.step("run", "Run the operating system through an emulator");
        const debug_step = b.step("debug", "Debug the operating system through an emulator");
        run_step.dependOn(&step.run);
        debug_step.dependOn(&step.debug);

        return step;
    }

    pub fn Interface(comptime is_test: bool) type {
        return struct {
            fn run(step: *Step) !void {
                const default_step = @fieldParentPtr(EmulatorSteps, if (!is_test) "run" else "test_run", step);
                const default = try readConfigFromFile();
                default_step.configuration = default.configuration;
                default_step.emulator = default.emulator;
                try EmulatorSteps.Interface(is_test).run(step);
            }

            fn debug(step: *Step) !void {
                const default_step = @fieldParentPtr(EmulatorSteps, if (!is_test) "debug" else "test_debug", step);
                const default = try readConfigFromFile();
                default_step.configuration = default.configuration;
                default_step.emulator = default.emulator;
                try EmulatorSteps.Interface(is_test).debug(step);
            }

            fn gdbScript(step: *Step) !void {
                const default_step = @fieldParentPtr(EmulatorSteps, if (!is_test) "gdb_script" else "test_gdb_script", step);
                const default = try readConfigFromFile();
                default_step.configuration = default.configuration;
                default_step.emulator = default.emulator;
                try EmulatorSteps.Interface(is_test).gdbScript(step);
            }

            fn readConfigFromFile() !DefaultStep {
                const config_file = try std.fs.cwd().readFileAlloc(b.allocator, "config/default.json", std.math.maxInt(usize));
                var token_stream = std.json.TokenStream.init(config_file);
                return try std.json.parse(DefaultStep, &token_stream, .{ .allocator = b.allocator });
            }
        };
    }
};

const EmulatorSteps = struct {
    configuration: Configuration,
    emulator: Emulator,
    override_virtualize: bool,
    run: Step,
    debug: Step,
    gdb_script: Step,
    test_run: Step,
    test_debug: Step,
    test_gdb_script: Step,

    fn getGDBScriptPath(configuration: Configuration) ![]const u8 {
        return try std.mem.concat(b.allocator, u8, &.{ "zig-cache/gdb_script_", @tagName(configuration.bootloader), "_", @tagName(configuration.architecture), "_", @tagName(configuration.boot_protocol) });
    }

    fn create(list: *std.ArrayList(EmulatorSteps), configuration: Configuration, emulator: Emulator, override_virtualize: bool) !*EmulatorSteps {
        const new_one = try list.addOne();
        new_one.* = .{
            .configuration = configuration,
            .emulator = emulator,
            .run = Step.init(.custom, "_run_", b.allocator, Interface(false).run),
            .debug = Step.init(.custom, "_debug_", b.allocator, Interface(false).debug),
            .gdb_script = Step.init(.custom, "_gdb_script_", b.allocator, Interface(false).gdbScript),
            .test_run = Step.init(.custom, "_test_run_", b.allocator, Interface(true).run),
            .test_debug = Step.init(.custom, "_test_debug_", b.allocator, Interface(true).debug),
            .test_gdb_script = Step.init(.custom, "_test_gdb_script_", b.allocator, Interface(true).gdbScript),
            .override_virtualize = override_virtualize,
        };

        new_one.debug.dependOn(&new_one.gdb_script);

        const suffix = try std.mem.concat(b.allocator, u8, &.{ try configuration.getSuffix(), "_", @tagName(emulator) });

        const run_step = b.step(try std.mem.concat(b.allocator, u8, &.{ "run", suffix }), "Run the operating system through an emulator");
        const debug_step = b.step(try std.mem.concat(b.allocator, u8, &.{ "debug", suffix }), "Debug the operating system through an emulator");
        run_step.dependOn(&new_one.run);
        debug_step.dependOn(&new_one.debug);
        const test_run_step = b.step(try std.mem.concat(b.allocator, u8, &.{ "test_run", suffix }), "Run the operating system through an emulator");
        const test_debug_step = b.step(try std.mem.concat(b.allocator, u8, &.{ "test_debug", suffix }), "Debug the operating system through an emulator");
        test_run_step.dependOn(&new_one.test_run);
        test_debug_step.dependOn(&new_one.test_debug);

        return new_one;
    }

    const RunError = error{
        failure,
    };

    pub fn Interface(comptime is_test: bool) type {
        return struct {
            fn run(step: *Step) !void {
                const emulator_steps = @fieldParentPtr(EmulatorSteps, if (!is_test) "run" else "test_run", step);
                try runDiskImageBuilder(emulator_steps.configuration);
                const is_debug = false;
                const arguments = try qemuCommon(emulator_steps, is_debug);
                for (arguments.list.items) |argument| {
                    std.log.debug("{s}", .{argument});
                }
                var process = std.ChildProcess.init(arguments.list.items, b.allocator);
                switch (try process.spawnAndWait()) {
                    .Exited => |exit_code| {
                        if (exit_code & 1 == 0) return RunError.failure;
                        const mask = common.maxInt(@TypeOf(exit_code)) - 1;
                        const qemu_exit_code = @intToEnum(common.QEMU.ExitCode, (exit_code & mask) >> 1);
                        if (qemu_exit_code != .success) {
                            common.log.err("QEMU exit code: {s}", .{@tagName(qemu_exit_code)});
                            return RunError.failure;
                        }
                    },
                    else => return RunError.failure,
                }
            }

            fn debug(step: *Step) !void {
                const emulator_steps = @fieldParentPtr(EmulatorSteps, if (!is_test) "debug" else "test_debug", step);
                try runDiskImageBuilder(emulator_steps.configuration);
                const is_debug = true;
                var arguments = try qemuCommon(emulator_steps, is_debug);

                if (!arguments.config.isVirtualizing(emulator_steps.override_virtualize)) {
                    try arguments.list.append("-S");
                }

                try arguments.list.append("-s");

                const debugger_process_arguments = switch (common.os) {
                    .linux => .{ "kitty", "gdb", "-x", try getGDBScriptPath(emulator_steps.configuration) },
                    else => return Error.not_implemented,
                };

                var debugger_process = std.ChildProcess.init(&debugger_process_arguments, b.allocator);
                _ = try debugger_process.spawn();

                var qemu_process = std.ChildProcess.init(arguments.list.items, b.allocator);
                _ = try qemu_process.spawnAndWait();
            }

            fn gdbScript(step: *Step) !void {
                const emulator_steps = @fieldParentPtr(EmulatorSteps, if (!is_test) "gdb_script" else "test_gdb_script", step);

                var gdb_script_buffer = std.ArrayList(u8).init(b.allocator);
                const architecture = emulator_steps.configuration.architecture;
                common.log.debug("Architecture: {}", .{architecture});
                switch (architecture) {
                    .x86_64 => try gdb_script_buffer.appendSlice("set disassembly-flavor intel\n"),
                    else => return Error.architecture_not_supported,
                }

                try gdb_script_buffer.appendSlice(try std.mem.concat(b.allocator, u8, &.{ "symbol-file zig-cache/cpu_driver_", if (is_test) "test_" else "", @tagName(emulator_steps.configuration.architecture), "\n" }));
                try gdb_script_buffer.appendSlice("target remote localhost:1234\n");

                const base_gdb_script = try std.fs.cwd().readFileAlloc(b.allocator, "config/gdb_script", common.maxInt(usize));
                try gdb_script_buffer.appendSlice(base_gdb_script);

                try std.fs.cwd().writeFile(try getGDBScriptPath(emulator_steps.configuration), gdb_script_buffer.items);
            }

            fn qemuCommon(emulator_steps: *EmulatorSteps, is_debug: bool) !struct { config: Arguments, list: std.ArrayList([]const u8) } {
                const config_file = try readConfig(emulator_steps.emulator);
                var token_stream = std.json.TokenStream.init(config_file);
                const arguments = try std.json.parse(Arguments, &token_stream, .{ .allocator = b.allocator });

                var argument_list = std.ArrayList([]const u8).init(b.allocator);

                try argument_list.append(try std.mem.concat(b.allocator, u8, &.{ "qemu-system-", @tagName(emulator_steps.configuration.architecture) }));

                if (is_test and !is_debug) {
                    try argument_list.appendSlice(&.{ "-device", b.fmt("isa-debug-exit,iobase=0x{x:0>2},iosize=0x{x:0>2}", .{ common.QEMU.isa_debug_exit.io_base, common.QEMU.isa_debug_exit.io_size }) });
                }

                switch (emulator_steps.configuration.boot_protocol) {
                    .uefi => try argument_list.appendSlice(&.{ "-bios", "tools/OVMF_CODE-pure-efi.fd" }),
                    else => {},
                }

                const image_config = try common.ImageConfig.get(b.allocator, common.ImageConfig.default_path);
                const disk_path = try common.concat(b.allocator, u8, &.{ cache_dir, image_config.image_name });
                try argument_list.appendSlice(&.{ "-drive", b.fmt("file={s},index=0,media=disk,format=raw", .{disk_path}) });

                try argument_list.append("-no-reboot");

                if (!is_test) {
                    try argument_list.append("-no-shutdown");
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

                if (virtualizeWithQEMU(arguments, emulator_steps.configuration, emulator_steps.override_virtualize)) {
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
                        var log_what = std.ArrayList(u8).init(b.allocator);

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
                            const tracee_slice = b.fmt("-{s}*", .{tracee});
                            try argument_list.append("-trace");
                            try argument_list.append(tracee_slice);
                        }
                    }
                }

                return .{ .config = arguments, .list = argument_list };
            }

            fn runDiskImageBuilder(configuration: Configuration) !void {
                var process = std.ChildProcess.init(&.{ "zig-cache/disk_image_builder", @tagName(configuration.bootloader), @tagName(configuration.architecture), @tagName(configuration.boot_protocol), if (is_test) "true" else "false" }, b.allocator);
                const termination = try process.spawnAndWait();
                switch (termination) {
                    .Exited => |exited| if (exited != 0) return Error.failed_to_run,
                    else => return Error.failed_to_run,
                }
            }
        };
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

        pub fn isVirtualizing(arguments: Arguments, override_virtualize: bool) bool {
            if (override_virtualize) return true;
            return arguments.virtualize orelse false;
        }
    };
};

fn readConfig(emulator: Emulator) ![]const u8 {
    return try std.fs.cwd().readFileAlloc(b.allocator, try std.mem.concat(b.allocator, u8, &.{"config/" ++ @tagName(emulator) ++ ".json"}), common.maxInt(usize));
}

const Error = error{
    not_implemented,
    architecture_not_supported,
    failed_to_run,
};

fn createCPUDriver(architecture: Target.Cpu.Arch, is_test: bool) !*CompileStep {
    const cpu_driver_path = "src/cpu/";
    const cpu_driver_main_source_file = "src/cpu/entry_point.zig";
    const exe_prefix = if (is_test) "cpu_driver_test_" else "cpu_driver_";
    const exe_name = try std.mem.concat(b.allocator, u8, &.{ exe_prefix, @tagName(architecture) });

    const cpu_driver_file = FileSource.relative(cpu_driver_main_source_file);
    const target = getTarget(architecture, .privileged);
    const cpu_driver = if (is_test) b.addTest(.{
        .name = exe_name,
        .root_source_file = FileSource.relative(cpu_driver_path ++ "test.zig"),
        .target = target,
        .kind = .test_exe,
    }) else b.addExecutable(.{
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

    if (is_test) cpu_driver.setTestRunner(cpu_driver_main_source_file);

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

    modules.addModule(cpu_driver, .lib);
    modules.addModule(cpu_driver, .bootloader);
    modules.addModule(cpu_driver, .privileged);
    modules.addModule(cpu_driver, .cpu);

    b.default_step.dependOn(&cpu_driver.step);

    return cpu_driver;
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
        disabled_features.addFeature(@enumToInt(Feature.avx512f));

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

fn virtualizeWithQEMU(arguments: EmulatorSteps.Arguments, configuration: Configuration, override: bool) bool {
    return canVirtualizeWithQEMU(configuration.architecture) and (override or (arguments.virtualize orelse false));
}
