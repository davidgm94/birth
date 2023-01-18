const host = @import("src/host.zig");

// Build types
const Builder = host.build.Builder;
const FileSource = host.build.FileSource;
const LibExeObjStep = host.build.LibExeObjStep;
const RunStep = host.build.RunStep;

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

pub fn get_emulators(comptime configuration: Configuration) []const Emulator{
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

pub fn build(builder: *host.build.Builder) !void {
    const ci = builder.option(bool, "ci", "CI mode") orelse false;
    _ = ci;

    lib_package.dependencies = &.{lib_package};
    rise_package.dependencies = &.{ lib_package, rise_package, privileged_package };
    user_package.dependencies = &.{lib_package};
    privileged_package.dependencies = &.{ lib_package, privileged_package };

    const disk_image_builder = createDiskImageBuilder(builder);

    inline for (host.bootloaders) |bootloader, bootloader_index| {
        const bootloader_id = @intToEnum(host.Bootloader.ID, bootloader_index);

        inline for (bootloader.supported_architectures) |architecture| {
            inline for (architecture.supported_protocols) |boot_protocol| {
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

                const emulators = comptime get_emulators(configuration);
                inline for (emulators) |emulator| {
                    switch (emulator) {
                        .qemu => {
                            const qemu_executable = "qemu-system-" ++ switch (configuration.architecture) {
                                else => @tagName(configuration.architecture),
                            };
                            _ = qemu_executable;
                            //return Error.not_implemented;
                        },
                    }
                }
            }
        }
    }

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
                const executable = builder.addExecutable("limine.elf", "src/bootloader/limine/limine.zig");
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

fn initPackageDependencies() void {
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

// const Kernel = struct {
//     builder: *host.build.Builder,
//     bootloader_executables: host.ArrayList(*host.build.LibExeObjStep) = undefined,
//     executable: *host.build.LibExeObjStep = undefined,
//     //userspace_programs: []*host.build.LibExeObjStep = &.{},
//     options: Options,
//     boot_image_step: host.build.Step = undefined,
//     disk_count: u64 = 0,
//     disk_step: host.build.Step = undefined,
//     debug_step: host.build.Step = undefined,
//     disk_image_builder_run_step: *host.build.RunStep = undefined,
//     run_argument_list: host.ArrayList([]const u8) = undefined,
//     debug_argument_list: host.ArrayList([]const u8) = undefined,
//     gdb_script: *host.build.WriteFileStep = undefined,
//
//     fn create(kernel: *Kernel) !void {
//
//         try kernel.create_bootloader();
//         kernel.create_executable();
//         try kernel.create_disassembly_step();
//         kernel.create_disk();
//         try kernel.create_run_and_debug_steps();
//     }
//
//
//     const Error = error{
//         not_implemented,
//         module_file_not_found,
//     };
//
//     fn create_run_and_debug_steps(kernel: *Kernel) !void {
//         kernel.run_argument_list = host.ArrayList([]const u8).init(kernel.builder.allocator);
//         switch (kernel.options.run.emulator) {
//             .qemu => {
//                 const qemu_name = try host.concat(kernel.builder.allocator, u8, &.{ "qemu-system-", @tagName(kernel.options.arch) });
//                 try kernel.run_argument_list.append(qemu_name);
//
//                 if (!kernel.options.is_virtualizing()) {
//                     try kernel.run_argument_list.append("-trace");
//                     try kernel.run_argument_list.append("-nvme*");
//                     try kernel.run_argument_list.append("-trace");
//                     try kernel.run_argument_list.append("-pci*");
//                     try kernel.run_argument_list.append("-trace");
//                     try kernel.run_argument_list.append("-ide*");
//                     try kernel.run_argument_list.append("-trace");
//                     try kernel.run_argument_list.append("-ata*");
//                     try kernel.run_argument_list.append("-trace");
//                     try kernel.run_argument_list.append("-ahci*");
//                     try kernel.run_argument_list.append("-trace");
//                     try kernel.run_argument_list.append("-sata*");
//                 }
//
//                 // Boot device
//                 switch (kernel.options.arch) {
//                     .x86_64 => {
//                         if (kernel.options.arch.x86_64.boot_protocol == .uefi) {
//                             try kernel.run_argument_list.appendSlice(&.{ "-bios", "tools/OVMF_CODE-pure-efi.fd" });
//                         }
//                     },
//                     else => return Error.not_implemented,
//                 }
//
//                 {
//                     try kernel.run_argument_list.append("-no-reboot");
//                     try kernel.run_argument_list.append("-no-shutdown");
//                 }
//
//                 {
//                     const memory_arg = kernel.builder.fmt("{}{s}", .{ kernel.options.run.memory.amount, @tagName(kernel.options.run.memory.unit) });
//                     try kernel.run_argument_list.append("-m");
//                     try kernel.run_argument_list.append(memory_arg);
//                 }
//
//                 if (kernel.options.run.emulator.qemu.smp) |smp_count| {
//                     try kernel.run_argument_list.append("-smp");
//                     try kernel.run_argument_list.append(kernel.builder.fmt("{}", .{smp_count}));
//                 }
//
//                 if (kernel.options.run.emulator.qemu.vga) |vga_option| {
//                     try kernel.run_argument_list.append("-vga");
//                     try kernel.run_argument_list.append(@tagName(vga_option));
//                 } else {
//                     try kernel.run_argument_list.append("-vga");
//                     try kernel.run_argument_list.append("none");
//                     try kernel.run_argument_list.append("-display");
//                     try kernel.run_argument_list.append("none");
//                     //kernel.run_argument_list.append("-nographic") ;
//                 }
//
//                 if (kernel.options.arch == .x86_64) {
//                     try kernel.run_argument_list.append("-debugcon");
//                     try kernel.run_argument_list.append("stdio");
//                 }
//
//                 try kernel.run_argument_list.append("-global");
//                 try kernel.run_argument_list.append("virtio-mmio.force-legacy=false");
//
//                 const image_config = try host.ImageConfig.get(kernel.builder.allocator, host.ImageConfig.default_path);
//                 const disk_path = try host.concat(kernel.builder.allocator, u8, &.{ cache_dir, image_config.image_name });
//                 // TODO: don't ignore system interface
//                 try kernel.run_argument_list.appendSlice(
//                 //&.{ "-hda", disk_path });
//                 &.{ "-drive", kernel.builder.fmt("file={s},index=0,media=disk,format=raw", .{disk_path}) });
//
//                 kernel.debug_argument_list = try kernel.run_argument_list.clone();
//                 if (kernel.options.is_virtualizing()) {
//                     const args = &.{
//                         "-accel",
//                         switch (host.os) {
//                             .windows => "whpx",
//                             .linux => "kvm",
//                             .macos => "hvf",
//                             else => @compileError("OS not supported"),
//                         },
//                         "-cpu",
//                         "host",
//                     };
//                     try kernel.run_argument_list.appendSlice(args);
//                     try kernel.debug_argument_list.appendSlice(args);
//                 } else {
//                     if (kernel.options.run.emulator.qemu.log) |log_options| {
//                         var log_what = host.ArrayList(u8).init(kernel.builder.allocator);
//                         if (log_options.guest_errors) try log_what.appendSlice("guest_errors,");
//                         if (log_options.cpu) try log_what.appendSlice("cpu,");
//                         if (log_options.interrupts) try log_what.appendSlice("int,");
//                         if (log_options.assembly) try log_what.appendSlice("in_asm,");
//                         if (log_options.pmode_exceptions) try log_what.appendSlice("pcall,");
//
//                         if (log_what.items.len > 0) {
//                             // Delete the last comma
//                             _ = log_what.pop();
//
//                             const log_flag = "-d";
//                             try kernel.run_argument_list.append(log_flag);
//                             try kernel.debug_argument_list.append(log_flag);
//                             try kernel.run_argument_list.append(log_what.items);
//                             try kernel.debug_argument_list.append(log_what.items);
//                         }
//
//                         if (log_options.file) |log_file| {
//                             const log_file_flag = "-D";
//                             try kernel.run_argument_list.append(log_file_flag);
//                             try kernel.debug_argument_list.append(log_file_flag);
//                             try kernel.run_argument_list.append(log_file);
//                             try kernel.debug_argument_list.append(log_file);
//                         }
//                     }
//                 }
//
//                 if (!kernel.options.is_virtualizing()) {
//                     try kernel.debug_argument_list.append("-S");
//                 }
//
//                 try kernel.debug_argument_list.append("-s");
//             },
//             .bochs => {
//                 try kernel.run_argument_list.append("bochs");
//             },
//         }
//
//         const run_command = kernel.builder.addSystemCommand(kernel.run_argument_list.items);
//         run_command.step.dependOn(kernel.builder.default_step);
//         run_command.step.dependOn(&kernel.disk_image_builder_run_step.step);
//
//         const run_step = kernel.builder.step("run", "run step");
//         run_step.dependOn(&run_command.step);
//
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
//     const Options = struct {
//         arch: Options.ArchSpecific,
//         run: RunOptions,
//
//         const x86_64 = struct {
//             bootloader: Bootloader,
//             boot_protocol: BootProtocol,
//
//             const BootProtocol = enum {
//                 bios,
//                 uefi,
//             };
//
//             const Bootloader = enum {
//                 rise,
//                 limine,
//             };
//         };
//
//         const ArchSpecific = union(Cpu.Arch) {
//             arm,
//             armeb,
//             aarch64,
//             aarch64_be,
//             aarch64_32,
//             arc,
//             avr,
//             bpfel,
//             bpfeb,
//             csky,
//             hexagon,
//             m68k,
//             mips,
//             mipsel,
//             mips64,
//             mips64el,
//             msp430,
//             powerpc,
//             powerpcle,
//             powerpc64,
//             powerpc64le,
//             r600,
//             amdgcn,
//             riscv32,
//             riscv64,
//             sparc,
//             sparc64,
//             sparcel,
//             s390x,
//             tce,
//             tcele,
//             thumb,
//             thumbeb,
//             x86,
//             x86_64: x86_64,
//             xcore,
//             nvptx,
//             nvptx64,
//             le32,
//             le64,
//             amdil,
//             amdil64,
//             hsail,
//             hsail64,
//             spir,
//             spir64,
//             kalimba,
//             shave,
//             lanai,
//             wasm32,
//             wasm64,
//             renderscript32,
//             renderscript64,
//             ve,
//             spu_2,
//             spirv32,
//             spirv64,
//             dxil,
//             loongarch32,
//             loongarch64,
//         };
//
//         const RunOptions = struct {
//             memory: Memory,
//             emulator: union(Emulator) {
//                 qemu: QEMU,
//                 bochs: Bochs,
//             },
//
//             const Emulator = enum {
//                 qemu,
//                 bochs,
//             };
//
//             const Memory = struct {
//                 amount: u64,
//                 unit: Unit,
//
//                 const Unit = enum(u3) {
//                     K = 1,
//                     M = 2,
//                     G = 3,
//                     T = 4,
//                 };
//             };
//
//             const QEMU = struct {
//                 vga: ?VGA,
//                 log: ?LogOptions,
//                 smp: ?u64,
//                 virtualize: bool,
//                 print_command: bool,
//                 const VGA = enum {
//                     std,
//                     virtio,
//                 };
//             };
//
//             const Bochs = struct {};
//
//             const DiskOptions = struct {
//                 interface: host.DiskType,
//                 filesystem: host.FilesystemType,
//             };
//
//             const LogOptions = struct {
//                 file: ?[]const u8,
//                 guest_errors: bool,
//                 cpu: bool,
//                 interrupts: bool,
//                 assembly: bool,
//                 pmode_exceptions: bool,
//             };
//         };
//
//         fn is_virtualizing(options: Options) bool {
//             return switch (options.run.emulator) {
//                 .qemu => options.run.emulator.qemu.virtualize and host.cpu.arch == options.arch,
//                 .bochs => false,
//             };
//         }
//     };
//
// };
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
