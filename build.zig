pub fn build(b: *Builder) void {
    const kernel = b.allocator.create(Kernel) catch unreachable;
    const emulator = Kernel.Options.RunOptions.Emulator.qemu;
    kernel.* = Kernel{
        .builder = b,
        .allocator = get_allocator(),
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
                                        .assembly = true,
                                        .interrupts = true,
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
        zig_std.io.getStdOut().writeAll("error: ") catch unreachable;
        zig_std.io.getStdOut().writeAll(@errorName(err)) catch unreachable;
        zig_std.io.getStdOut().writer().writeByte('\n') catch unreachable;
        unreachable;
    };
}

const common = @import("src/common.zig");
const zig_std = @import("std");
const assert = zig_std.debug.assert;

comptime {
    if (os == .freestanding) @compileError("This is only meant to be imported in build.zig");
}

const Builder = zig_std.build.Builder;
const FileSource = zig_std.build.FileSource;
const LibExeObjStep = zig_std.build.LibExeObjStep;
const OptionsStep = zig_std.build.OptionsStep;
const Package = zig_std.build.Pkg;
const RunStep = zig_std.build.RunStep;
const Step = zig_std.build.Step;
const WriteFileStep = zig_std.build.WriteFileStep;

const Target = zig_std.Target;
const Arch = Target.Cpu.Arch;
const CrossTarget = zig_std.zig.CrossTarget;

const os = @import("builtin").target.os.tag;
const arch = @import("builtin").target.cpu.arch;

const fork = zig_std.os.fork;
const ChildProcess = zig_std.ChildProcess;
const waitpid = zig_std.os.waitpid;

const Allocator = common.Allocator;
const CustomAllocator = common.CustomAllocator;
const RiseFS = common.RiseFS;

const cache_dir = "zig-cache/";
const kernel_name = "kernel.elf";
const kernel_path = cache_dir ++ kernel_name;

const resource_files = [_][]const u8{ "zap-light16.psf", "FiraSans-Regular.otf" };

var common_package = Package{
    .name = "common",
    .source = FileSource.relative("src/common.zig"),
};

var bootloader_package = Package{
    .name = "bootloader",
    .source = FileSource.relative("src/bootloader.zig"),
};

var rise_package = Package{
    .name = "rise",
    .source = FileSource.relative("src/rise.zig"),
};

var privileged_package = Package{
    .name = "privileged",
    .source = FileSource.relative("src/privileged.zig"),
};

var user_package = Package{
    .name = "user",
    .source = FileSource.relative("src/user.zig"),
};

fn allocate_zero_memory(bytes: u64) ![]align(0x1000) u8 {
    switch (os) {
        .windows => {
            const windows = zig_std.os.windows;
            return @ptrCast([*]align(0x1000) u8, @alignCast(0x1000, try windows.VirtualAlloc(null, bytes, windows.MEM_RESERVE | windows.MEM_COMMIT, windows.PAGE_READWRITE)))[0..bytes];
        },
        else => {
            const mmap = zig_std.os.mmap;
            const PROT = zig_std.os.PROT;
            const MAP = zig_std.os.MAP;
            return try mmap(null, bytes, PROT.READ | PROT.WRITE, MAP.PRIVATE | MAP.ANONYMOUS, -1, 0);
        },
    }
}

fn get_allocator() CustomAllocator {
    return CustomAllocator{
        .callback_allocate = allocate,
        .callback_resize = resize,
        .callback_free = free,
    };
}

const zero_allocator = CustomAllocator{
    .callback_allocate = zero_allocate,
    .callback_resize = resize,
    .callback_free = free,
};

fn allocate(allocator: *CustomAllocator, size: u64, alignment: u64) CustomAllocator.Error!CustomAllocator.Result {
    const kernel = @fieldParentPtr(Kernel, "allocator", allocator);
    const result = try kernel.builder.allocator.allocBytes(@intCast(u29, alignment), size, 0, 0);
    return CustomAllocator.Result{
        .address = @ptrToInt(result.ptr),
        .size = result.len,
    };
}

fn resize(allocator: *CustomAllocator, old_memory: []u8, old_alignment: u29, new_size: usize) ?usize {
    _ = allocator;
    _ = old_memory;
    _ = old_alignment;
    _ = new_size;
    unreachable;
}

fn free(allocator: *CustomAllocator, memory: []u8, alignment: u29) void {
    _ = allocator;
    _ = memory;
    _ = alignment;
    unreachable;
}

fn zero_allocate(allocator: *CustomAllocator, size: u64, alignment: u64) CustomAllocator.Error!CustomAllocator.Result {
    _ = allocator;
    assert(alignment <= 0x1000);
    const result = allocate_zero_memory(size) catch return CustomAllocator.Error.OutOfMemory;
    return CustomAllocator.Result{
        .address = @ptrToInt(result.ptr),
        .size = result.len,
    };
}

const cwd = zig_std.fs.cwd;
const Dir = zig_std.fs.Dir;
const path = zig_std.fs.path;
const basename = zig_std.fs.path.basename;
const dirname = zig_std.fs.path.dirname;

fn add_qemu_debug_isa_exit(builder: *Builder, list: *common.ArrayListManaged([]const u8), qemu_debug_isa_exit: common.QEMU.ISADebugExit) !void {
    try list.append("-device");
    try list.append(builder.fmt("isa-debug-exit,iobase=0x{x},iosize=0x{x}", .{ qemu_debug_isa_exit.port, qemu_debug_isa_exit.size }));
}

const Disk = struct {
    type: common.Disk.Type = .memory,
    buffer: BufferType,
    sector_size: u64 = 0x200,

    const BufferType = common.ArrayListAligned(u8, 0x1000);

    fn make(step: *Step) !void {
        const kernel = @fieldParentPtr(Kernel, "disk_step", step);

        var disk = Disk{
            .buffer = try BufferType.initCapacity(zero_allocator.get_allocator(), 1024 * 1024 * 1024),
        };

        const max_file_length = common.max_int(usize);
        switch (kernel.options.arch) {
            .x86_64 => {
                const x86_64 = kernel.options.arch.x86_64;
                switch (x86_64.boot_protocol) {
                    .bios => {
                        const mbr_file = try cwd().readFileAlloc(kernel.builder.allocator, "zig-cache/mbr.bin", max_file_length);
                        assert(mbr_file.len == 0x200);
                        disk.buffer.appendSliceAssumeCapacity(mbr_file);
                        const mbr = @ptrCast(*MBRBIOS, disk.buffer.items.ptr);
                        const loader_file = try cwd().readFileAlloc(kernel.builder.allocator, "zig-cache/rise.elf", max_file_length);
                        disk.buffer.appendNTimesAssumeCapacity(0, 0x200);
                        mbr.dap = .{
                            .sector_count = @intCast(u16, common.align_forward(loader_file.len, 0x200) >> 9),
                            .pointer = 0x7e00,
                            .lba = disk.buffer.items.len >> 9,
                        };
                        //zig_std.debug.print("DAP sector count: {}, pointer: 0x{x}, lba: 0x{x}", .{ mbr.dap.sector_count, mbr.dap.pointer, mbr.dap.lba });
                        //if (true) unreachable;
                        //const a = @ptrToInt(&mbr.dap.pointer);
                        //const b = @ptrToInt(mbr);
                        //zig_std.debug.print("A: 0x{x}\n", .{a - b});
                        //if (true) unreachable;
                        disk.buffer.appendSliceAssumeCapacity(loader_file);
                        //assert(loader_file.len < 0x200);
                        disk.buffer.appendNTimesAssumeCapacity(0, common.align_forward(loader_file.len, 0x200) - loader_file.len);
                    },
                    .uefi => {
                        unreachable;
                    },
                }
            },
            else => unreachable,
        }

        //assert(resource_files.len > 0);

        //for (resource_files) |filename| {
        //const file_content = try cwd().readFileAlloc(kernel.builder.allocator, kernel.builder.fmt("resources/{s}", .{filename}), max_file_length);
        //try filesystem.write_file(kernel.allocator, filename, file_content);
        //}

        //assert(kernel.userspace_programs.len > 0);

        //for (kernel.userspace_programs) |program| {
        //const filename = program.out_filename;
        //const file_path = program.output_path_source.getPath();
        //const file_content = try cwd().readFileAlloc(kernel.builder.allocator, file_path, max_file_length);
        //try filesystem.write_file(get_allocator(), filename, file_content);
        //}

        // TODO: use filesystem
        try cwd().writeFile(kernel.builder.fmt("{s}disk.bin", .{cache_dir}), disk.buffer.items);
    }
};

const MBRUEFI = extern struct {
    bootstrap: [440]u8 = [1]u8{0} ** 440,
    disk_signature: [4]u8,
    copy_protection: [2]u8,
    partition: [4]Partition,
    boot_signature: [2]u8,

    comptime {
        assert(@sizeOf(MBRUEFI) == 0x200);
    }
};

const Partition = extern struct {
    boot_indicator: u8,
    first_sector: [3]u8,
    partition_type: u8,
    last_sector: [3]u8,
    first_lba: u32,
    sector_count: u32,

    comptime {
        assert(@sizeOf(Partition) == 0x10);
    }
};

const MBRBIOS = extern struct {
    jmp_code: [3]u8,
    bpb: [40]u8,
    code: [381]u8,
    dap: DAP align(1),
    disk_signature: [4]u8,
    disk_signature_extended: [2]u8,
    partitions: [4]Partition align(1),
    magic: [2]u8,

    comptime {
        assert(@sizeOf(MBRBIOS) == 0x200);
    }

    const DAP = extern struct {
        size: u8 = 0x10,
        unused: u8 = 0,
        sector_count: u16,
        pointer: u32,
        lba: u64,
    };
};

const GPT = extern struct {};

//const BootImage = struct {
//fn build(step: *Step) !void {
//const kernel = @fieldParentPtr(Kernel, "boot_image_step", step);

//switch (kernel.options.arch) {
//.x86_64 => {
//switch (kernel.options.arch.x86_64.bootloader) {
//.rise_uefi => {
//var cache_dir_handle = try zig_std.fs.cwd().openDir(kernel.builder.cache_root, .{});
//defer cache_dir_handle.close();
//const img_dir_path = kernel.builder.fmt("{s}/img_dir", .{kernel.builder.cache_root});
//const current_directory = cwd();
//current_directory.deleteFile(Limine.image_path) catch {};
//const img_dir = try current_directory.makeOpenPath(img_dir_path, .{});
//const img_efi_dir = try img_dir.makeOpenPath("EFI/BOOT", .{});

//try Dir.copyFile(cache_dir_handle, "BOOTX64.efi", img_efi_dir, "BOOTX64.EFI", .{});
//try Dir.copyFile(cache_dir_handle, "kernel.elf", img_dir, "kernel.elf", .{});
//// TODO: copy all userspace programs
//try Dir.copyFile(cache_dir_handle, "init", img_dir, "init", .{});
//},
//.rise_bios => {},
//.limine => {
//const img_dir_path = kernel.builder.fmt("{s}/img_dir", .{kernel.builder.cache_root});
//const current_directory = cwd();
//current_directory.deleteFile(Limine.image_path) catch {};
//const img_dir = try current_directory.makeOpenPath(img_dir_path, .{});
//const img_efi_dir = try img_dir.makeOpenPath("EFI/BOOT", .{});

//const limine_dir = try current_directory.openDir(Limine.installables_path, .{});

//const limine_efi_bin_file = "limine-cd-efi.bin";
//const files_to_copy_from_limine_dir = [_][]const u8{
//"limine.cfg",
//"limine.sys",
//"limine-cd.bin",
//limine_efi_bin_file,
//};

//for (files_to_copy_from_limine_dir) |filename| {
//try Dir.copyFile(limine_dir, filename, img_dir, filename, .{});
//}
//try Dir.copyFile(limine_dir, "BOOTX64.EFI", img_efi_dir, "BOOTX64.EFI", .{});
//try Dir.copyFile(current_directory, kernel_path, img_dir, path.basename(kernel_path), .{});

//const xorriso_executable = switch (common.os) {
//.windows => "tools/xorriso-windows/xorriso.exe",
//else => "xorriso",
//};
//var xorriso_process = ChildProcess.init(&.{ xorriso_executable, "-as", "mkisofs", "-quiet", "-b", "limine-cd.bin", "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table", "--efi-boot", limine_efi_bin_file, "-efi-boot-part", "--efi-boot-image", "--protective-msdos-label", img_dir_path, "-o", Limine.image_path }, kernel.builder.allocator);
//// Ignore stderr and stdout
//xorriso_process.stdin_behavior = ChildProcess.StdIo.Ignore;
//xorriso_process.stdout_behavior = ChildProcess.StdIo.Ignore;
//xorriso_process.stderr_behavior = ChildProcess.StdIo.Ignore;
//_ = try xorriso_process.spawnAndWait();

//try Limine.installer.install(Limine.image_path, false, null);
//},
//}
//},
//else => unreachable,
//}
//}
//};

const Module = struct {
    type: Type,
    dependencies: []const []const u8,

    fn parse(allocator: common.Allocator, file: []const u8) !Module {
        var token_stream = zig_std.json.TokenStream.init(file);
        const module = try zig_std.json.parse(Module, &token_stream, .{ .allocator = allocator });
        return module;
    }

    fn from_source_file(source_file: anytype) *const Module {
        return &source_file.module.module;
    }

    fn get_path_to_file(module: Module, allocator: common.Allocator, file: []const u8) []const u8 {
        const directory_length = common.last_index_of(u8, module.path, "module.zig") orelse unreachable;
        const directory_path = module.path[0..directory_length];
        const path_to_file = try common.concatenate(allocator, u8, &.{ directory_path, file });
        return path_to_file;
    }

    fn get_program_name(module: Module) []const u8 {
        const directory_length = common.last_index_of(u8, module.path, "module.zig") orelse unreachable;
        const directory_path = module.path[0..directory_length];
        const directory_name = basename(directory_path);
        return directory_name;
    }

    const Type = enum(u32) {
        zig_exe = 0,
        zig_static_lib = 1,
        zig_dynamic_lib = 2,
        c_objects = 3,
    };
};

const UserProgram = struct {
    module: Module,
    path: []const u8,
    name: []const u8,

    fn make(allocator: common.Allocator, module: Module, program_name: []const u8, source_path: []const u8) UserProgram {
        assert(module.type == .zig_exe);
        _ = allocator;
        //_ = module.get_path_to_file(allocator, "main.zig");
        return UserProgram{
            .module = module,
            .path = source_path,
            .name = program_name,
        };
    }
};

const Filesystem = struct {
    disk: *Disk,

    fn write_file(filesystem: *Filesystem, allocator: CustomAllocator, filename: []const u8, file_content: []const u8) !void {
        try RiseFS.write_file(filesystem, allocator, filename, file_content, null);
    }
};

const Kernel = struct {
    builder: *Builder,
    bootloader: ?*LibExeObjStep = null,
    executable: *LibExeObjStep = undefined,
    userspace_programs: []*LibExeObjStep = &.{},
    options: Options,
    boot_image_step: Step = undefined,
    disk_count: u64 = 0,
    disk_step: Step = undefined,
    debug_step: Step = undefined,
    run_argument_list: common.ArrayListManaged([]const u8) = undefined,
    debug_argument_list: common.ArrayListManaged([]const u8) = undefined,
    gdb_script: *WriteFileStep = undefined,
    allocator: CustomAllocator,

    fn create(kernel: *Kernel) !void {
        // Initialize package dependencies here
        common_package.dependencies = &.{common_package};
        rise_package.dependencies = &.{ common_package, rise_package, privileged_package };
        user_package.dependencies = &.{common_package};
        privileged_package.dependencies = &.{ common_package, privileged_package };

        kernel.create_bootloader();
        kernel.create_executable();
        try kernel.create_disassembly_step();
        try kernel.create_userspace_programs();
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
                                bootloader_exe.addPackage(common_package);
                                bootloader_exe.addPackage(privileged_package);
                                bootloader_exe.strip = true;
                                bootloader_exe.setBuildMode(.ReleaseSafe);

                                kernel.builder.default_step.dependOn(&bootloader_exe.step);
                                kernel.bootloader = bootloader_exe;
                            },
                            .bios => {
                                const mbr = kernel.builder.addSystemCommand(&.{ "nasm", "-fbin", "src/bootloader/rise/mbr.S", "-o", "zig-cache/mbr.bin" });
                                //const mbr = kernel.builder.addExecutable("rise.bin", null);
                                //mbr.addAssemblyFile("src/bootloader/rise/mbr.S");
                                //mbr.setLinkerScriptPath(FileSource.relative("src/bootloader/rise/mbr.ld"));
                                //mbr.setTarget(get_target(.x86, false));
                                //mbr.setOutputDir(cache_dir);
                                //mbr.addPackage(common_package);
                                //mbr.addPackage(privileged_package);
                                //mbr.strip = true;
                                //mbr.setBuildMode(kernel.builder.standardReleaseOptions());

                                kernel.builder.default_step.dependOn(&mbr.step);
                                //kernel.bootloader = bootloader_exe;

                                const bootloader_exe = kernel.builder.addExecutable("rise.elf", "src/bootloader/rise/bios.zig");
                                bootloader_exe.setTarget(get_target(.x86, false));
                                bootloader_exe.setOutputDir(cache_dir);
                                bootloader_exe.addPackage(common_package);
                                bootloader_exe.addPackage(privileged_package);
                                bootloader_exe.strip = true;
                                bootloader_exe.link_gc_sections = true;
                                bootloader_exe.want_lto = true;
                                bootloader_exe.force_pic = true;
                                bootloader_exe.setLinkerScriptPath(FileSource.relative("src/bootloader/rise/bios.ld"));
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
                        bootloader_exe.addPackage(common_package);
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
                //kernel.executable.pie = true;
                kernel.executable.code_model = .kernel;
                kernel.executable.setLinkerScriptPath(FileSource.relative(kernel_source_path ++ "arch/x86_64/linker.ld"));
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

        kernel.executable.addPackage(common_package);
        kernel.executable.addPackage(bootloader_package);
        kernel.executable.addPackage(rise_package);
        kernel.executable.addPackage(privileged_package);

        kernel.executable.setMainPkgPath("src");

        kernel.builder.default_step.dependOn(&kernel.executable.step);
    }

    fn create_disassembly_step(kernel: *Kernel) !void {
        var arg_list = common.ArrayListManaged([]const u8).init(kernel.builder.allocator);
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

    fn create_userspace_programs(kernel: *Kernel) !void {
        const linker_script_path = kernel.builder.fmt("src/user/arch/{s}/linker.ld", .{@tagName(kernel.options.arch)});
        const user_programs_path = "src/user/programs";
        const user_programs_dir = try cwd().openIterableDir(user_programs_path, .{});
        var it = user_programs_dir.iterate();

        var unique_programs = common.ArrayListManaged(UserProgram).init(kernel.builder.allocator);
        while (try it.next()) |module_entry| {
            if (module_entry.kind == .Directory) {
                const module_dir = try user_programs_dir.dir.openDir(module_entry.name, .{});
                const module_configuration_file = module_dir.readFileAlloc(kernel.builder.allocator, "module.json", 0x1000 * 16) catch return Error.module_file_not_found;
                const module = try Module.parse(kernel.builder.allocator, module_configuration_file);
                // TODO: change path
                const source_file_path = try common.concatenate(kernel.builder.allocator, u8, &.{ user_programs_path, "/", module_entry.name, "/main.zig" });
                const unique_program = UserProgram.make(kernel.builder.allocator, module, module_entry.name, source_file_path);
                try unique_programs.append(unique_program);
            }
        }

        var libexeobj_steps = try common.ArrayListManaged(*LibExeObjStep).initCapacity(kernel.builder.allocator, unique_programs.items.len);

        for (unique_programs.items) |unique_program| {
            const filename = unique_program.name;
            const source_path = unique_program.path;
            const program = kernel.builder.addExecutable(filename, source_path);

            program.setMainPkgPath("src");
            program.setTarget(get_target(kernel.options.arch, true));
            program.setOutputDir(cache_dir);
            program.setBuildMode(kernel.builder.standardReleaseOptions());
            //program.setBuildMode(.ReleaseSafe);
            program.setLinkerScriptPath(FileSource.relative(linker_script_path));
            program.entry_symbol_name = "user_entry_point";

            program.addPackage(common_package);
            program.addPackage(user_package);

            kernel.builder.default_step.dependOn(&program.step);

            libexeobj_steps.appendAssumeCapacity(program);
        }

        kernel.userspace_programs = libexeobj_steps.toOwnedSlice();
    }

    //fn create_boot_image(kernel: *Kernel) void {
    //kernel.boot_image_step = Step.init(.custom, "_inhouse_image_", kernel.builder.allocator, BootImage.build);
    //const bootloader_step = kernel.bootloader orelse unreachable;
    //kernel.boot_image_step.dependOn(&bootloader_step.step);
    //kernel.boot_image_step.dependOn(&kernel.executable.step);
    //kernel.boot_image_step.dependOn(kernel.builder.default_step);
    //}

    fn create_disk(kernel: *Kernel) void {
        kernel.disk_step = Step.init(.custom, "disk_create", kernel.builder.allocator, Disk.make);

        const named_step = kernel.builder.step("disk", "Create a disk blob to use with QEMU");
        named_step.dependOn(&kernel.disk_step);

        for (kernel.userspace_programs) |program| {
            kernel.disk_step.dependOn(&program.step);
        }
    }

    const Error = error{
        not_implemented,
        module_file_not_found,
    };

    fn create_run_and_debug_steps(kernel: *Kernel) !void {
        kernel.run_argument_list = common.ArrayListManaged([]const u8).init(kernel.builder.allocator);
        switch (kernel.options.run.emulator) {
            .qemu => {
                //defer {
                //if (kernel.options.run.emulator.qemu.print_command) {
                //for (kernel.run_argument_list.items) |arg| {
                //print("{s} ", .{arg});
                //}
                //print("\n\n", .{});
                //}
                //}

                const qemu_name = try common.concatenate(kernel.builder.allocator, u8, &.{ "qemu-system-", @tagName(kernel.options.arch) });
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

                const disk_path = kernel.builder.fmt("{s}disk.bin", .{cache_dir});
                // TODO: don't ignore system interface
                try kernel.run_argument_list.appendSlice(&.{ "-hda", disk_path });
                //&.{ "-drive", kernel.builder.fmt("file={s},index=0,media=disk,format=raw", .{disk_path}) });

                kernel.debug_argument_list = try kernel.run_argument_list.clone();
                if (kernel.options.is_virtualizing()) {
                    const args = &.{
                        "-accel",
                        switch (common.os) {
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
                        var log_what = common.ArrayListManaged(u8).init(kernel.builder.allocator);
                        if (log_options.guest_errors) try log_what.appendSlice("guest_errors,");
                        if (log_options.cpu) try log_what.appendSlice("cpu,");
                        if (log_options.interrupts) try log_what.appendSlice("int,");
                        if (log_options.assembly) try log_what.appendSlice("in_asm,");

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

                try add_qemu_debug_isa_exit(kernel.builder, &kernel.run_argument_list, switch (kernel.options.arch) {
                    .x86_64 => common.QEMU.x86_64_debug_exit,
                    else => return Error.not_implemented,
                });

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
        run_command.step.dependOn(&kernel.disk_step);
        const run_step = kernel.builder.step("run", "run step");
        run_step.dependOn(&run_command.step);

        switch (kernel.options.arch) {
            .x86_64 => run_command.step.dependOn(&kernel.disk_step),
            else => return Error.not_implemented,
        }

        var gdb_script_buffer = common.ArrayListManaged(u8).init(kernel.builder.allocator);
        switch (kernel.options.arch) {
            .x86_64 => try gdb_script_buffer.appendSlice("set disassembly-flavor intel\n"),
            else => return Error.not_implemented,
        }

        const gdb_script_chunk = if (kernel.options.is_virtualizing())
            \\symbol-file zig-cache/kernel.elf
            \\target remote localhost:1234
            \\c
        else
            \\symbol-file zig-cache/kernel.elf
            \\target remote localhost:1234
            \\b kernel_entry_point
            \\c
            ;

        try gdb_script_buffer.appendSlice(gdb_script_chunk);

        kernel.gdb_script = kernel.builder.addWriteFile("gdb_script", gdb_script_buffer.items);
        kernel.builder.default_step.dependOn(&kernel.gdb_script.step);

        // We need a member variable because we need consistent memory around it to do @fieldParentPtr
        kernel.debug_step = Step.init(.custom, "_debug_", kernel.builder.allocator, do_debug_step);
        kernel.debug_step.dependOn(&kernel.boot_image_step);
        kernel.debug_step.dependOn(&kernel.gdb_script.step);
        kernel.debug_step.dependOn(&kernel.disk_step);

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
            //disk: DiskOptions,
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

        fn is_virtualizing(options: Options) bool {
            return switch (options.run.emulator) {
                .qemu => options.run.emulator.qemu.virtualize and arch == options.arch,
                .bochs => false,
            };
        }
    };

    fn get_target(asked_arch: Arch, user: bool) CrossTarget {
        var enabled_features = Target.Cpu.Feature.Set.empty;
        var disabled_features = Target.Cpu.Feature.Set.empty;

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

fn do_debug_step(step: *Step) !void {
    const kernel = @fieldParentPtr(Kernel, "debug_step", step);
    const gdb_script_path = kernel.gdb_script.getFileSource(kernel.gdb_script.files.first.?.data.basename).?.getPath(kernel.builder);
    switch (common.os) {
        .linux, .macos => {
            const first_pid = try fork();
            if (first_pid == 0) {
                switch (common.os) {
                    .linux => {
                        var debugger_process = ChildProcess.init(&[_][]const u8{ "gf2", "-x", gdb_script_path }, kernel.builder.allocator);
                        _ = try debugger_process.spawnAndWait();
                    },
                    .macos => {
                        var debugger_process = ChildProcess.init(&[_][]const u8{ "wezterm", "start", "--cwd", kernel.builder.build_root, "--", "x86_64-elf-gdb", "-x", gdb_script_path }, kernel.builder.allocator);
                        _ = try debugger_process.spawnAndWait();
                    },
                    else => @compileError("OS not supported"),
                }
            } else {
                var qemu_process = ChildProcess.init(kernel.debug_argument_list.items, kernel.builder.allocator);
                try qemu_process.spawn();

                _ = waitpid(first_pid, 0);
                _ = try qemu_process.kill();
            }
        },
        else => {
            @panic("todo implement");
        },
    }
}

const Limine = struct {
    const base_path = "src/bootloader/limine";
    const installables_path = base_path ++ "/installables";
    const image_path = cache_dir ++ "universal.iso";
    const installer = @import("src/bootloader/limine/installer.zig");
};
