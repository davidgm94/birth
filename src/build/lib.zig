const std = @import("../common.zig");
const zig_std = @import("std");

comptime {
    if (os == .freestanding) @compileError("This is only meant to be imported in build.zig");
}

pub const Builder = zig_std.build.Builder;
pub const FileSource = zig_std.build.FileSource;
pub const LibExeObjStep = zig_std.build.LibExeObjStep;
pub const OptionsStep = zig_std.build.OptionsStep;
pub const Package = zig_std.build.Pkg;
pub const RunStep = zig_std.build.RunStep;
pub const Step = zig_std.build.Step;
pub const WriteFileStep = zig_std.build.WriteFileStep;

pub const Target = zig_std.Target;
pub const Arch = Target.Cpu.Arch;
pub const CrossTarget = zig_std.zig.CrossTarget;

pub const os = @import("builtin").target.os.tag;
pub const arch = @import("builtin").target.cpu.arch;

pub const print = zig_std.debug.print;
pub const log = std.log;

pub const fork = zig_std.os.fork;
pub const ChildProcess = zig_std.ChildProcess;
pub const waitpid = zig_std.os.waitpid;

const Allocator = std.Allocator;
const CustomAllocator = std.CustomAllocator;
const RNUFS = std.RNUFS;

const cache_dir = "zig-cache/";
const kernel_name = "kernel.elf";
const kernel_path = cache_dir ++ kernel_name;

const user_programs = .{@import("../user/programs/desktop/dependency.zig")};
const resource_files = [_][]const u8{ "zap-light16.psf", "FiraSans-Regular.otf" };

var common_package = Package{
    .name = "common",
    .source = FileSource.relative("src/common.zig"),
};

var bootloader_package = Package{
    .name = "bootloader",
    .source = FileSource.relative("src/bootloader.zig"),
};

var arch_package = Package{
    .name = "arch",
    .source = FileSource.relative("src/arch.zig"),
};

var rnu_package = Package{
    .name = "RNU",
    .source = FileSource.relative("src/rnu.zig"),
};

var kernel_package = Package{
    .name = "kernel",
    .source = FileSource.relative("src/kernel.zig"),
};

var user_package = Package{
    .name = "user",
    .source = FileSource.relative("src/user.zig"),
};

var privileged_package = Package{
    .name = "privileged",
    .source = FileSource.relative("src/privileged.zig"),
};

pub fn allocate_zero_memory(bytes: u64) ![]align(0x1000) u8 {
    switch (os) {
        .windows => {
            const windows = zig_std.os.windows;
            return @ptrCast([*]align(0x1000) u8, try windows.VirtualAlloc(null, bytes, windows.MEM_RESERVE | windows.MEM_COMMIT, windows.PAGE_READWRITE))[0..bytes];
        },
        else => {
            const mmap = zig_std.os.mmap;
            const PROT = zig_std.os.PROT;
            const MAP = zig_std.os.MAP;
            return try mmap(null, bytes, PROT.READ | PROT.WRITE, MAP.PRIVATE | MAP.ANONYMOUS, -1, 0);
        },
    }
}

pub fn get_allocator() CustomAllocator {
    return CustomAllocator{
        .callback_allocate = allocate,
        .callback_resize = resize,
        .callback_free = free,
    };
}

pub const zero_allocator = CustomAllocator{
    .callback_allocate = zero_allocate,
    .callback_resize = resize,
    .callback_free = free,
};

fn allocate(allocator: *CustomAllocator, size: u64, alignment: u64) CustomAllocator.Error!CustomAllocator.Result {
    const kernel = @fieldParentPtr(Kernel, "allocator", allocator);
    const result = kernel.builder.allocator.allocBytes(@intCast(u29, alignment), size, 0, 0) catch unreachable;
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
    std.assert(alignment <= 0x1000);
    const result = allocate_zero_memory(size) catch unreachable;
    return CustomAllocator.Result{
        .address = @ptrToInt(result.ptr),
        .size = result.len,
    };
}

pub const cwd = zig_std.fs.cwd;
pub const Dir = zig_std.fs.Dir;
pub const path = zig_std.fs.path;
pub const basename = zig_std.fs.path.basename;
pub const dirname = zig_std.fs.path.dirname;

pub fn add_qemu_debug_isa_exit(builder: *Builder, list: *std.ArrayListManaged([]const u8), qemu_debug_isa_exit: std.QEMU.ISADebugExit) !void {
    try list.append("-device");
    try list.append(builder.fmt("isa-debug-exit,iobase=0x{x},iosize=0x{x}", .{ qemu_debug_isa_exit.port, qemu_debug_isa_exit.size }));
}

pub const Disk = struct {
    type: std.Disk.Type = .memory,
    buffer: BufferType,
    sector_size: u64 = 0x200,

    const BufferType = std.ArrayListAligned(u8, 0x1000);

    pub fn access(disk: *Disk, buffer: []u8, work: std.Disk.Work, extra_context: ?*anyopaque) u64 {
        switch (work.operation) {
            .read => unreachable,
            .write => unreachable,
        }
        _ = disk;
        _ = extra_context;
        _ = buffer;
        @panic("todo disk access");
        //const build_disk = @fieldParentPtr(Disk, "disk", disk);
        //_ = extra_context;
        //const sector_size = disk.sector_size;
        ////log.debug("Disk work: {}", .{disk_work});
        //switch (disk_work.operation) {
        //.write => {
        //const work_byte_size = disk_work.sector_count * sector_size;
        //const byte_count = work_byte_size;
        //const write_source_buffer = @intToPtr([*]const u8, buffer.virtual_address)[0..byte_count];
        //const disk_slice_start = disk_work.sector_offset * sector_size;
        //log.debug("Disk slice start: {}. Disk len: {}", .{ disk_slice_start, build_disk.buffer.items.len });
        //std.assert(disk_slice_start == build_disk.buffer.items.len);
        //build_disk.buffer.appendSliceAssumeCapacity(write_source_buffer);

        //return byte_count;
        //},
        //.read => {
        //const offset = disk_work.sector_offset * sector_size;
        //const bytes = disk_work.sector_count * sector_size;
        //const previous_len = build_disk.buffer.items.len;

        //if (offset >= previous_len or offset + bytes > previous_len) build_disk.buffer.items.len = build_disk.buffer.capacity;
        //std.copy(u8, @intToPtr([*]u8, buffer.virtual_address)[0..bytes], build_disk.buffer.items[offset .. offset + bytes]);
        //if (offset >= previous_len or offset + bytes > previous_len) build_disk.buffer.items.len = previous_len;

        //return disk_work.sector_count;
        //},
        //}
    }

    pub fn new(allocator: CustomAllocator, capacity: u64) Disk {
        return Disk{
            .buffer = BufferType.initCapacity(allocator.get_allocator(), capacity) catch unreachable,
        };
    }

    fn create(kernel: *Kernel) void {
        kernel.disk_step = Step.init(.custom, "disk_create", kernel.builder.allocator, make);

        const named_step = kernel.builder.step("disk", "Create a disk blob to use with QEMU");
        named_step.dependOn(&kernel.disk_step);

        for (kernel.userspace_programs) |program| {
            kernel.disk_step.dependOn(&program.step);
        }
    }

    fn make(step: *Step) !void {
        const kernel = @fieldParentPtr(Kernel, "disk_step", step);
        const max_file_length = std.max_int(usize);

        // TODO:
        for (kernel.options.run.disks) |_, disk_i| {
            var disk = Disk.new(zero_allocator, 1024 * 1024 * 1024);
            var filesystem = Filesystem.new(&disk);

            std.assert(resource_files.len > 0);

            for (resource_files) |filename| {
                const file_content = try cwd().readFileAlloc(kernel.builder.allocator, kernel.builder.fmt("resources/{s}", .{filename}), max_file_length);
                filesystem.write_file(kernel.allocator, filename, file_content) catch unreachable;
            }

            std.assert(kernel.userspace_programs.len > 0);

            for (kernel.userspace_programs) |program| {
                const filename = program.out_filename;
                std.log.debug("Exe name: {s}", .{filename});
                const file_path = program.output_path_source.getPath();
                std.log.debug("Exe path: {s}", .{file_path});
                const file_content = try cwd().readFileAlloc(kernel.builder.allocator, file_path, std.max_int(usize));
                filesystem.write_file(get_allocator(), filename, file_content) catch unreachable;
            }

            //const disk_size = build_disk.buffer.items.len;
            //const disk_sector_count = @divFloor(disk_size, build_disk.disk.sector_size);
            //log.debug("Disk size: {}. Disk sector count: {}", .{ disk_size, disk_sector_count });

            try cwd().writeFile(kernel.builder.fmt("{s}disk{}.bin", .{ cache_dir, disk_i }), filesystem.disk.buffer.items);
        }
    }

    fn find_userspace_program(kernel: *Kernel, userspace_program_name: []const u8) ?*LibExeObjStep {
        for (kernel.userspace_programs) |userspace_program| {
            const ending = ".elf";
            std.assert(std.ends_with(u8, userspace_program.out_filename, ending));
            const name = userspace_program.out_filename[0 .. userspace_program.out_filename.len - ending.len];
            if (std.equal(u8, name, userspace_program_name)) {
                return userspace_program;
            }
        }

        return null;
    }
};

pub const Dependency = struct {
    type: Type,
    path: []const u8,
    dependencies: []const *const Dependency,

    pub fn from_source_file(source_file: anytype) *const Dependency {
        return &source_file.dependency.dependency;
    }

    pub fn get_path_to_file(dependency: Dependency, allocator: std.Allocator, file: []const u8) []const u8 {
        const directory_length = std.last_index_of(u8, dependency.path, "dependency.zig") orelse unreachable;
        const directory_path = dependency.path[0..directory_length];
        const path_to_file = std.concatenate(allocator, u8, &.{ directory_path, file }) catch unreachable;
        return path_to_file;
    }

    fn get_program_name(dependency: Dependency) []const u8 {
        const directory_length = std.last_index_of(u8, dependency.path, "/dependency.zig") orelse unreachable;
        const directory_path = dependency.path[0..directory_length];
        const directory_name = basename(directory_path);
        return directory_name;
    }

    pub const Type = enum(u32) {
        zig_exe = 0,
        zig_static_lib = 1,
        zig_dynamic_lib = 2,
        c_objects = 3,
    };
};

pub const CObject = struct {
    dependency: Dependency,
    objects: []const []const u8,
};

pub const UserProgram = struct {
    dependency: Dependency,
    path: []const u8 = undefined,
    name: []const u8 = undefined,

    pub fn make(allocator: std.Allocator, dependencies_file: anytype) UserProgram {
        var zig_exe = dependencies_file.dependency;
        std.assert(zig_exe.dependency.type == .zig_exe);
        zig_exe.path = zig_exe.dependency.get_path_to_file(allocator, "main.zig");
        zig_exe.name = zig_exe.dependency.get_program_name();

        return zig_exe;
    }
};

pub const Filesystem = struct {
    disk: *Disk,

    pub fn new(disk: *Disk) Filesystem {
        disk.buffer.appendSliceAssumeCapacity(&RNUFS.default_signature);
        disk.buffer.items.len = @sizeOf(RNUFS.Superblock);
        return Filesystem{
            .disk = disk,
        };
    }

    pub fn write_file(filesystem: *Filesystem, allocator: CustomAllocator, filename: []const u8, file_content: []const u8) !void {
        try RNUFS.write_file(filesystem, allocator, filename, file_content, null);
    }
};

pub const Kernel = struct {
    builder: *Builder,
    bootloader: ?*LibExeObjStep = null,
    executable: *LibExeObjStep = undefined,
    userspace_programs: []*LibExeObjStep = &.{},
    options: Options,
    boot_image_step: Step = undefined,
    disk_count: u64 = 0,
    disk_step: Step = undefined,
    debug_step: Step = undefined,
    run_argument_list: std.ArrayListManaged([]const u8) = undefined,
    debug_argument_list: std.ArrayListManaged([]const u8) = undefined,
    gdb_script: *WriteFileStep = undefined,
    allocator: CustomAllocator,

    pub fn create(kernel: *Kernel) void {
        // Initialize package dependencies here
        common_package.dependencies = &.{common_package};
        rnu_package.dependencies = &.{ common_package, arch_package, rnu_package, kernel_package, privileged_package };
        arch_package.dependencies = &.{ common_package, bootloader_package, privileged_package, arch_package };
        kernel_package.dependencies = &.{ common_package, rnu_package, arch_package, kernel_package };
        user_package.dependencies = &.{common_package};
        privileged_package.dependencies = &.{ common_package, arch_package, privileged_package };

        kernel.create_bootloader();
        kernel.create_executable();
        kernel.create_disassembly_step();
        kernel.create_userspace_programs();
        kernel.create_boot_image();
        kernel.create_disk();
        kernel.create_run_and_debug_steps();
    }

    fn create_bootloader(kernel: *Kernel) void {
        switch (kernel.options.arch) {
            .x86_64 => {
                switch (kernel.options.arch.x86_64.bootloader) {
                    .limine => {},
                    .inhouse => {
                        const loader = kernel.builder.addSystemCommand(&.{ "nasm", "-fbin", "src/bootloader/inhouse/uefi_trampoline.asm", "-o", "zig-cache/uefi_trampoline.bin" });
                        const bootloader_exe = kernel.builder.addExecutable("BOOTX64", "src/bootloader/inhouse/uefi.zig");
                        bootloader_exe.setTarget(.{
                            .cpu_arch = .x86_64,
                            .os_tag = .uefi,
                            .abi = .msvc,
                        });
                        bootloader_exe.setOutputDir(cache_dir);
                        bootloader_exe.addPackage(common_package);
                        bootloader_exe.addPackage(privileged_package);
                        bootloader_exe.addPackage(arch_package);
                        //bootloader_exe.strip = true;
                        //bootloader_exe.setBuildMode(.ReleaseFast);
                        bootloader_exe.step.dependOn(&loader.step);

                        kernel.builder.default_step.dependOn(&bootloader_exe.step);
                        kernel.builder.default_step.dependOn(&loader.step);
                        kernel.bootloader = bootloader_exe;
                    },
                }
            },
            else => unreachable,
        }
    }

    fn create_executable(kernel: *Kernel) void {
        const target = get_target(kernel.options.arch, false);

        switch (kernel.options.arch) {
            .x86_64 => {
                const zig_root_file = switch (kernel.options.arch.x86_64.bootloader) {
                    .inhouse => "src/kernel/arch/x86_64/inhouse_entry_point.zig",
                    .limine => "src/kernel/arch/x86_64/limine_entry_point.zig",
                };

                kernel.executable = kernel.builder.addExecutable(kernel_name, zig_root_file);
                kernel.executable.code_model = .kernel;
                //kernel.executable.pie = true;
                kernel.executable.force_pic = true;
                kernel.executable.disable_stack_probing = true;
                kernel.executable.stack_protector = false;
                kernel.executable.strip = false;
                kernel.executable.code_model = .kernel;
                kernel.executable.red_zone = false;
                kernel.executable.omit_frame_pointer = false;
                kernel.executable.entry_symbol_name = "kernel_entry_point";
                kernel.executable.setLinkerScriptPath(FileSource.relative("src/kernel/arch/x86_64/linker.ld"));
            },
            else => unreachable,
        }

        kernel.executable.addPackage(common_package);
        kernel.executable.addPackage(bootloader_package);
        kernel.executable.addPackage(kernel_package);
        kernel.executable.addPackage(rnu_package);
        kernel.executable.addPackage(arch_package);

        kernel.executable.setMainPkgPath("src");
        kernel.executable.setTarget(target);
        kernel.executable.setBuildMode(kernel.builder.standardReleaseOptions());
        kernel.executable.setOutputDir(cache_dir);
        kernel.executable.emit_llvm_ir = .{ .emit_to = cache_dir ++ "kernel_llvm.ir" };

        kernel.builder.default_step.dependOn(&kernel.executable.step);
    }

    fn create_disassembly_step(kernel: *Kernel) void {
        var arg_list = std.ArrayListManaged([]const u8).init(kernel.builder.allocator);
        const main_args = &.{ "llvm-objdump", kernel_path };
        const common_flags = &.{ "-d", "-S" };
        arg_list.appendSlice(main_args) catch unreachable;
        arg_list.appendSlice(common_flags) catch unreachable;
        switch (kernel.options.arch) {
            .x86_64 => arg_list.append("-Mintel") catch unreachable,
            else => {},
        }
        const disassembly_kernel = kernel.builder.addSystemCommand(arg_list.items);
        disassembly_kernel.step.dependOn(&kernel.executable.step);
        const disassembly_kernel_step = kernel.builder.step("disasm", "Disassembly the kernel ELF");
        disassembly_kernel_step.dependOn(&disassembly_kernel.step);
    }

    fn create_userspace_programs(kernel: *Kernel) void {
        const linker_script_path = kernel.builder.fmt("src/user/arch/{s}/linker.ld", .{@tagName(kernel.options.arch)});

        var libexeobj_steps = std.ArrayListManaged(*LibExeObjStep).initCapacity(kernel.builder.allocator, user_programs.len) catch unreachable;
        inline for (user_programs) |user_program| {
            const unique_program = UserProgram.make(kernel.builder.allocator, user_program);
            const out_filename = kernel.builder.fmt("{s}.elf", .{unique_program.name});
            const main_source_file = unique_program.path;
            const program = kernel.builder.addExecutable(out_filename, main_source_file);

            for (unique_program.dependency.dependencies) |dependency| {
                switch (dependency.type) {
                    .c_objects => {
                        const cobjects = @ptrCast(*const CObject, dependency);
                        for (cobjects.objects) |object_name| {
                            const path_to_cobject = cobjects.dependency.get_path_to_file(kernel.builder.allocator, object_name);
                            program.addObjectFile(path_to_cobject);
                        }
                        std.assert(cobjects.dependency.dependencies.len == 0);
                    },
                    else => unreachable,
                }
            }

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

        kernel.userspace_programs = libexeobj_steps.items;
    }

    fn create_boot_image(kernel: *Kernel) void {
        kernel.boot_image_step = Step.init(.custom, "_inhouse_image_", kernel.builder.allocator, BootImage.build);
        const bootloader_step = kernel.bootloader orelse unreachable;
        kernel.boot_image_step.dependOn(&bootloader_step.step);
        kernel.boot_image_step.dependOn(&kernel.executable.step);
        kernel.boot_image_step.dependOn(kernel.builder.default_step);
    }

    fn create_disk(kernel: *Kernel) void {
        Disk.create(kernel);
    }

    fn create_run_and_debug_steps(kernel: *Kernel) void {
        kernel.run_argument_list = std.ArrayListManaged([]const u8).init(kernel.builder.allocator);
        switch (kernel.options.run.emulator) {
            .qemu => {
                const qemu_name = std.concatenate(kernel.builder.allocator, u8, &.{ "qemu-system-", @tagName(kernel.options.arch) }) catch unreachable;
                kernel.run_argument_list.append(qemu_name) catch unreachable;

                if (!kernel.options.is_virtualizing()) {
                    kernel.run_argument_list.append("-trace") catch unreachable;
                    kernel.run_argument_list.append("-nvme*") catch unreachable;
                    kernel.run_argument_list.append("-trace") catch unreachable;
                    kernel.run_argument_list.append("-pci*") catch unreachable;
                    kernel.run_argument_list.append("-trace") catch unreachable;
                    kernel.run_argument_list.append("-ide*") catch unreachable;
                    kernel.run_argument_list.append("-trace") catch unreachable;
                    kernel.run_argument_list.append("-ata*") catch unreachable;
                    kernel.run_argument_list.append("-trace") catch unreachable;
                    kernel.run_argument_list.append("-ahci*") catch unreachable;
                    kernel.run_argument_list.append("-trace") catch unreachable;
                    kernel.run_argument_list.append("-sata*") catch unreachable;
                }

                // Boot device
                switch (kernel.options.arch) {
                    .x86_64 => {
                        switch (kernel.options.arch.x86_64.bootloader) {
                            .inhouse => {
                                kernel.run_argument_list.appendSlice(&.{ "-hdd", "fat:rw:./zig-cache/img_dir" }) catch unreachable;
                                kernel.run_argument_list.appendSlice(&.{ "-bios", "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd" }) catch unreachable;
                                kernel.run_argument_list.appendSlice(&.{ "-L", "zig-cache/ovmf" }) catch unreachable;
                            },
                            .limine => {
                                kernel.run_argument_list.appendSlice(&.{ "-cdrom", Limine.image_path }) catch unreachable;
                            },
                        }
                    },
                    .riscv64 => {
                        kernel.run_argument_list.append("-bios") catch unreachable;
                        kernel.run_argument_list.append("default") catch unreachable;
                        kernel.run_argument_list.append("-kernel") catch unreachable;
                        kernel.run_argument_list.append(kernel_path) catch unreachable;
                    },
                    else => unreachable,
                }

                {
                    kernel.run_argument_list.append("-no-reboot") catch unreachable;
                    kernel.run_argument_list.append("-no-shutdown") catch unreachable;
                }

                {
                    const memory_arg = kernel.builder.fmt("{}{s}", .{ kernel.options.run.memory.amount, @tagName(kernel.options.run.memory.unit) });
                    kernel.run_argument_list.append("-m") catch unreachable;
                    kernel.run_argument_list.append(memory_arg) catch unreachable;
                }

                if (kernel.options.run.emulator.qemu.smp) |smp_count| {
                    kernel.run_argument_list.append("-smp") catch unreachable;
                    kernel.run_argument_list.append(kernel.builder.fmt("{}", .{smp_count})) catch unreachable;
                }

                if (kernel.options.run.emulator.qemu.vga) |vga_option| {
                    kernel.run_argument_list.append("-vga") catch unreachable;
                    kernel.run_argument_list.append(@tagName(vga_option)) catch unreachable;
                } else {
                    kernel.run_argument_list.append("-vga") catch unreachable;
                    kernel.run_argument_list.append("none") catch unreachable;
                    kernel.run_argument_list.append("-display") catch unreachable;
                    kernel.run_argument_list.append("none") catch unreachable;
                    //kernel.run_argument_list.append("-nographic") catch unreachable;
                }

                if (kernel.options.arch == .x86_64) {
                    kernel.run_argument_list.append("-debugcon") catch unreachable;
                    kernel.run_argument_list.append("stdio") catch unreachable;
                }

                kernel.run_argument_list.append("-global") catch unreachable;
                kernel.run_argument_list.append("virtio-mmio.force-legacy=false") catch unreachable;

                for (kernel.options.run.disks) |disk, disk_i| {
                    const disk_id = kernel.builder.fmt("disk{}", .{disk_i});
                    const disk_path = kernel.builder.fmt("{s}{s}.bin", .{ cache_dir, disk_id });

                    switch (disk.interface) {
                        .nvme => {
                            kernel.run_argument_list.append("-device") catch unreachable;
                            const device_options = kernel.builder.fmt("nvme,drive={s},serial=1234", .{disk_id});
                            kernel.run_argument_list.append(device_options) catch unreachable;
                            kernel.run_argument_list.append("-drive") catch unreachable;
                            const drive_options = kernel.builder.fmt("file={s},if=none,id={s},format=raw", .{ disk_path, disk_id });
                            kernel.run_argument_list.append(drive_options) catch unreachable;
                        },
                        .virtio => {
                            kernel.run_argument_list.append("-device") catch unreachable;
                            const device_type = switch (kernel.options.arch) {
                                .x86_64 => "pci",
                                .riscv64 => "device",
                                else => unreachable,
                            };
                            const device_options = kernel.builder.fmt("virtio-blk-{s},drive={s}", .{ device_type, disk_id });
                            kernel.run_argument_list.append(device_options) catch unreachable;
                            kernel.run_argument_list.append("-drive") catch unreachable;
                            const drive_options = kernel.builder.fmt("file={s},if=none,id={s},format=raw", .{ disk_path, disk_id });
                            kernel.run_argument_list.append(drive_options) catch unreachable;
                        },
                        .ide => {
                            kernel.run_argument_list.append("-device") catch unreachable;
                            std.assert(kernel.options.arch == .x86_64);
                            kernel.run_argument_list.append("piix3-ide,id=ide") catch unreachable;

                            kernel.run_argument_list.append("-drive") catch unreachable;
                            kernel.run_argument_list.append(kernel.builder.fmt("id={s},file={s},format=raw,if=none", .{ disk_id, disk_path })) catch unreachable;
                            kernel.run_argument_list.append("-device") catch unreachable;
                            // ide bus port is hardcoded to avoid errors
                            kernel.run_argument_list.append(kernel.builder.fmt("ide-hd,drive={s},bus=ide.0", .{disk_id})) catch unreachable;
                        },
                        .ahci => {
                            kernel.run_argument_list.append("-device") catch unreachable;
                            kernel.run_argument_list.append("ahci,id=ahci") catch unreachable;

                            kernel.run_argument_list.append("-drive") catch unreachable;
                            kernel.run_argument_list.append(kernel.builder.fmt("id={s},file={s},format=raw,if=none", .{ disk_id, disk_path })) catch unreachable;
                            kernel.run_argument_list.append("-device") catch unreachable;
                            // ide bus port is hardcoded to avoid errors
                            kernel.run_argument_list.append(kernel.builder.fmt("ide-hd,drive={s},bus=ahci.0", .{disk_id})) catch unreachable;
                        },

                        else => unreachable,
                    }
                }

                // Here the arch-specific stuff start and that's why the lists are split.
                //kernel.run_argument_list.append("-machine") catch unreachable;
                kernel.debug_argument_list = kernel.run_argument_list.clone() catch unreachable;
                //const machine = switch (kernel.options.arch) {
                //.x86_64 => "q35",
                //.riscv64 => "virt",
                //else => unreachable,
                //};
                //kernel.debug_argument_list.append(machine) catch unreachable;
                if (kernel.options.is_virtualizing()) {
                    const args = &.{ "-enable-kvm", "-cpu", "host" };
                    kernel.run_argument_list.appendSlice(args) catch unreachable;
                    kernel.debug_argument_list.appendSlice(args) catch unreachable;
                } else {
                    //kernel.run_argument_list.append(machine) catch unreachable;
                    if (kernel.options.run.emulator.qemu.log) |log_options| {
                        var log_what = std.ArrayListManaged(u8).init(kernel.builder.allocator);
                        if (log_options.guest_errors) log_what.appendSlice("guest_errors,") catch unreachable;
                        if (log_options.cpu) log_what.appendSlice("cpu,") catch unreachable;
                        if (log_options.interrupts) log_what.appendSlice("int,") catch unreachable;
                        if (log_options.assembly) log_what.appendSlice("in_asm,") catch unreachable;

                        if (log_what.items.len > 0) {
                            // Delete the last comma
                            _ = log_what.pop();

                            const log_flag = "-d";
                            kernel.run_argument_list.append(log_flag) catch unreachable;
                            kernel.debug_argument_list.append(log_flag) catch unreachable;
                            kernel.run_argument_list.append(log_what.items) catch unreachable;
                            kernel.debug_argument_list.append(log_what.items) catch unreachable;
                        }

                        if (log_options.file) |log_file| {
                            const log_file_flag = "-D";
                            kernel.run_argument_list.append(log_file_flag) catch unreachable;
                            kernel.debug_argument_list.append(log_file_flag) catch unreachable;
                            kernel.run_argument_list.append(log_file) catch unreachable;
                            kernel.debug_argument_list.append(log_file) catch unreachable;
                        }
                    }
                }

                add_qemu_debug_isa_exit(kernel.builder, &kernel.run_argument_list, switch (kernel.options.arch) {
                    .x86_64 => std.QEMU.x86_64_debug_exit,
                    else => unreachable,
                }) catch unreachable;

                if (!kernel.options.is_virtualizing()) {
                    kernel.debug_argument_list.append("-S") catch unreachable;
                }

                kernel.debug_argument_list.append("-s") catch unreachable;
            },
        }

        if (kernel.options.run.emulator.qemu.print_command) {
            for (kernel.run_argument_list.items) |arg| {
                print("{s} ", .{arg});
            }
            print("\n\n", .{});
        }

        const run_command = kernel.builder.addSystemCommand(kernel.run_argument_list.items);
        run_command.step.dependOn(kernel.builder.default_step);
        run_command.step.dependOn(&kernel.disk_step);
        const run_step = kernel.builder.step("run", "run step");
        run_step.dependOn(&run_command.step);

        switch (kernel.options.arch) {
            .x86_64 => run_command.step.dependOn(&kernel.boot_image_step),
            else => unreachable,
        }

        var gdb_script_buffer = std.ArrayListManaged(u8).init(kernel.builder.allocator);
        switch (kernel.options.arch) {
            .x86_64 => gdb_script_buffer.appendSlice("set disassembly-flavor intel\n") catch unreachable,
            else => {},
        }
        if (kernel.options.is_virtualizing()) {
            gdb_script_buffer.appendSlice(
                \\symbol-file zig-cache/kernel.elf
                \\target remote localhost:1234
                \\c
            ) catch unreachable;
        } else {
            gdb_script_buffer.appendSlice(
                \\symbol-file zig-cache/kernel.elf
                \\target remote localhost:1234
                \\b kernel_entry_point
                \\c
            ) catch unreachable;
        }

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

    const BootImage = struct {
        fn build(step: *Step) !void {
            const kernel = @fieldParentPtr(Kernel, "boot_image_step", step);

            switch (kernel.options.arch) {
                .x86_64 => {
                    switch (kernel.options.arch.x86_64.bootloader) {
                        .inhouse => {
                            var cache_dir_handle = try zig_std.fs.cwd().openDir(kernel.builder.cache_root, .{});
                            defer cache_dir_handle.close();
                            const img_dir_path = kernel.builder.fmt("{s}/img_dir", .{kernel.builder.cache_root});
                            const current_directory = cwd();
                            current_directory.deleteFile(Limine.image_path) catch {};
                            const img_dir = try current_directory.makeOpenPath(img_dir_path, .{});
                            const img_efi_dir = try img_dir.makeOpenPath("EFI/BOOT", .{});

                            try Dir.copyFile(cache_dir_handle, "BOOTX64.efi", img_efi_dir, "BOOTX64.EFI", .{});
                            try Dir.copyFile(cache_dir_handle, "kernel.elf", img_dir, "kernel.elf", .{});
                            try Dir.copyFile(cache_dir_handle, "uefi_trampoline.bin", img_dir, "uefi_trampoline.bin", .{});
                        },
                        .limine => {
                            const img_dir_path = kernel.builder.fmt("{s}/img_dir", .{kernel.builder.cache_root});
                            const current_directory = cwd();
                            current_directory.deleteFile(Limine.image_path) catch {};
                            const img_dir = try current_directory.makeOpenPath(img_dir_path, .{});
                            const img_efi_dir = try img_dir.makeOpenPath("EFI/BOOT", .{});

                            const limine_dir = try current_directory.openDir(Limine.installables_path, .{});

                            const limine_efi_bin_file = "limine-cd-efi.bin";
                            const files_to_copy_from_limine_dir = [_][]const u8{
                                "limine.cfg",
                                "limine.sys",
                                "limine-cd.bin",
                                limine_efi_bin_file,
                            };

                            for (files_to_copy_from_limine_dir) |filename| {
                                log.debug("Trying to copy {s}", .{filename});
                                try Dir.copyFile(limine_dir, filename, img_dir, filename, .{});
                            }
                            try Dir.copyFile(limine_dir, "BOOTX64.EFI", img_efi_dir, "BOOTX64.EFI", .{});
                            try Dir.copyFile(current_directory, kernel_path, img_dir, path.basename(kernel_path), .{});

                            const xorriso_executable = switch (std.os) {
                                .windows => "tools/xorriso-windows/xorriso.exe",
                                else => "xorriso",
                            };
                            var xorriso_process = ChildProcess.init(&.{ xorriso_executable, "-as", "mkisofs", "-quiet", "-b", "limine-cd.bin", "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table", "--efi-boot", limine_efi_bin_file, "-efi-boot-part", "--efi-boot-image", "--protective-msdos-label", img_dir_path, "-o", Limine.image_path }, kernel.builder.allocator);
                            // Ignore stderr and stdout
                            xorriso_process.stdin_behavior = ChildProcess.StdIo.Ignore;
                            xorriso_process.stdout_behavior = ChildProcess.StdIo.Ignore;
                            xorriso_process.stderr_behavior = ChildProcess.StdIo.Ignore;
                            _ = try xorriso_process.spawnAndWait();

                            try Limine.installer.install(Limine.image_path, false, null);
                        },
                    }
                },
                else => unreachable,
            }
        }
        //const x86_64 = struct {
        //const InHouse = struct {
        //const flat_binaries = &[_][]const u8{ "mbr", "stage1" };

        //fn build(step: *Step) !void {
        //const kernel = @fieldParentPtr(Kernel, "boot_image_step", step);
        //var disk_buffer = std.ArrayListManaged(u8).init(kernel.builder.allocator);
        //const bootloader_file_handle = try zig_std.fs.cwd().openFile("zig-cache/bootloader.elf", .{});
        //defer bootloader_file_handle.close();
        //try bootloader_file_handle.reader().readAllArrayList(&disk_buffer, 0xffff_ffff_ffff_ffff);

        //log.debug("disk len: {}", .{disk_buffer.items.len});
        //std.assert(disk_buffer.items.len < 100000);
        //try disk_buffer.appendNTimes(0, 100000 - disk_buffer.items.len);

        //const kernel_file_handle = try zig_std.fs.cwd().openFile(kernel_path, .{});
        //defer kernel_file_handle.close();

        //try kernel_file_handle.reader().readAllArrayList(&disk_buffer, 0xffff_ffff_ffff_ffff);
        //try disk_buffer.appendNTimes(0, std.align_forward(disk_buffer.items.len, 0x200) - disk_buffer.items.len);

        //try zig_std.fs.cwd().writeFile("zig-cache/disk.bin", disk_buffer.items);
        //}
        //};

        //const Limine = struct {
        //const image_path = cache_dir ++ "universal.iso";

        //fn new(kernel: *Kernel) Step {
        //var step = Step.init(.custom, "_limine_image_", kernel.builder.allocator, Limine.build);
        //step.dependOn(&kernel.executable.step);
        //return step;
        //}

        //fn build(step: *Step) !void {
        //const kernel = @fieldParentPtr(Kernel, "boot_image_step", step);
        //std.assert(kernel.options.arch == .x86_64);
        //}
        //};
        //};
    };

    pub const Options = struct {
        arch: Options.ArchSpecific,
        run: RunOptions,

        pub const x86_64 = struct {
            bootloader: union(Bootloader) {
                limine: void,
                inhouse: void,
            },

            const Bootloader = enum {
                inhouse,
                limine,
            };

            pub fn new(context: anytype) Options.ArchSpecific {
                return switch (context.bootloader) {
                    .inhouse => .{
                        .x86_64 = .{
                            .bootloader = .{
                                .inhouse = {},
                            },
                        },
                    },
                    .limine => .{
                        .x86_64 = .{
                            .bootloader = .{
                                .limine = {},
                            },
                        },
                    },
                    else => unreachable,
                };
            }
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
            riscv64: void,
            sparc,
            sparc64,
            sparcel,
            s390x,
            tce,
            tcele,
            thumb,
            thumbeb,
            i386,
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
            disks: []const DiskOptions,
            memory: Memory,
            emulator: union(enum) {
                qemu: QEMU,
            },

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

            const DiskOptions = struct {
                interface: std.Disk.Type,
                filesystem: std.Filesystem.Type,
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
            return options.run.emulator.qemu.virtualize and arch == options.arch;
        }
    };
    const CPUFeatures = struct {
        enabled: Target.Cpu.Feature.Set,
        disabled: Target.Cpu.Feature.Set,

        fn disable_fpu(features: *CPUFeatures) void {
            const Feature = Target.x86.Feature;
            features.disabled.addFeature(@enumToInt(Feature.x87));
            features.disabled.addFeature(@enumToInt(Feature.mmx));
            features.disabled.addFeature(@enumToInt(Feature.sse));
            features.disabled.addFeature(@enumToInt(Feature.sse2));
            features.disabled.addFeature(@enumToInt(Feature.avx));
            features.disabled.addFeature(@enumToInt(Feature.avx2));

            features.enabled.addFeature(@enumToInt(Feature.soft_float));
        }
    };
    fn get_x86_base_features() CPUFeatures {
        var features = CPUFeatures{
            .enabled = Target.Cpu.Feature.Set.empty,
            .disabled = Target.Cpu.Feature.Set.empty,
        };

        return features;
    }
    //
    //fn CPUFeatures

    fn get_target(asked_arch: Arch, user: bool) CrossTarget {
        var cpu_features = CPUFeatures{
            .enabled = Target.Cpu.Feature.Set.empty,
            .disabled = Target.Cpu.Feature.Set.empty,
        };

        if (!user) {
            cpu_features.disable_fpu();
        }

        const target = CrossTarget{
            .cpu_arch = asked_arch,
            .os_tag = .freestanding,
            .abi = .none,
            .cpu_features_add = cpu_features.enabled,
            .cpu_features_sub = cpu_features.disabled,
        };

        return target;
    }
};
fn do_debug_step(step: *Step) !void {
    const kernel = @fieldParentPtr(Kernel, "debug_step", step);
    const gdb_script_path = kernel.gdb_script.getFileSource(kernel.gdb_script.files.first.?.data.basename).?.getPath(kernel.builder);
    switch (std.os) {
        .linux, .macos => {
            const first_pid = try fork();
            if (first_pid == 0) {
                switch (std.os) {
                    .linux => {
                        var debugger_process = ChildProcess.init(&[_][]const u8{ "gf2", "-x", gdb_script_path }, kernel.builder.allocator);
                        _ = try debugger_process.spawnAndWait();
                    },
                    .macos => {
                        var debugger_process = ChildProcess.init(&[_][]const u8{ "wezterm", "start", "--cwd", kernel.builder.build_root, "--", "x86_64-elf-gdb", "-x", gdb_script_path }, kernel.builder.allocator);
                        _ = try debugger_process.spawnAndWait();
                    },
                    else => unreachable,
                }
            } else {
                var qemu_process = ChildProcess.init(kernel.debug_argument_list.items, kernel.builder.allocator);
                try qemu_process.spawn();

                _ = waitpid(first_pid, 0);
                _ = try qemu_process.kill();
            }
        },
        else => unreachable,
    }
}

pub const Limine = struct {
    const base_path = "src/bootloader/limine";
    const installables_path = base_path ++ "/installables";
    const image_path = cache_dir ++ "universal.iso";
    const installer = @import("../bootloader/limine/installer.zig");
};
