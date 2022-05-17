const std = @import("std");
const builtin = @import("builtin");

const fs = @import("src/build/fs.zig");
const Builder = std.build.Builder;

const building_os = builtin.target.os.tag;
const current_arch = std.Target.Cpu.Arch.riscv64;

const cache_dir = "zig-cache";
const kernel_name = "kernel.elf";
const kernel_path = cache_dir ++ "/" ++ kernel_name;

fn get_target_base(arch: std.Target.Cpu.Arch) std.zig.CrossTarget {
    var enabled_features = std.Target.Cpu.Feature.Set.empty;
    var disabled_features = std.Target.Cpu.Feature.Set.empty;

    switch (arch) {
        .riscv64 => {
            const features = std.Target.riscv.Feature;
            enabled_features.addFeature(@enumToInt(features.a));
        },
        else => unreachable,
    }

    return std.zig.CrossTarget{
        .cpu_arch = arch,
        .os_tag = .freestanding,
        .abi = .none,
        .cpu_features_add = enabled_features,
        .cpu_features_sub = disabled_features,
    };
}

fn set_target_specific_parameters(kernel_exe: *std.build.LibExeObjStep) void {
    switch (current_arch) {
        .riscv64 => {
            var target = get_target_base(.riscv64);
            target.cpu_features_sub.addFeature(@enumToInt(std.Target.riscv.Feature.d));

            kernel_exe.entry_symbol_name = "_start";
            kernel_exe.code_model = .medium;
            kernel_exe.setTarget(target);
            kernel_exe.setLinkerScriptPath(std.build.FileSource.relative("src/kernel/arch/riscv64/linker.ld"));
            const riscv_folder = "src/kernel/arch/riscv64/";
            const riscv_asssembly_files = [_][]const u8{
                riscv_folder ++ "start.S",
                riscv_folder ++ "interrupt.S",
            };
            inline for (riscv_asssembly_files) |asm_file| {
                kernel_exe.addAssemblyFile(asm_file);
            }
        },
        else => @compileError("CPU architecture not supported\n"),
    }
}

pub fn build(b: *Builder) void {
    const kernel = b.addExecutable(kernel_name, "src/kernel/root.zig");
    set_target_specific_parameters(kernel);
    kernel.setMainPkgPath("src");
    kernel.setBuildMode(b.standardReleaseOptions());
    kernel.setOutputDir(cache_dir);
    b.default_step.dependOn(&kernel.step);

    const minimal = b.addExecutable("minimal.elf", "src/user/minimal/main.zig");
    minimal.setTarget(get_target_base(current_arch));
    minimal.setOutputDir(cache_dir);
    b.default_step.dependOn(&minimal.step);

    const disk = HDD.create(b);
    disk.step.dependOn(&minimal.step);
    const qemu = qemu_command(b);
    qemu.step.dependOn(&kernel.step);
    // TODO: as disk is not written, this dependency doesn't need to be executed for every time the run step is executed
    //qemu.step.dependOn(&disk.step);

    const debug = Debug.create(b);
    debug.step.dependOn(&kernel.step);
    debug.step.dependOn(&disk.step);
}

const HDD = struct {
    const block_size = 0x400;
    const block_count = 32;
    var buffer: [block_size * block_count]u8 align(0x1000) = undefined;
    const path = "zig-cache/hdd.bin";

    step: std.build.Step,
    b: *std.build.Builder,

    fn create(b: *Builder) *HDD {
        const step = b.allocator.create(HDD) catch @panic("out of memory\n");
        step.* = .{
            .step = std.build.Step.init(.custom, "hdd_create", b.allocator, make),
            .b = b,
        };

        return step;
    }

    fn make(step: *std.build.Step) !void {
        const parent = @fieldParentPtr(HDD, "step", step);
        const allocator = parent.b.allocator;
        const font_file = try std.fs.cwd().readFileAlloc(allocator, "resources/zap-light16.psf", std.math.maxInt(usize));
        std.debug.print("Font file size: {} bytes\n", .{font_file.len});
        var disk = fs.MemoryDisk{
            .bytes = buffer[0..],
        };
        fs.add_file(disk, "font.psf", font_file);
        fs.read(disk);
        //std.mem.copy(u8, &buffer, font_file);

        try std.fs.cwd().writeFile(HDD.path, &HDD.buffer);
    }
};

fn qemu_command(b: *Builder) *std.build.RunStep {
    const run_step = b.addSystemCommand(&qemu_command_str);
    const step = b.step("run", "run step");
    step.dependOn(&run_step.step);
    return run_step;
}

const Debug = struct {
    step: std.build.Step,
    b: *std.build.Builder,

    fn create(b: *std.build.Builder) *Debug {
        const self = b.allocator.create(@This()) catch @panic("out of memory\n");
        self.* = Debug{
            .step = std.build.Step.init(.custom, "_debug_", b.allocator, make),
            .b = b,
        };

        const named_step = b.step("debug", "Debug the program with QEMU and GDB");
        named_step.dependOn(&self.step);
        return self;
    }

    fn make(step: *std.build.Step) !void {
        const self = @fieldParentPtr(Debug, "step", step);
        const b = self.b;
        const terminal_thread = try std.Thread.spawn(.{}, terminal_and_gdb_thread, .{b});
        const process = std.ChildProcess.init(&qemu_command_str ++ [_][]const u8{ "-S", "-s" }, b.allocator) catch unreachable;
        _ = process.spawnAndWait() catch unreachable;

        terminal_thread.join();
    }

    fn terminal_and_gdb_thread(b: *std.build.Builder) void {
        switch (building_os) {
            .linux, .macos => {
                // zig fmt: off
                const process = std.ChildProcess.init(&.{
                    "kitty", "--start-as=maximized",
                    "riscv64-elf-gdb",
                    "-tui",
                    "-ex", "symbol-file zig-cache/kernel.elf",
                    "-ex", "target remote :1234",
                    "-ex", "b riscv_start",
                    "-ex", "b kernel.panic.panic",
                    "-ex", "c",
                }, b.allocator) catch unreachable;
                // zig fmt: on
                _ = process.spawnAndWait() catch unreachable;
            },
            else => unreachable,
        }
    }

    fn get_terminal_name() []const []const u8 {
        if (builtin.target.os.tag == .linux) {
            return "kitty";
        } else unreachable;
    }
};

// zig fmt: off
const qemu_command_str = [_][]const u8 {
    "qemu-system-riscv64",
    "-no-reboot", "-no-shutdown",
    "-machine", "virt",
    "-cpu", "rv64",
    "-m", "4G",
    "-bios", "default",
    "-kernel", kernel_path,
    "-serial", "mon:stdio",
    "-drive", "if=none,format=raw,file=zig-cache/hdd.bin,id=foo",
    "-global", "virtio-mmio.force-legacy=false",
    "-device", "virtio-blk-device,drive=foo",
    "-device", "virtio-gpu-device",
    "-d", "guest_errors,int",
    //"-D", "logfile",

    //"-trace", "virtio*",
    //"-S", "-s",
};
// zig fmt: on
