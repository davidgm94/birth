const std = @import("std");
const builtin = @import("builtin");
const Builder = std.build.Builder;

const os = builtin.target.os.tag;

const current_arch = std.Target.Cpu.Arch.riscv64;

const cache_dir = "zig-cache";
const kernel_name = "kernel.elf";
const kernel_path = cache_dir ++ "/" ++ kernel_name;

fn set_target_specific_parameters(kernel_exe: *std.build.LibExeObjStep) void {
    switch (current_arch) {
        .riscv64 => {
            var enabled_features = std.Target.Cpu.Feature.Set.empty;
            const features = std.Target.riscv.Feature;
            enabled_features.addFeature(@enumToInt(features.a));
            var disabled_features = std.Target.Cpu.Feature.Set.empty;
            disabled_features.addFeature(@enumToInt(features.d));
            const target = std.zig.CrossTarget{
                .cpu_arch = .riscv64,
                .os_tag = .freestanding,
                .abi = .none,
                .cpu_features_add = enabled_features,
                .cpu_features_sub = disabled_features,
            };
            kernel_exe.code_model = .medium;
            kernel_exe.setTarget(target);
            kernel_exe.setLinkerScriptPath(std.build.FileSource.relative("src/kernel/arch/riscv64/linker.ld"));
        },
        else => @compileError("Not supported arch\n"),
    }
}

pub fn build(b: *Builder) void {
    const exe = b.addExecutable(kernel_name, "src/kernel/root.zig");
    set_target_specific_parameters(exe);
    exe.setBuildMode(b.standardReleaseOptions());
    exe.setOutputDir(cache_dir);
    b.default_step.dependOn(&exe.step);

    const disk = HDD.create(b);
    const qemu = qemu_command(b);
    qemu.step.dependOn(&exe.step);
    qemu.step.dependOn(&disk.step);

    const debug = Debug.create(b);
    debug.step.dependOn(&exe.step);
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
        std.mem.copy(u8, &buffer, font_file);
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
        switch (os) {
            .linux, .macos => {
                // zig fmt: off
                const process = std.ChildProcess.init(&.{
                    "kitty", "--start-as=maximized",
                    "riscv64-unknown-elf-gdb",
                    "-ex", "symbol-file zig-cache/kernel.elf",
                    "-ex", "target remote :1234",
                    "-ex", "b main",
                    "-ex", "b panic",
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
    "-m", "128M",
    "-bios", "default",
    "-kernel", kernel_path,
    "-serial", "mon:stdio",
    "-drive", "if=none,format=raw,file=zig-cache/hdd.bin,id=foo",
    "-device", "virtio-blk-device,drive=foo",
    "-device", "virtio-gpu-device",
    "-d", "guest_errors,int",
    "-trace", "virtio*",
    //"-S", "-s",
};
// zig fmt: on
