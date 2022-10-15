const common = @import("src/common.zig");
const Build = @import("src/build/lib.zig");
const Arch = Build.Arch;

const ExecutionEnvironment = enum {
    os,
    software_renderer,
};
const execution_environment = ExecutionEnvironment.os;

pub fn build(b: *Build.Builder) void {
    switch (execution_environment) {
        .os => {
            const kernel = b.allocator.create(Build.Kernel) catch unreachable;
            kernel.* = Build.Kernel{
                .builder = b,
                .allocator = Build.get_allocator(),
                .options = .{
                    .arch = Build.Kernel.Options.x86_64.new(.{
                        .bootloader = .limine,
                        .protocol = .limine,
                    }),
                    .run = .{
                        .disks = &.{
                            .{
                                .interface = .ahci,
                                .filesystem = .RNU,
                            },
                        },
                        .memory = .{
                            .amount = 4,
                            .unit = .G,
                        },
                        .emulator = .{
                            .qemu = .{
                                .vga = .std,
                                .smp = null,
                                .log = .{
                                    .file = null,
                                    .guest_errors = true,
                                    .cpu = false,
                                    .assembly = false,
                                    .interrupts = true,
                                },
                                .virtualize = false,
                                .print_command = true,
                            },
                        },
                    },
                },
            };

            kernel.create();
        },
        .software_renderer => {
            const SDL = @import("./src/software_renderer/dependencies/sdl/Sdk.zig");
            const sdl = SDL.init(b);
            const software_renderer_root_dir = "src/software_renderer/";
            const exe_source_path = software_renderer_root_dir ++ "main.zig";
            const exe_name = "software-renderer";
            const exe = b.addExecutable(exe_name, exe_source_path);
            const target = b.standardTargetOptions(.{});
            const build_mode = b.standardReleaseOptions();

            sdl.link(exe, .dynamic);
            exe.addPackage(sdl.getWrapperPackage("sdl"));
            //exe.defineCMacroRaw("USE_WAYLAND_API=OFF");
            exe.setTarget(target);
            exe.setBuildMode(build_mode);
            exe.setMainPkgPath("src");
            exe.setOutputDir(Build.cache_dir);

            b.default_step.dependOn(&exe.step);

            const run_cmd = exe.run();
            run_cmd.step.dependOn(b.getInstallStep());
            if (b.args) |args| {
                run_cmd.addArgs(args);
            }

            const run_step = b.step("run", "Run the app");
            run_step.dependOn(&run_cmd.step);

            const exe_tests = b.addTest(exe_source_path);
            exe_tests.setMainPkgPath("src");
            exe_tests.setTarget(target);
            exe_tests.setBuildMode(build_mode);

            const test_step = b.step("test", "Run unit tests");
            test_step.dependOn(&exe_tests.step);

            const debug_cmd = b.addSystemCommand(&.{ "gf2", Build.cache_dir ++ exe_name });
            debug_cmd.step.dependOn(&exe.step);

            const debug_step = b.step("debug", "Debug the app");
            debug_step.dependOn(&debug_cmd.step);
        },
    }
}

//fn get_riscv_base_features() CPUFeatures {
//var features = CPUFeatures{
//.enabled = Build.Target.Cpu.Feature.Set.empty,
//.disabled = Build.Target.Cpu.Feature.Set.empty,
//};
//const Feature = Build.Target.riscv.Feature;
//features.enabled.addFeature(@enumToInt(Feature.a));

//return features;
//}

