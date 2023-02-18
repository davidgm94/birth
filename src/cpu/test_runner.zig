const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.TEST);
const privileged = @import("privileged");
const QEMU = lib.QEMU;

const RunAllTestResult = error{
    failure,
};

pub fn runAllTests() RunAllTestResult!void {
    comptime assert(lib.is_test);
    const test_functions = @import("builtin").test_functions;
    var failed_test_count: usize = 0;
    for (test_functions) |test_function| {
        test_function.func() catch |err| {
            log.err("Test failed: {}", .{err});
            failed_test_count += 1;
        };
    }

    const test_count = test_functions.len;
    assert(QEMU.isa_debug_exit.io_size == @sizeOf(u32));
    const success = failed_test_count == 0;
    if (success) {
        log.info("All {} tests passed.", .{test_count});
    } else {
        log.info("Run {} tests. Failed {}.", .{ test_count, failed_test_count });
    }

    comptime assert(@sizeOf(QEMU.ExitCode) == @sizeOf(u32));
    privileged.arch.io.write(u32, QEMU.isa_debug_exit.io_base, @enumToInt(switch (success) {
        true => QEMU.ExitCode.success,
        false => QEMU.ExitCode.failure,
    }));
}
