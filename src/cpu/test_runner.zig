const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.TEST);
const privileged = @import("privileged");
const QEMU = lib.QEMU;

const cpu = @import("cpu");

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
    const exit_code = switch (failed_test_count) {
        0 => blk: {
            log.info("All {} tests passed.", .{test_count});
            break :blk .success;
        },
        else => blk: {
            log.info("Run {} tests. Failed {}.", .{ test_count, failed_test_count });
            break :blk .failure;
        },
    };

    cpu.shutdown(exit_code);
}
