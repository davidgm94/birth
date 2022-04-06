const kernel = @import("../../kernel.zig");
const TODO = kernel.TODO;
const print = kernel.arch.early_print;
const write = kernel.arch.early_write;

var plic: []volatile u32 = undefined;
const max_interrupt = 64;
pub fn init() void {
    const plic_dt = kernel.arch.device_tree.find_property("soc", "reg", .exact, &[_][]const u8{"plic"}, &[_]kernel.arch.DeviceTree.SearchType { .start }) orelse @panic("unable to find PLIC in the device tree\n");
    plic.ptr = @intToPtr([*]u32, kernel.arch.dt_read_int(u64, plic_dt.value));
    plic.len = kernel.arch.dt_read_int(u64, plic_dt.value[@sizeOf(u64)..]);
    print("PLIC: {any}\n", .{plic});

    var interrupt_i: u64 = 1;
    while (interrupt_i <= max_interrupt) : (interrupt_i += 1) {
        plic[interrupt_i] = 0xffff_ffff;
    }
    TODO(@src());
}
