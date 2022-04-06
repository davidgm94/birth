const kernel = @import("../../kernel.zig");
const TODO = kernel.TODO;
const print = kernel.arch.early_print;
const write = kernel.arch.early_write;

pub fn init() void {
    const plic_dt = kernel.arch.device_tree.find_property("soc", &[_][]const u8{"plic"}, "reg", .start) orelse @panic("unable to find PLIC in the device tree\n");
    const address = kernel.arch.dt_read_int(u64, plic_dt.value);
    const size = kernel.arch.dt_read_int(u64, plic_dt.value[@sizeOf(u64)..]);
    print("Address 0x{x}. Size: {}\n", .{ address, size });
    TODO(@src());
}
