pub const root = @import("root");
pub const common = @import("common");
pub const identity = blk: {
    if (@hasDecl(root, "identity")) {
        break :blk root.identity;
    } else {
        break :blk common.ExecutableIdentity.build;
    }
};

pub const page_size = common.arch.valid_page_sizes[0];
comptime {
    common.comptime_assert(page_size == 0x1000);
}
pub const page_shifter = @ctz(u64, page_size);

pub var max_physical_address_bit: u6 = 0;
