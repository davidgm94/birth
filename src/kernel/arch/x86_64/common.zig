pub const valid_page_sizes = [3]comptime_int{ 0x1000, 0x1000 * 512, 0x1000 * 512 * 512 };
pub const page_size = valid_page_sizes[0];
pub const page_shifter = @ctz(u64, page_size);
pub var max_physical_address_bit: u6 = 0;
