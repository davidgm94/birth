// Only for the bootloader
pub const default_page_size = valid_page_sizes[0];
pub const reasonable_page_size = valid_page_sizes[1];
pub const valid_page_sizes = [2]comptime_int{ 0x1000, 0x1000 * 0x200 };
