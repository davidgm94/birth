const kernel = @import("kernel.zig");
pub const page_size = kernel.arch.check_page_size(0x1000);
pub const max_cpus = 1024;
