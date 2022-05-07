const kernel = @import("../../kernel.zig");
const arch = kernel.arch;

const log = kernel.log.scoped(.init);

const file_size = 5312;
var file_buffer: [kernel.align_forward(file_size, arch.sector_size)]u8 align(kernel.arch.page_size) = undefined;
