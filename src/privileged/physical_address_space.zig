const PhysicalAddressSpace = @This();

const common = @import("common");
const assert = common.assert;
const log = common.log.scoped(.PhysicalAddressSpace);
const valid_page_sizes = common.arch.valid_page_sizes;

const privileged = @import("privileged");
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
