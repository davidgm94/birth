const lib = @import("lib");
const log = lib.log.scoped(.PhysicalMap);

const user = @import("user");
const SlotAllocator = user.SlotAllocator;
const VirtualAddressSpace = user.VirtualAddressSpace;

pub const PhysicalMap = extern struct {
    virtual_address_space: *VirtualAddressSpace,
    slot_allocator: *SlotAllocator,

    pub usingnamespace user.arch.PhysicalMapInterface;

    pub fn initPageTableManagement(physical_map: *PhysicalMap) !void {
        const current_physical_map = user.process.getPhysicalMap();
        log.debug("CURR: 0x{x}. PHYS: 0x{x}", .{ @intFromPtr(current_physical_map), @intFromPtr(physical_map) });
        if (current_physical_map == physical_map) {
            @panic("TODO: if");
        } else {
            log.warn("TODO: slab_init", .{});
            _ = user.libc.malloc(lib.arch.valid_page_sizes[0]);
            @panic("TODO: else");
        }
    }
};
