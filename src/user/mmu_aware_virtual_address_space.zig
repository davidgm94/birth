const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.MMUAwareVirtualAddressSpace);

const user = @import("user");
const PhysicalMemoryRegion = user.PhysicalMemoryRegion;
const SlotAllocator = user.SlotAllocator;
const VirtualMemoryRegion = user.VirtualMemoryRegion;

pub const MMUAwareVirtualAddressSpace = extern struct {
    size: usize,
    alignment: usize,
    consumed: usize = 0,
    /// This is a index into the architecture-specific page sizes
    page_size: u8,
    slot_allocator: *SlotAllocator,
    physical_memory_region: PhysicalMemoryRegion.Anonymous,
    virtual_memory_region: VirtualMemoryRegion,
    // struct vregion vregion;           ///< Needs just one vregion
    // struct memobj_anon memobj;        ///< Needs just one memobj
    // lvaddr_t offset;    ///< Offset of free space in anon
    // lvaddr_t mapoffset; ///< Offset into the anon that has been mapped in

    pub fn init(size: usize) !MMUAwareVirtualAddressSpace {
        const slot_allocator = SlotAllocator.getDefault();
        const alignment = lib.arch.valid_page_sizes[0];
        return initAligned(slot_allocator, size, alignment, .{ .write = true });
    }

    pub fn initAligned(slot_allocator: *SlotAllocator, size: usize, alignment: usize, flags: VirtualMemoryRegion.Flags) !MMUAwareVirtualAddressSpace {
        assert(flags.preferred_page_size < lib.arch.valid_page_sizes.len);
        var result = MMUAwareVirtualAddressSpace{
            .size = size,
            .alignment = alignment,
            .page_size = flags.preferred_page_size,
            .slot_allocator = slot_allocator,
            .physical_memory_region = try PhysicalMemoryRegion.Anonymous.new(size),
            .virtual_memory_region = undefined,
        };
        // TODO: fix this API
        result.virtual_memory_region = try user.process.getVirtualAddressSpace().mapAligned(result.physical_memory_region.getGeneric().*, 0, size, alignment, flags);

        // TODO: create memobj
        // TODO: map memobj into vregion

        @panic("TODO: MMUAwareVirtualAddressSpace.initAligned");
    }

    const Error = error{
        alignment,
    };

    pub fn map(virtual_address_space: *MMUAwareVirtualAddressSpace, size: usize) ![]u8 {
        if (!lib.isAligned(size, lib.arch.valid_page_sizes[0])) {
            return error.alignment;
        }
        _ = virtual_address_space;
        log.warn("[map] TODO: slot allocation", .{});
        //virtual_address_space.slot_allocator.allocate();
        @panic("TODO: MMUAwareVirtualAddressSpace.map");
    }
};
