const kernel = @import("root");
const TODO = kernel.TODO;
const AddresPair = kernel.Memory.AddressPair;
const Physical = kernel.arch.Physical;

const Heap = @This();

pub const AllocationResult = struct {
    physical: u64,
    virtual: u64,
    asked_size: u64,
    given_size: u64,
};

const Region = struct {
    physical: u64,
    virtual: u64,
    size: u64,
};

regions: [16]?*Region,
// TODO: use another synchronization primitive
lock: kernel.Spinlock,

const region_default_size = 0x10000;

pub fn allocate(self: *Heap, size: u64, zero: bool, separate_page: bool) ?AllocationResult {
    _ = zero;
    self.lock.acquire();
    defer self.lock.release();
    kernel.assert(@src(), size < kernel.maxInt(u32));

    if (separate_page) {
        const page_count = kernel.bytes_to_pages(size);
        const physical_result = Physical.allocate1(page_count) orelse return null;
        return AllocationResult{
            .physical = physical_result,
            .virtual = physical_result,
            .asked_size = @intCast(u32, size),
            .given_size = @intCast(u32, page_count * kernel.arch.page_size),
        };
    } else {
        if (size < region_default_size) {
            for (self.regions) |maybe_region| {
                if (maybe_region) |region| {
                    _ = region;
                    TODO(@src());
                } else {
                    TODO(@src());
                }
            }
        } else {
            TODO(@src());
        }
        TODO(@src());
    }
}
