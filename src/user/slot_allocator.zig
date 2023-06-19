const log = @import("lib").log;
const user = @import("user");

pub const SlotAllocator = extern struct {
    foo: u32 = 0,

    /// This function is inlined because it's only called once
    pub inline fn init() !void {
        log.warn("TODO: implement the whole SlotAllocator.init", .{});
        const state = user.process.getSlotAllocatorState();
        const default_allocator = state.default_allocator;
        _ = default_allocator;
    }

    pub fn getDefault() *SlotAllocator {
        const process_slot_allocator_state = user.process.getSlotAllocatorState();
        return &process_slot_allocator_state.default_allocator.allocator;
    }

    pub const State = extern struct {
        default_allocator: MultiSlotAllocator,
    };
};

pub const MultiSlotAllocator = extern struct {
    allocator: SlotAllocator,
    // TODO:
};
