//! Physical memory management

const std = @import("std");
const builtin = @import("builtin");
const math = std.math;
const kernel = @import("../../kernel.zig");
const arch = kernel.arch;
const Spinlock = arch.Spinlock;
const page_size = arch.page_size;

const log = std.log.scoped(.vm_physical);

/// init add the given range of pages to the buddy system
/// @param start_addr must be rounded up to page_size
pub fn init(start_addr: usize, end_addr: usize) void {

    // Initial buddy allocator
    allocator.lock = Spinlock{
        ._lock = 0,
        .hart = -1,
    };
    // Double linked list
    var i: usize = 0;
    while (i < MAX_ORDER) : (i += 1) {
        allocator.free_list[i].next = &allocator.free_list[i];
        allocator.free_list[i].prev = &allocator.free_list[i];
    }

    // Fill memory with junk when debugging
    if (builtin.mode == .Debug) {
        log.debug("filling all memory with junk", .{});
        @memset(@intToPtr([*]u8, start_addr), 7, end_addr - start_addr - 1);
    }

    // Start initialization
    allocator.free(start_addr, end_addr - start_addr);

    // Debug
    allocator.printFreeStats();
}

/// free one page
/// use allocator api directly if more than one page
pub fn free(addr: usize) void {
    allocator.free(addr, arch.page_size);
}

/// alloc allocate one physical page 
/// return empty if out of memory
pub fn alloc() ?usize {
    return allocator.alloc(arch.page_size, 1); // 1 for no alignment
}

pub fn allocate_pages(page_count: u64) ?usize {
    return allocator.alloc(arch.page_size * page_count, page_size);
}

/// page struct is stored in the first few bytes of the page
const page = struct {

    // these two pointer must be initialized
    prev: *page = undefined,
    next: *page = undefined,
    ref_count: i64 = 0,

    pub fn remove(self: @This()) void {
        self.prev.next = self.next;
        self.next.prev = self.prev;
    }
};

pub var allocator = buddyAllocator{};

const MAX_ORDER = 11;

/// Buddy allocator
const buddyAllocator = struct {
    free_list: [MAX_ORDER]page = .{page{}} ** MAX_ORDER, // free list
    free_cnt: [MAX_ORDER]u64 = .{0} ** (MAX_ORDER), // count
    lock: Spinlock = undefined,

    /// alloc aquires a range of pages from the buddy system
    /// alignment = 0 is not allowed 
    pub fn alloc(self: *buddyAllocator, size: usize, alignment: usize) ?usize {
        // Check alignment if reasonable
        if (alignment > (arch.page_size * 1 << MAX_ORDER)) {
            @panic("vm/physical: alignment not allowed");
        }
        if ((@popCount(usize, alignment) != 1)) {
            log.err("vm/physical: alignment is not the power of 2, [alignment] = .{}", .{alignment});
            @panic("vm/physical: alignment is not the power of 2");
        }

        // Get aligned size
        // const align_order = math.log2_int(usize, alignment);
        // const aligned_size = (size + (@intCast(usize, 1) << align_order) - 1) & ~((@intCast(usize, 1) << align_order) - 1);
        const aligned_size = size;

        // find start of alloc_order
        var alloc_order: u6 = 0;
        while (aligned_size > (@as(usize, arch.page_size) << alloc_order)) : (alloc_order += 1) {}

        while (alloc_order < MAX_ORDER) : (alloc_order += 1) {
            if (self.free_cnt[alloc_order] > 0) { // found usable space

                // get the block out
                const list_head: *page = self.free_list[alloc_order].next;
                list_head.remove();
                self.free_cnt[alloc_order] -= 1;

                // move the unused block to the other level of the free list
                // TODO: get a better way to do this
                var drop_len = (@as(usize, arch.page_size) << alloc_order) - aligned_size;
                var offset: usize = 0;
                while (offset < drop_len) : (offset += arch.page_size) {
                    const addr = @ptrToInt(list_head) + offset + aligned_size;
                    self.free(addr, arch.page_size);
                }

                // return the block
                return @ptrToInt(list_head);
            }
        }
        return null;
    }

    /// free add some pages to the buddy system
    /// size is counted by bytes
    pub fn free(self: *buddyAllocator, addr: usize, size: usize) void {

        // check if size is aligned to page size
        if (size % arch.page_size != 0) {
            log.err("free size is not aligned to page size, [size] = {d}", .{size});
            @panic("size not aligned to page size");
        }

        // free pages one by one
        // TODO: better way to do this
        var i: usize = 0;
        while (i < size) : (i += arch.page_size) {
            var order: u6 = 0;
            var current_addr = addr + i;
            // from bottom to top find buddy pages and move
            while (order < MAX_ORDER) : (order += 1) {
                // buddy
                const buddy_addr = current_addr ^ (@as(usize, arch.page_size) << order);

                if (self.findInFreeList(buddy_addr, order)) |buddy| {
                    if (order != MAX_ORDER - 1) { // Deal with largest block
                        buddy.remove();
                        self.free_cnt[order] -= 1;
                        current_addr = (current_addr & ~(@as(usize, arch.page_size) << order));
                        continue;
                    }
                }
                // add current_addr to free list
                var current_page = @intToPtr(*page, current_addr);
                current_page.* = page{};

                // Double linked list insert
                self.free_list[order].next.prev = current_page;
                current_page.next = self.free_list[order].next;
                current_page.prev = &self.free_list[order];
                self.free_list[order].next = current_page;
                self.free_cnt[order] += 1;
                break;
            }
        }
    }

    fn findInFreeList(self: @This(), addr: usize, order: usize) ?*page {
        var iter: *page = self.free_list[order].next;
        while (true) {
            if (iter.next != &self.free_list[order]) {
                if (@ptrToInt(iter) == addr) {
                    return iter;
                } else {
                    iter = iter.next;
                }
            } else {
                return null;
            }
        }
    }

    pub fn printFreeStats(self: @This()) void {
        @setCold(true);

        for (self.free_cnt) |cnt, order| {
            log.debug("order: {}, cnt: {}, head: {*}", .{ order, cnt, self.free_list[order].next });
        }
    }
};

fn test_alloc() void {
    const _page = alloc();
    if (_page) |p| {
        std.log.debug("page addr: {x}", .{p});
        free(p);
    } else {
        @panic("allocate physical page failed");
    }
}
