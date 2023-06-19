const user = @import("user");

pub export fn malloc(size: usize) ?*anyopaque {
    const morecore_state = user.process.getMoreCoreState();
    const result = morecore_state.mmu_state.map(size) catch return null;
    return result.ptr;
}
