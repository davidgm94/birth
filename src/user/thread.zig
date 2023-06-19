const lib = @import("lib");
const log = lib.log.scoped(.thread);
const user = @import("user");
const rise = @import("rise");

const MoreCore = user.MoreCore;
const MMUAwareVirtualAddressSpace = user.MMUAwareVirtualAddressSpace;
const SlotAllocator = user.SlotAllocator;
const VirtualAddress = lib.VirtualAddress;
const VirtualAddressSpace = user.VirtualAddressSpace;

const max_thread_count = 256;

pub const Thread = extern struct {
    self: *Thread,
    previous: ?*Thread,
    next: ?*Thread,
    stack: [*]u8,
    stack_top: [*]align(lib.arch.stack_alignment) u8,
    register_arena: rise.arch.RegisterArena align(lib.arch.stack_alignment),
    core_id: u32,

    pub fn init(thread: *Thread, scheduler: *user.arch.Scheduler) void {
        thread.self = thread;
        thread.previous = null;
        thread.next = null;
        thread.core_id = scheduler.generic.core_id;
    }
};

pub const Mutex = extern struct {
    locked: bool = false,

    pub inline fn internalLock(mutex: *volatile Mutex) void {
        mutex.locked = true;
    }
};

var static_stack: [0x10000]u8 align(lib.arch.stack_alignment) = undefined;
var static_thread: Thread = undefined;
var static_thread_lock = Mutex{};

pub fn initDisabled(scheduler: *user.arch.Scheduler) noreturn {
    const thread = &static_thread;
    static_thread_lock.internalLock();
    thread.stack = &static_stack;
    thread.stack_top = static_stack[static_stack.len..];
    thread.init(scheduler);

    // TODO: use RAX as parameter?

    user.arch.setInitialState(&thread.register_arena, VirtualAddress.new(bootstrapThread), VirtualAddress.new(thread.stack_top), .{0} ** 6);

    scheduler.common.generic.has_work = true;

    scheduler.restore(&thread.register_arena);
}

const SpawnDomainParams = extern struct {};

// TODO:
const Foo = struct {};

pub var slab_allocator: Foo = undefined;
pub var slab_virtual_address_space: user.MMUAwareVirtualAddressSpace = undefined;

fn initThread(parameters: *SpawnDomainParams) !void {
    _ = parameters;
    // TODO:
    // - waitset
    // - ram alloc init

    try VirtualAddressSpace.initializeCurrent();

    try SlotAllocator.init();

    if (false) {
        // TODO:
        log.warn("TODO: handle the case where spawn domain parameters exist", .{});
    } else if (user.is_init) {
        log.warn("Known init page table layout. Take advantage of that!", .{});
    }

    if (user.is_init) {
        log.debug("More core init start", .{});
        try MoreCore.init(lib.arch.valid_page_sizes[0]);
        log.debug("More core init end", .{});
        log.warn("TODO: implement memory initialization -> morecore_init()", .{});
    } else {
        @panic("TODO: not init userspace binary");
    }

    log.warn("TODO: Should we do LMP endpoints?", .{});

    if (!user.is_init) {
        @panic("TODO: not init user binaries");
    }
}

fn bootstrapThread(parameters: *SpawnDomainParams) callconv(.C) noreturn {

    // TODO: Do we have TLS data?
    // tls_block_init_base = params->tls_init_base;
    // tls_block_init_len = params->tls_init_len;
    // tls_block_total_len = params->tls_total_len;

    initThread(parameters) catch |err| user.panic("initThread failed: {}", .{err});
    // // Allocate storage region for real threads
    // size_t blocksize = sizeof(struct thread) + tls_block_total_len + THREAD_ALIGNMENT;
    // err = vspace_mmu_aware_init(&thread_slabs_vm, MAX_THREADS * blocksize);

    // TODO: make this declaration value assignment complete
    const block_size = @sizeOf(Thread);
    slab_virtual_address_space = try MMUAwareVirtualAddressSpace.init(max_thread_count * block_size);
    // if (err_is_fail(err)) {
    //     USER_PANIC_ERR(err, "vspace_mmu_aware_init for thread region failed\n");
    // }
    // // XXX: do this nicer, but we need struct threads to be in Vspace < 4GB so
    // // we can set the thread segment register. -SG, 2017-02-28.
    // // We can't use the assertion yet, as the init domain has it's thread
    // // slabs above 4G.
    // //assert(vregion_get_base_addr(&thread_slabs_vm.vregion) + vregion_get_size(&thread_slabs_vm.vregion) < 1ul << 32);
    // slab_init(&thread_slabs, blocksize, refill_thread_slabs);

    if (user.is_init) {
        // No allocation path
        mainThread(parameters);
    } else {
        // Do allocations
        while (true) {}
    }
}

fn mainThread(parameters: ?*anyopaque) noreturn {
    // TODO: parameters
    _ = parameters;
    const root = @import("root");
    if (@hasDecl(root, "main")) {
        const result = switch (@typeInfo(@typeInfo(@TypeOf(root.main)).Fn.return_type.?)) {
            .NoReturn => root.main(),
            .Void => blk: {
                root.main();
                break :blk 0;
            },
            .Int => root.main(),
            .ErrorUnion => blk: {
                const result = root.main() catch {
                    // TODO: log
                    break :blk 1;
                };

                switch (@typeInfo(@TypeOf(result))) {
                    .Void => break :blk 0,
                    .Int => break :blk result,
                    else => @compileError("Unexpected return type"),
                }
            },
            else => @compileError("Unexpected return type"),
        };
        _ = result;
        @panic("ASdasd");
    } else {
        const result = _main();
        _ = result;
    }
}

export fn _main() i32 {
    // global constructors
    // array
    return 0;
}
