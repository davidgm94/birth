const lib = @import("lib");
const Allocator = lib.Allocator;
const assert = lib.assert;
const ELF = lib.ELF(64);
const log = lib.log;
const Spinlock = lib.Spinlock;
const bootloader = @import("bootloader");
const privileged = @import("privileged");
const panic = cpu.panic;
const PageAllocator = cpu.PageAllocator;
const x86_64 = privileged.arch.x86_64;
const APIC = x86_64.APIC;
const paging = x86_64.paging;
const TSS = x86_64.TSS;
const cr0 = x86_64.registers.cr0;
const cr3 = x86_64.registers.cr3;
const cr4 = x86_64.registers.cr4;
const PhysicalAddress = privileged.PhysicalAddress;
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const VirtualAddress = privileged.VirtualAddress;
const VirtualMemoryRegion = privileged.VirtualMemoryRegion;

const cpu = @import("cpu");
const Heap = cpu.Heap;
const VirtualAddressSpace = cpu.VirtualAddressSpace;

const init = @import("./x86/64/init.zig");
pub const entryPoint = init.entryPoint;

const rise = @import("rise");

pub const writer = privileged.E9Writer{ .context = {} };
var writer_lock: Spinlock = .released;

pub const Registers = extern struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    syscall_number_or_error_code: u64,
    rip: u64,
    cs: u64,
    rflags: lib.arch.x86_64.registers.RFLAGS,
    rsp: u64,
    ss: u64,
};

const interrupt_kind: u32 = 0;

export fn interruptHandler(regs: *const InterruptRegisters, interrupt_number: u8) void {
    switch (interrupt_number) {
        local_timer_vector => {
            APIC.write(.eoi, 0);
            nextTimer(10);
        },
        else => cpu.panicFromInstructionPointerAndFramePointer(regs.rip, regs.rbp, "Exception: 0x{x}", .{interrupt_number}),
    }
}

const InterruptRegisters = extern struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    error_code: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
};

const SyscallRegisters = extern struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    syscall_number: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
};

inline fn result(res: struct {
    value: u64 = 0,
    another_value: u32 = 0,
    @"error": u16 = 0,
    another_more_value: u8 = 0,
    flags: u7 = 0,
}) rise.syscall.Result {
    return .{
        .rise = .{
            .first = .{
                .padding1 = res.another_value,
                .@"error" = res.@"error",
                .padding2 = res.another_more_value,
                .padding3 = res.flags,
                .convention = .rise,
            },
            .second = res.value,
        },
    };
}

/// SYSCALL documentation
/// ABI:
/// - RAX: System call options (number for Linux)
/// - RCX: Return address
/// - R11: Saved rflags
/// - RDI: argument 0
/// - RSI: argument 1
/// - RDX: argument 2
/// - R10: argument 3
/// - R8:  argument 4
/// - R9:  argument 5
export fn syscall(regs: *const SyscallRegisters) callconv(.C) rise.syscall.Result {
    const options = @bitCast(rise.syscall.Options, regs.syscall_number);
    const arguments = [_]u64{ regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9 };

    // TODO: check capability address
    return switch (options.general.convention) {
        .rise => switch (options.rise.type) {
            inline else => |capability_type| blk: {
                const command = @intToEnum(capability_type.toCommand(), options.rise.command);
                if (cpu.user_scheduler.capability_root_node.hasPermissions(capability_type, command)) switch (capability_type) {
                    .io => switch (command) {
                        .log => {
                            const message_ptr = @intToPtr(?[*]const u8, arguments[0]) orelse @panic("message null");
                            const message_len = arguments[1];
                            const message = message_ptr[0..message_len];
                            writer.writeAll(message) catch unreachable;

                            break :blk result(.{});
                        },
                        _ => break :blk result(.{ .@"error" = 1 }),
                    },
                    .cpu => switch (command) {
                        .shutdown => privileged.exitFromQEMU(.success),
                        .get_core_id => break :blk result(.{
                            .value = cpu.core_id,
                        }),
                        // _ => @panic("Unknown cpu command"),
                    },
                    else => @panic(@tagName(capability_type)),
                } else break :blk result(.{ .@"error" = 1 });
            },
        },
        .linux => @panic("linux syscall"),
    };
}

const local_timer_vector = 0xef;
pub export var ticks_per_ms: privileged.arch.x86_64.TicksPerMS = undefined;
pub inline fn nextTimer(ms: u32) void {
    APIC.write(.lvt_timer, local_timer_vector | (1 << 17));
    APIC.write(.timer_initcnt, ticks_per_ms.lapic * ms);
}

const ApicPageAllocator = extern struct {
    pages: [4]PhysicalAddress = .{PhysicalAddress.invalid()} ** 4,

    const PageEntry = cpu.VirtualAddressSpace.PageEntry;

    fn allocate(context: ?*anyopaque, size: u64, alignment: u64, options: privileged.PageAllocator.AllocateOptions) Allocator.Allocate.Error!PhysicalMemoryRegion {
        const apic_allocator = @ptrCast(?*ApicPageAllocator, @alignCast(@alignOf(ApicPageAllocator), context)) orelse return Allocator.Allocate.Error.OutOfMemory;
        assert(size == lib.arch.valid_page_sizes[0]);
        assert(alignment == lib.arch.valid_page_sizes[0]);
        assert(options.count == 1);
        assert(options.level_valid);
        const physical_memory = try cpu.page_allocator.allocate(size, alignment);
        apic_allocator.pages[@enumToInt(options.level)] = physical_memory.address;
        return physical_memory;
    }
};

var apic_page_allocator = ApicPageAllocator{};
const apic_page_allocator_interface = privileged.PageAllocator{
    .allocate = ApicPageAllocator.allocate,
    .context = &apic_page_allocator,
    .context_type = .cpu,
};

pub inline fn writerStart() void {
    writer_lock.acquire();
}

pub inline fn writerEnd() void {
    writer_lock.release();
}

/// Architecture-specific implementation of mapping when you already can create user-space virtual address spaces
pub fn map(virtual_address_space: *VirtualAddressSpace, asked_physical_address: PhysicalAddress, asked_virtual_address: VirtualAddress, size: u64, general_flags: privileged.Mapping.Flags) !void {
    if (general_flags.user) {
        assert(!general_flags.secret);
    }

    try virtual_address_space.arch.map(asked_physical_address, asked_virtual_address, size, general_flags, virtual_address_space.getPageAllocatorInterface());
    if (!general_flags.secret) {
        const cpu_pml4 = try virtual_address_space.arch.getCpuPML4Table();
        const user_pml4 = try virtual_address_space.arch.getUserPML4Table();
        const first_indices = paging.computeIndices(asked_virtual_address.value());
        const last_indices = paging.computeIndices(asked_virtual_address.offset(size - lib.arch.valid_page_sizes[0]).value());
        const first_index = first_indices[@enumToInt(paging.Level.PML4)];
        const last_index = @intCast(u9, last_indices[@enumToInt(paging.Level.PML4)]) +| 1;

        for (cpu_pml4[first_index..last_index], user_pml4[first_index..last_index]) |cpu_pml4te, *user_pml4te| {
            user_pml4te.* = cpu_pml4te;
        }
    }
}
pub const PageTableEntry = paging.Level;
pub const root_page_table_entry = @intToEnum(cpu.arch.PageTableEntry, 0);

pub const IOMap = extern struct {
    debug: bool,
};
