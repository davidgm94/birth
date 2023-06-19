const cpu = @import("cpu");
const lib = @import("lib");
const log = lib.log;
const privileged = @import("privileged");
const rise = @import("rise");

const assert = lib.assert;

const cr3 = privileged.arch.x86_64.registers.cr3;

const cr3_user_page_table_mask = 1 << @bitOffsetOf(cr3, "address");
const cr3_user_page_table_and_pcid_mask = cr3_user_page_table_mask | pcid_mask;
const pcid_bit = 11;
const pcid_mask = 1 << pcid_bit;

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
fn riseSyscall(comptime Syscall: type, raw_arguments: rise.syscall.Arguments) Syscall.ErrorSet.Error!Syscall.Result {
    cpu.syscall_count += 1;
    comptime assert(Syscall == rise.capabilities.Syscall(Syscall.capability, Syscall.command));
    const capability: rise.capabilities.Type = Syscall.capability;
    const command: rise.capabilities.Command(capability) = Syscall.command;
    const arguments = try Syscall.toArguments(raw_arguments);

    return if (cpu.user_scheduler.capability_root_node.hasPermissions(capability, command)) switch (capability) {
        .io => switch (command) {
            .copy, .mint, .retype, .delete, .revoke, .create => unreachable,
            .log => blk: {
                const message = arguments;
                cpu.writer.writeAll(message) catch unreachable;
                comptime assert(Syscall.Result == usize);
                break :blk message.len;
            },
        },
        .cpu => switch (command) {
            .copy, .mint, .retype, .delete, .revoke, .create => unreachable,
            .get_core_id => cpu.core_id,
            .shutdown => cpu.shutdown(.success),
            .get_command_buffer => {
                const command_buffer = arguments;
                _ = command_buffer;
                @panic("TODO: get_command_buffer");
            },
        },
        .cpu_memory => switch (command) {
            .allocate => blk: {
                comptime assert(@TypeOf(arguments) == usize);
                const size = arguments;
                const physical_region = try cpu.user_scheduler.capability_root_node.allocatePages(size);
                try cpu.user_scheduler.capability_root_node.allocateCPUMemory(physical_region, .{ .privileged = false });
                break :blk physical_region.address;
            },
            else => @panic(@tagName(command)),
        },
        .ram => unreachable,
        .boot => switch (command) {
            .get_bundle_size => cpu.bundle.len,
            .get_bundle_file_list_size => cpu.bundle_files.len,
            else => @panic(@tagName(command)),
        },
        .process => switch (command) {
            .exit => switch (arguments) {
                true => cpu.shutdown(.success),
                false => cpu.panic("User process panicked", .{}),
            },
            else => @panic(@tagName(command)),
        },
        .page_table => @panic("TODO: page_table"),
    } else error.forbidden;
}

export fn syscall(registers: *const Registers) callconv(.C) rise.syscall.Result {
    const options = @as(rise.syscall.Options, @bitCast(registers.syscall_number));
    const arguments = rise.syscall.Arguments{ registers.rdi, registers.rsi, registers.rdx, registers.r10, registers.r8, registers.r9 };

    return switch (options.general.convention) {
        .rise => switch (options.rise.type) {
            inline else => |capability| switch (@as(rise.capabilities.Command(capability), @enumFromInt(options.rise.command))) {
                inline else => |command| blk: {
                    const Syscall = rise.capabilities.Syscall(capability, command);
                    const result: Syscall.Result = riseSyscall(Syscall, arguments) catch |err| break :blk Syscall.errorToRaw(err);
                    break :blk Syscall.resultToRaw(result);
                },
            },
        },
        .linux => @panic("linux syscall"),
    };
}

/// SYSCALL documentation
/// ABI:
/// - RAX: System call number
/// - RCX: Return address
/// - R11: Saved rflags
/// - RDI: argument 0
/// - RSI: argument 1
/// - RDX: argument 2
/// - R10: argument 3
/// - R8:  argument 4
/// - R9:  argument 5
pub fn entryPoint() callconv(.Naked) void {
    asm volatile (
        \\endbr64
        \\swapgs
        \\movq %rsp, user_stack(%rip)
    );

    if (cpu.arch.x86_64.kpti) {
        asm volatile (
            \\mov %cr3, %rsp
            ::: "memory");

        if (cpu.arch.pcid) {
            @compileError("pcid support not yet implemented");
        }

        asm volatile (
            \\andq %[mask], %rsp
            \\mov %rsp, %cr3
            :
            : [mask] "i" (~@as(u64, cr3_user_page_table_and_pcid_mask)),
            : "memory"
        );
    }

    // Safe stack
    asm volatile ("movabsq %[capability_address_space_stack_top], %rsp"
        :
        : [capability_address_space_stack_top] "i" (cpu.arch.x86_64.capability_address_space_stack_top),
        : "memory", "rsp"
    );

    asm volatile (
        \\pushq %[user_ds]
        \\pushq (user_stack)
        \\pushq %r11
        \\pushq %[user_cs]
        \\pushq %rcx
        \\pushq %rax
        :
        : [user_ds] "i" (cpu.arch.x86_64.user_data_selector),
          [user_cs] "i" (cpu.arch.x86_64.user_code_selector),
        : "memory"
    );

    // Push and clear registers
    asm volatile (
    // Push
        \\pushq %rdi
        \\pushq %rsi
        \\pushq %rdx
        \\pushq %rcx
        \\pushq %rax
        \\pushq %r8
        \\pushq %r9
        \\pushq %r10
        \\pushq %r11
        \\pushq %rbx
        \\pushq %rbp
        \\pushq %r12
        \\pushq %r13
        \\pushq %r14
        \\pushq %r15
        // Clear
        \\xorl %esi, %esi
        \\xorl %edx, %edx
        \\xorl %ecx, %ecx
        \\xorl %r8d,  %r8d
        \\xorl %r9d,  %r9d
        \\xorl %r10d, %r10d
        \\xorl %r11d, %r11d
        \\xorl %ebx,  %ebx
        \\xorl %ebp,  %ebp
        \\xorl %r12d, %r12d
        \\xorl %r13d, %r13d
        \\xorl %r14d, %r14d
        \\xorl %r15d, %r15d
        ::: "memory");

    // Pass arguments
    asm volatile (
        \\mov %rsp, %rdi
        \\mov %rax, %rsi
        ::: "memory");

    // TODO: more security stuff
    asm volatile (
        \\call syscall
        ::: "memory");

    // TODO: more security stuff

    // Pop registers
    asm volatile (
        \\popq %r15
        \\popq %r14
        \\popq %r13
        \\popq %r12
        \\popq %rbp
        \\popq %rbx
        \\popq %r11
        \\popq %r10
        \\popq %r9
        \\popq %r8
        \\popq %rcx
        // RAX
        \\popq %rcx
        // RDX
        \\popq %rsi
        \\popq %rsi
        \\popq %rdi
        ::: "memory");

    if (cpu.arch.x86_64.kpti) {
        // Restore CR3
        asm volatile (
            \\mov %cr3, %rsp
            ::: "memory");

        if (cpu.arch.x86_64.pcid) {
            @compileError("PCID not supported yet");
        }

        asm volatile (
            \\orq %[user_cr3_mask], %rsp
            \\mov %rsp, %cr3
            :
            : [user_cr3_mask] "i" (cr3_user_page_table_mask),
            : "memory"
        );
    }

    // Restore RSP
    asm volatile (
        \\mov user_stack(%rip), %rsp
        ::: "memory");

    asm volatile (
        \\swapgs
        \\sysretq
        ::: "memory");

    asm volatile (
        \\int3
        ::: "memory");

    unreachable;
}

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
    syscall_number: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
};
