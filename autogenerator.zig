const std = @import("std");

fn has_error_code(i: u64) bool
{
    return switch (i)
    {
        // Exceptions
        0x00...0x07 => false,
        0x08 => true,
        0x09 => false,
        0x0A...0x0E => true,
        0x0F...0x10 => false,
        0x11 => true,
        0x12...0x14 => false,
        //0x15 ... 0x1D => unreachable,
        0x1E => true,
        //0x1F          => unreachable,

        // Other interrupts
        else => false,
    };
}

pub fn generate_interrupts(allocator: std.mem.Allocator) ![]const u8
{
    @setEvalBranchQuota(std.math.maxInt(u32));
    const interrupt_context =
        \\pub const Context = extern struct
        \\{
        \\    es: u64,
        \\    ds: u64,
        \\    fx_save: [512 + 16]u8,
        \\    _check: u64,
        \\    r15: u64,
        \\    r14: u64,
        \\    r13: u64,
        \\    r12: u64,
        \\    r11: u64,
        \\    r10: u64,
        \\    r9: u64,
        \\    r8: u64,
        \\    rbp: u64,
        \\    rdi: u64,
        \\    rsi: u64,
        \\    rdx: u64,
        \\    rcx: u64,
        \\    rbx: u64,
        \\    rax: u64,
        \\    interrupt_number: u64,
        \\    error_code: u64,
        \\    rip: u64,
        \\    cs: u64,
        \\    eflags: u64,
        \\    rsp: u64,
        \\    ss: u64,
        \\};
    ;

    const interrupt_common_prologue =
        \\    asm volatile(
        \\        \\cld
        \\        \\push %%rax
        \\        \\push %%rbx
        \\        \\push %%rcx
        \\        \\push %%rdx
        \\        \\push %%rbp
        \\        \\push %%rsi
        \\        \\push %%rdi
        \\        \\push %%r8
        \\        \\push %%r9
        \\        \\push %%r10
        \\        \\push %%r11
        \\        \\push %%r12
        \\        \\push %%r13
        \\        \\push %%r14
        \\        \\push %%r15
        \\        \\mov $0x123456789ABCDEF, %%rax
        \\        \\push %%rax
        \\        \\mov %%rsp, %%rbx
        \\        \\and $~0xf, %%rsp 
        \\        \\fxsave -0x200(%%rsp)
        \\        \\mov %%rbx, %%rsp
        \\        \\sub $0x210, %%rsp
        \\        \\xor %%rax, %%rax
        \\        \\mov %%ds, %%ax
        \\        \\push %%rax
        \\        \\xor %%rax, %%rax
        \\        \\mov %%es, %%rax
        \\        \\push %%rax
        \\        \\mov %%rsp, %%rdi
        \\        \\mov $0x10, %%ax
        \\        \\mov %%ax, %%ds
        \\        \\mov %%ax, %%es
        \\        \\mov %%rsp, %%rbx
        \\        \\and $~0xf, %%rsp 
        \\    );
        \\
        \\
        ;

    const interrupt_common_epilogue = 
        \\    asm volatile(
        \\        \\mov %%rbx, %%rsp
        \\        \\pop %%rbx
        \\        \\mov %%bx, %%es
        \\        \\pop %%rbx
        \\        \\mov %%bx, %%ds
        \\        \\add $0x210, %%rsp
        \\        \\mov %%rsp, %%rbx
        \\        \\and $~0xf, %%rbx
        \\        \\and $~0xf, %%rbx
        \\        \\fxrstor -0x200(%%rbx)
        \\        // @TODO: if this is a new thread, we must initialize the FPU
        \\        \\pop %%rax
        //\\        \\mov $0x123456789ABCDEF, %%rbx
        //\\        \\cmp %%rbx, %%rax
        //\\        \\.loop:
        //\\        \\jne .loop
        \\        \\pop %%r15
        \\        \\pop %%r14
        \\        \\pop %%r13
        \\        \\pop %%r12
        \\        \\pop %%r11
        \\        \\pop %%r10
        \\        \\pop %%r9
        \\        \\pop %%r8
        \\        \\pop %%rbp
        \\        \\pop %%rdi
        \\        \\pop %%rsi
        \\        \\pop %%rdx
        \\        \\pop %%rcx
        \\        \\pop %%rbx
        \\        \\pop %%rax
        \\        \\add $0x10, %%rsp
        \\        \\iretq
        \\    );
        \\
        \\
        ;

    var array_list = std.ArrayList(u8).init(allocator);
    try array_list.appendSlice(
        \\const x86_64 = @import("../x86_64.zig");
        \\const page_size = x86_64.page_size;
        \\const std = @import("std");
        \\const assert = std.debug.assert;
        \\
    );
    try array_list.appendSlice(interrupt_context);
    var i: u16 = 0;
    while (i < 256) : (i += 1)
    {
        const first = try std.fmt.allocPrint(allocator, "pub export fn raw_interrupt_handler{}() callconv(.Naked) void\n{c}\n", .{i, '{'});
        try array_list.appendSlice(first);

        if (has_error_code(i))
        {
            array_list.appendSlice("    asm volatile(\"push $0\");\n") catch unreachable;
        }

        const rest = try std.fmt.allocPrint(allocator,
            \\    asm volatile("push %[vector_number]"
            \\        :
            \\        : [vector_number] "i" (@as(u8, {})));
            \\
            \\
            , .{i});
        try array_list.appendSlice(rest);

        try array_list.appendSlice(interrupt_common_prologue);

        const handler = try std.fmt.allocPrint(allocator,
            \\    asm volatile(
            \\        \\mov $interrupt_handlers, %%rax
            \\        \\add ${}, %%rax
            \\        \\callq *%%rax
            \\    );
            \\
            \\
            , .{i * 8});
        try array_list.appendSlice(handler);

        try array_list.appendSlice(interrupt_common_epilogue);

        try array_list.appendSlice(try std.fmt.allocPrint(allocator, "    unreachable;\n{c}\n", .{'}'}));
    }

    try array_list.appendSlice("pub export var interrupt_handlers = [256]fn(context: *Context) callconv(.C) void\n{\n");
    i = 0;
    while (i < 256) : (i += 1)
    {
        try array_list.appendSlice("    unhandled_interrupt,\n");
    }
    try array_list.appendSlice("};\n");

    try array_list.appendSlice("pub export fn unhandled_interrupt(_: *Context) callconv(.C) void { while (true) { } }\n\n");

    const idt_common = 
        \\pub const IDT = struct
        \\{
        \\    pub const Descriptor = packed struct
        \\    {
        \\        offset_low: u16,
        \\        segment_selector: u16,
        \\        interrupt_stack_table: u3,
        \\        reserved0: u5 = 0,
        \\        type: u4,
        \\        reserved1: u1 = 0, // storage?
        \\        descriptor_privilege_level: u2,
        \\        present: u1,
        \\        offset_mid: u16,
        \\        offset_high: u32,
        \\        reserved2: u32 = 0,
        \\    };
        \\
        \\    pub const Register = extern struct
        \\    {
        \\        limit: u16 = @sizeOf(IDT.Table) - 1,
        \\        address: *IDT.Table,
        \\    };
        \\
        \\    comptime { assert(@sizeOf(Descriptor) == 16); }
        \\
        \\    const Table = [256]Descriptor;
        \\    pub var table: IDT.Table align(page_size) = undefined;
        \\
        \\    pub fn fill() void
        \\    {
        \\
        ;
    try array_list.appendSlice(idt_common);

    i = 0;
    while (i < 256) : (i += 1)
    {
        try array_list.appendSlice(try std.fmt.allocPrint(allocator,
            \\    table[{}] = Descriptor
            , .{i}));
        try array_list.appendSlice(
            \\    {
        );

        const descriptor = try std.fmt.allocPrint(allocator,
            \\        .offset_low = @truncate(u16, @ptrToInt(raw_interrupt_handler{})),
            \\        .offset_mid = @truncate(u16, @ptrToInt(raw_interrupt_handler{}) >> 16),
            \\        .offset_high = @truncate(u32, @ptrToInt(raw_interrupt_handler{}) >> 32),
            \\        .segment_selector = 0x08, // @TODO: this should change as the GDT selector changes
            \\        .interrupt_stack_table = 0,
            \\        .type = 0xe,
            \\        .descriptor_privilege_level = 0,
            \\        .present = 1,
            , .{i, i, i});
        try array_list.appendSlice(descriptor);

        try array_list.appendSlice(
            \\    };
            \\
        );
    }

    try array_list.appendSlice("\n}\n};\n");


    return array_list.items;
}

pub const InstallInSourceStep = struct
{
    step: std.build.Step,
    b: *std.build.Builder,
    generated_source_in_cache: std.build.FileSource,
    install_path: []const u8,

    pub fn init(b: *std.build.Builder, source: std.build.FileSource, install_path: []const u8) *InstallInSourceStep
    {
        const step = b.allocator.create(InstallInSourceStep) catch @panic("out of memory");
        step.* = InstallInSourceStep
        {
            .step = std.build.Step.init(.custom, "foo", b.allocator, make),
            .b = b,
            .generated_source_in_cache = source.dupe(b),
            .install_path = b.dupePath(install_path),
        };

        return step;
    }

    fn make(step: *std.build.Step) !void
    {
        const self = @fieldParentPtr(InstallInSourceStep, "step", step);
        const src_path = self.generated_source_in_cache.getPath(self.b);
        const dst_path = std.build.FileSource.relative(self.install_path).getPath(self.b);
        try self.b.updateFile(src_path, dst_path);
    }
};
