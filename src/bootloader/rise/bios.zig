comptime {
    asm (
        \\.section .text
        \\.code16
        \\.global hang
        \\hang:
        \\cli
        \\hlt
    );
}
extern fn hang() callconv(.C) noreturn;

pub const cr0 = packed struct(usize) {
    protected_mode_enable: bool = true,
    monitor_coprocessor: bool = false,
    emulation: bool = false,
    task_switched: bool = false,
    extension_type: bool = false,
    numeric_error: bool = false,
    reserved: u10 = 0,
    write_protect: bool = true,
    reserved1: u1 = 0,
    alignment_mask: bool = false,
    reserved2: u10 = 0,
    not_write_through: bool = false,
    cache_disable: bool = false,
    paging: bool = true,
    //upper_32_bits: u32 = 0,

    pub inline fn read() cr0 {
        return asm volatile ("mov %%cr0, %[result]"
            : [result] "=r" (-> cr0),
        );
    }

    pub inline fn write(cr0r: cr0) void {
        asm volatile (
            \\mov %[cr0], %%cr0
            :
            : [cr0] "r" (cr0r),
        );
    }
};

export fn _start() noreturn {
    var mycr0 = cr0.read();
    mycr0.protected_mode_enable = false;
    mycr0.write();

    asm volatile (
        \\jmp $0x0, $hang
    );

    while (true) {}
}
