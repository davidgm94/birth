pub const Ports = struct {
    pub const DMA1 = 0x0000;
    pub const PIC1 = 0x0020;
    pub const Cyrix_MSR = 0x0022;
    pub const PIT_data = 0x0040;
    pub const PIT_command = 0x0043;
    pub const PS2 = 0x0060;
    pub const CMOS_RTC = 0x0070;
    pub const DMA_page_registers = 0x0080;
    pub const A20 = 0x0092;
    pub const PIC2 = 0x00a0;
    pub const DMA2 = 0x00c0;
    pub const E9_hack = 0x00e9;
    pub const ATA2 = 0x0170;
    pub const ATA1 = 0x01f0;
    pub const parallel_port = 0x0278;
    pub const serial2 = 0x02f8;
    pub const IBM_VGA = 0x03b0;
    pub const floppy = 0x03f0;
    pub const serial1 = 0x03f8;
    pub const PCI_config = 0x0cf8;
    pub const PCI_data = 0x0cfc;
};

pub inline fn read(comptime T: type, port: u16) T {
    return switch (T) {
        u8 => asm volatile ("inb %[port], %[result]"
            : [result] "={al}" (-> u8),
            : [port] "N{dx}" (port),
        ),
        u16 => asm volatile ("inw %[port], %[result]"
            : [result] "={ax}" (-> u16),
            : [port] "N{dx}" (port),
        ),
        u32 => asm volatile ("inl %[port], %[result]"
            : [result] "={eax}" (-> u32),
            : [port] "N{dx}" (port),
        ),

        else => unreachable,
    };
}

pub inline fn write(comptime T: type, port: u16, value: T) void {
    switch (T) {
        u8 => asm volatile ("outb %[value], %[port]"
            :
            : [value] "{al}" (value),
              [port] "N{dx}" (port),
        ),
        u16 => asm volatile ("outw %[value], %[port]"
            :
            : [value] "{ax}" (value),
              [port] "N{dx}" (port),
        ),
        u32 => asm volatile ("outl %[value], %[port]"
            :
            : [value] "{eax}" (value),
              [port] "N{dx}" (port),
        ),
        else => unreachable,
    }
}
