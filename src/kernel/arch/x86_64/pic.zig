const x86_64 = @import("../x86_64.zig");
const IOPort = x86_64.IOPort;
const out = x86_64.out;

pub const master_command = IOPort.PIC1;
pub const master_data = IOPort.PIC1 + 1;
pub const slave_command = IOPort.PIC2;
pub const slave_data = IOPort.PIC2 + 1;

pub inline fn wait() void {
    out(u8, 0x80, undefined);
}

pub fn disable() void {
    out(u8, master_command, 0x11);
    wait();
    out(u8, slave_command, 0x11);
    wait();
    out(u8, master_data, 0x20);
    wait();
    out(u8, slave_data, 0x28);
    wait();
    out(u8, master_data, 0b0000_0100);
    wait();
    out(u8, slave_data, 0b0000_0010);
    wait();
    out(u8, master_data, 0x01);
    wait();
    out(u8, slave_data, 0x01);
    wait();

    // Masking out all PIC interrupts
    out(u8, master_data, 0xFF);
    out(u8, slave_data, 0xFF);
    wait();
}
