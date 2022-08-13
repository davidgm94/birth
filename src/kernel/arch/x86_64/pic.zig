const io = @import("io.zig");
pub const master_command = io.Ports.PIC1;
pub const master_data = io.Ports.PIC1 + 1;
pub const slave_command = io.Ports.PIC2;
pub const slave_data = io.Ports.PIC2 + 1;

pub inline fn wait() void {
    io.write(u8, 0x80, undefined);
}

pub fn disable() void {
    io.write(u8, master_command, 0x11);
    wait();
    io.write(u8, slave_command, 0x11);
    wait();
    io.write(u8, master_data, 0x20);
    wait();
    io.write(u8, slave_data, 0x28);
    wait();
    io.write(u8, master_data, 0b0000_0100);
    wait();
    io.write(u8, slave_data, 0b0000_0010);
    wait();
    io.write(u8, master_data, 0x01);
    wait();
    io.write(u8, slave_data, 0x01);
    wait();

    // Masking out all PIC interrupts
    io.write(u8, master_data, 0xFF);
    io.write(u8, slave_data, 0xFF);
    wait();
}
