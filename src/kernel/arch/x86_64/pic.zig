const IOPort = x86_64.IOPort;
const io_write = x86_64.io_write;

pub const master_command = IOPort.PIC1;
pub const master_data = IOPort.PIC1 + 1;
pub const slave_command = IOPort.PIC2;
pub const slave_data = IOPort.PIC2 + 1;

pub inline fn wait() void {
    io_write(u8, 0x80, undefined);
}

pub fn disable() void {
    io_write(u8, master_command, 0x11);
    wait();
    io_write(u8, slave_command, 0x11);
    wait();
    io_write(u8, master_data, 0x20);
    wait();
    io_write(u8, slave_data, 0x28);
    wait();
    io_write(u8, master_data, 0b0000_0100);
    wait();
    io_write(u8, slave_data, 0b0000_0010);
    wait();
    io_write(u8, master_data, 0x01);
    wait();
    io_write(u8, slave_data, 0x01);
    wait();

    // Masking out all PIC interrupts
    io_write(u8, master_data, 0xFF);
    io_write(u8, slave_data, 0xFF);
    wait();
}
