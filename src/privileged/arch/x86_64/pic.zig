const common = @import("common");
const log = common.log.scoped(.PIC);

const privileged = @import("privileged");
const io = privileged.arch.x86_64.io;

pub const PIC1_command = io.Ports.PIC1;
pub const PIC2_command = io.Ports.PIC2;
pub const PIC1_data = io.Ports.PIC1 + 1;
pub const PIC2_data = io.Ports.PIC2 + 1;

pub inline fn wait() void {}

pub inline fn write(port: u8, value: u8) void {
    asm volatile ("outb %[value], %[port]\n\t"
        :
        : [value] "{al}" (value),
          [port] "i" (port),
    );
}

pub fn disable() void {
    const a1 = io.read(u8, PIC1_data);
    write(0x80, undefined);
    const a2 = io.read(u8, PIC2_data);
    write(0x80, undefined);

    write(PIC1_command, 0x11);
    write(0x80, undefined);
    write(PIC2_command, 0x11);

    write(PIC1_data, 0x20);
    write(0x80, undefined);
    write(PIC2_data, 0x28);
    write(0x80, undefined);

    write(PIC1_data, 0x04);
    write(0x80, undefined);
    write(PIC2_data, 0x02);
    write(0x80, undefined);

    write(PIC1_data, 0x01);
    write(0x80, undefined);
    write(PIC2_data, 0x01);
    write(0x80, undefined);

    write(PIC1_data, a1);
    write(0x80, undefined);
    write(PIC2_data, a2);
    write(0x80, undefined);

    write(PIC1_data, 0b11111000);
    write(0x80, undefined);
    write(PIC2_data, 0b11101111);
    write(0x80, undefined);

    write(PIC1_data, 0xff);
    write(0x80, undefined);
    write(PIC2_data, 0xff);
    write(0x80, undefined);
}
