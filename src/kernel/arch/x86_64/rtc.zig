const arch = @import("arch");

const index_port = 0x70;
const cmos_port = 0x71;

pub fn index_write(value: Value) void {
    arch.x86_64.io.write(u8, index_port, @enumToInt(value));
}

pub fn cmos_read() u8 {
    return arch.x86_64.io.read(u8, cmos_port);
}

pub fn read_seconds() void {
    //arch.x86_64.io.write(u8, 0x70
}

pub const Time = struct {
    hours: u8,
    minutes: u8,
    seconds: u8,
};

fn read_raw(value: Value) u8 {
    index_write(value);
    return cmos_read();
}

//pub fn read() Time {
//const hours = read_raw(.hours);
//const minutes = read_raw(.minutes);
//const seconds = read_raw(.seconds);
//index_write(.regb);

//}

const Value = enum(u8) {
    seconds = 0x0,
    al_seconds = 0x1,
    minutes = 0x2,
    al_minutes = 0x3,
    hours = 0x4,
    al_hours = 0x5,
    weekday = 0x6,
    date = 0x7,
    month = 0x8,
    year = 0x9,
    rega = 0xa,
    regb = 0xb,
    regc = 0xc,
    regd = 0xd,
};

const RegisterA = packed struct(u8) {
    rate_selection: u4,
    time_frequency_divider: u3,
    update_status: enum(u1) { can_read, in_progress },
};
