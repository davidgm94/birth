const lib = @import("lib");
const log = lib.log.scoped(.capabilities);
const privileged = @import("privileged");
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const rise = @import("rise");
const cpu = @import("cpu");

pub const PhysicalAddress = extern struct {
    region: PhysicalMemoryRegion,
    address_space: u16,
    reserved: u16 = 0,
    reserved1: u32 = 0,
};

pub const RAM = PhysicalAddress;

pub const Capability = extern struct {
    u: extern union {
        physical_address: PhysicalAddress,
    },
    rights: Rights,
    type: Type,

    pub const Type = enum {};
    pub const Rights = packed struct {
        reserved: u8 = 0,
    };
};

pub const Static = enum {
    cpu,
    io,

    pub const count = lib.enumCount(@This());
    pub const Bitmap = [count]bool;
};

pub inline fn hasPermissions(capability_type: rise.capabilities.Type) bool {
    switch (capability_type) {
        // static
        inline .cpu, .io => |capability| {
            const static_capability = @field(Static, @tagName(capability));
            return cpu.user_scheduler.static_capability_bitmap[@enumToInt(static_capability)];
        },
        // dynamic
        // _ => return false,
    }
}
