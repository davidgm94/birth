var lock: Spinlock = undefined;

inline fn notify_config_op(bus: u8, slot: u8, function: u8, offset: u8) void {
    io_write(u32, IOPort.PCI_config, 0x80000000 | (@as(u32, bus) << 16) | (@as(u32, slot) << 11) | (@as(u32, function) << 8) | offset);
}

pub fn pci_read_config(comptime T: type, bus: u8, slot: u8, function: u8, offset: u8) T {
    lock.acquire();
    defer lock.release();

    const IntType = std.IntType(.unsigned, @bitSizeOf(T));
    comptime std.assert(IntType == u8 or IntType == u16 or IntType == u32);

    notify_config_op(bus, slot, function, offset);
    const result_int = io_read(IntType, IOPort.PCI_data + @intCast(u16, offset % 4));
    switch (@typeInfo(T)) {
        .Enum => {
            const result = @intToEnum(T, result_int);
            return result;
        },
        else => {
            const result = @bitCast(T, result_int);
            return result;
        },
    }
}

//pub fn pci_write_config(comptime T: type, value: T, bus: u8, slot: u8, function: u8, offset: u8) void {
    //lock.acquire();
    //defer lock.release();

    //const IntType = std.IntType(.unsigned, @bitSizeOf(T));
    //comptime std.assert(IntType == u8 or IntType == u16 or IntType == u32);

    //std.assert(std.is_aligned(offset, 4));
    //notify_config_op(bus, slot, function, offset);

    //io_write(IntType, IOPort.PCI_data + @intCast(u16, offset % 4), value);
//}

    //pub fn enable_single_interrupt(device: *Device, virtual_address_space: *VirtualAddressSpace, handler: x86_64.interrupts.HandlerInfo) bool {
        //if (device.enable_MSI(handler)) return true;
        //if (device.interrupt_pin == 0) return false;
        //if (device.interrupt_pin > 4) return false;

        //const result = device.enable_features(Features.from_flag(.interrupts), virtual_address_space);
        //std.assert(@src(), result);

        //// TODO: consider some stuff Essence does?
        //const interrupt_line: ?u64 = null;

        //if (handler.register_IRQ(interrupt_line, device)) {
            //return true;
        //}

        //TODO(@src());
    //}

    //pub fn enable_MSI(device: *Device, handler: x86_64.interrupts.HandlerInfo) bool {
        //_ = handler;
        //const status = device.read_config(u32, 0x04) >> 16;

        //if (~status & (1 << 4) != 0) return false;

        //var pointer = device.read_config(u8, 0x34);
        //var index: u64 = 0;

        //while (true) {
            //if (pointer == 0) break;
            //if (index >= 0xff) break;
            //index += 1;

            //const dw = device.read_config(u32, pointer);
            //const next_pointer = @truncate(u8, dw >> 8);
            //const id = @truncate(u8, dw);

            //if (id != 5) {
                //pointer = next_pointer;
                //continue;
            //}

            //// TODO: maybe this is a bug.NVMe should support MSI
            //TODO(@src());
            ////const msi =
        //}

        //return false;
    //}
