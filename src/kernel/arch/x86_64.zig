const kernel = @import("root");
const common = @import("common");
const drivers = @import("../../drivers.zig");
const PCI = drivers.PCI;
const NVMe = drivers.NVMe;
const Virtio = drivers.Virtio;
const Disk = drivers.Disk;
const Filesystem = drivers.Filesystem;
const RNUFS = drivers.RNUFS;

const TODO = common.TODO;
const Allocator = common.Allocator;
const PhysicalAddress = common.PhysicalAddress;
const PhysicalAddressSpace = common.PhysicalAddressSpace;
const PhysicalMemoryRegion = common.PhysicalMemoryRegion;
const VirtualAddress = common.VirtualAddress;
const VirtualAddressSpace = common.VirtualAddressSpace;
const VirtualMemoryRegion = common.VirtualMemoryRegion;

const log = common.log.scoped(.x86_64);

pub const entry = @import("x86_64/entry.zig");

const CPU = common.arch.CPU;
const Thread = common.arch.Thread;
const Context = common.arch.Context;

const x86_64 = common.arch.x86_64;

pub const DefaultWriterError = SerialWriter.Error;
pub const DefaultErrorContext = SerialWriter.Context;
pub const default_writer_function = SerialWriter.function;

pub const SerialWriter = struct {
    const Error = error{};
    const Context = void;

    fn function(context: Context, bytes: []const u8) Error!usize {
        _ = context;
        for (bytes) |byte| {
            _ = byte;
            @panic("wtF");
            //io_write(u8, IOPort.E9_hack, byte);
        }

        return bytes.len;
    }
};
