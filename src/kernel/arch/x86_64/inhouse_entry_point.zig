const common = @import("common");
const assert = common.assert;
const logger = common.log.scoped(.EntryPoint);

const privileged = @import("privileged");
const PhysicalAddress = privileged.PhysicalAddress;
const PhysicalMemoryRegion = privileged.PhysicalMemoryRegion;
const PhysicalAddressSpace = privileged.PhysicalAddressSpace;
const VirtualAddress = privileged.VirtualAddress;
const UEFI = privileged.UEFI;

const arch = @import("arch");
const CPU = arch.CPU;
const x86_64 = arch.x86_64;
const APIC = x86_64.APIC;
const IDT = x86_64.IDT;

const MemoryMap = struct {
    const Entry = struct {
        physical_address: PhysicalAddress,
        size: u64,
        native_attributes: u64,
        tag: Type,
        const Type = enum {
            usable,
            bootloader_reserved,
            bootloader_information,
            bootloader_reclaimable,
            firmware_reserved,
            firmware_reclaimable,
            reserved,
        };
    };
};

export fn kernel_entry_point(bootloader_information: *UEFI.BootloaderInformation) noreturn {
    logger.debug("Hello kernel", .{});
    IDT.setup();
    logger.debug("Loaded IDT", .{});

    // Claim some memory left from the bootloader
    //arch.startup.bsp_allocator = .{
    //.address = PhysicalAddress.new(bootloader_information.memory.address + bootloader_information.memory.allocated).to_higher_half_virtual_address(),
    //.allocated = 0,
    //.size = bootloader_information.memory.size - bootloader_information.memory.allocated,
    //};

    //const uefi_memory_map_size = bootloader_information.memory_map.region.size;
    //const uefi_memory_map_descriptor_size = bootloader_information.memory_map.descriptor_size;
    //const uefi_memory_map_descriptor_version = bootloader_information.memory_map.descriptor_version;
    //assert(uefi_memory_map_descriptor_version == 1);
    //var uefi_memory_map_pointer = bootloader_information.memory_map.region.address.value;
    //const top_uefi_memory_map_pointer = uefi_memory_map_pointer + uefi_memory_map_size;
    //const entry_count = @divExact(uefi_memory_map_size, uefi_memory_map_descriptor_size);

    //const ram_physical_address_space_allocation = arch.startup.bsp_allocator.allocate(@sizeOf(PhysicalAddressSpace.Region) * entry_count, @alignOf(PhysicalAddressSpace.Region)) catch @panic("WTF");
    //const ram_usable_entries = ram_physical_address_space_allocation.access([*]PhysicalAddressSpace.Region)[0..entry_count];
    //var ram_usable_entry_index: usize = 0;
    //var maybe_previous: ?*PhysicalAddressSpace.Region = null;

    //while (uefi_memory_map_pointer < top_uefi_memory_map_pointer) : (uefi_memory_map_pointer += uefi_memory_map_descriptor_size) {
    //const uefi_memory_map_entry = @intToPtr(*const UEFI.MemoryDescriptor, uefi_memory_map_pointer);

    //if (uefi_memory_map_entry.type == .ConventionalMemory) {
    //const ram_usable_entry = &ram_usable_entries[ram_usable_entry_index];
    //ram_usable_entry_index += 1;

    //ram_usable_entry.* = .{
    //.descriptor = .{
    //.address = PhysicalAddress.new(uefi_memory_map_entry.physical_start),
    //.size = uefi_memory_map_entry.number_of_pages * 0x1000,
    //},
    //.previous = maybe_previous,
    //.next = null,
    //};

    //if (maybe_previous) |previous| {
    //previous.next = ram_usable_entry;
    //}

    //maybe_previous = ram_usable_entry;
    //}
    //}

    //arch.startup.bsp_address_space = PhysicalAddressSpace{
    //.free_list = .{
    //.first = &ram_usable_entries[0],
    //.last = &ram_usable_entries[ram_usable_entries.len - 1],
    //.count = ram_usable_entries.len,
    //},
    //};

    CPU.stop();

    logger.debug("Left size: {}", .{bootloader_information.memory.size - bootloader_information.memory.allocated});

    APIC.init();
    CPU.stop();
}

pub fn log(comptime level: common.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    const scope_prefix = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    const prefix = "[" ++ @tagName(level) ++ "] " ++ scope_prefix;
    writer.writeAll(prefix) catch unreachable;

    writer.print(format, args) catch unreachable;
    writer.writeByte('\n') catch unreachable;
}

pub fn panic(message: []const u8, _: ?*common.StackTrace, _: ?usize) noreturn {
    asm volatile (
        \\cli
    );
    common.log.scoped(.PANIC).err("{s}", .{message});
    CPU.stop();
}

const Writer = common.Writer(void, error{}, e9_write);
const writer = Writer{ .context = {} };
fn e9_write(_: void, bytes: []const u8) error{}!usize {
    const bytes_left = asm volatile (
        \\cld
        \\rep outsb
        : [ret] "={rcx}" (-> usize),
        : [dest] "{dx}" (0xe9),
          [src] "{rsi}" (bytes.ptr),
          [len] "{rcx}" (bytes.len),
    );
    return bytes.len - bytes_left;
}
