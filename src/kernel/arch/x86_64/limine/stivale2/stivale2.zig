const std = @import("std");
const assert = std.debug.assert;
const stivale = @import("header.zig");
const log = std.log.scoped(.stivale2);
const kernel = @import("../../../../kernel.zig");
pub const Struct = stivale.Struct;

pub const Error = error{
    memory_map,
    higher_half_direct_map,
    kernel_file,
    pmrs,
};

pub fn process_bootloader_information(stivale2_struct: *Struct) Error!void {
    kernel.PhysicalMemory.map = try process_memory_map(stivale2_struct);
    kernel.higher_half_direct_map = try process_higher_half_direct_map(stivale2_struct);
    kernel.file = try process_kernel_file(stivale2_struct);
    kernel.sections_in_memory = try process_pmrs(stivale2_struct);
}

pub fn find(comptime StructT: type, stivale2_struct: *Struct) ?*align(1) StructT {
    var tag_opt = @intToPtr(?*align(1) stivale.Tag, stivale2_struct.tags);

    while (tag_opt) |tag| {
        if (tag.identifier == StructT.id) {
            return @ptrCast(*align(1) StructT, tag);
        }

        tag_opt = @intToPtr(?*align(1) stivale.Tag, tag.next);
    }

    return null;
}

pub fn process_memory_map(stivale2_struct: *Struct) Error!kernel.Physical.Memory.Map {
    const memory_map_struct = find(Struct.MemoryMap, stivale2_struct) orelse return Error.memory_map;
    const memory_map_entries = memory_map_struct.memmap()[0..memory_map_struct.entry_count];
    var result = kernel.Physical.Memory.Map{
        .usable = &[_]kernel.Physical.Memory.Map.Entry{},
        .reclaimable = &[_]kernel.Physical.Memory.Map.Entry{},
        .framebuffer = &[_]kernel.Physical.Memory.Region{},
        .kernel_and_modules = &[_]kernel.Physical.Memory.Region{},
        .reserved = &[_]kernel.Physical.Memory.Region{},
    };

    // First, it is required to find a spot in memory big enough to host all the memory map entries in a architecture-independent and bootloader-independent way. This is the host entry
    const host_entry = blk: {
        for (memory_map_entries) |*entry| {
            if (entry.type == .usable) {
                const bitset = kernel.Physical.Memory.Map.Entry.get_bitset_from_address_and_size(kernel.Physical.Address.new(entry.address), entry.size);
                const bitset_size = bitset.len * @sizeOf(kernel.Physical.Memory.Map.Entry.BitsetBaseType);
                // INFO: this is separated since the bitset needs to be in a different page than the memory map
                const bitset_page_count = kernel.bytes_to_pages(bitset_size, false);
                // Allocate a bit more memory than needed just in case
                const memory_map_allocation_size = memory_map_struct.entry_count * @sizeOf(kernel.Physical.Memory.Map.Entry);
                const memory_map_page_count = kernel.bytes_to_pages(memory_map_allocation_size, false);
                const total_allocated_page_count = bitset_page_count + memory_map_page_count;
                const total_allocation_size = kernel.arch.page_size * total_allocated_page_count;
                kernel.assert(@src(), entry.size > total_allocation_size);
                result.usable = @intToPtr([*]kernel.Physical.Memory.Map.Entry, entry.address + kernel.align_forward(bitset_size, kernel.arch.page_size))[0..1];
                var block = &result.usable[0];
                block.* = kernel.Physical.Memory.Map.Entry{
                    .descriptor = kernel.Physical.Memory.Region{
                        .address = kernel.Physical.Address.new(entry.address),
                        .size = entry.size,
                    },
                    .allocated_size = 0,
                    .type = .usable,
                };

                block.setup_bitset(total_allocated_page_count);

                break :blk block;
            }
        }

        @panic("There is no memory map entry big enough to store the memory map entries");
    };

    // The counter starts with one because we have already filled the memory map with the host entry
    for (memory_map_entries) |*entry| {
        if (entry.type == .usable) {
            if (entry.address == host_entry.descriptor.address.value) continue;

            const index = result.usable.len;
            result.usable.len += 1;
            var result_entry = &result.usable[index];
            result_entry.* = kernel.Physical.Memory.Map.Entry{
                .descriptor = kernel.Physical.Memory.Region{
                    .address = kernel.Physical.Address.new(entry.address),
                    .size = entry.size,
                },
                .allocated_size = 0,
                .type = .usable,
            };

            result_entry.setup_bitset_alone();
        }
    }

    result.reclaimable.ptr = @intToPtr(@TypeOf(result.reclaimable.ptr), @ptrToInt(result.usable.ptr) + (@sizeOf(kernel.Physical.Memory.Map.Entry) * result.usable.len));

    for (memory_map_entries) |*entry| {
        if (entry.type == .bootloader_reclaimable) {
            const index = result.reclaimable.len;
            result.reclaimable.len += 1;
            var result_entry = &result.reclaimable[index];
            result_entry.* = kernel.Physical.Memory.Map.Entry{
                .descriptor = kernel.Physical.Memory.Region{
                    .address = kernel.Physical.Address.new(entry.address),
                    .size = entry.size,
                },
                .allocated_size = 0,
                .type = .reclaimable,
            };

            // Don't use the bitset here because it would imply using memory that may not be usable at the moment of writing the bitset to this region
        }
    }

    result.framebuffer.ptr = @intToPtr(@TypeOf(result.framebuffer.ptr), @ptrToInt(result.reclaimable.ptr) + (@sizeOf(kernel.Physical.Memory.Map.Entry) * result.reclaimable.len));

    for (memory_map_entries) |*entry| {
        if (entry.type == .framebuffer) {
            const index = result.framebuffer.len;
            result.framebuffer.len += 1;
            var result_entry = &result.framebuffer[index];
            result_entry.* = kernel.Physical.Memory.Region{
                .address = kernel.Physical.Address.new(entry.address),
                .size = entry.size,
            };

            // Don't use the bitset here because it would imply using memory that may not be usable at the moment of writing the bitset to this region
        }
    }

    result.kernel_and_modules.ptr = @intToPtr(@TypeOf(result.kernel_and_modules.ptr), @ptrToInt(result.framebuffer.ptr) + (@sizeOf(kernel.Physical.Memory.Region) * result.framebuffer.len));

    for (memory_map_entries) |*entry| {
        if (entry.type == .kernel_and_modules) {
            const index = result.kernel_and_modules.len;
            result.kernel_and_modules.len += 1;
            var result_entry = &result.kernel_and_modules[index];
            result_entry.* = kernel.Physical.Memory.Region{
                .address = kernel.Physical.Address.new(entry.address),
                .size = entry.size,
            };

            // Don't use the bitset here because it would imply using memory that may not be usable at the moment of writing the bitset to this region
        }
    }

    kernel.assert(@src(), result.kernel_and_modules.len == 1);

    result.reserved.ptr = @intToPtr(@TypeOf(result.reserved.ptr), @ptrToInt(result.kernel_and_modules.ptr) + (@sizeOf(kernel.Physical.Memory.Region) * result.kernel_and_modules.len));

    for (memory_map_entries) |*entry| {
        if (entry.type == .reserved) {
            const index = result.reserved.len;
            result.reserved.len += 1;
            var result_entry = &result.reserved[index];
            result_entry.* = kernel.Physical.Memory.Region{
                .address = kernel.Physical.Address.new(entry.address),
                .size = entry.size,
            };

            // Don't use the bitset here because it would imply using memory that may not be usable at the moment of writing the bitset to this region
        }
    }

    return result;
}

pub fn process_higher_half_direct_map(stivale2_struct: *Struct) Error!kernel.Virtual.Address {
    const hhdm_struct = find(Struct.HHDM, stivale2_struct) orelse return Error.higher_half_direct_map;
    return kernel.Virtual.Address.new(hhdm_struct.addr);
}

pub fn process_pmrs(stivale2_struct: *Struct) Error![]kernel.Virtual.Memory.RegionWithPermissions {
    const pmrs_struct = find(stivale.Struct.PMRs, stivale2_struct) orelse return Error.pmrs;
    const pmrs = pmrs_struct.pmrs()[0..pmrs_struct.entry_count];
    if (pmrs.len == 0) return Error.pmrs;
    const kernel_section_allocation = kernel.PhysicalMemory.allocate_pages(1) orelse return Error.pmrs;
    const kernel_sections = kernel_section_allocation.access_identity([*]kernel.Virtual.Memory.RegionWithPermissions)[0..pmrs.len];

    for (pmrs) |pmr, i| {
        const kernel_section = &kernel_sections[i];
        kernel_section.descriptor.address = kernel.Virtual.Address.new(pmr.address);
        kernel_section.descriptor.size = pmr.size;
        const permissions = pmr.permissions;
        kernel_section.read = permissions & (1 << stivale.Struct.PMRs.PMR.readable) != 0;
        kernel_section.write = permissions & (1 << stivale.Struct.PMRs.PMR.writable) != 0;
        kernel_section.execute = permissions & (1 << stivale.Struct.PMRs.PMR.executable) != 0;
    }

    return kernel_sections;
}

/// This procedure copies the kernel file in a region which is usable and whose allocationcan be registered in the physical allocator bitset
pub fn process_kernel_file(stivale2_struct: *Struct) Error!kernel.File {
    const kernel_file = find(stivale.Struct.KernelFileV2, stivale2_struct) orelse return Error.kernel_file;
    const file_address = kernel_file.kernel_file;
    const file_size = kernel_file.kernel_size;
    const kernel_page_count = kernel.bytes_to_pages(file_size, false);
    const allocation = kernel.PhysicalMemory.allocate_pages(kernel_page_count) orelse return Error.kernel_file;
    const dst = allocation.access_identity([*]u8)[0..file_size];
    const src = @intToPtr([*]u8, file_address)[0..file_size];
    log.debug("Copying kernel file...", .{});
    kernel.copy(u8, dst, src);
    kernel.file.address = kernel.Physical.Address.new(@ptrToInt(dst.ptr));
    kernel.file.size = file_size;
    return kernel.File{
        .address = kernel.Physical.Address.new(@ptrToInt(dst.ptr)),
        .size = file_size,
    };
}
