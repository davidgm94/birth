const lib = @import("lib");
const assert = lib.assert;
const Arch = lib.Target.Cpu.Arch;
const privileged = @import("privileged");
const CoreLocality = privileged.CoreLocality;

pub fn Interface(comptime Usize: type) type {
    return extern struct {
        pub fn PhysicalAddress(comptime core_locality: CoreLocality) type {
            return enum(Usize) {
                _,
                const PA = @This();

                pub inline fn new(address: Usize) PA {
                    if (address >= lib.config.cpu_driver_higher_half_address) @panic("Trying to write a higher half virtual address value into a physical address");
                    return @intToEnum(PA, address);
                }

                pub inline fn maybeInvalid(address: Usize) PA {
                    return @intToEnum(PA, address);
                }

                pub inline fn invalid() PA {
                    return maybeInvalid(0);
                }

                pub inline fn value(physical_address: PA) Usize {
                    return @enumToInt(physical_address);
                }

                pub inline fn toIdentityMappedVirtualAddress(physical_address: PA) VirtualAddress(core_locality) {
                    return VirtualAddress(core_locality).new(physical_address.value());
                }

                pub inline fn toHigherHalfVirtualAddress(physical_address: PA) VirtualAddress(core_locality) {
                    return physical_address.toIdentityMappedVirtualAddress().offset(lib.config.cpu_driver_higher_half_address);
                }

                pub inline fn addOffset(physical_address: *PA, asked_offset: Usize) void {
                    physical_address.* = physical_address.offset(asked_offset);
                }

                pub inline fn offset(physical_address: PA, asked_offset: Usize) PA {
                    return @intToEnum(PA, @enumToInt(physical_address) + asked_offset);
                }

                pub inline fn isAligned(physical_address: PA, alignment: Usize) bool {
                    const alignment_mask = alignment - 1;
                    return physical_address.value() & alignment_mask == 0;
                }

                pub inline fn toLocal(physical_address: PA) PhysicalAddress(.local) {
                    return @intToEnum(PhysicalAddress(.local), physical_address.value());
                }
            };
        }

        pub fn VirtualAddress(comptime core_locality: CoreLocality) type {
            _ = core_locality;

            return enum(Usize) {
                null = 0,
                _,

                const VA = @This();

                pub inline fn new(address: Usize) VA {
                    return @intToEnum(VA, address);
                }

                pub inline fn value(virtual_address: VA) Usize {
                    return @enumToInt(virtual_address);
                }

                pub inline fn access(virtual_address: VA, comptime Ptr: type) Ptr {
                    return @intToPtr(Ptr, lib.safeArchitectureCast(virtual_address.value()));
                }

                pub inline fn isValid(virtual_address: VA) bool {
                    _ = virtual_address;
                    return true;
                }

                pub inline fn offset(virtual_address: VA, asked_offset: Usize) VA {
                    return @intToEnum(VA, virtual_address.value() + asked_offset);
                }

                pub inline fn negativeOffset(virtual_address: VA, asked_offset: Usize) VA {
                    return @intToEnum(VA, virtual_address.value() - asked_offset);
                }

                pub inline fn toLocal(virtual_address: VA) VirtualAddress(.local) {
                    return @intToEnum(VirtualAddress(.local), virtual_address.value());
                }
            };
        }

        pub fn PhysicalMemoryRegion(comptime core_locality: CoreLocality) type {
            return extern struct {
                address: PhysicalAddress(core_locality),
                size: Usize,

                const PMR = @This();

                pub inline fn new(address: PhysicalAddress(core_locality), size: Usize) PMR {
                    return .{
                        .address = address,
                        .size = size,
                    };
                }

                pub inline fn toIdentityMappedVirtualAddress(physical_memory_region: PMR) VirtualMemoryRegion(core_locality) {
                    return .{
                        .address = physical_memory_region.address.toIdentityMappedVirtualAddress(),
                        .size = physical_memory_region.size,
                    };
                }

                pub inline fn toHigherHalfVirtualAddress(physical_memory_region: PMR) VirtualMemoryRegion(core_locality) {
                    return .{
                        .address = physical_memory_region.address.toHigherHalfVirtualAddress(),
                        .size = physical_memory_region.size,
                    };
                }

                pub inline fn offset(physical_memory_region: PMR, asked_offset: Usize) PMR {
                    const address = physical_memory_region.address.offset(asked_offset);
                    const size = physical_memory_region.size - asked_offset;

                    return .{
                        .address = address,
                        .size = size,
                    };
                }

                pub inline fn takeSlice(physical_memory_region: PMR, asked_size: Usize) PMR {
                    if (asked_size >= physical_memory_region.size) @panic("asked size is greater than size of region");

                    return .{
                        .address = physical_memory_region.address,
                        .size = asked_size,
                    };
                }

                pub inline fn overlaps(physical_memory_region: PMR, other: PMR) bool {
                    if (other.address.value() >= physical_memory_region.address.offset(physical_memory_region.size).value()) return false;
                    if (other.address.offset(other.size).value() <= physical_memory_region.address.value()) return false;

                    const region_inside = other.address.value() >= physical_memory_region.address.value() and other.address.offset(other.size).value() <= physical_memory_region.address.offset(physical_memory_region.size).value();
                    const region_overlap_left = other.address.value() <= physical_memory_region.address.value() and other.address.offset(other.size).value() > physical_memory_region.address.value();
                    const region_overlap_right = other.address.value() < physical_memory_region.address.offset(physical_memory_region.size).value() and other.address.offset(other.size).value() > physical_memory_region.address.offset(physical_memory_region.size).value();
                    return region_inside or region_overlap_left or region_overlap_right;
                }
            };
        }

        pub fn VirtualMemoryRegion(comptime core_locality: CoreLocality) type {
            const VA = VirtualAddress(core_locality);
            const PMR = PhysicalMemoryRegion(core_locality);
            _ = PMR;

            return extern struct {
                address: VA,
                size: Usize,

                const VMR = @This();

                pub inline fn access(virtual_memory_region: VMR, comptime T: type) []T {
                    const slice_len = @divExact(virtual_memory_region.size, @sizeOf(T));
                    const result = virtual_memory_region.address.access([*]T)[0..lib.safeArchitectureCast(slice_len)];
                    return result;
                }
            };
        }

        const PhysicalAddressSpace = extern struct {
            free_list: List = .{},
            heap_list: List = .{},

            const AllocateError = error{
                not_base_page_aligned,
                out_of_memory,
            };

            const valid_page_sizes = lib.arch.valid_page_sizes;

            pub fn allocate(physical_address_space: *PhysicalAddressSpace, size: u64, page_size: u64) AllocateError!PhysicalMemoryRegion(.local) {
                if (size >= valid_page_sizes[0]) {
                    if (!lib.isAligned(size, valid_page_sizes[0])) {
                        //log.err("Size is 0x{x} but alignment should be at least 0x{x}", .{ size, valid_page_sizes[0] });
                        return AllocateError.not_base_page_aligned;
                    }

                    var node_ptr = physical_address_space.free_list.first;

                    const allocated_region = blk: {
                        while (node_ptr) |node| : (node_ptr = node.next) {
                            const result_address = node.descriptor.address.alignedForward(page_size);
                            const size_up = size + result_address.value() - node.descriptor.address.value();
                            if (node.descriptor.size > size_up) {
                                const allocated_region = PhysicalMemoryRegion(.local){
                                    .address = result_address,
                                    .size = size,
                                };
                                node.descriptor.address.addOffset(size_up);
                                node.descriptor.size -= size_up;

                                break :blk allocated_region;
                            } else if (node.descriptor.size == size_up) {
                                const allocated_region = node.descriptor.offset(size_up - size);
                                if (node.previous) |previous| previous.next = node.next;
                                if (node.next) |next| next.previous = node.previous;
                                if (node_ptr == physical_address_space.free_list.first) physical_address_space.free_list.first = node.next;
                                if (node_ptr == physical_address_space.free_list.last) physical_address_space.free_list.last = node.previous;

                                break :blk allocated_region;
                            }
                        }

                        return AllocateError.out_of_memory;
                    };

                    // For now, just zero it out.
                    // TODO: in the future, better organization of physical memory to know for sure if the memory still obbeys the upcoming zero flag
                    const region_bytes = allocated_region.toHigherHalfVirtualAddress().accessBytes();
                    lib.zero(region_bytes);

                    return allocated_region;
                } else {
                    if (physical_address_space.heap_list.last) |last| {
                        if (last.descriptor.size >= size) {
                            const chop = last.descriptor.chop(size);
                            return chop;
                        } else {
                            @panic("insufficient size");
                        }
                    } else {
                        var heap_region = try physical_address_space.allocate(valid_page_sizes[1], valid_page_sizes[0]);
                        const region_ptr = heap_region.chop(@sizeOf(Region)).address.toHigherHalfVirtualAddress().access(*Region);
                        region_ptr.* = .{
                            .descriptor = heap_region,
                        };
                        physical_address_space.heap_list.append(region_ptr);

                        return try physical_address_space.allocate(size, page_size);
                    }
                }
            }

            pub fn free(physical_address_space: *PhysicalAddressSpace, size: u64) void {
                _ = physical_address_space;
                _ = size;

                @panic("todo free pages");
            }

            const List = extern struct {
                first: ?*Region = null,
                last: ?*Region = null,
                count: u64 = 0,

                pub fn append(list: *List, node: *Region) void {
                    defer list.count += 1;
                    if (list.last) |last| {
                        last.next = node;
                        node.previous = last;
                        list.last = node;
                    } else {
                        list.first = node;
                        list.last = node;
                    }
                }

                pub fn remove(list: *List, node: *Region) void {
                    if (list.first) |first| {
                        if (first == node) {
                            list.first = node.next;
                        }
                    }

                    if (list.last) |last| {
                        if (last == node) {
                            list.last = node.previous;
                        }
                    }

                    if (node.previous) |previous| {
                        previous.next = node.next;
                    }

                    if (node.next) |next| {
                        next.previous = node.previous;
                    }
                }
            };

            pub const Region = extern struct {
                descriptor: PhysicalMemoryRegion(.local),
                previous: ?*Region = null,
                next: ?*Region = null,
            };
        };

        pub fn VirtualAddressSpace(comptime architecture: Arch) type {
            _ = architecture;
            return extern struct {
                arch: paging.Specific,

                const VAS = @This();

                pub const paging = privileged.arch.current.paging;

                // pub const needed_physical_memory_for_bootstrapping_cpu_driver_address_space = paging.needed_physical_memory_for_bootstrapping_cpu_driver_address_space;
                //
                // pub fn kernelBSP(physical_memory_region: PhysicalMemoryRegion(.local)) VAS {
                //     return paging.initKernelBSP(physical_memory_region);
                // }

                pub fn user(physical_address_space: *PhysicalAddressSpace) VAS {
                    // TODO: defer memory free when this produces an error
                    // TODO: Maybe consume just the necessary space? We are doing this to avoid branches in the kernel heap allocator
                    var virtual_address_space = VAS{
                        .arch = undefined,
                    };

                    paging.init_user(&virtual_address_space, physical_address_space);

                    return virtual_address_space;
                }

                pub inline fn makeCurrent(virtual_address_space: *const VAS) void {
                    paging.makeCurrent(virtual_address_space);
                }

                pub const Flags = packed struct(u32) {
                    write: bool = false,
                    cache_disable: bool = false,
                    global: bool = false,
                    execute: bool = false,
                    user: bool = false,
                    reserved: u27 = 0,

                    pub inline fn empty() Flags {
                        return .{};
                    }

                    pub inline fn toArchitectureSpecific(flags: Flags, comptime locality: CoreLocality) paging.MemoryFlags {
                        return paging.newFlags(flags, locality);
                    }
                };
            };
        }
    };
}
