// This package provides of privileged data structures and routines to both kernel and bootloaders, for now

const lib = @import("lib");
const assert = lib.assert;
const maxInt = lib.maxInt;
const Allocator = lib.Allocator;

pub const arch = @import("privileged/arch.zig");
pub const BIOS = @import("privileged/bios.zig");
pub const Capabilities = @import("privileged/capabilities.zig");
pub const ELF = @import("privileged/elf.zig");
pub const Executable = @import("privileged/executable.zig");
pub const MappingDatabase = @import("privileged/mapping_database.zig");
pub const UEFI = @import("privileged/uefi.zig");
pub const VirtualAddressSpace = GenericVirtualAddressSpace(lib.cpu.arch);
pub const scheduler_type = SchedulerType.round_robin;
pub const Scheduler = switch (scheduler_type) {
    .round_robin => @import("privileged/round_robin.zig"),
    else => @compileError("other scheduler is not supported right now"),
};

pub fn GenericVirtualAddressSpace(comptime desired_architecture: lib.Target.Cpu.Arch) type {
    return extern struct {
        const VAS = @This();
        pub const paging = switch (desired_architecture) {
            .x86 => arch.x86.paging,
            .x86_64 => arch.x86_64.paging,
            else => @compileError("error: paging"),
    };

        pub const needed_physical_memory_for_bootstrapping_kernel_address_space = paging.needed_physical_memory_for_bootstrapping_kernel_address_space;
        pub fn kernelBSP(physical_memory_region: GenericPhysicalMemoryRegion(.x86_64, .local)) VAS {
            return paging.initKernelBSP(physical_memory_region);
        }
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
            paging.make_current(virtual_address_space);
        }

        pub const Flags = packed struct {
            write: bool = false,
           cache_disable: bool = false,
           global: bool = false,
           execute: bool = false,
           user: bool = false,

           pub inline fn empty() Flags {
               return .{};
           }

       pub inline fn toArchitectureSpecific(flags: Flags, comptime locality: CoreLocality) paging.MemoryFlags {
           return paging.new_flags(flags, locality);
       }
        };

        arch: paging.Specific,
    };
}

const E9WriterError = error{};
pub const E9Writer = lib.Writer(void, E9WriterError, writeToE9);

fn writeToE9(_: void, bytes: []const u8) E9WriterError!usize {
    return arch.io.write_bytes(bytes);
}

pub const ResourceOwner = enum(u2) {
    bootloader = 0,
    kernel = 1,
    user = 2,
};

pub const CoreSupervisorData = extern struct {
    is_valid: bool,
    next: ?*CoreSupervisorData,
    previous: ?*CoreSupervisorData,
    mdb_root: VirtualAddress(.local),
    init_rootcn: Capabilities.CTE,
    scheduler_state: Scheduler.State,
    kernel_offset: i64,
    irq_in_use: [arch.dispatch_count]u8, // bitmap of handed out caps
    irq_dispatch: [arch.dispatch_count]Capabilities.CTE,
    pending_ram_in_use: u8,
    pending_ram: [4]RAM,
};

const RAM = extern struct {
    base: u64,
    bytes: u64,
};

pub const RBED = struct {
    queue_head: ?*CoreDirectorData,
    queue_tail: ?*CoreDirectorData,
    // TODO: more stuff
};

pub const SchedulerType = enum(u8) {
    round_robin,
    rate_based_earliest_deadline,
};

pub const CoreDirectorData = extern struct {
    dispatcher_handle: VirtualAddress(.local),
    disabled: bool,
    cspace: CTE,
    vspace: usize,
    dispatcher_cte: CTE,
    faults_taken: u32,
    is_vm_guest: bool,
    // TODO: guest desc
    domain_id: u64,
    // TODO: wakeup time
    wakeup_previous: ?*CoreDirectorData,
    wakeup_next: ?*CoreDirectorData,
    next: ?*CoreDirectorData,
    previous: ?*CoreDirectorData,

    pub fn contextSwitch(core_director_data: *CoreDirectorData) void {
        arch.paging.context_switch(core_director_data.vspace);
        context_switch_counter += 1;
        // TODO: implement LDT
    }

    var context_switch_counter: usize = 0;
};

pub const CoreDirectorSharedGeneric = extern struct {
    disabled: u32,
    haswork: u32,
    udisp: VirtualAddress(.local),
    lmp_delivered: u32,
    lmp_seen: u32,
    lmp_hint: VirtualAddress(.local),
    dispatcher_run: VirtualAddress(.local),
    dispatcher_lrpc: VirtualAddress(.local),
    dispatcher_page_fault: VirtualAddress(.local),
    dispatcher_page_fault_disabled: VirtualAddress(.local),
    dispatcher_trap: VirtualAddress(.local),
    // TODO: time
    systime_frequency: u64,
    core_id: CoreId,

    pub fn getDisabledSaveArea(core_director_shared_generic: *CoreDirectorSharedGeneric) *arch.Registers {
        const core_director_shared_arch = @fieldParentPtr(arch.CoreDirectorShared, "base", core_director_shared_generic);
        return &core_director_shared_arch.disabled_save_area;
    }
};

pub const CoreLocality = enum {
    local,
    global,
};

pub fn PhysicalAddress(comptime locality: CoreLocality) type {
    return GenericPhysicalAddressExtended(lib.cpu.arch, locality);
}

pub fn GenericPhysicalAddress(comptime architecture: lib.Target.Cpu.Arch) fn(comptime locality: CoreLocality) type {
    return struct {
        fn result(comptime locality: CoreLocality) type {
            return GenericPhysicalAddressExtended(architecture, locality);
        }
    }.result;
}

pub fn GenericPhysicalAddressExtended(comptime architecture: lib.Target.Cpu.Arch, comptime locality: CoreLocality) type {
    const Usize = TargetUsize(architecture);
    return enum(Usize) {
        null = 0,
        _,

        const PA = @This();
        const VA = GenericVirtualAddressExtended(architecture, locality);

        pub fn new(new_value: Usize) PA {
            const physical_address = @intToEnum(PA, new_value);

            if (!physical_address.isValid()) {
                @panic("Physical address is invalid");
            }

            return physical_address;
        }

        pub fn temporaryInvalid() PA {
            return maybeInvalid(0);
        }

        pub fn maybeInvalid(new_value: Usize) PA {
            return @intToEnum(PA, new_value);
        }

        pub fn isValid(physical_address: PA) bool {
            if (physical_address == PA.null) return false;

            if (arch.max_physical_address_bit != 0) {
                const max = @as(Usize, 1) << arch.max_physical_address_bit;
                return physical_address.value() <= max;
            } else {
                return true;
            }
        }

        pub fn value(physical_address: PA) Usize {
            return @enumToInt(physical_address);
        }

        pub fn isEqual(physical_address: PA, other: PA) bool {
            return physical_address.value == other.value;
        }

        pub fn isAligned(physical_address: PA, alignment: Usize) bool {
            return lib.is_aligned(physical_address.value(), alignment);
        }

        pub fn belongsToRegion(physical_address: PA, region: PhysicalMemoryRegion) bool {
            return physical_address.value >= region.address.value and physical_address.value < region.address.value + region.size;
        }

        pub fn offset(physical_address: PA, asked_offset: Usize) PA {
            return @intToEnum(PA, @enumToInt(physical_address) + asked_offset);
        }

        pub fn addOffset(physical_address: *PA, asked_offset: Usize) void {
            physical_address.* = physical_address.offset(asked_offset);
        }

        pub fn alignedForward(physical_address: PA, alignment: Usize) PA {
            return @intToEnum(PA, lib.alignForward(physical_address.value(), alignment));
        }

        pub fn alignedBackward(physical_address: PA, alignment: Usize) PA {
            return @intToEnum(PA, lib.alignBackward(physical_address.value(), alignment));
        }

        pub fn alignForward(physical_address: *PA, alignment: Usize) void {
            physical_address.* = physical_address.aligned_forward(alignment);
        }

        pub fn alignBackward(physical_address: *PA, alignment: Usize) void {
            physical_address.* = physical_address.aligned_backward(alignment);
        }

        pub fn toIdentityMappedVirtualAddress(physical_address: PA) VA {
            return VA.new(physical_address.value());
        }

        pub fn toHigherHalfVirtualAddress(physical_address: PA) VA {
            const address = VA.new(physical_address.value() + lib.config.kernel_higher_half_address);
            return address;
        }

        pub fn toGlobal(physical_address: PA) PhysicalAddress(.global) {
            comptime {
                assert(locality == .local);
            }
            return @intToEnum(PhysicalAddress(.global), @enumToInt(physical_address));
        }

        pub fn toLocal(physical_address: PA) PhysicalAddress(.local) {
            comptime {
                assert(locality == .global);
            }
            return @intToEnum(PhysicalAddress(.local), @enumToInt(physical_address));
        }

        pub fn format(physical_address: PA, comptime _: []const u8, _: lib.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
            try lib.format(writer, "0x{x}", .{physical_address.value()});
        }
    };
}

fn TargetUsize(comptime architecture: lib.Target.Cpu.Arch) type {
    return switch (architecture) {
        .x86 => u32,
        .x86_64 => u64,
        else => @compileError("Architecture not supported"),
    };
}

pub fn VirtualAddress(comptime locality: CoreLocality) type {
    return GenericVirtualAddressExtended(lib.cpu.arch, locality);
}

pub fn GenericVirtualAddress(comptime architecture: lib.Target.Cpu.Arch) fn(comptime locality: CoreLocality) type {
    return struct {
        fn result(comptime locality: CoreLocality) type {
            return GenericVirtualAddressExtended(architecture, locality);
        }
    }.result;
}

pub fn GenericVirtualAddressExtended(comptime architecture: lib.Target.Cpu.Arch, comptime locality: CoreLocality) type {
    const Usize = TargetUsize(architecture);
    return enum(Usize) {
        null = 0,
        _,

        const VA = @This();

        pub fn new(new_value: Usize) VA {
            const virtual_address = @intToEnum(VA, new_value);
            assert(virtual_address.isValid());
            return virtual_address;
        }

        pub fn invalid() VA {
            return VA.null;
        }

        pub fn value(virtual_address: VA) Usize {
            return @enumToInt(virtual_address);
        }

        pub fn isValid(virtual_address: VA) bool {
            return virtual_address != VA.null;
        }

        pub fn access(virtual_address: VA, comptime Ptr: type) Ptr {
            return @intToPtr(Ptr, lib.safeArchitectureCast(virtual_address.value()));
        }

        pub fn offset(virtual_address: VA, asked_offset: Usize) VA {
            return @intToEnum(VA, virtual_address.value() + asked_offset);
        }

        pub fn addOffset(virtual_address: *VA, asked_offset: Usize) void {
            virtual_address.* = virtual_address.offset(asked_offset);
        }

        pub fn alignedForward(virtual_address: VA, alignment: Usize) VA {
            return @intToEnum(VA, lib.align_forward(virtual_address.value(), alignment));
        }

        pub fn alignedBackward(virtual_address: VA, alignment: Usize) VA {
            return @intToEnum(VA, lib.align_backward(virtual_address.value(), alignment));
        }

        pub fn alignForward(virtual_address: *VA, alignment: Usize) void {
            virtual_address.* = virtual_address.aligned_forward(alignment);
        }

        pub fn alignBackward(virtual_address: *VA, alignment: Usize) void {
            virtual_address.* = virtual_address.aligned_backward(alignment);
        }

        pub fn isAligned(virtual_address: VA, alignment: Usize) bool {
            return lib.is_aligned(virtual_address.value(), alignment);
        }

        pub fn toPhysicalAddress(virtual_address: VA) PhysicalAddress(locality) {
            assert(virtual_address.value() >= lib.config.kernel_higher_half_address);
            const address = PhysicalAddress(locality).new(virtual_address.value() - lib.config.kernel_higher_half_address);
            return address;
        }

        pub fn toLocal(virtual_address: VA) VirtualAddress(.local) {
            comptime {
                assert(locality == .global);
            }
            return @intToEnum(VirtualAddress(.local), @enumToInt(virtual_address));
        }

        pub fn toGlobal(virtual_address: VA) VirtualAddress(.global) {
            comptime {
                assert(locality == .local);
            }
            return @intToEnum(VirtualAddress(.global), @enumToInt(virtual_address));
        }

        pub fn format(virtual_address: VA, comptime _: []const u8, _: lib.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
            try lib.format(writer, "0x{x}", .{virtual_address.value()});
        }
    };
}

pub fn PhysicalMemoryRegion(comptime locality: CoreLocality) type {
    return GenericPhysicalMemoryRegion(lib.cpu.arch, locality);
}

pub fn GenericPhysicalMemoryRegion(comptime architecture: lib.Target.Cpu.Arch, comptime locality: CoreLocality) type {
    const Usize = TargetUsize(architecture);

    return extern struct {
        address: GenericPhysicalAddressExtended(architecture, locality),
        size: u64,

        const PMR = @This();
        const VMR = GenericVirtualMemoryRegion(architecture, locality);

        pub fn toHigherHalfVirtualAddress(physical_memory_region: PMR) VMR {
            return VMR {
                .address = physical_memory_region.address.toHigherHalfVirtualAddress(),
                .size = physical_memory_region.size,
            };
        }

        pub fn toIdentityMappedVirtualAddress(physical_memory_region: PMR) VMR {
            return VMR {
                .address = physical_memory_region.address.toIdentityMappedVirtualAddress(),
                .size = physical_memory_region.size,
            };
        }

        pub fn offset(physical_memory_region: PMR, asked_offset: Usize) PMR {
            assert(asked_offset < physical_memory_region.size);

            var result = physical_memory_region;
            result.address = result.address.offset(asked_offset);
            result.size -= asked_offset;
            return result;
        }

        pub fn addOffset(physical_memory_region: *PMR, asked_offset: Usize) void {
            physical_memory_region.* = physical_memory_region.offset(asked_offset);
        }

        /// Result: chop, the rest is modified through the pointer
        pub fn chop(physical_memory_region: *PMR, asked_offset: Usize) PMR {
            const ptr_result = physical_memory_region.offset(asked_offset);
            const result = PMR{
                .address = physical_memory_region.address,
                .size = physical_memory_region.size - ptr_result.size,
            };
            physical_memory_region.* = ptr_result;

            return result;
        }

        pub fn takeSlice(physical_memory_region: PMR, size: Usize) PMR {
            assert(size < physical_memory_region.size);

            var result = physical_memory_region;
            result.size = size;
            return result;
        }
    };
}

pub fn VirtualMemoryRegion(comptime locality: CoreLocality) type {
    return GenericVirtualMemoryRegion(lib.cpu.arch, locality);
}
pub fn GenericVirtualMemoryRegion(comptime architecture: lib.Target.Cpu.Arch, comptime locality: CoreLocality) type {
    const Usize = TargetUsize(architecture);

    return struct {
        address: VA,
        size: u64,

        const VA = GenericVirtualAddressExtended(architecture, locality);
        const VMR = @This();

        pub fn new(address: VA, size: u64) VMR {
            return VMR{
                .address = address,
                .size = size,
            };
        }

        pub fn accessBytes(virtual_memory_region: VMR) []u8 {
            const result = virtual_memory_region.address.access([*]u8)[0..virtual_memory_region.size];
            return result;
        }

        pub fn access(virtual_memory_region: VMR, comptime T: type) []T {
            const slice_len = @divExact(virtual_memory_region.size, @sizeOf(T));
            const result = virtual_memory_region.address.access([*]T)[0..lib.safeArchitectureCast(slice_len)];
            return result;
        }

        pub fn offset(virtual_memory_region: VMR, asked_offset: Usize) VMR {
            assert(asked_offset < virtual_memory_region.size);

            var result = virtual_memory_region;
            result.address = result.address.offset(asked_offset);
            result.size -= asked_offset;
            return result;
        }
    };
}


pub const PassId = u32;
pub const CoreId = u8;
pub const CapAddr = u32;

const CTE = Capabilities.CTE;
pub const SpawnState = struct {
    cnodes: struct {
        task: ?*CTE = null,
        seg: ?*CTE = null,
        super: ?*CTE = null,
        physical_address: ?*CTE = null,
        module: ?*CTE = null,
        page: ?*CTE = null,
        base_page: ?*CTE = null,
        early_cnode: ?*CTE = null,
        slot_alloc0: ?*CTE = null,
        slot_alloc1: ?*CTE = null,
        slot_alloc2: ?*CTE = null,
    } = .{},
    slots: struct {
        seg: Capabilities.Slot = 0,
        super: Capabilities.Slot = 0,
        physical_address: Capabilities.Slot = 0,
        module: Capabilities.Slot = 0,
    } = .{},
    argument_page_address: PhysicalAddress(.local) = .null,
};

pub fn panic(comptime format: []const u8, arguments: anytype) noreturn {
    const panic_logger = lib.log.scoped(.PANIC);
    panic_logger.err(format, arguments);
    arch.CPU_stop();
}

pub const PhysicalAddressSpace = extern struct {
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

const LoaderProtocol = enum {
    bios,
    uefi,
};

pub fn MemoryMap(comptime architecture: lib.Target.Cpu.Arch) type {
    return struct {
        type: LoaderProtocol,
          region: GenericVirtualMemoryRegion(architecture, .global),
          descriptor_size: u32,
          descriptor_version: u32 = 1,
          loader: LoaderProtocol,

          pub fn getEntries(memory_map: MemoryMap(architecture), comptime EntryType: type) []EntryType {
              const entries = memory_map.region.access(EntryType);
              return entries;
          }

          pub fn fromBIOS(entries: []const BIOS.MemoryMapEntry) struct { entry_index: u32, memory_map: MemoryMap(architecture) } {
              const entry_total_size = entries.len * @sizeOf(BIOS.MemoryMapEntry);
              const bootstrap_index = blk: {
                  for (entries) |entry, entry_index| {
                      if (entry.isLowMemory()) continue;
                      if (entry.base < lib.maxInt(usize) and entry.len >= entry_total_size) {
                          break :blk entry_index;
                      }
                  }

                  @panic("todo");
              };

              const bootstrap_memory_region = entries[bootstrap_index].toPhysicalMemoryRegion().toIdentityMappedVirtualAddress();
              const dst = bootstrap_memory_region.access(BIOS.MemoryMapEntry);
              lib.copy(BIOS.MemoryMapEntry, dst, entries);

              return .{
                  .entry_index = bootstrap_index,
                      .memory_map = .{
                          .type = .bios,
                          .region = .{
                              .address = bootstrap_memory_region.address,
                              .size = entry_total_size,
                          },
                          .descriptor_size = @sizeOf(BIOS.MemoryMapEntry),
                          .loader = .bios,
                      } };
          }
    };
}

pub fn MemoryManager(comptime architecture: lib.Target.Cpu.Arch) type {
    return struct {
        memory_map: MemoryMap(architecture),
        size_counters: []u64,
        allocator: Allocator,

        pub fn allocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
            const memory_manager = @fieldParentPtr(MemoryManager(architecture), "allocator", allocator);
            return switch (memory_manager.memory_map.loader) {
                inline else => |loader_protocol| blk: {
                    const allocation_result = try Interface(loader_protocol).allocate(memory_manager.*, size, alignment);
break :blk .{
           .address = allocation_result.address.value(),
               .size = allocation_result.size,
       };
                },
            };
        }

            pub fn Interface(comptime loader_protocol: LoaderProtocol) type {
                return struct {
                    const EntryType = switch (loader_protocol) {
                        .bios => BIOS.MemoryMapEntry,
                        .uefi => UEFI.MemoryDescriptor,
                    };

                    const GenericEntry = extern struct {
address: u64,
             size: u64,
             usable: bool,
                    };

                    fn get_generic_entry(entry: anytype) GenericEntry {
                        return switch (@TypeOf(entry)) {
                            BIOS.MemoryMapEntry => .{
                                .address = entry.base,
                                    .size = entry.len,
                                    .usable = entry.base >= 1 * lib.mb,
                            },
                                UEFI.MemoryDescriptor => .{
                                    .address = entry.physical_start,
                                    .size = entry.number_of_pages * lib.arch.valid_page_sizes[0],
                                    .usable = @panic("UEFI usable"),
                                },
                                else => @compileError("Type not admitted"),
                        };
                    }

                    pub fn fromMemoryMap(memory_map: MemoryMap(architecture), bootstrap_index: u32) MemoryManager(architecture) {
                        comptime {
                            assert(lib.arch.valid_page_sizes[0] == 0x1000);
                        }
                        const aligned_memory_map_size = lib.alignForwardGeneric(u64, memory_map.region.size, lib.arch.valid_page_sizes[0]);
                        const entry_count = @divExact(memory_map.region.size, memory_map.descriptor_size);
                        const size_counters_size = entry_count * @sizeOf(u64);

                        const entries = memory_map.region.access(EntryType);

                        for (entries) |entry, entry_index| {
                            const generic_entry = get_generic_entry(entry);
                            if (generic_entry.usable and generic_entry.size > size_counters_size + (if (entry_index == bootstrap_index) aligned_memory_map_size else 0)) {
                                const offset = if (bootstrap_index == entry_index) aligned_memory_map_size else 0;
                                const size_counters = @intToPtr([*]u64, lib.safeArchitectureCast(generic_entry.address + offset))[0..lib.safeArchitectureCast(entry_count)];
                                size_counters[bootstrap_index] += @divExact(aligned_memory_map_size, lib.arch.valid_page_sizes[0]);
                                size_counters[entry_index] += @divExact(lib.alignForwardGeneric(u64, size_counters_size, lib.arch.valid_page_sizes[0]), lib.arch.valid_page_sizes[0]);

                                return .{
                                    .memory_map = memory_map,
                                        .size_counters = size_counters,
                                        .allocator = .{
                                            .callback_allocate = MemoryManager(architecture).allocate,
                                        },
                                };
                            }
                        }

                        @panic("cannot create from_memory_map");
                    }

                    pub fn allocate(memory_manager: MemoryManager(architecture), asked_size: u64, asked_alignment: u64) !GenericPhysicalMemoryRegion(architecture, .global) {
                        // TODO: satisfy alignment
                        if (asked_size % lib.arch.valid_page_sizes[0] != 0) {
                            @panic("not page-aligned allocate");
                        }

                        const four_kb_pages = @divExact(asked_size, lib.arch.valid_page_sizes[0]);

                        const entries = memory_manager.memory_map.getEntries(EntryType);
                        for (entries) |entry, entry_index| {
                            const generic_entry = get_generic_entry(entry);
                            const busy_size = memory_manager.size_counters[entry_index] * lib.arch.valid_page_sizes[0];
                            const size_left = generic_entry.size - busy_size; 

                            if (generic_entry.usable and size_left > asked_size) {
                                if (generic_entry.address % asked_alignment != 0) @panic("WTF alignment");

                                const result = .{
                                    .address = GenericPhysicalAddressExtended(architecture, .global).maybeInvalid(generic_entry.address).offset(busy_size),
                                        .size = asked_size,
                                };

                                memory_manager.size_counters[entry_index] += four_kb_pages;

                                return result;
                            }
                        }

                        return Allocator.Allocate.Error.OutOfMemory;
                    }
                };
            }
    };
}

pub fn PhysicalHeap(comptime architecture: lib.Target.Cpu.Arch) type {
    return  extern struct {
allocator: Allocator = .{
               .callback_allocate = callback_allocate,
           },
regions: [6]GenericPhysicalMemoryRegion(architecture, .global) = lib.zeroes([6]GenericPhysicalMemoryRegion(architecture, .global)),
         page_allocator: *Allocator,

         const Region = extern struct {
descriptor: PhysicalMemoryRegion,
         };

           pub fn callback_allocate(allocator: *Allocator, size: u64, alignment: u64) Allocator.Allocate.Error!Allocator.Allocate.Result {
               _ = alignment;
               const physical_heap = @fieldParentPtr(PhysicalHeap(architecture), "allocator", allocator);
               for (physical_heap.regions) |*region| {
                   if (region.size > size) {
                       const result = .{
                           .address = region.address.value(),
                               .size = size,
                       };
                       region.size -= size;
                       region.address.addOffset(size);
                       return result;
                   }
               }

               const size_to_page_allocate = lib.alignForwardGeneric(u64, size, lib.arch.valid_page_sizes[0]);
               for (physical_heap.regions) |*region| {
                   if (region.size == 0) {
                       const allocated_region = try physical_heap.page_allocator.allocateBytes(size_to_page_allocate, lib.arch.valid_page_sizes[0]);
                       region.* = .{
                           .address = GenericPhysicalAddressExtended(architecture, .global).new(allocated_region.address),
                               .size = allocated_region.size,
                       };
                       const result = .{
                           .address = region.address.value(),
                               .size = size,
                       };
                       region.address.addOffset(size);
                       region.size -= size;
                       return result;
                   }
               }

               @panic("todo: allocate");
           }
    };
}
