// TODO: legacy stuff; refactor when SMP is implemented

// pub fn initializeSMP(bootloader_information: *Information, madt: *const ACPI.MADT) void {
//     if (bootloader_information.bootloader != .rise) @panic("Protocol not supported");
//
//     const smp_records = bootloader_information.getSlice(.smps);
//
//     switch (lib.cpu.arch) {
//         .x86, .x86_64 => {
//             const cr3 = bootloader_information.virtual_address_space.arch.cr3;
//             if (@bitCast(u64, cr3) > lib.maxInt(u32)) {
//                 lib.log.err("CR3: 0x{x}, {}", .{ @bitCast(u64, cr3), cr3 });
//                 @panic("CR3 overflow");
//             }
//
//             const cpuid = lib.arch.x86_64.cpuid;
//             const lapicWrite = privileged.arch.x86_64.APIC.lapicWrite;
//
//             if (cpuid(1).edx & (1 << 9) == 0) {
//                 @panic("No APIC detected");
//             }
//
//             var iterator = madt.getIterator();
//             var smp_index: usize = 0;
//
//             const smp_trampoline_physical_address = PhysicalAddress.new(@ptrToInt(&arch.x86_64.smp_trampoline));
//             // Sanity checks
//             const trampoline_argument_symbol = @extern(*SMP.Trampoline.Argument, .{ .name = "smp_trampoline_arg_start" });
//             const smp_core_booted_symbol = @extern(*bool, .{ .name = "smp_core_booted" });
//             const trampoline_argument_start = @ptrToInt(trampoline_argument_symbol);
//             const trampoline_argument_offset = @intCast(u32, trampoline_argument_start - smp_trampoline_physical_address.value());
//             const smp_core_booted_offset = @intCast(u32, @ptrToInt(smp_core_booted_symbol) - smp_trampoline_physical_address.value());
//             if (!lib.isAligned(trampoline_argument_start, @alignOf(SMP.Trampoline.Argument))) @panic("SMP trampoline argument alignment must match");
//             const trampoline_argument_end = @ptrToInt(@extern(*u8, .{ .name = "smp_trampoline_arg_end" }));
//             const trampoline_argument_size = trampoline_argument_end - trampoline_argument_start;
//             if (trampoline_argument_size != @sizeOf(SMP.Trampoline.Argument)) {
//                 @panic("SMP trampoline argument size must match");
//             }
//
//             const smp_trampoline_size = @ptrToInt(@extern(*u8, .{ .name = "smp_trampoline_end" })) - smp_trampoline_physical_address.value();
//             if (smp_trampoline_size > lib.arch.valid_page_sizes[0]) {
//                 @panic("SMP trampoline too big");
//             }
//
//             const smp_trampoline = @intCast(u32, switch (lib.cpu.arch) {
//                 .x86 => smp_trampoline_physical_address.toIdentityMappedVirtualAddress().value(),
//                 .x86_64 => blk: {
//                     const page_counters = bootloader_information.getPageCounters();
//                     for (bootloader_information.getMemoryMapEntries(), 0..) |memory_map_entry, index| {
//                         if (memory_map_entry.type == .usable and memory_map_entry.region.address.value() < lib.mb and lib.isAligned(memory_map_entry.region.address.value(), lib.arch.valid_page_sizes[0])) {
//                             const page_counter = &page_counters[index];
//                             const offset = page_counter.* * lib.arch.valid_page_sizes[0];
//                             if (offset < memory_map_entry.region.size) {
//                                 page_counter.* += 1;
//                                 const smp_trampoline_buffer_region = memory_map_entry.region.offset(offset).toIdentityMappedVirtualAddress();
//
//                                 privileged.arch.x86_64.paging.setMappingFlags(&bootloader_information.virtual_address_space, smp_trampoline_buffer_region.address.value(), .{
//                                     .write = true,
//                                     .execute = true,
//                                     .global = true,
//                                 }) catch @panic("can't set smp trampoline flags");
//
//                                 const smp_trampoline_buffer = smp_trampoline_buffer_region.access(u8);
//                                 const smp_trampoline_region = PhysicalMemoryRegion.new(smp_trampoline_physical_address, smp_trampoline_size);
//                                 const smp_trampoline_source = smp_trampoline_region.toIdentityMappedVirtualAddress().access(u8);
//
//                                 @memcpy(smp_trampoline_buffer, smp_trampoline_source);
//                                 break :blk smp_trampoline_buffer_region.address.value();
//                             }
//                         }
//                     }
//
//                     @panic("No suitable region found for SMP trampoline");
//                 },
//                 else => @compileError("Architecture not supported"),
//             });
//
//             const trampoline_argument = @intToPtr(*SMP.Trampoline.Argument, smp_trampoline + trampoline_argument_offset);
//             trampoline_argument.* = .{
//                 .hhdm = bootloader_information.higher_half,
//                 .cr3 = @intCast(u32, @bitCast(u64, cr3)),
//                 .gdt_descriptor = undefined,
//                 .gdt = .{},
//             };
//
//             trampoline_argument.gdt_descriptor = trampoline_argument.gdt.getDescriptor();
//
//             const smp_core_booted = @intToPtr(*bool, smp_trampoline + smp_core_booted_offset);
//
//             while (iterator.next()) |entry| {
//                 switch (entry.type) {
//                     .LAPIC => {
//                         const lapic_entry = @fieldParentPtr(ACPI.MADT.LAPIC, "record", entry);
//                         const lapic_id = @as(u32, lapic_entry.APIC_ID);
//                         smp_records[smp_index] = .{
//                             .acpi_id = lapic_entry.ACPI_processor_UID,
//                             .lapic_id = lapic_id,
//                             .entry_point = 0,
//                             .argument = 0,
//                         };
//
//                         if (lapic_entry.APIC_ID == bootloader_information.smp.bsp_lapic_id) {
//                             smp_index += 1;
//                             continue;
//                         }
//
//                         lapicWrite(.icr_high, lapic_id << 24);
//                         lapicWrite(.icr_low, 0x4500);
//
//                         arch.x86_64.delay(10_000_000);
//
//                         const icr_low = (smp_trampoline >> 12) | 0x4600;
//                         lapicWrite(.icr_high, lapic_id << 24);
//                         lapicWrite(.icr_low, icr_low);
//
//                         for (0..100) |_| {
//                             if (@cmpxchgStrong(bool, smp_core_booted, true, false, .SeqCst, .SeqCst) == null) {
//                                 lib.log.debug("Booted core #{}", .{lapic_id});
//                                 break;
//                             }
//
//                             arch.x86_64.delay(10_000_000);
//                         } else @panic("SMP not booted");
//                     },
//                     .x2APIC => @panic("x2APIC"),
//                     else => {
//                         lib.log.warn("Unhandled {s} entry", .{@tagName(entry.type)});
//                     },
//                 }
//             }
//
//             lib.log.debug("Enabled all cores!", .{});
//         },
//         else => @compileError("Architecture not supported"),
//     }
// }
