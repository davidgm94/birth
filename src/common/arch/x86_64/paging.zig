// Paging behavior is controlled by the following control bits:
// • The WP and PG flags in control register CR0 (bit 16 and bit 31, respectively).
// • The PSE, PAE, PGE, LA57, PCIDE, SMEP, SMAP, PKE, CET, and PKS flags in control register CR4 (bit 4, bit 5, bit 7, bit 12, bit 17, bit 20, bit 21, bit 22, bit 23, and bit 24, respectively).
// • The LME and NXE flags in the IA32_EFER MSR (bit 8 and bit 11, respectively).
// • The AC flag in the EFLAGS register (bit 18).
// • The “enable HLAT” VM-execution control (tertiary processor-based VM-execution control bit 1; see Section 24.6.2, “Processor-Based VM-Execution Controls,” in the Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 3C).

const common = @import("../../../common.zig");
const context = @import("context");
const root = @import("root");

const x86_64 = common.arch.x86_64;

const TODO = common.TODO;
const log = common.log.scoped(.Paging_x86_64);
const Allocator = common.Allocator;
const VirtualAddress = common.VirtualAddress;
const VirtualMemoryRegion = common.VirtualMemoryRegion;
const PhysicalAddress = common.PhysicalAddress;
const PhysicalAddressSpace = common.PhysicalAddressSpace;

pub var should_log = false;
