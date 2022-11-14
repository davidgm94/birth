const common = @import("common");
const assert = common.assert;
const valid_page_sizes = common.arch.valid_page_sizes;
const page_mask = common.arch.page_mask;

const privileged = @import("privileged");
const CoreDirector = privileged.CoreDirector;
const CoreSupervisor = privileged.CoreSupervisor;
const CTE = privileged.CTE;
const PhysicalAddress = privileged.PhysicalAddress;
const VirtualAddress = privileged.VirtualAddress;

const Rights = packed struct(u8) {
    read: bool,
    write: bool,
    execute: bool,
    grant: bool,
    identify: bool,
    reserved: u3 = 0,
};

pub const Capability = struct {
    object: union(Type) {
        @"null": void,
        physical_address: struct {
            base: PhysicalAddress,
            bytes: usize,
            pasid: PassId,
        },
        ram: struct {
            base: PhysicalAddress,
            bytes: usize,
            pasid: PassId,
        },
        l1cnode: struct {
            cnode: PhysicalAddress,
            rights: Rights,
            allocated_bytes: usize,
        },
        l2cnode: struct {
            cnode: PhysicalAddress,
            rights: Rights,
        },
        fcnode: struct {
            cnode: PhysicalAddress,
            rights: Rights,
            core_id: CoreId,
            guard_size: u8,
            cap_addr: u32,
        },
        dispatcher: struct {
            current: *CoreDirector,
        },
        end_point_lmp: struct {
            listener: *CoreDirector,
            epoffset: VirtualAddress,
            epbufflen: u32,
            iftype: u16,
        },
        frame: struct {
            base: PhysicalAddress,
            bytes: usize,
            pasid: PassId,
        },
        frame_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        end_point_ump: struct {
            base: PhysicalAddress,
            bytes: usize,
            pasid: PassId,
            iftype: u16,
        },
        end_point_ump_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        device_frame: struct {
            base: PhysicalAddress,
            bytes: usize,
            pasid: PassId,
        },
        device_frame_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        kernel: void,
        vnode_x86_64_pml5: struct {
            base: PhysicalAddress,
        },
        vnode_x86_64_pml5_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        vnode_x86_64_pml4: struct {
            base: PhysicalAddress,
        },
        vnode_x86_64_pml4_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        vnode_x86_64_pdpt: struct {
            base: PhysicalAddress,
        },
        vnode_x86_64_pdpt_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        vnode_x86_64_pdir: struct {
            base: PhysicalAddress,
        },
        vnode_x86_64_pdir_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        vnode_x86_64_ptable: struct {
            base: PhysicalAddress,
        },
        vnode_x86_64_ptable_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        vnode_x86_64_ept_pml4: struct {
            base: PhysicalAddress,
        },
        vnode_x86_64_ept_pml4_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        vnode_x86_64_ept_pdpt: struct {
            base: PhysicalAddress,
        },
        vnode_x86_64_ept_pdpt_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        vnode_x86_64_ept_pdir: struct {
            base: PhysicalAddress,
        },
        vnode_x86_64_ept_pdir_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        vnode_x86_64_ept_ptable: struct {
            base: PhysicalAddress,
        },
        vnode_x86_64_ept_ptable_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        vnode_VTd_root_table: struct {
            base: PhysicalAddress,
        },
        vnode_VTd_root_table_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        vnode_VTd_context_table: struct {
            base: PhysicalAddress,
        },
        vnode_VTd_context_table_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        vnode_x86_32_pdpt: struct {
            base: PhysicalAddress,
        },
        vnode_x86_32_pdpt_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        vnode_x86_32_pdir: struct {
            base: PhysicalAddress,
        },
        vnode_x86_32_pdir_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        vnode_x86_32_ptable: struct {
            base: PhysicalAddress,
        },
        vnode_x86_32_ptable_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        vnode_arm_l1_ptable: struct {
            base: PhysicalAddress,
        },
        vnode_arm_l1_ptable_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        vnode_arm_l2_ptable: struct {
            base: PhysicalAddress,
        },
        vnode_arm_l2_ptable_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        vnode_aarch64_l1_ptable: struct {
            base: PhysicalAddress,
        },
        vnode_aarch64_l1_ptable_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        vnode_aarch64_l2_ptable: struct {
            base: PhysicalAddress,
        },
        vnode_aarch64_l2_ptable_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        vnode_aarch64_l3_ptable: struct {
            base: PhysicalAddress,
        },
        vnode_aarch64_l3_ptable_mapping: struct {
            capability: *Capability,
            ptable: *CTE,
            entry: u16,
            pte_count: u16,
        },
        irq_table: void,
        irq_dest: struct {
            cpu: u64,
            vector: u64,
        },
        irq_src: struct {
            start: u64,
            end: u64,
        },
        io: struct {
            start: u16,
            end: u16,
        },
        notify_ipi: struct {
            core_id: CoreId,
            channel_id: u16,
        },
        id: struct {
            core_id: CoreId,
            core_local_id: u32,
        },
        performance_monitor: void,
        kernel_control_block: *CoreSupervisor,
        ipi: void,
        process_manager: void,
        domain: struct {
            core_id: CoreId,
            core_local_id: u32,
        },
        device_manager: void,
        device_id: struct {
            segment: u16,
            bus: u8,
            device: u8,
            function: u8,
            type: u8,
            flags: u16,
        },
    },
    rights: Rights,
};

const PassId = u32;
const CoreId = u8;
const CapAddr = u32;

const Type = enum(u8) {
    Null = 0,
    PhysAddr = 1,
    RAM = 2,
    L1CNode = 3,
    L2CNode = 4,
    FCNode = 5,
    Dispatcher = 6,
    EndPointLMP = 7,
    Frame = 8,
    Frame_Mapping = 9,
    EndPointUMP = 10,
    EndPointUMP_Mapping = 11,
    DevFrame = 12,
    DevFrame_Mapping = 13,
    Kernel = 14,
    VNode_x86_64_pml5 = 15,
    VNode_x86_64_pml5_Mapping = 16,
    VNode_x86_64_pml4 = 17,
    VNode_x86_64_pml4_Mapping = 18,
    VNode_x86_64_pdpt = 19,
    VNode_x86_64_pdpt_Mapping = 20,
    VNode_x86_64_pdir = 21,
    VNode_x86_64_pdir_Mapping = 22,
    VNode_x86_64_ptable = 23,
    VNode_x86_64_ptable_Mapping = 24,
    VNode_x86_64_ept_pml4 = 25,
    VNode_x86_64_ept_pml4_Mapping = 26,
    VNode_x86_64_ept_pdpt = 27,
    VNode_x86_64_ept_pdpt_Mapping = 28,
    VNode_x86_64_ept_pdir = 29,
    VNode_x86_64_ept_pdir_Mapping = 30,
    VNode_x86_64_ept_ptable = 31,
    VNode_x86_64_ept_ptable_Mapping = 32,
    VNode_VTd_root_table = 33,
    VNode_VTd_root_table_Mapping = 34,
    VNode_VTd_ctxt_table = 35,
    VNode_VTd_ctxt_table_Mapping = 36,
    VNode_x86_32_pdpt = 37,
    VNode_x86_32_pdpt_Mapping = 38,
    VNode_x86_32_pdir = 39,
    VNode_x86_32_pdir_Mapping = 40,
    VNode_x86_32_ptable = 41,
    VNode_x86_32_ptable_Mapping = 42,
    VNode_ARM_l1 = 43,
    VNode_ARM_l1_Mapping = 44,
    VNode_ARM_l2 = 45,
    VNode_ARM_l2_Mapping = 46,
    VNode_AARCH64_l0 = 47,
    VNode_AARCH64_l0_Mapping = 48,
    VNode_AARCH64_l1 = 49,
    VNode_AARCH64_l1_Mapping = 50,
    VNode_AARCH64_l2 = 51,
    VNode_AARCH64_l2_Mapping = 52,
    VNode_AARCH64_l3 = 53,
    VNode_AARCH64_l3_Mapping = 54,
    IRQTable = 55,
    IRQDest = 56,
    IRQSrc = 57,
    IO = 58,
    Notify_IPI = 59,
    ID = 60,
    PerfMon = 61,
    KernelControlBlock = 62,
    IPI = 63,
    ProcessManager = 64,
    Domain = 65,
    DeviceIDManager = 66,
    DeviceID = 67,

    pub fn is_vnode(t: Type) bool {
        return switch (t) {
            .VNode_x86_64_pml5,
            .VNode_x86_64_pml5_Mapping,
            .VNode_x86_64_pml4,
            .VNode_x86_64_pml4_Mapping,
            .VNode_x86_64_pdpt,
            .VNode_x86_64_pdpt_Mapping,
            .VNode_x86_64_pdir,
            .VNode_x86_64_pdir_Mapping,
            .VNode_x86_64_ptable,
            .VNode_x86_64_ptable_Mapping,
            .VNode_x86_64_ept_pml4,
            .VNode_x86_64_ept_pml4_Mapping,
            .VNode_x86_64_ept_pdpt,
            .VNode_x86_64_ept_pdpt_Mapping,
            .VNode_x86_64_ept_pdir,
            .VNode_x86_64_ept_pdir_Mapping,
            .VNode_x86_64_ept_ptable,
            .VNode_x86_64_ept_ptable_Mapping,
            .VNode_VTd_root_table,
            .VNode_VTd_root_table_Mapping,
            .VNode_VTd_ctxt_table,
            .VNode_VTd_ctxt_table_Mapping,
            .VNode_x86_32_pdpt,
            .VNode_x86_32_pdpt_Mapping,
            .VNode_x86_32_pdir,
            .VNode_x86_32_pdir_Mapping,
            .VNode_x86_32_ptable,
            .VNode_x86_32_ptable_Mapping,
            .VNode_ARM_l1,
            .VNode_ARM_l1_Mapping,
            .VNode_ARM_l2,
            .VNode_ARM_l2_Mapping,
            .VNode_AARCH64_l0,
            .VNode_AARCH64_l0_Mapping,
            .VNode_AARCH64_l1,
            .VNode_AARCH64_l1_Mapping,
            .VNode_AARCH64_l2,
            .VNode_AARCH64_l2_Mapping,
            .VNode_AARCH64_l3,
            .VNode_AARCH64_l3_Mapping,
            => true,
            else => false,
        };
    }

    pub fn is_mappable(t: Type) bool {
        return switch (t) {
            .Frame,
            .EndPointUMP,
            .DevFrame,
            .VNode_VTd_root_table,
            .VNode_VTd_ctxt_table,
            .VNode_x86_64_pml5,
            .VNode_x86_64_pml4,
            .VNode_x86_64_pdpt,
            .VNode_x86_64_pdir,
            .VNode_x86_64_ptable,
            .VNode_x86_32_pdpt,
            .VNode_x86_32_pdir,
            .VNode_x86_32_ptable,
            .VNode_ARM_l1,
            .VNode_ARM_l2,
            .VNode_AARCH64_l0,
            .VNode_AARCH64_l1,
            .VNode_AARCH64_l2,
            .VNode_AARCH64_l3,
            => true,
            else => false,
        };
    }

    pub fn is_mappinng(t: Type) bool {
        return switch (t) {
            .Frame_Mapping,
            .EndPointUMP_Mapping,
            .DevFrame_Mapping,
            .VNode_VTd_root_table_Mapping,
            .VNode_VTd_ctxt_table_Mapping,
            .VNode_x86_64_pml5_Mapping,
            .VNode_x86_64_pml4_Mapping,
            .VNode_x86_64_pdpt_Mapping,
            .VNode_x86_64_pdir_Mapping,
            .VNode_x86_64_ptable_Mapping,
            .VNode_x86_64_ept_pml4_Mapping,
            .VNode_x86_64_ept_pdpt_Mapping,
            .VNode_x86_64_ept_pdir_Mapping,
            .VNode_x86_64_ept_ptable_Mapping,
            .VNode_x86_32_pdpt_Mapping,
            .VNode_x86_32_pdir_Mapping,
            .VNode_x86_32_ptable_Mapping,
            .VNode_ARM_l1_Mapping,
            .VNode_ARM_l2_Mapping,
            .VNode_AARCH64_l0_Mapping,
            .VNode_AARCH64_l1_Mapping,
            .VNode_AARCH64_l2_Mapping,
            .VNode_AARCH64_l3_Mapping,
            => true,
            else => false,
        };
    }

    pub fn vnode_objsize(t: Type) usize {
        if (!t.is_vnode()) unreachable;

        return switch (t) {
            .VNode_VTd_root_table,
            .VNode_VTd_ctxt_table,
            .VNode_x86_64_pml5,
            .VNode_x86_64_pml4,
            .VNode_x86_64_pdpt,
            .VNode_x86_64_pdir,
            .VNode_x86_64_ptable,
            .VNode_x86_64_ept_pml4,
            .VNode_x86_64_ept_pdpt,
            .VNode_x86_64_ept_pdir,
            .VNode_x86_64_ept_ptable,
            .VNode_x86_32_pdpt,
            .VNode_x86_32_pdir,
            .VNode_x86_32_ptable,
            => 0x1000,
            .VNode_AARCH64_l0,
            .VNode_AARCH64_l1,
            .VNode_AARCH64_l2,
            .VNode_AARCH64_l3,
            => 0x1000,
            .VNode_ARM_l1 => 16384,
            .VNode_ARM_l2 => 0x400,
            else => unreachable,
        };
    }

    pub fn get_max_object_count(t: Type, source_size: u64, object_size: u64) usize {
        switch (t) {
            .PhysAddr,
            .RAM,
            .Frame,
            .EndPointUMP,
            .DevFrame,
            => {
                if (object_size > source_size) {
                    return 0;
                } else {
                    return source_size / object_size;
                }
            },
            .L1CNode => {
                if (source_size < Size.l2cnode or object_size < Size.l2cnode) {
                    // disallow L1 CNode to be smaller than 16kB.
                    return 0;
                } else {
                    return source_size / object_size;
                }
            },
            .L2CNode => {
                if (source_size < Size.l2cnode or object_size != Size.l2cnode) {
                    // disallow L2 CNode creation if source too small or objsize wrong
                    return 0;
                } else {
                    return source_size / object_size;
                }
            },
            .VNode_VTd_root_table,
            .VNode_VTd_ctxt_table,
            .VNode_x86_64_pml5,
            .VNode_x86_64_pml4,
            .VNode_x86_64_pdpt,
            .VNode_x86_64_pdir,
            .VNode_x86_64_ptable,
            .VNode_x86_64_ept_pml4,
            .VNode_x86_64_ept_pdpt,
            .VNode_x86_64_ept_pdir,
            .VNode_x86_64_ept_ptable,
            .VNode_x86_32_pdpt,
            .VNode_x86_32_pdir,
            .VNode_x86_32_ptable,
            .VNode_ARM_l1,
            .VNode_ARM_l2,
            .VNode_AARCH64_l0,
            .VNode_AARCH64_l1,
            .VNode_AARCH64_l2,
            .VNode_AARCH64_l3,
            => {
                if (source_size < t.vnode_objsize()) {
                    return 0;
                } else {
                    return source_size / t.vnode_objsize();
                }
            },
            .Dispatcher => {
                if (source_size < Size.dispatcher) {
                    return 0;
                } else {
                    return source_size / Size.dispatcher;
                }
            },
            .KernelControlBlock => {
                if (source_size < Size.kcb) {
                    return 0;
                } else {
                    return source_size / Size.kcb;
                }
            },
            .Domain => return l2_cnode_slots,
            .Kernel,
            .IRQTable,
            .IRQDest,
            .IRQSrc,
            .IO,
            .EndPointLMP,
            .ID,
            .Notify_IPI,
            .PerfMon,
            .IPI,
            .ProcessManager,
            .DeviceID,
            .DeviceIDManager,
            .VNode_ARM_l1_Mapping,
            .VNode_ARM_l2_Mapping,
            .VNode_AARCH64_l0_Mapping,
            .VNode_AARCH64_l1_Mapping,
            .VNode_AARCH64_l2_Mapping,
            .VNode_AARCH64_l3_Mapping,
            .VNode_x86_64_pml4_Mapping,
            .VNode_x86_64_pdpt_Mapping,
            .VNode_x86_64_pdir_Mapping,
            .VNode_x86_64_ptable_Mapping,
            .VNode_x86_64_ept_pml4_Mapping,
            .VNode_x86_64_ept_pdpt_Mapping,
            .VNode_x86_64_ept_pdir_Mapping,
            .VNode_x86_64_ept_ptable_Mapping,
            .VNode_x86_32_pdpt_Mapping,
            .VNode_x86_32_pdir_Mapping,
            .VNode_x86_32_ptable_Mapping,
            .DevFrame_Mapping,
            .Frame_Mapping,
            => return 1,

            else => unreachable,
        }
    }
};

pub const Size = struct {
    pub const l2cnode = 16384;
    pub const dispatcher = 1024;
    pub const vnode = 4096;
    pub const vnode_arm_l1 = 16384;
    pub const vnode_arm_l2 = 1024;
    pub const kcb = 131072;
    pub const mapping = 1;
};

pub fn new(capability_type: Type, address: PhysicalAddress(.local), bytes: usize, object_size: usize, owner: CoreId, cte: *CTE) !void {
    assert(capability_type != .EndPointLMP);
    _ = owner;
    _ = cte;

    assert(check_arguments(capability_type, bytes, object_size, false));
    assert(address == .null or check_arguments(capability_type, bytes, object_size, true));

    const object_count = capability_type.get_max_object_count(bytes, object_size);
    assert(object_count > 0);

    @panic("capabilities new todo");
}

fn create(capability_type: Type, address: PhysicalAddress, size: u64, object_size: u64, count: usize, owner: CoreId, cte: *CTE) !void {
    _ = address;
    _ = size;
    _ = object_size;
    _ = owner;
    _ = count;
    _ = cte;
    assert(capability_type != .null);
    assert(!capability_type.is_mapping());
    @panic("cap create");
}

const objbits_cte = 6;
const l2_cnode_bits = 8;
const l2_cnode_slots = 1 << l2_cnode_bits;

pub fn check_arguments(capability_type: Type, bytes: usize, object_size: usize, exact: bool) bool {
    const base_mask = if (capability_type.is_vnode()) capability_type.vnode_objsize() - 1 else page_mask(valid_page_sizes[0]);
    _ = base_mask;
    if (capability_type.is_mappable()) {
        @panic("mappable");
    } else {
        switch (capability_type) {
            .L1CNode => {
                if (bytes < Size.l2cnode or object_size < Size.l2cnode) return false;
                if (exact and bytes % object_size != 0) return false;
                return object_size % (1 << objbits_cte) == 0;
            },
            .L2CNode => {
                @panic("l2cnode");
            },
            .Dispatcher => {
                @panic("dispatcher");
            },
            else => return true,
        }
    }
    @panic("capabilities check arguments todo");
}
