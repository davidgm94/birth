const common = @import("common");
const assert = common.assert;
const log = common.log.scoped(.Capabilities);
const page_mask = common.arch.page_mask;
const valid_page_sizes = common.arch.valid_page_sizes;

const privileged = @import("privileged");
const CoreDirector = privileged.CoreDirector;
const CoreId = privileged.CoreId;
const CoreSupervisor = privileged.CoreSupervisor;
const MappingDatabase = privileged.MappingDatabase;
const PassId = privileged.PassId;
const PhysicalAddress = privileged.PhysicalAddress;
const VirtualAddress = privileged.VirtualAddress;

extern var core_id: u8;

pub const Rights = packed struct(u8) {
    read: bool,
    write: bool,
    execute: bool,
    grant: bool,
    identify: bool,
    reserved: u3 = 0,

    pub const all = Rights{
        .read = true,
        .write = true,
        .execute = true,
        .grant = true,
        .identify = true,
    };
};

pub const Capability = extern struct {
    object: extern union {
        @"null": void align(1),
        physical_address: extern struct {
            base: PhysicalAddress(.global) align(1),
            bytes: usize align(1),
            pasid: PassId align(1),
        } align(1),
        ram: extern struct {
            base: PhysicalAddress(.global) align(1),
            bytes: usize align(1),
            pasid: PassId align(1),
        } align(1),
        l1cnode: extern struct {
            cnode: PhysicalAddress(.local) align(1),
            rights: Rights align(1),
            allocated_bytes: usize align(1),
        } align(1),
        l2cnode: extern struct {
            cnode: PhysicalAddress(.local) align(1),
            rights: Rights align(1),
        } align(1),
        fcnode: extern struct {
            cnode: PhysicalAddress(.global),
            rights: Rights align(1),
            core_id: CoreId align(1),
            guard_size: u8 align(1),
            cap_addr: u32 align(1),
        } align(1),
        dispatcher: extern struct {
            current: *CoreDirector,
        } align(1),
        end_point_lmp: extern struct {
            listener: *CoreDirector align(1),
            epoffset: VirtualAddress(.local) align(1),
            epbufflen: u32 align(1),
            iftype: u16 align(1),
        } align(1),
        frame: extern struct {
            base: PhysicalAddress(.global) align(1),
            bytes: usize align(1),
            pasid: PassId align(1),
        } align(1),
        frame_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        end_point_ump: extern struct {
            base: PhysicalAddress(.global) align(1),
            bytes: usize align(1),
            pasid: PassId align(1),
            iftype: u16 align(1),
        } align(1),
        end_point_ump_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        device_frame: extern struct {
            base: PhysicalAddress(.global) align(1),
            bytes: usize align(1),
            pasid: PassId align(1),
        } align(1),
        device_frame_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        kernel: void align(1),
        vnode_x86_64_pml5: extern struct {
            base: PhysicalAddress(.global) align(1),
        } align(1),
        vnode_x86_64_pml5_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        vnode_x86_64_pml4: extern struct {
            base: PhysicalAddress(.global) align(1),
        } align(1),
        vnode_x86_64_pml4_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        vnode_x86_64_pdpt: extern struct {
            base: PhysicalAddress(.global) align(1),
        } align(1),
        vnode_x86_64_pdpt_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        vnode_x86_64_pdir: extern struct {
            base: PhysicalAddress(.global) align(1),
        } align(1),
        vnode_x86_64_pdir_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        vnode_x86_64_ptable: extern struct {
            base: PhysicalAddress(.global) align(1),
        } align(1),
        vnode_x86_64_ptable_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        vnode_x86_64_ept_pml4: extern struct {
            base: PhysicalAddress(.global) align(1),
        } align(1),
        vnode_x86_64_ept_pml4_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        vnode_x86_64_ept_pdpt: extern struct {
            base: PhysicalAddress(.global) align(1),
        } align(1),
        vnode_x86_64_ept_pdpt_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        vnode_x86_64_ept_pdir: extern struct {
            base: PhysicalAddress(.global) align(1),
        } align(1),
        vnode_x86_64_ept_pdir_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        vnode_x86_64_ept_ptable: extern struct {
            base: PhysicalAddress(.global) align(1),
        } align(1),
        vnode_x86_64_ept_ptable_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        vnode_vtd_root_table: extern struct {
            base: PhysicalAddress(.global) align(1),
        } align(1),
        vnode_vtd_root_table_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        vnode_vtd_context_table: extern struct {
            base: PhysicalAddress(.global) align(1),
        } align(1),
        vnode_vtd_context_table_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        vnode_x86_32_pdpt: extern struct {
            base: PhysicalAddress(.global) align(1),
        } align(1),
        vnode_x86_32_pdpt_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        vnode_x86_32_pdir: extern struct {
            base: PhysicalAddress(.global) align(1),
        } align(1),
        vnode_x86_32_pdir_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        vnode_x86_32_ptable: extern struct {
            base: PhysicalAddress(.global) align(1),
        } align(1),
        vnode_x86_32_ptable_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        vnode_arm_l1: extern struct {
            base: PhysicalAddress(.global) align(1),
        } align(1),
        vnode_arm_l1_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        vnode_arm_l2: extern struct {
            base: PhysicalAddress(.global) align(1),
        } align(1),
        vnode_arm_l2_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        vnode_aarch64_l0: extern struct {
            base: PhysicalAddress(.global) align(1),
        } align(1),
        vnode_aarch64_l0_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        vnode_aarch64_l1: extern struct {
            base: PhysicalAddress(.global) align(1),
        } align(1),
        vnode_aarch64_l1_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        vnode_aarch64_l2: extern struct {
            base: PhysicalAddress(.global) align(1),
        } align(1),
        vnode_aarch64_l2_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        vnode_aarch64_l3: extern struct {
            base: PhysicalAddress(.global) align(1),
        } align(1),
        vnode_aarch64_l3_mapping: extern struct {
            capability: *Capability align(1),
            ptable: *CTE align(1),
            entry: u16 align(1),
            pte_count: u16 align(1),
        } align(1),
        irq_table: void align(1),
        irq_dest: extern struct {
            cpu: u64 align(1),
            vector: u64 align(1),
        } align(1),
        irq_src: extern struct {
            start: u64 align(1),
            end: u64 align(1),
        } align(1),
        io: extern struct {
            start: u16 align(1),
            end: u16 align(1),
        } align(1),
        notify_ipi: extern struct {
            core_id: CoreId align(1),
            channel_id: u16 align(1),
        } align(1),
        id: extern struct {
            core_id: CoreId align(1),
            core_local_id: u32 align(1),
        } align(1),
        performance_monitor: void align(1),
        kernel_control_block: *CoreSupervisor align(1),
        ipi: void align(1),
        process_manager: void align(1),
        domain: extern struct {
            core_id: CoreId align(1),
            core_local_id: u32 align(1),
        } align(1),
        device_id_manager: void align(1),
        device_id: extern struct {
            segment: u16 align(1),
            bus: u8 align(1),
            device: u8 align(1),
            function: u8 align(1),
            type: u8 align(1),
            flags: u16 align(1),
        } align(1),
    } align(1),
    type: Type align(1),
    rights: Rights align(1),

    pub fn get_address(capability: Capability) PhysicalAddress(.global) {
        switch (capability.type) {
            // TODO: returning global for a local makes no sense here?
            .l1cnode => return capability.object.l1cnode.cnode.to_global(),
            .l2cnode => return capability.object.l2cnode.cnode.to_global(),
            else => @panic(@tagName(capability.type)),
        }
    }

    pub fn get_size(capability: Capability) usize {
        switch (capability.type) {
            .l1cnode => return capability.object.l1cnode.allocated_bytes,
            .l2cnode => return 16384,
            else => @panic(@tagName(capability.type)),
        }
    }

    pub fn compare(a: Capability, b: Capability, tiebreak: bool) i8 {
        const type_root_a = a.type.get_type_root();
        const type_root_b = b.type.get_type_root();
        if (type_root_a != type_root_b) {
            if (type_root_a < type_root_b) {
                return -1;
            } else {
                return 1;
            }
        }

        const address_a = a.get_address().value();
        const address_b = b.get_address().value();
        if (address_a != address_b) {
            if (address_a < address_b) {
                return -1;
            } else {
                return 1;
            }
        }

        const size_a = a.get_size();
        const size_b = b.get_size();
        if (size_a != size_b) {
            if (size_a < size_b) {
                return -1;
            } else {
                return 1;
            }
        }

        if (a.type != b.type) {
            if (@enumToInt(a.type) < @enumToInt(b.type)) {
                return -1;
            } else {
                return 1;
            }
        }

        switch (a.type) {
            else => @panic(@tagName(a.type)),
        }

        if (tiebreak) {
            @panic("tiebreak");
        }
    }
};

pub const Type = enum(u8) {
    null = 0,
    physical_address = 1,
    ram = 2,
    l1cnode = 3,
    l2cnode = 4,
    fcnode = 5,
    dispatcher = 6,
    end_point_lmp = 7,
    frame = 8,
    frame_mapping = 9,
    end_point_ump = 10,
    end_point_ump_mapping = 11,
    device_frame = 12,
    device_frame_mapping = 13,
    kernel = 14,
    vnode_x86_64_pml5 = 15,
    vnode_x86_64_pml5_mapping = 16,
    vnode_x86_64_pml4 = 17,
    vnode_x86_64_pml4_mapping = 18,
    vnode_x86_64_pdpt = 19,
    vnode_x86_64_pdpt_mapping = 20,
    vnode_x86_64_pdir = 21,
    vnode_x86_64_pdir_mapping = 22,
    vnode_x86_64_ptable = 23,
    vnode_x86_64_ptable_mapping = 24,
    vnode_x86_64_ept_pml4 = 25,
    vnode_x86_64_ept_pml4_mapping = 26,
    vnode_x86_64_ept_pdpt = 27,
    vnode_x86_64_ept_pdpt_mapping = 28,
    vnode_x86_64_ept_pdir = 29,
    vnode_x86_64_ept_pdir_mapping = 30,
    vnode_x86_64_ept_ptable = 31,
    vnode_x86_64_ept_ptable_mapping = 32,
    vnode_vtd_root_table = 33,
    vnode_vtd_root_table_mapping = 34,
    vnode_vtd_context_table = 35,
    vnode_vtd_context_table_mapping = 36,
    vnode_x86_32_pdpt = 37,
    vnode_x86_32_pdpt_mapping = 38,
    vnode_x86_32_pdir = 39,
    vnode_x86_32_pdir_mapping = 40,
    vnode_x86_32_ptable = 41,
    vnode_x86_32_ptable_mapping = 42,
    vnode_arm_l1 = 43,
    vnode_arm_l1_mapping = 44,
    vnode_arm_l2 = 45,
    vnode_arm_l2_mapping = 46,
    vnode_aarch64_l0 = 47,
    vnode_aarch64_l0_mapping = 48,
    vnode_aarch64_l1 = 49,
    vnode_aarch64_l1_mapping = 50,
    vnode_aarch64_l2 = 51,
    vnode_aarch64_l2_mapping = 52,
    vnode_aarch64_l3 = 53,
    vnode_aarch64_l3_mapping = 54,
    irq_table = 55,
    irq_dest = 56,
    irq_src = 57,
    io = 58,
    notify_ipi = 59,
    id = 60,
    performance_monitor = 61,
    kernel_control_block = 62,
    ipi = 63,
    process_manager = 64,
    domain = 65,
    device_id_manager = 66,
    device_id = 67,

    pub fn is_vnode(t: Type) bool {
        return switch (t) {
            .vnode_x86_64_pml5,
            .vnode_x86_64_pml5_mapping,
            .vnode_x86_64_pml4,
            .vnode_x86_64_pml4_mapping,
            .vnode_x86_64_pdpt,
            .vnode_x86_64_pdpt_mapping,
            .vnode_x86_64_pdir,
            .vnode_x86_64_pdir_mapping,
            .vnode_x86_64_ptable,
            .vnode_x86_64_ptable_mapping,
            .vnode_x86_64_ept_pml4,
            .vnode_x86_64_ept_pml4_mapping,
            .vnode_x86_64_ept_pdpt,
            .vnode_x86_64_ept_pdpt_mapping,
            .vnode_x86_64_ept_pdir,
            .vnode_x86_64_ept_pdir_mapping,
            .vnode_x86_64_ept_ptable,
            .vnode_x86_64_ept_ptable_mapping,
            .vnode_vtd_root_table,
            .vnode_vtd_root_table_mapping,
            .vnode_vtd_context_table,
            .vnode_vtd_context_table_mapping,
            .vnode_x86_32_pdpt,
            .vnode_x86_32_pdpt_mapping,
            .vnode_x86_32_pdir,
            .vnode_x86_32_pdir_mapping,
            .vnode_x86_32_ptable,
            .vnode_x86_32_ptable_mapping,
            .vnode_arm_l1,
            .vnode_arm_l1_mapping,
            .vnode_arm_l2,
            .vnode_arm_l2_mapping,
            .vnode_aarch64_l0,
            .vnode_aarch64_l0_mapping,
            .vnode_aarch64_l1,
            .vnode_aarch64_l1_mapping,
            .vnode_aarch64_l2,
            .vnode_aarch64_l2_mapping,
            .vnode_aarch64_l3,
            .vnode_aarch64_l3_mapping,
            => true,
            else => false,
        };
    }

    pub fn is_mappable(t: Type) bool {
        return switch (t) {
            .frame,
            .end_point_ump,
            .device_frame,
            .vnode_vtd_root_table,
            .vnode_vtd_context_table,
            .vnode_x86_64_pml5,
            .vnode_x86_64_pml4,
            .vnode_x86_64_pdpt,
            .vnode_x86_64_pdir,
            .vnode_x86_64_ptable,
            .vnode_x86_32_pdpt,
            .vnode_x86_32_pdir,
            .vnode_x86_32_ptable,
            .vnode_arm_l1,
            .vnode_arm_l2,
            .vnode_aarch64_l0,
            .vnode_aarch64_l1,
            .vnode_aarch64_l2,
            .vnode_aarch64_l3,
            => true,
            else => false,
        };
    }

    pub fn is_mapping(t: Type) bool {
        return switch (t) {
            .frame_mapping,
            .end_point_ump_mapping,
            .device_frame_mapping,
            .vnode_vtd_root_table_mapping,
            .vnode_vtd_context_table_mapping,
            .vnode_x86_64_pml5_mapping,
            .vnode_x86_64_pml4_mapping,
            .vnode_x86_64_pdpt_mapping,
            .vnode_x86_64_pdir_mapping,
            .vnode_x86_64_ptable_mapping,
            .vnode_x86_64_ept_pml4_mapping,
            .vnode_x86_64_ept_pdpt_mapping,
            .vnode_x86_64_ept_pdir_mapping,
            .vnode_x86_64_ept_ptable_mapping,
            .vnode_x86_32_pdpt_mapping,
            .vnode_x86_32_pdir_mapping,
            .vnode_x86_32_ptable_mapping,
            .vnode_arm_l1_mapping,
            .vnode_arm_l2_mapping,
            .vnode_aarch64_l0_mapping,
            .vnode_aarch64_l1_mapping,
            .vnode_aarch64_l2_mapping,
            .vnode_aarch64_l3_mapping,
            => true,
            else => false,
        };
    }

    pub fn vnode_objsize(t: Type) usize {
        if (!t.is_vnode()) unreachable;

        return switch (t) {
            .vnode_vtd_root_table,
            .vnode_vtd_context_table,
            .vnode_x86_64_pml5,
            .vnode_x86_64_pml4,
            .vnode_x86_64_pdpt,
            .vnode_x86_64_pdir,
            .vnode_x86_64_ptable,
            .vnode_x86_64_ept_pml4,
            .vnode_x86_64_ept_pdpt,
            .vnode_x86_64_ept_pdir,
            .vnode_x86_64_ept_ptable,
            .vnode_x86_32_pdpt,
            .vnode_x86_32_pdir,
            .vnode_x86_32_ptable,
            => 0x1000,
            .vnode_aarch64_l0,
            .vnode_aarch64_l1,
            .vnode_aarch64_l2,
            .vnode_aarch64_l3,
            => 0x1000,
            .vnode_arm_l1 => 16384,
            .vnode_arm_l2 => 0x400,
            else => unreachable,
        };
    }

    pub fn get_max_object_count(t: Type, source_size: u64, object_size: u64) usize {
        switch (t) {
            .physical_address,
            .ram,
            .frame,
            .end_point_ump,
            .device_frame,
            => {
                if (object_size > source_size) {
                    return 0;
                } else {
                    return source_size / object_size;
                }
            },
            .l1cnode => {
                if (source_size < Size.l2cnode or object_size < Size.l2cnode) {
                    // disallow L1 CNode to be smaller than 16kB.
                    return 0;
                } else {
                    return source_size / object_size;
                }
            },
            .l2cnode => {
                if (source_size < Size.l2cnode or object_size != Size.l2cnode) {
                    // disallow L2 CNode creation if source too small or objsize wrong
                    return 0;
                } else {
                    return source_size / object_size;
                }
            },
            .vnode_vtd_root_table,
            .vnode_vtd_context_table,
            .vnode_x86_64_pml5,
            .vnode_x86_64_pml4,
            .vnode_x86_64_pdpt,
            .vnode_x86_64_pdir,
            .vnode_x86_64_ptable,
            .vnode_x86_64_ept_pml4,
            .vnode_x86_64_ept_pdpt,
            .vnode_x86_64_ept_pdir,
            .vnode_x86_64_ept_ptable,
            .vnode_x86_32_pdpt,
            .vnode_x86_32_pdir,
            .vnode_x86_32_ptable,
            .vnode_arm_l1,
            .vnode_arm_l2,
            .vnode_aarch64_l0,
            .vnode_aarch64_l1,
            .vnode_aarch64_l2,
            .vnode_aarch64_l3,
            => {
                if (source_size < t.vnode_objsize()) {
                    return 0;
                } else {
                    return source_size / t.vnode_objsize();
                }
            },
            .dispatcher => {
                if (source_size < Size.dispatcher) {
                    return 0;
                } else {
                    return source_size / Size.dispatcher;
                }
            },
            .kernel_control_block => {
                if (source_size < Size.kcb) {
                    return 0;
                } else {
                    return source_size / Size.kcb;
                }
            },
            .domain => return l2_cnode_slots,
            .kernel,
            .irq_table,
            .irq_dest,
            .irq_src,
            .io,
            .end_point_lmp,
            .id,
            .notify_ipi,
            .performance_monitor,
            .ipi,
            .process_manager,
            .device_id,
            .device_id_manager,
            .vnode_arm_l1_mapping,
            .vnode_arm_l2_mapping,
            .vnode_aarch64_l0_mapping,
            .vnode_aarch64_l1_mapping,
            .vnode_aarch64_l2_mapping,
            .vnode_aarch64_l3_mapping,
            .vnode_x86_64_pml4_mapping,
            .vnode_x86_64_pdpt_mapping,
            .vnode_x86_64_pdir_mapping,
            .vnode_x86_64_ptable_mapping,
            .vnode_x86_64_ept_pml4_mapping,
            .vnode_x86_64_ept_pdpt_mapping,
            .vnode_x86_64_ept_pdir_mapping,
            .vnode_x86_64_ept_ptable_mapping,
            .vnode_x86_32_pdpt_mapping,
            .vnode_x86_32_pdir_mapping,
            .vnode_x86_32_ptable_mapping,
            .device_frame_mapping,
            .frame_mapping,
            => return 1,

            else => unreachable,
        }
    }

    pub fn get_type_root(t: Type) u8 {
        return switch (t) {
            .device_id => 13,
            .device_id_manager => 13,
            .domain => 12,
            .process_manager => 12,
            .ipi => 11,
            .kernel_control_block => 1,
            .performance_monitor => 10,
            .id => 9,
            .notify_ipi => 8,
            .io => 7,
            .irq_src => 6,
            .irq_dest => 5,
            .irq_table => 4,
            .vnode_aarch64_l3_mapping => 1,
            .vnode_aarch64_l3 => 1,
            .vnode_aarch64_l2_mapping => 1,
            .vnode_aarch64_l2 => 1,
            .vnode_aarch64_l1_mapping => 1,
            .vnode_aarch64_l1 => 1,
            .vnode_aarch64_l0_mapping => 1,
            .vnode_aarch64_l0 => 1,
            .vnode_arm_l2_mapping => 1,
            .vnode_arm_l2 => 1,
            .vnode_arm_l1_mapping => 1,
            .vnode_arm_l1 => 1,
            .vnode_x86_32_ptable_mapping => 1,
            .vnode_x86_32_ptable => 1,
            .vnode_x86_32_pdir_mapping => 1,
            .vnode_x86_32_pdir => 1,
            .vnode_x86_32_pdpt_mapping => 1,
            .vnode_x86_32_pdpt => 1,
            .vnode_vtd_context_table_mapping => 1,
            .vnode_vtd_context_table => 1,
            .vnode_vtd_root_table_mapping => 1,
            .vnode_vtd_root_table => 1,
            .vnode_x86_64_ept_ptable_mapping => 1,
            .vnode_x86_64_ept_ptable => 1,
            .vnode_x86_64_ept_pdir_mapping => 1,
            .vnode_x86_64_ept_pdir => 1,
            .vnode_x86_64_ept_pdpt_mapping => 1,
            .vnode_x86_64_ept_pdpt => 1,
            .vnode_x86_64_ept_pml4_mapping => 1,
            .vnode_x86_64_ept_pml4 => 1,
            .vnode_x86_64_ptable_mapping => 1,
            .vnode_x86_64_ptable => 1,
            .vnode_x86_64_pdir_mapping => 1,
            .vnode_x86_64_pdir => 1,
            .vnode_x86_64_pdpt_mapping => 1,
            .vnode_x86_64_pdpt => 1,
            .vnode_x86_64_pml4_mapping => 1,
            .vnode_x86_64_pml4 => 1,
            .vnode_x86_64_pml5_mapping => 1,
            .vnode_x86_64_pml5 => 1,
            .kernel => 3,
            .device_frame_mapping => 1,
            .device_frame => 1,
            .end_point_ump_mapping => 1,
            .end_point_ump => 1,
            .frame_mapping => 1,
            .frame => 1,
            .end_point_lmp => 1,
            .dispatcher => 1,
            .fcnode => 2,
            .l2cnode => 1,
            .l1cnode => 1,
            .ram => 1,
            .physical_address => 1,
            .null => 0,
        };
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

pub const CTE = extern struct {
    capability: Capability,
    padding_0: [common.align_forward(@sizeOf(Capability), 8) - @sizeOf(Capability)]u8,
    mdb_node: MappingDatabase.Node,
    padding_1: [common.align_forward(@sizeOf(MappingDatabase.Node), 8) - @sizeOf(MappingDatabase.Node)]u8,
    delete_node: DeleteList,
    padding: [
        (1 << objbits_cte) - @sizeOf(DeleteList) -
            common.align_forward(@sizeOf(MappingDatabase.Node), 8) -
            common.align_forward(@sizeOf(Capability), 8)
    ]u8,

    pub fn get_cnode(cte: *CTE) PhysicalAddress(.global) {
        return cte.capability.get_address();
    }
};

pub const CNodeSlot = enum(Slot) {
    task = 0,
    page = 1,
    base_page = 2,
    super = 3,
    seg = 4,
    physical_addres = 5,
    module = 6,
    slot_alloc0 = 7,
    slot_alloc1 = 8,
    slot_alloc2 = 9,
    root_mapping = 10,
    arg = 11,
    bsp_kernel_control_block = 12,
    early_cnode = 13,
    user = 14,
};

const DeleteList = extern struct {
    next: ?*CTE,
};

comptime {
    const total_size = common.align_forward(@sizeOf(Capability), 8) + common.align_forward(@sizeOf(MappingDatabase.Node), 8) + @sizeOf(DeleteList);
    assert(total_size <= (1 << objbits_cte));
}

pub fn new(capability_type: Type, address: PhysicalAddress(.local), bytes: usize, object_size: usize, owner: CoreId, capabilities: [*]CTE) !void {
    assert(capability_type != .end_point_lmp);

    assert(check_arguments(capability_type, bytes, object_size, false));
    assert(address == .null or check_arguments(capability_type, bytes, object_size, true));

    const object_count = capability_type.get_max_object_count(bytes, object_size);
    assert(object_count > 0);

    try create(capability_type, address, bytes, object_size, object_count, owner, capabilities);

    MappingDatabase.set_init_mapping(capabilities[0..object_count]);
}

fn zero_objects(capability_type: Type, address: PhysicalAddress(.local), object_size: u64, count: usize) !void {
    const virtual_address = address.to_higher_half_virtual_address();

    switch (capability_type) {
        .frame,
        .end_point_ump,
        => {
            common.zero(virtual_address.access([*]u8)[0 .. object_size * count]);
        },
        .l1cnode,
        .l2cnode,
        => {
            common.zero(virtual_address.access([*]u8)[0 .. object_size * count]);
        },
        else => @panic(@tagName(capability_type)),
    }
}

fn create(capability_type: Type, address: PhysicalAddress(.local), size: u64, object_size: u64, count: usize, owner: CoreId, cte_ptr: [*]CTE) !void {
    _ = size;
    assert(capability_type != .null);
    assert(!capability_type.is_mapping());
    const global_address = address.to_higher_half_virtual_address();
    _ = global_address;

    if (owner == core_id) {
        try zero_objects(capability_type, address, object_size, count);
    }

    const ctes = cte_ptr[0..count];
    common.zero_slice(CTE, ctes);

    switch (capability_type) {
        .l1cnode => {
            assert(object_size >= Size.l2cnode);
            assert(object_size % Size.l2cnode == 0);
            log.debug("Object count: {}", .{count});
            for (ctes) |*cte, i| {
                cte.capability = .{
                    .object = .{
                        .l1cnode = .{
                            .cnode = address.offset(i * object_size),
                            .rights = Rights.all,
                            .allocated_bytes = object_size,
                        },
                    },
                    .rights = Rights.all,
                    .type = .l1cnode,
                };
            }
        },
        .l2cnode => {
            for (ctes) |*cte, i| {
                cte.capability = .{
                    .object = .{
                        .l2cnode = .{
                            .cnode = address.offset(i * object_size),
                            .rights = Rights.all,
                        },
                    },
                    .rights = Rights.all,
                    .type = .l2cnode,
                };
            }
        },
        else => @panic(@tagName(capability_type)),
    }

    for (ctes) |*cte| {
        cte.mdb_node.owner = owner;
    }
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
            .l1cnode, .l2cnode => {
                if (bytes < Size.l2cnode or object_size < Size.l2cnode) return false;
                if (exact and bytes % object_size != 0) return false;
                return object_size % (1 << objbits_cte) == 0;
            },
            .dispatcher => {
                @panic("dispatcher");
            },
            else => return true,
        }
    }
    @panic("capabilities check arguments todo");
}

pub const Address = u32;
pub const Slot = Address;

pub fn locate_slot(cnode: PhysicalAddress(.local), offset: Slot) *CTE {
    log.debug("slot = {}", .{offset});
    const total_offset = (1 << objbits_cte) * offset;
    log.debug("total offset: {}", .{total_offset});
    return cnode.to_higher_half_virtual_address().offset(total_offset).access(*CTE);
}
