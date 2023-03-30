pub const Address = u16;
pub const Slot = Address;

pub const cptr_rootcn = @enumToInt(Node.TaskSlot.rootcn);

const l2_cnode_bits = 8;

inline fn rootSlotAddress(slot: Slot) Slot {
    return slot << l2_cnode_bits;
}

const cptr_taskcn_base = rootSlotAddress(@enumToInt(Node.RootSlot.taskcn));
const cptr_base_page_cn_base = rootSlotAddress(@enumToInt(Node.RootSlot.base_page_cn));
const cptr_supercn_base = rootSlotAddress(@enumToInt(Node.RootSlot.supercn));
const cptr_pagecn_base = rootSlotAddress(@enumToInt(Node.RootSlot.pagecn));
const cptr_modulecn_base = rootSlotAddress(@enumToInt(Node.RootSlot.modulecn));

pub const Capability = extern struct {
    pub const Reference = extern struct {
        node: Node.Reference,
        slot: Slot,

        fn fromTaskNode(slot: Node.TaskSlot) Reference {
            return Reference{
                .node = Node.task,
                .slot = @enumToInt(slot),
            };
        }

        pub inline fn isNull(reference: Reference) bool {
            return reference.node.isNull() and reference.slot == 0;
        }

        pub fn getAddress(reference: Reference) Address {
            return switch (reference.isNull()) {
                false => switch (reference.node.level) {
                    0 => reference.slot << l2_cnode_bits,
                    1 => reference.node.node | reference.slot,
                    else => @panic("invalid level value"),
                },
                true => 0,
            };
        }

        pub fn getLevel(reference: Reference) u4 {
            return switch (reference.isNull()) {
                true => 0,
                false => @intCast(u4, reference.node.level + 1),
            };
        }
    };

    pub const root = Reference.fromTaskNode(.root);
    pub const irq = Reference.fromTaskNode(.irq);
    pub const io = Reference.fromTaskNode(.io);
    pub const self_end_point = Reference.fromTaskNode(.user_self_endpoint);
    pub const dispatcher = Reference.fromTaskNode(.dispatcher);
    pub const dispatcher_frame = Reference.fromTaskNode(.dispframe);
    pub const argcn = Reference{
        .node = Node.Reference.root,
        .slot = Node.RootSlot.argcn,
    };
    pub const monitor_end_point = Reference.fromTaskNode(.user_init_monitor_end_point);
    pub const kernel = Reference.fromTaskNode(.kernelcap);
    pub const ipi = Reference.fromTaskNode(.ipi);
    pub const performance_monitor = Reference.fromTaskNode(.perf_mon);
    pub const init_end_point = Reference.fromTaskNode(.user_init_monitor_end_point);
    pub const session_id = Reference.fromTaskNode(.sessionid);
    pub const process_manager = Reference.fromTaskNode(.proc_mng);
    pub const domain_id = Reference.fromTaskNode(.domainid);
    pub const vnode_root = Reference{
        .node = Node.page,
        .slot = 0,
    };
};

pub const Node = extern struct {
    pub const Reference = extern struct {
        root: Address,
        node: Address,
        level: u8,

        pub inline fn isNull(reference: Reference) bool {
            return reference.root == 0 and reference.node == 0;
        }
    };

    pub const root = Reference{
        .root = cptr_rootcn,
        .node = 0,
        .level = 1,
    };

    pub const task = Reference{
        .root = cptr_rootcn,
        .node = cptr_taskcn_base,
        .level = 1,
    };

    pub const base = Reference{
        .root = cptr_rootcn,
        .node = cptr_base_page_cn_base,
        .level = 1,
    };

    pub const super = Reference{
        .root = cptr_rootcn,
        .node = cptr_supercn_base,
        .level = 1,
    };

    pub const page = Reference{
        .root = cptr_rootcn,
        .node = cptr_pagecn_base,
        .level = 1,
    };

    pub const module = Reference{
        .root = cptr_rootcn,
        .node = cptr_modulecn_base,
        .level = 1,
    };

    pub const RootSlot = enum(u4) {
        taskcn = 0, //< Taskcn slot in root cnode
        pagecn = 1, //< Pagecn slot in root cnode
        base_page_cn = 2, //< Slot for a cnode of BASE_PAGE_SIZE frames
        supercn = 3, //< Slot for a cnode of SUPER frames
        segcn = 4, //< SegCN slot in root cnode
        pacn = 5, //< PhysAddr cnode slot in root cnode
        modulecn = 6, //< Multiboot modules cnode slot in root cnode
        slot_alloc0 = 7, //< Used for base cn slot allocator in early code
        slot_alloc1 = 8, //< Root of slot alloc1
        slot_alloc2 = 9, //< Root of slot alloc2
        root_mapping = 10, //< Slot for a cnode for the root vnode mappings
        argcn = 11, //< Argcn slot in root cnode
        bspkcb = 12, //< BSP KCB cap to fix reverse lookup issues
        early_cn_cn = 13, //< Slot for a cnode of L2_CNODE_SIZE frames
        _user = 14, //< First free slot in root cnode for user
    };

    pub const TaskSlot = enum(u5) {
        const user = 21;
        taskcn = 0, //< Task Node in itself (XXX)
        dispatcher = 1, //< Dispatcher cap in task cnode
        rootcn = 2, //< RootCN slot in task cnode
        dispframe = 4, //< Dispatcher frame cap in task cnode
        irq = 5, //< IRQ cap in task cnode
        io = 6, //< IO cap in task cnode
        bootinfo = 7, //< Bootinfo frame slot in task cnode
        kernelcap = 8, //< Kernel cap in task cnode
        tracebuf = 9, //< Trace buffer cap in task cnode
        argspage = 10, //< ?
        mon_urpc = 11, //< Frame cap for urpc comm.
        sessionid = 12, //< Session ID domain belongs to
        fdspage = 13, //< cap for inherited file descriptors
        perf_mon = 14, //< cap for performance monitoring
        sysmem = 15, //< ???
        coreboot = 16, //< Copy of realmode section used to bootstrap a core
        ipi = 17, //< Copy of IPI cap
        proc_mng = 18, //< Cap for the process manager
        domainid = 19, //< Domain ID cap
        devman = 20, //< DeviceID manager capability
        user_self_endpoint = user + 0,
        user_init_monitor_end_point = user + 1,

        // /* Size of CNodes in Root CNode if not the default size */
        // #define SLOT_ALLOC_CNODE_BITS   L2_CNODE_BITS
        // #define SLOT_ALLOC_CNODE_SLOTS  L2_CNODE_SLOTS
        // /* Only allocate 32 chunks for early cnode allocator */
        // #define EARLY_CNODE_ALLOCATED_BITS  (L2_CNODE_BITS - 2)
        // #define EARLY_CNODE_ALLOCATED_SLOTS (1ULL << EARLY_CNODE_ALLOCATED_BITS)
        //
        // /* Task CNode */
        //
        // /* Page CNode */
        // #define PAGECN_SLOT_VROOT       0 ///< First slot of page cnode is root page table
        //
        // #define ROOTCN_SLOT_LEVEL       CSPACE_LEVEL_L1
        // #define ROOTCN_SLOT_ADDR(slot)  ((slot) << L2_CNODE_BITS)
        //
        // // Cspace addresses for well-defined L2 CNodes
        // #define CPTR_TASKCN_BASE        ROOTCN_SLOT_ADDR(ROOTCN_SLOT_TASKCN)
        // #define CPTR_BASE_PAGE_CN_BASE  ROOTCN_SLOT_ADDR(ROOTCN_SLOT_BASE_PAGE_CN)
        // #define CPTR_SUPERCN_BASE       ROOTCN_SLOT_ADDR(ROOTCN_SLOT_SUPERCN)
        // #define CPTR_PHYADDRCN_BASE     ROOTCN_SLOT_ADDR(ROOTCN_SLOT_PACN)
        // #define CPTR_MODULECN_BASE      ROOTCN_SLOT_ADDR(ROOTCN_SLOT_MODULECN)
        // #define CPTR_PAGECN_BASE        ROOTCN_SLOT_ADDR(ROOTCN_SLOT_PAGECN)
    };
};

pub const Command = extern struct {
    pub const Node = enum {
        copy,
        mint,
        retype,
        delete,
        revoke,
        create,
        get_state,
        get_size,
        resize,
        identify,
    };

    pub const VNode = enum {
        map,
        unmap,
        modify_flags,
        clean_dirty_bits,
        copy_remap,
        inherit,
    };

    pub const Mapping = enum {
        modify,
        destroy,
    };

    pub const Kernel = enum {
        spawn_core,
        identify,
        identify_domain_capabilities,
        remote_relations,
        has_cap_relations,
        create_capability,
        copy_existing,
        get_core_id,
        gert_arch_id,
        nullify_capability,
        setup_trace,
        register,
        domain_id,
        get_capability_owner,
        set_capability_owner,
        lock_capability,
        unlock_capability,
        delete_last,
        delete_foreign,
        revoke_mark_target,
        revoke_mark_relations,
        delete_step,
        clear_step,
        retype,
        has_descendents,
        is_retypeable,
        sync_timer,
        ipi_register,
        ipi_delete,
        get_global_physical,
        add_kcb,
        remove_kcb,
        suspend_kcb_scheduling,
        get_platform,
        reclaim_ram,
    };

    pub const Dispatcher = enum {
        setup,
        properties,
        performance_monitor,
        setup_guest,
        dump_page_tables,
        dump_capabilities,
        vmread,
        vmwrite,
        vmptrld,
        vmclear,
    };

    pub const KCB = enum {
        identify,
        clone,
    };

    pub const RAM = enum {
        nop,
    };

    pub const IRQTable = enum {
        allocate,
        allocate_dest_capability,
        set,
        delete,
    };

    pub const IRQDestination = enum {
        connect,
        get_vector,
        get_cpu,
    };

    pub const IRQSource = enum {
        get_vector_start,
        get_vector_end,
    };

    pub const IO = enum {
        outb,
        outw,
        outd,
        inb,
        inw,
        ind,
        log_message,
    };

    pub const DeviceIDManager = enum {
        create,
    };

    pub const Notify = enum {
        send,
    };

    pub const PerformanceMonitor = enum {
        activate,
        deactivate,
        write,
    };

    pub const ID = enum {
        identify,
    };

    pub const IPI = enum {
        send_start,
        send_init,
    };
};
