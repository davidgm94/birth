const std = @import("std");

const default_block_size = 0x2000;

const Superblock = struct {
    inode_count: u32,
    block_count: u32,
    superuser_reserved_block_count: u32,
    unallocated_block_count: u32,
    unallocated_inode_count: u32,
    superblock_block_number: u32,
    log2_block_size: u32,
    log2_fragment_size: u32,
    block_group_block_count: u32,
    block_group_fragment_count: u32,
    block_group_inode_count: u32,
    last_mount_time: u32,
    last_written_time: u32,
    mount_count_since_last_consistency_check: u16,
    mount_count_allowed_before_consistency_check: u16,
    ext2_signature: u16,
    filesystem_state: u16,
    error_handling_method: u16,
    version_minor: u16,
    last_consistency_check_time: u32,
    interval_between_forced_consistency_checks: u32,
    operating_system_id: u32,
    version_major: u32,
    user_id: u16,
    group_id: u16,

    const offset = 0x400;
    const size = 0x400;

    pub fn get_block_group_count(self: @This()) u64 {
        const block_group_count = (self.block_count / self.block_group_block_count) + @boolToInt(self.block_count % self.block_group_block_count != 0);
        const inode_group_count = (self.inode_count / self.block_group_inode_count) + @boolToInt(self.inode_count % self.block_group_inode_count != 0);
        return block_group_count + inode_group_count;
    }

    pub fn get_from_memory(bytes: []const u8) *Superblock {
        return @ptrCast(*Superblock, @alignCast(@alignOf(Superblock), bytes.ptr));
    }

    // TODO: handle corruption
    pub fn get_filesystem_state(self: @This()) FilesystemState {
        return @intToEnum(FilesystemState, self.filesystem_state);
    }

    // TODO: handle corruption
    pub fn get_error_handling_method(self: @This()) ErrorHandlingMethod {
        return @intToEnum(ErrorHandlingMethod, self.error_handling_method);
    }
};

const FilesystemState = enum(u16) {
    clean = 1,
    errors = 2,
};

const ErrorHandlingMethod = enum(u16) {
    ignore = 1,
    remount_filesystem_as_readonly = 2,
    panic = 3,
};

// TODO: extended

const BlockGroup = struct {
    const Descriptor = struct {
        block_usage_bitmap_block_address: u32,
        inode_usage_bitmap_block_address: u32,
        inode_table_starting_block_address: u32,
        unallocated_block_count: u16,
        unallocated_inode_count: u16,
        directory_count: u16,
        padding: [14]u8,
    };

    const descriptor_table_byte_offset = Superblock.offset + Superblock.size;
};

const INode = struct {
    type_and_permissions: u16,
    user_id: u16,
    size_lower: u32,
    last_access_time: u32,
    creation_time: u32,
    last_modification_time: u32,
    deletion_time: u32,
    group_id: u16,
    hard_link_count: u16, // When this reaches 0, the data blocks are marked as unallocated
    disk_sector_count: u32, //not counting the actual inode structure nor directory entries linking to the inode.
    flags: u32,
    os_specific1: u32,
    direct_block_pointers: [12]u32,
    singly_indirect_block_pointer: u32,
    doubly_indirect_block_pointer: u32,
    triply_indirect_block_pointer: u32,
    generation_number: u32,
    // not if version >= 1
    reserved1: u32,
    // not if version >= 1
    reserved2: u32,
    fragment_block_address: u32,
    os_specific2: [12]u8,
};

const INodeType = enum(u16) {
    fifo = 0x1000,
    character_device = 0x2000,
    directory = 0x4000,
    block_device = 0x6000,
    regular_file = 0x8000,
    symbolic_link = 0xa000,
    unix_socket = 0xc000,
};

const INodePermission = enum(u16) {
    other_execute = 0x0001,
    other_write = 0x0002,
    other_read = 0x0004,
    group_execute = 0x0008,
    group_write = 0x0010,
    group_read = 0x0020,
    user_execute = 0x0040,
    user_write = 0x0080,
    user_read = 0x0100,
    sticky_bit = 0x200,
    set_group_id = 0x400,
    set_user_id = 0x800,
};
