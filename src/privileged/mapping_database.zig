const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.MappingDatabase);
const privileged = @import("privileged");
const Capabilities = privileged.Capabilities;
const CoreId = privileged.CoreId;
const CoreSupervisorData = privileged.CoreSupervisorData;
const CTE = Capabilities.CTE;
const PhysicalAddress = privileged.PhysicalAddress;
const VirtualAddress = privileged.VirtualAddress;

pub var core_supervisor: *CoreSupervisorData = undefined;
pub var mapping_database_root: ?*CTE = null;

const Error = error{
    invalid_core_supervisor,
    duplicate_entry,
};

pub const Node = extern struct {
    left: ?*CTE = null,
    right: ?*CTE = null,
    end: PhysicalAddress(.global),
    end_root: u8,
    level: u8,
    more: packed struct(u8) {
        remote_copies: bool,
        remote_ancs: bool,
        remote_descs: bool,
        locked: bool,
        in_delete: bool,
        reserved: u3 = 0,
    },
    owner: CoreId,
};

pub fn init(given_core_supervisor: *CoreSupervisorData) !void {
    core_supervisor = given_core_supervisor;
    if (!core_supervisor.is_valid) {
        // Empty core supervisor
        return;
    }

    @panic("mdb init");
}

pub fn set_init_mapping(start: []CTE) void {
    for (start) |*node| {
        insert(node) catch unreachable;
    }
}

pub fn insert(node: *CTE) !void {
    try insert_extended(node, &mapping_database_root);
}

fn insert_extended(node: *CTE, current_ptr: *?*CTE) !void {
    if (current_ptr.*) |current| {
        const compare = node.capability.compare(&current.capability, true);
        if (compare < 0) {
            try insert_extended(node, &current.mdb_node.left);
        } else if (compare > 0) {
            try insert_extended(node, &current.mdb_node.right);
        } else {
            return Error.duplicate_entry;
        }

        update_end(current);
        const new_current = split(skew(current));
        current_ptr.* = new_current;
    } else {
        update_end(node);
        current_ptr.* = node;
    }
}

fn update_end(cte: *CTE) void {
    const node = &cte.mdb_node;
    node.end_root = blk: {
        var end_root = cte.capability.type.get_type_root();
        if (node.left) |left| {
            end_root = @max(end_root, left.mdb_node.end_root);
        }
        if (node.right) |right| {
            end_root = @max(end_root, right.mdb_node.end_root);
        }

        break :blk end_root;
    };

    node.end = blk: {
        var end = PhysicalAddress(.global).null;
        if (cte.capability.type.get_type_root() == node.end_root) {
            end = cte.capability.get_address().offset(cte.capability.get_size());
        }
        if (node.left) |left| {
            if (left.mdb_node.end_root == node.end_root) {
                end = PhysicalAddress(.global).maybeInvalid(@max(end.value(), left.mdb_node.end.value()));
            }
        }
        if (node.right) |right| {
            if (right.mdb_node.end_root == node.end_root) {
                end = PhysicalAddress(.global).maybeInvalid(@max(end.value(), right.mdb_node.end.value()));
            }
        }

        break :blk end;
    };
}

fn skew(maybe_node: ?*CTE) ?*CTE {
    if (maybe_node) |node| {
        if (node.mdb_node.left) |left| {
            if (node.mdb_node.level == left.mdb_node.level) {
                node.mdb_node.left = left.mdb_node.right;
                left.mdb_node.right = node;
                if (@ptrToInt(node) < lib.config.kernel_higher_half_address) {
                    @panic("mapping_database: skew");
                }
                update_end(node);
                update_end(left);

                if (mapping_database_root == node) {
                    set_root(left);
                }

                return left;
            }
        }
    }

    return maybe_node;
}

fn split(maybe_node: ?*CTE) ?*CTE {
    if (maybe_node) |node| {
        if (node.mdb_node.right) |right| {
            if (right.mdb_node.right) |right_right| {
                if (node.mdb_node.level == right_right.mdb_node.level) {
                    node.mdb_node.right = right.mdb_node.left;
                    right.mdb_node.left = node;
                    right.mdb_node.level += 1;
                    update_end(node);
                    update_end(right);

                    if (mapping_database_root == node) {
                        set_root(right);
                    }

                    return right;
                }
            }
        }
    }

    return maybe_node;
}

fn set_root(new_root: *CTE) void {
    mapping_database_root = new_root;
    core_supervisor.mdb_root = VirtualAddress(.local).new(@ptrToInt(new_root));
}
