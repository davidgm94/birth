const common = @import("common");
const assert = common.assert;
const log = common.log.scoped(.RoundRobin);
const privileged = @import("privileged");
const CoreDirectorData = privileged.CoreDirectorData;
const CoreSupervisorData = privileged.CoreSupervisorData;
const rise = @import("rise");

extern var current_core_supervisor_data: *CoreSupervisorData;
pub fn make_runnable(core_director_data: *CoreDirectorData) void {
    if (core_director_data.previous == null or core_director_data.next == null) {
        assert(core_director_data.previous == null and core_director_data.next == null);

        if (current_core_supervisor_data.scheduler_state.current == null) {
            current_core_supervisor_data.scheduler_state.current = core_director_data;
            core_director_data.next = core_director_data;
        }

        core_director_data.previous = current_core_supervisor_data.scheduler_state.current;
        core_director_data.next = current_core_supervisor_data.scheduler_state.current.?.next;
        current_core_supervisor_data.scheduler_state.current.?.next.?.previous = core_director_data;
        current_core_supervisor_data.scheduler_state.current.?.next = core_director_data;
    }
}

pub const State = extern struct {
    current: ?*CoreDirectorData,
};
