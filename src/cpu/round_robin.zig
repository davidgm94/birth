const lib = @import("lib");
const assert = lib.assert;
const log = lib.log.scoped(.RoundRobin);
const cpu = @import("cpu");
const CoreDirectorData = cpu.CoreDirectorData;
const CoreSupervisorData = cpu.CoreSupervisorData;

pub fn make_runnable(core_director_data: *CoreDirectorData) void {
    if (core_director_data.previous == null or core_director_data.next == null) {
        assert(core_director_data.previous == null and core_director_data.next == null);

        if (cpu.current_supervisor.?.scheduler_state.current == null) {
            cpu.current_supervisor.?.scheduler_state.current = core_director_data;
            core_director_data.next = core_director_data;
        }

        core_director_data.previous = cpu.current_supervisor.?.scheduler_state.current;
        core_director_data.next = cpu.current_supervisor.?.scheduler_state.current.?.next;
        cpu.current_supervisor.?.scheduler_state.current.?.next.?.previous = core_director_data;
        cpu.current_supervisor.?.scheduler_state.current.?.next = core_director_data;
    }
}

pub const State = extern struct {
    current: ?*CoreDirectorData,
};
