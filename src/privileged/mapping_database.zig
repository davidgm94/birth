const privileged = @import("privileged");
const CoreSupervisor = privileged.CoreSupervisor;
const CTE = privileged.CTE;

pub var core_supervisor: *CoreSupervisor = undefined;
pub var mapping_database_root: *CTE = undefined;
const Error = error{
    invalid_core_supervisor,
};
pub fn init(given_core_supervisor: *CoreSupervisor) !void {
    core_supervisor = given_core_supervisor;
    if (!core_supervisor.is_valid) {
        // Empty core supervisor
        return;
    }

    @panic("mdb init");
}
