const lib = @import("lib");
const assert = lib.assert;
const rise = @import("rise");

// TODO: ref
pub fn frameCreate(ref: usize, bytes: usize) !usize {
    return mappableCapabilityCreate(ref, .cpu_memory, bytes);
}

fn mappableCapabilityCreate(ref: usize, mappable_capability: rise.capabilities.Type.Mappable, bytes: usize) !usize {
    _ = mappable_capability;
    _ = ref;
    assert(bytes > 0);
}

fn ramDescendantCreate(ref: usize, ) !usize {
    _ = ref;
}
