const CPUID = @This();

eax: u32,
ebx: u32,
edx: u32,
ecx: u32,

/// Returns the maximum number bits a physical address is allowed to have in this CPU
pub inline fn get_max_physical_address_bit() u6 {
    return @truncate(u6, cpuid(0x80000008).eax);
}

pub inline fn cpuid(leaf: u32) CPUID {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var edx: u32 = undefined;
    var ecx: u32 = undefined;

    asm volatile (
        \\cpuid
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [edx] "={edx}" (edx),
          [ecx] "={ecx}" (ecx),
        : [leaf] "{eax}" (leaf),
    );

    return CPUID{
        .eax = eax,
        .ebx = ebx,
        .edx = edx,
        .ecx = ecx,
    };
}
