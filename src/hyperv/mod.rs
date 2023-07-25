// SPDX-License-Identifier: Apache-2.0

use std::arch::x86_64::__cpuid;

const CPUID_HYPERV_SIG: &str = "Microsoft Hv";
const CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS: u32 = 0x40000000;
const CPUID_HYPERV_FEATURES: u32 = 0x40000003;
const CPUID_HYPERV_MIN: u32 = 0x40000005;
const CPUID_HYPERV_MAX: u32 = 0x4000ffff;
const CPUID_HYPERV_ISOLATION: u32 = 1 << 22;
const CPUID_HYPERV_CPU_MANAGEMENT: u32 = 1 << 12;
const CPUID_HYPERV_ISOLATION_CONFIG: u32 = 0x4000000C;
const CPUID_HYPERV_ISOLATION_TYPE_MASK: u32 = 0xf;
const CPUID_HYPERV_ISOLATION_TYPE_SNP: u32 = 2;

pub fn present() -> bool {
    let cpuid = unsafe { __cpuid(CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS) };
    if cpuid.eax < CPUID_HYPERV_MIN || cpuid.eax > CPUID_HYPERV_MAX {
        return false;
    }

    let mut sig: Vec<u8> = vec![];
    sig.append(&mut cpuid.ebx.to_le_bytes().to_vec());
    sig.append(&mut cpuid.ecx.to_le_bytes().to_vec());
    sig.append(&mut cpuid.edx.to_le_bytes().to_vec());

    if sig != CPUID_HYPERV_SIG.as_bytes() {
        return false;
    }

    let cpuid = unsafe { __cpuid(CPUID_HYPERV_FEATURES) };

    let isolated: bool = (cpuid.ebx & CPUID_HYPERV_ISOLATION) != 0;
    let managed: bool = (cpuid.ebx & CPUID_HYPERV_CPU_MANAGEMENT) != 0;

    if !isolated || managed {
        return false;
    }

    let cpuid = unsafe { __cpuid(CPUID_HYPERV_ISOLATION_CONFIG) };
    let mask = cpuid.ebx & CPUID_HYPERV_ISOLATION_TYPE_MASK;
    let snp = CPUID_HYPERV_ISOLATION_TYPE_SNP;

    if mask != snp {
        return false;
    }

    true
}
