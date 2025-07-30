// SPDX-License-Identifier: Apache-2.0
// This file contains code related to Hyper-V integration (Hypervisor). It provides a flag (`hyperv::present`) indicating whether the SNP Guest is running within a Hyper-V guest environment.

use super::*;

use std::arch::x86_64::__cpuid;
use std::mem::size_of;

const CPUID_GET_HIGHEST_FUNCTION: u32 = 0x80000000;
const CPUID_PROCESSOR_INFO_AND_FEATURE_BITS: u32 = 0x1;

const CPUID_FEATURE_HYPERVISOR: u32 = 1 << 31;

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

const RSV1_SIZE: usize = size_of::<u32>() * 8;
const REPORT_SIZE: usize = 1184;
const RSV2_SIZE: usize = size_of::<u32>() * 5;
const TOTAL_SIZE: usize = RSV1_SIZE + REPORT_SIZE + RSV2_SIZE;
const REPORT_RANGE: std::ops::Range<usize> = RSV1_SIZE..(RSV1_SIZE + REPORT_SIZE);

pub fn present() -> bool {
    let mut cpuid = unsafe { __cpuid(CPUID_PROCESSOR_INFO_AND_FEATURE_BITS) };
    if (cpuid.ecx & CPUID_FEATURE_HYPERVISOR) == 0 {
        return false;
    }

    cpuid = unsafe { __cpuid(CPUID_GET_HIGHEST_FUNCTION) };
    if cpuid.eax < CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS {
        return false;
    }

    cpuid = unsafe { __cpuid(CPUID_HYPERV_VENDOR_AND_MAX_FUNCTIONS) };
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

    cpuid = unsafe { __cpuid(CPUID_HYPERV_FEATURES) };

    let isolated: bool = (cpuid.ebx & CPUID_HYPERV_ISOLATION) != 0;
    let managed: bool = (cpuid.ebx & CPUID_HYPERV_CPU_MANAGEMENT) != 0;

    if !isolated || managed {
        return false;
    }

    cpuid = unsafe { __cpuid(CPUID_HYPERV_ISOLATION_CONFIG) };
    let mask = cpuid.ebx & CPUID_HYPERV_ISOLATION_TYPE_MASK;
    let snp = CPUID_HYPERV_ISOLATION_TYPE_SNP;

    if mask != snp {
        return false;
    }

    true
}

pub mod report {
    use super::*;

    use anyhow::{anyhow, Context};
    use serde::{Deserialize, Serialize};
    use sev::firmware::guest::AttestationReport;
    use tss_esapi::{
        abstraction::nv,
        handles::NvIndexTpmHandle,
        interface_types::{resource_handles::NvAuth, session_handles::AuthSession},
        tcti_ldr::{DeviceConfig, TctiNameConf},
    };

    const VTPM_HCL_REPORT_NV_INDEX: u32 = 0x01400001;

    #[repr(C)]
    #[derive(Deserialize, Serialize, Debug, Clone, Copy)]
    struct Hcl {
        rsv1: [u32; 8],
        report: AttestationReport,
        rsv2: [u32; 5],
    }

    pub fn get(vmpl: u32) -> Result<AttestationReport> {
        if vmpl > 0 {
            eprintln!("Warning: --vmpl argument was ignored because attestation report is pre-fetched at VMPL 0 and stored in vTPM.");
        }
        let bytes = tpm2_read().context("unable to read attestation report bytes from vTPM")?;

        hcl_report(&bytes)
    }

    fn tpm2_read() -> Result<Vec<u8>> {
        let handle = NvIndexTpmHandle::new(VTPM_HCL_REPORT_NV_INDEX)
            .context("unable to initialize TPM handle")?;
        let mut ctx = tss_esapi::Context::new(TctiNameConf::Device(DeviceConfig::default()))?;
        ctx.set_sessions((Some(AuthSession::Password), None, None));

        nv::read_full(&mut ctx, NvAuth::Owner, handle)
            .context("unable to read non-volatile vTPM data")
    }

    fn hcl_report(bytes: &[u8]) -> Result<AttestationReport> {
        if bytes.len() < TOTAL_SIZE {
            return Err(anyhow!(
                "HCL report size mismatch: expected at least {}, got {}",
                TOTAL_SIZE,
                bytes.len()
            ));
        }

        let report_bytes = &bytes[REPORT_RANGE];

        AttestationReport::from_bytes(report_bytes)
            .context("Unable to convert HCL report bytes to AttestationReport")
    }
}
