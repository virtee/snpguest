// SPDX-License-Identifier: Apache-2.0
// This file contains code for requesting attestation reports from vTPMs on Azure Confidential VMs.

use super::tpm;
use anyhow::{anyhow, Context, Result};
use sev::{firmware::guest::AttestationReport, parser::ByteParser};
use tss_esapi::{
    abstraction::nv,
    handles::NvIndexTpmHandle,
    interface_types::{resource_handles::NvAuth, session_handles::AuthSession},
    tcti_ldr::{DeviceConfig, TctiNameConf},
};

const VTPM_HCL_REPORT_NV_INDEX: u32 = 0x01400001;
const VTPM_USER_DATA_NV_INDEX: u32 = 0x01400002;
const VTPM_USER_DATA_SIZE: usize = 64;

const HCL_REPORT_HEADER_SIZE: usize = 32;
const HW_REPORT_SIZE: usize = 1184;
const REPORT_RANGE: std::ops::Range<usize> =
    HCL_REPORT_HEADER_SIZE..(HCL_REPORT_HEADER_SIZE + HW_REPORT_SIZE);

pub fn get(data: [u8; VTPM_USER_DATA_SIZE]) -> Result<AttestationReport> {
    write_user_data_to_vtpm(data).context("unable to write user data to vTPM")?;
    let hcl_report_bytes =
        read_hcl_report_from_vtpm().context("unable to read attestation report bytes from vTPM")?;
    if hcl_report_bytes.len() < HCL_REPORT_HEADER_SIZE + HW_REPORT_SIZE {
        return Err(anyhow!(
            "HCL report size mismatch: expected at least {}, got {}",
            HCL_REPORT_HEADER_SIZE + HW_REPORT_SIZE,
            hcl_report_bytes.len()
        ));
    }
    let hw_report_bytes = &hcl_report_bytes[REPORT_RANGE];
    AttestationReport::from_bytes(hw_report_bytes)
        .context("unable to convert HCL report bytes to AttestationReport")
}

fn read_hcl_report_from_vtpm() -> Result<Vec<u8>> {
    let handle = NvIndexTpmHandle::new(VTPM_HCL_REPORT_NV_INDEX)
        .context("unable to initialize TPM handle")?;
    let mut ctx = tss_esapi::Context::new(TctiNameConf::Device(DeviceConfig::default()))?;
    ctx.set_sessions((Some(AuthSession::Password), None, None));

    nv::read_full(&mut ctx, NvAuth::Owner, handle).context("unable to read non-volatile vTPM data")
}

fn write_user_data_to_vtpm(data: [u8; VTPM_USER_DATA_SIZE]) -> Result<()> {
    let mut ctx = tss_esapi::Context::new(TctiNameConf::Device(DeviceConfig::default()))?;
    ctx.set_sessions((Some(AuthSession::Password), None, None));

    let handle = NvIndexTpmHandle::new(VTPM_USER_DATA_NV_INDEX)
        .context("unable to initialize TPM handle")?;

    let result = tpm::find_nv_index(&mut ctx, handle)?;

    if let Some((public, _)) = result {
        if public.data_size() != VTPM_USER_DATA_SIZE {
            tpm::nv_undefine(&mut ctx, handle)?;
            tpm::nv_define(&mut ctx, handle, VTPM_USER_DATA_SIZE)?;
        }
    } else {
        tpm::nv_define(&mut ctx, handle, VTPM_USER_DATA_SIZE)?;
    }

    tpm::nv_write(&mut ctx, handle, &data).context("unable to write data to NV index")?;

    Ok(())
}
