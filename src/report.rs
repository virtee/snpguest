// SPDX-License-Identifier: Apache-2.0

//! Requests attestation reports from AMD-SP or vTPM.
//!
//! This module provides the `report` subcommand which requests attestation
//! reports from the AMD Secure Processor (via `/dev/sev-guest`) or from the
//! vTPM (on Azure CVMs with the `hyperv` feature).
//!
//! The report request can include:
//!
//! - User-provided 64-byte request data read from a file
//! - Randomly generated 64-byte request data (`--random`)
//! - Platform-provided request data from the vTPM (`--platform`, Azure CVMs only)
//!
//! ## `report`
//!
//! ```sh
//! snpguest report $ATT_REPORT_PATH $REQUEST_FILE [OPTIONS]
//! ```
//!
//! Requests an attestation report from the AMD Secure Processor (ASP), and writes
//! it as raw binary.
//! This command is a wrapper of the `SNP_GUEST_REQUEST(MSG_REPORT_REQ)` ioctl.
//!
//! ### Arguments and Options
//!
//! | Argument/Option | Description | Default |
//! | :--      | :--        | :--    |
//! | `$ATT_REPORT_PATH` | The path where the attestation report would be stored. | *required* |
//! | `$REQUEST_FILE` | The path to the 64-byte request file. | *required* |
//! | `-v, --vmpl $VMPL` | The VMPL value to put in the attestation report (0-3). Must be greater than or equal to the current VMPL. | 1 |
//! | `-r, --random` | Generate 64 random bytes of data for the report request. | - |
//! | `-p, --platform` | Get an attestation report from the vTPM NV index (Only available for Azure CVMs). | - |
//!
//! Without `-p, --platform` or `-r, --random`, the user can pass 64 bytes of
//! data in any file format into `$REQUEST_FILE` to request an attestation report.
//! The request file is interpreted as raw binary, and the first 64 bytes of the
//! binary are sent to the AMD-SP as the request data. The request data will be
//! bound to the REPORT_DATA field in the attestation report.
//!
//! With the `-r, --random` flag, this command generates a random data for the
//! request, which will be written into `$REQUEST_FILE`.
//!
//! The `-v, --vmpl` option specifies the Virtual Machine Privilege Level (VMPL)
//! to request an attestation report (0 to 3). The default value is 1. This
//! value must be greater than or equal to the current VMPL. Specifying a
//! privilege level higher than the actual level (smaller VMPL value) will result
//! in a firmware error.
//!
//! With the `-p, --platform` flag, this command retrieves an attestation report
//! from vTPM NV index `0x01400001` instead of the ASP, and writes the Report
//! Data field in the retrieved report into `$REQUEST_FILE`. This attestation
//! route is available (and mandatory) on Microsoft Azure Confidential VMs with
//! SEV-SNP isolation. This flag requires the `hyperv` feature. Currently, only
//! the pre-generated attestation report can be retrieved. To request a (fresh)
//! report with the user-provided request data, use any TPM2 tool to write the
//! request data to vTPM NV index `0x01400002`, then execute this command.
//!
//! ### Example
//!
//! ```bash
//! # Request attestation report with user-provided data
//! snpguest report report.bin request-file.bin
//!
//! # Request attestation report with randomly generated data
//! snpguest report report.bin request-file.bin --random
//!
//! # Get attestation report and request data from vTPM
//! snpguest report report.bin request-file.bin --platform
//! ```
//!

use super::*;

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
};

use anyhow::{anyhow, Result};
use rand::{thread_rng, RngCore};

use sev::{
    firmware::guest::{AttestationReport, Firmware},
    parser::{ByteParser, Encoder},
};

/// Read and parse a binary-formatted attestation report from a file.
pub fn read_report(att_report_path: PathBuf) -> Result<AttestationReport, anyhow::Error> {
    let mut attestation_file = fs::File::open(att_report_path)?;

    let mut report_bytes = Vec::new();
    attestation_file
        .read_to_end(&mut report_bytes)
        .context("Failed to read the report bytes.")?;

    let attestation_report = AttestationReport::from_bytes(&report_bytes)
        .context("Failed to build report from the raw bytes. Report could be malformed.")?;

    Ok(attestation_report)
}

/// Create 64 random bytes of data for an attestation report request.
pub fn create_random_request() -> [u8; 64] {
    let mut data = [0u8; 64];
    thread_rng().fill_bytes(&mut data);
    data
}

/// CLI arguments for the `report` subcommand.
///
/// Requests an attestation report from the AMD Secure Processor and writes
/// it to `att_report_path` as raw binary.
#[derive(Parser)]
pub struct ReportArgs {
    /// Path where the attestation report will be stored.
    #[arg(value_name = "att-report-path", required = true)]
    pub att_report_path: PathBuf,

    /// Generate 64 random bytes of data for the report request. The random
    /// data will be written to the path specified by `request-file`.
    #[arg(short, long, default_value_t = false, conflicts_with = "platform")]
    pub random: bool,

    /// VMPL (Virtual Machine Privilege Level) value for the report (0-3).
    /// Must be greater than or equal to the current VMPL. Default is 1.
    #[arg(short, long, default_value = "1", value_name = "vmpl")]
    pub vmpl: Option<u32>,

    /// Path to the 64-byte request data file. Without `--random` or
    /// `--platform`, the first 64 bytes of this file are sent as the
    /// request data. With `--random`, the generated data is written here.
    /// With `--platform`, the report data from the vTPM is written here.
    #[arg(value_name = "request-file", required = true)]
    pub request_file: PathBuf,

    /// Retrieve the attestation report from the vTPM NV index instead of the
    /// AMD Secure Processor. Only available on Azure CVMs with SEV-SNP
    /// isolation (requires the `hyperv` feature).
    #[arg(short, long, conflicts_with = "random")]
    pub platform: bool,
}

impl ReportArgs {
    /// Validate argument combinations (e.g., `--random` and `--platform` are mutually exclusive,
    /// `--platform` requires Hyper-V with SEV-SNP isolation).
    pub fn verify(&self, hyperv: bool) -> Result<()> {
        if self.random && self.platform {
            return Err(anyhow!(
                "--random and --platform both enabled (not allowed). Consult man page."
            ));
        }

        if self.platform && !hyperv {
            #[cfg(feature = "hyperv")]
            let msg = "--platform enabled yet Hyper-V guest with SEV-SNP isolation not detected (not allowed). Consult man page.";
            #[cfg(not(feature = "hyperv"))]
            let msg =
                "--platform requires a binary built with --features hyperv. Consult man page.";

            return Err(anyhow!(msg));
        }

        Ok(())
    }
}

fn request_hardware_report(
    data: Option<[u8; 64]>,
    vmpl: Option<u32>,
    _platform: bool,
) -> Result<AttestationReport> {
    #[cfg(feature = "hyperv")]
    if _platform {
        return hyperv::report::get(vmpl.unwrap_or(0));
    }

    let mut fw = Firmware::open().context("unable to open /dev/sev-guest")?;
    Ok(AttestationReport::from_bytes(
        fw.get_report(None, data, vmpl)
            .context("unable to fetch attestation report")?
            .as_slice(),
    )?)
}

/// Request an attestation report and write it to a file.
///
/// Depending on the flags, request data is either read from `request_file`,
/// generated randomly (`--random`), or retrieved from the vTPM (`--platform`).
/// The resulting attestation report is serialized and written to `att_report_path`.
pub fn get_report(args: ReportArgs, hv: bool) -> Result<()> {
    args.verify(hv)?;

    let data: Option<[u8; 64]> = if args.random {
        Some(create_random_request())
    } else if args.platform {
        None
    } else {
        /*
         * Read from the request file.
         */
        let mut bytes = [0u8; 64];
        let mut file = File::open(&args.request_file)?;
        file.read_exact(&mut bytes)
            .context("unable to read 64 bytes from REQUEST_FILE")?;

        Some(bytes)
    };

    let report = request_hardware_report(data, args.vmpl, args.platform)?;

    /*
     * Serialize and write attestation report.
     */
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&args.att_report_path)?;

    report.encode(&mut file, ())?;

    /*
     * Write reports report data (only for --random or --platform).
     */
    if args.random {
        if let Some(data) = data {
            reqdata_write(args.request_file, &data)
                .context("unable to write random request data to specified file")?;
        } else {
            return Err(anyhow!("unable to write empty buffer to specified file."));
        }
    } else if args.platform {
        // Because random data cannot be provided for platform, we will pull the
        // data provided by the vTPM from the report.
        reqdata_write(args.request_file, &report.report_data)
            .context("unable to write platform request data")?;
    }

    Ok(())
}

fn reqdata_write(name: PathBuf, report_data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(name)
        .context("unable to create or write to request data file")?;

    file.write_all(report_data)
        .context("unable to write report data to REQUEST_FILE")
}
