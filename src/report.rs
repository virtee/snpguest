// SPDX-License-Identifier: Apache-2.0
// This file defines the CLI for requesting attestation reports. It contains functions for requesting attestation reports and saving them to files. Additionally, it includes code for reading and parsing attestation reports.

use super::*;

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
};

use anyhow::{anyhow, Result};
use rand::{thread_rng, RngCore};
use sev::firmware::guest::{AttestationReport, Firmware};

// Read a bin-formatted attestation report.
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

// Create 64 random bytes of data for attestation report request
pub fn create_random_request() -> [u8; 64] {
    let mut data = [0u8; 64];
    thread_rng().fill_bytes(&mut data);
    data
}

/// Report command to request an attestation report.
#[derive(Parser)]
pub struct ReportArgs {
    /// File to write the attestation report to.
    #[arg(value_name = "att-report-path", required = true)]
    pub att_report_path: PathBuf,

    /// Use random data for attestation report request. Writes data
    /// to ./random-request-file.txt by default, use --request to specify
    /// where to write data.
    #[arg(short, long, default_value_t = false, conflicts_with = "platform")]
    pub random: bool,

    /// Specify an integer VMPL level between 0 and 3 that the Guest is running on.
    #[arg(short, long, default_value = "1", value_name = "vmpl")]
    pub vmpl: Option<u32>,

    /// Provide file with data for attestation-report request. If provided
    /// with random flag, then the random data will be written in the
    /// provided path.
    #[arg(value_name = "request-file", required = true)]
    pub request_file: PathBuf,

    /// Expect that the 64-byte report data will already be provided by the platform provider.
    #[arg(short, long, conflicts_with = "random")]
    pub platform: bool,
}

impl ReportArgs {
    pub fn verify(&self, hyperv: bool) -> Result<()> {
        if self.random && self.platform {
            return Err(anyhow!(
                "--random and --platform both enabled (not allowed). Consult man page."
            ));
        }

        if self.random && hyperv {
            return Err(anyhow!(
                "--random enabled yet Hyper-V guest detected (not allowed). Consult man page."
            ));
        }

        if self.platform && !hyperv {
            return Err(anyhow!("--platform enabled yet Hyper-V guest not detected (not allowed). Consult man page."));
        }

        Ok(())
    }
}

#[cfg(feature = "hyperv")]
fn request_hardware_report(
    _data: Option<[u8; 64]>,
    vmpl: Option<u32>,
) -> Result<AttestationReport> {
    hyperv::report::get(vmpl.unwrap_or(0))
}

#[cfg(not(feature = "hyperv"))]
fn request_hardware_report(data: Option<[u8; 64]>, vmpl: Option<u32>) -> Result<AttestationReport> {
    let mut fw = Firmware::open().context("unable to open /dev/sev-guest")?;
    Ok(AttestationReport::from_bytes(
        fw.get_report(None, data, vmpl)
            .context("unable to fetch attestation report")?
            .as_slice(),
    )?)
}

// Request attestation report and write it into a file
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

    let report = request_hardware_report(data, args.vmpl)?;

    /*
     * Serialize and write attestation report.
     */
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&args.att_report_path)?;

    report.write_bytes(&mut file)?;

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
        reqdata_write(args.request_file, &*report.report_data)
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
