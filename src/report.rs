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

use sev::{
    firmware::guest::{AttestationReport, Firmware},
    parser::{ByteParser, Encoder},
};

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

    /// Provide file with data for attestation-report request. If provided
    /// with random flag, then the random data will be written in the
    /// provided path.
    #[arg(value_name = "request-file", required = true)]
    pub request_file: PathBuf,

    /// Use random data for attestation report request and write it to the request file.
    #[arg(short, long, default_value_t = false)]
    pub random: bool,

    /// Specify an integer VMPL level between 0 and 3 that the Guest is running on.
    #[arg(short, long, default_value = "1", value_name = "vmpl")]
    pub vmpl: Option<u32>,

    /// Request attestation report on vTPM-based Azure Confidential VM.
    #[arg(short, long)]
    pub azure_cvm: bool,
}

fn request_hardware_report(
    data: [u8; 64],
    vmpl: Option<u32>,
    _azure_cvm: bool,
) -> Result<AttestationReport> {
    #[cfg(feature = "hyperv")]
    if _azure_cvm {
        if vmpl.unwrap_or(0) > 0 {
            eprintln!("Warning: --vmpl argument was ignored because attestation report is requested by the paravisor at VMPL 0.");
        }
        return hyperv::report::get(data);
    }

    let mut fw = Firmware::open().context("unable to open /dev/sev-guest")?;
    Ok(AttestationReport::from_bytes(
        fw.get_report(None, Some(data), vmpl)
            .context("unable to get attestation report")?
            .as_slice(),
    )?)
}

// Request attestation report and write it into a file
pub fn get_report(args: ReportArgs, azcvm_present: bool) -> Result<()> {
    if args.azure_cvm && !azcvm_present {
        #[cfg(feature = "hyperv")]
        let msg =
            "--azure-cvm enabled yet Hyper-V guest with SEV-SNP isolation not detected (not allowed).";
        #[cfg(not(feature = "hyperv"))]
        let msg =
            "--azure-cvm requires a binary built with --features hyperv. Please rebuild with --features hyperv.";
        return Err(anyhow!(msg));
    }

    let data: [u8; 64] = if args.random {
        create_random_request()
    } else {
        /*
         * Read from the request file.
         */
        let mut bytes = [0u8; 64];
        let mut file = File::open(&args.request_file)?;
        file.read_exact(&mut bytes)
            .context("unable to read 64 bytes from REQUEST_FILE")?;

        bytes
    };

    let report = request_hardware_report(data, args.vmpl, args.azure_cvm)?;

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
        reqdata_write(args.request_file, &data)
            .context("unable to write random request data to specified file")?;
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
