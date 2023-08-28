// SPDX-License-Identifier: Apache-2.0

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
    let attestation_file = fs::File::open(att_report_path)?;

    let attestation_report = bincode::deserialize_from(attestation_file)
        .context("Could not parse attestation report.")?;

    Ok(attestation_report)
}

// Create 64 random bytes of data for attestation report request
pub fn create_random_request() -> [u8; 64] {
    let mut data = [0u8; 64];
    thread_rng().fill_bytes(&mut data);
    data
}

#[derive(StructOpt)]
pub struct ReportArgs {
    #[structopt(help = "File to write the attestation report to.")]
    pub att_report_path: PathBuf,

    #[structopt(
        long = "random",
        short,
        help = "Use random data for attestation report request. Writes data to ./random-request-file.txt by default, use --request to specify where to write data."
    )]
    pub random: bool,

    #[structopt(
        long = "vmpl",
        short,
        help = "Specify VMPL level the Guest is running on. Defaults to 1."
    )]
    pub vmpl: Option<u32>,

    #[structopt(
        help = "Provide file with data for attestation-report request. If provided with random flag, then the random data will be written in the provided path."
    )]
    pub request_file: PathBuf,

    #[structopt(
        long,
        short,
        help = "Expect that the 64-byte report data will already be provided by the platform provider."
    )]
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
    let mut fw = Firmware::open().context("unable to open /dev/sev")?;
    fw.get_report(None, data, vmpl)
        .context("unable to fetch attestation report")
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

    write!(&mut file, "{}", report).context(format!(
        "unable to write attestation report to {}",
        args.att_report_path.display()
    ))?;

    /*
     * Write reports report data (only for --random or --platform).
     */
    if args.random {
        reqdata_write(args.request_file, &report).context("unable to write random request data")?;
    } else if args.platform {
        reqdata_write(args.request_file, &report)
            .context("unable to write platform request data")?;
    }

    Ok(())
}

fn reqdata_write(name: PathBuf, report: &AttestationReport) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(name)
        .context("unable to create or write to request data file")?;

    write_hex(&mut file, &report.report_data).context("unable to write report data to REQUEST_FILE")
}

pub fn write_hex(file: &mut File, data: &[u8]) -> Result<()> {
    let mut line_counter = 0;
    for val in data {
        // Make it blocks for easier read
        if line_counter.eq(&16) {
            writeln!(file)?;
            line_counter = 0;
        }

        write!(file, "{:02x}", val)?;
        line_counter += 1;
    }
    Ok(())
}
