// SPDX-License-Identifier: Apache-2.0

use super::*;

use std::{
    fs,
    fs::File,
    io::{BufWriter, Read, Write},
    path::PathBuf,
    str::FromStr,
};

use certs::write_cert;
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
    return data;
}

// Write data into given file. Split it into 16 byte lines.
pub fn write_hex<W: Write>(file: &mut BufWriter<W>, data: &[u8]) -> Result<()> {
    let mut line_counter = 0;
    for val in data {
        // Make it blocks for easier read
        if line_counter.eq(&16) {
            write!(file, "\n").context("Failed to write data to file")?;
            line_counter = 0;
        }
        // Write byte into file
        write!(file, "{:02x}", val).context("Failed to write data to file")?;
        line_counter += 1;
    }
    Ok(())
}

// Request an attestation report with default vmpl and random data
pub fn request_default_report() -> Result<AttestationReport, anyhow::Error> {
    let mut sev_fw: Firmware = Firmware::open().context("failed to open SEV firmware device.")?;

    let request_buf = create_random_request();

    let att_report = sev_fw
        .get_report(None, Some(request_buf), None)
        .context("Failed to get report.")?;

    Ok(att_report)
}

#[derive(StructOpt)]
pub struct ReportArgs {
    #[structopt(
        long,
        short,
        requires = "certs-dir",
        help = "Request an extended report instead of the regular report."
    )]
    pub extended_report: bool,

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
        long = "request-data",
        short = "d",
        help = "Provide file with data for attestation-report request. If provided with random flag, then the random data will be written in the provided path."
    )]
    pub request_file: Option<PathBuf>,

    #[structopt(
        long = "att-report",
        short,
        help = "File to write the attestation report to. Defaults to ./attestation_report.bin"
    )]
    pub att_report_path: Option<PathBuf>,

    #[structopt(
        help = "Directory to store certificates in. Required if requesting an extended-report."
    )]
    pub certs_dir: Option<PathBuf>,
}

// Request attestation report and write it into a file
pub fn get_report(args: ReportArgs) -> Result<()> {
    let mut sev_fw: Firmware = Firmware::open().context("failed to open SEV firmware device.")?;

    // Read request data from file, or generate random data for request
    let request_data = match args.request_file {
        Some(path) => {
            // Generate random request data and place in specified path
            let request_data = if args.random {
                let request_buf = create_random_request();

                // Overwrite data if file already exists
                let request_file = if path.exists() {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .open(path)
                        .context("Unable to overwrite request file contents")?
                } else {
                    fs::File::create(path).context("Unable to create request file.")?
                };
                write_hex(&mut BufWriter::new(request_file), &request_buf)
                    .context("Failed to write request data in request file")?;
                request_buf

            // Read contents from provided file
            } else {
                let mut request_file =
                    File::open(path).context("Could not open the report request file.")?;
                let mut request_buf: [u8; 64] = [0; 64];
                request_file
                    .read(&mut request_buf)
                    .context("Could not read report request file.")?;
                request_buf
            };

            request_data
        }

        // No request path was provided
        None => {
            // Generate random data and write it to default directory
            let request_data = if args.random {
                let request_buf = create_random_request();

                // Overwrite data if file already exists
                let request_file = if PathBuf::from("./random-request-file.txt").exists() {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .truncate(true)
                        .open("./random-request-file.txt")
                        .context("Unable to overwrite request file contents")?
                } else {
                    fs::File::create("./random-request-file.txt")
                        .context("Unable to create request file contents")?
                };

                write_hex(&mut BufWriter::new(request_file), &request_buf)
                    .context("Failed to write request data in request file")?;

                request_buf
            } else {
                return Err(anyhow::anyhow!("Please provide a request-file or use --random flag to create one in order request attestation report."));
            };

            request_data
        }
    };

    // Create attestation report path
    let att_report_path = match args.att_report_path {
        Some(path) => path,
        None => PathBuf::from_str("./attestation_report.bin")
            .context("unable to create default path")?,
    };

    // Get attestation report from either regular or extended report
    let att_report = if !args.extended_report {
        // Request regular report
        sev_fw
            .get_report(None, Some(request_data), args.vmpl)
            .context("Failed to get report.")?

    // Extended report requested
    } else {
        // Request extended attestation report
        let (att_report, certificates) = sev_fw
            .get_ext_report(None, Some(request_data), args.vmpl)
            .context("Failed to get extended report.")?;

        if certificates.is_empty() {
            return Err(anyhow::anyhow!(
                "The certificate chain is empty! Certificates probably not loaded by the host."
            ));
        }

        // Generate path from provided certs path
        let certs_path = match args.certs_dir {
            Some(path) => path,
            None => return Err(anyhow::anyhow!("No cert directory provided.")),
        };

        // Create certificate directory if missing
        if !certs_path.exists() {
            fs::create_dir(certs_path.clone()).context("Could not create certs folder")?;
        };

        // Write certs into directory
        for cert in certificates.iter() {
            let path = certs_path.clone();

            write_cert(path, &cert.cert_type, &cert.data)?;
        }

        att_report
    };

    // Write attestation report into desired file
    let mut attestation_file = if att_report_path.exists() {
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(att_report_path)
            .context("Unable to overwrite attestation report file contents")?
    } else {
        fs::File::create(att_report_path)
            .context("Unable to create attestation report file contents")?
    };
    bincode::serialize_into(&mut attestation_file, &att_report)
        .context("Could not serialize attestation report into file.")?;

    Ok(())
}
