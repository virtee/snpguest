// SPDX-License-Identifier: Apache-2.0

use super::*;

use std::{
    fs,
    fs::File,
    io::{BufWriter, Read, Write},
    path::PathBuf,
};

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

// Write data into given file. Split it into 16 byte lines.
pub fn write_hex<W: Write>(file: &mut BufWriter<W>, data: &[u8]) -> Result<()> {
    let mut line_counter = 0;
    for val in data {
        // Make it blocks for easier read
        if line_counter.eq(&16) {
            writeln!(file).context("Failed to write data to file")?;
            line_counter = 0;
        }
        // Write byte into file
        write!(file, "{:02x}", val).context("Failed to write data to file")?;
        line_counter += 1;
    }
    Ok(())
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
}

// Request attestation report and write it into a file
pub fn get_report(args: ReportArgs) -> Result<()> {
    let mut sev_fw: Firmware = Firmware::open().context("failed to open SEV firmware device.")?;

    let request_data = match args.random {
        true => {
            let request_buf = create_random_request();

            // Overwrite data if file already exists
            let request_file = if args.request_file.exists() {
                std::fs::OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(args.request_file)
                    .context("Unable to overwrite request file contents")?
            } else {
                fs::File::create(args.request_file).context("Unable to create request file.")?
            };
            write_hex(&mut BufWriter::new(request_file), &request_buf)
                .context("Failed to write request data in request file")?;
            request_buf
        }
        false => {
            let mut request_file =
                File::open(args.request_file).context("Could not open the report request file.")?;
            let mut request_buf: [u8; 64] = [0; 64];
            request_file
                .read(&mut request_buf)
                .context("Could not read report request file.")?;
            request_buf
        }
    };

    // Get attestation report
    let att_report = sev_fw
        .get_report(None, Some(request_data), args.vmpl)
        .context("Failed to get report.")?;

    // Write attestation report into desired file
    let mut attestation_file = if args.att_report_path.exists() {
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(args.att_report_path)
            .context("Unable to overwrite attestation report file contents")?
    } else {
        fs::File::create(args.att_report_path)
            .context("Unable to create attestation report file contents")?
    };
    bincode::serialize_into(&mut attestation_file, &att_report)
        .context("Could not serialize attestation report into file.")?;

    Ok(())
}
