use super::*;

use certs::{identify_cert, CertFormat};
use rand::{thread_rng, RngCore};
use sev::firmware::{
    guest::{AttestationReport, Firmware},
    host::CertType,
};
use std::{
    fs,
    fs::File,
    io::{BufWriter, Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

// Function used to read contents of an attestation report file. Returns AttestationReport. (Has to be in bin format)
pub fn read_report(att_report_path: PathBuf) -> Result<AttestationReport, anyhow::Error> {
    // Open file from specified path
    let attestation_file = fs::File::open(att_report_path)?;

    // Deserialize content into AttestationReport
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

#[derive(StructOpt)]
pub struct ReportArgs {
    #[structopt(
        long = "extended",
        short,
        help = "Request an extended report instead of the regular report"
    )]
    pub extended_report: bool,

    #[structopt(
        long = "random",
        short,
        help = "Generate a random request file for the attestation report. Defaults to ./random-request-file.txt"
    )]
    pub random: bool,
    
    #[structopt(
        long = "vmpl",
        short,
        help = "VMPL level the Guest is running on. Defaults to 1"
    )]
    pub vmpl: Option<u32>,

    #[structopt(
        long = "request",
        help = "Path pointing to were the request-file location. If provided with random flag, then a random request file will be generated at that location"
    )]
    pub request_file: Option<PathBuf>,

    #[structopt(
        long = "att-report",
        short,
        help = "File to write the attestation report to. Defaults to ./attestation_report.bin"
    )]
    pub att_report_path: Option<PathBuf>,

    #[structopt(
        long = "certs",
        short,
        help = "Directory to store certificates. Defaults to ./certs"
    )]
    pub certs_path: Option<PathBuf>,
}

// Request report function
pub fn get_report(args: ReportArgs) -> Result<()> {
    let mut sev_fw: Firmware = Firmware::open().context("failed to open SEV firmware device.")?;

    // Get Request data
    let request_data = match args.request_file {
        // Request path provided
        Some(path) => {
            // Generate random request data and place in specified path
            let request_data = if args.random {
                let request_buf = create_random_request();
                let file = File::create(path)
                    .context("Failed to create a random request file for report request")?;
                write_hex(&mut BufWriter::new(file), &request_buf)
                    .context("Failed to write request data in request file")?;
                request_buf

            // Open and read data on specified file
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
            // random flag was passed, generate random buffer and place in default path
            let request_data = if args.random {
                let request_buf = create_random_request();
                let file = File::create("./random-request-file.txt")
                    .context("Failed to create a random request file for report request")?;
                write_hex(&mut BufWriter::new(file), &request_buf)
                    .context("Failed to write request data in request file")?;
                request_buf

            // Random flag was not passed, return error
            } else {
                return Err(anyhow::anyhow!("Please provide a request-file or use --random flag to create one in order request attestation report."));
            };

            request_data
        }
    };

    // Get VMPL level from arg
    let vmpl = match args.vmpl {
        Some(level) => {
            if level > 3 {
                return Err(anyhow::anyhow!("Invalid VMPL level provided"));
            } else {
                level
            }
        }
        None => 1,
    };

    // Regular report requested
    if !args.extended_report {
        // Get attestation report path
        let att_report_path = match args.att_report_path {
            Some(path) => path,
            None => PathBuf::from_str("./attestation_report.bin")
                .context("unable to create default path")?,
        };

        // Request attestation rerport
        let att_report = sev_fw
            .get_report(None, Some(request_data), vmpl)
            .context("Failed to get report.")?;

        // Write attestation report into bin file
        let mut attestation_file =
            File::create(att_report_path).context("Failed to create Attestation Report File")?;
        bincode::serialize_into(&mut attestation_file, &att_report)
            .context("Could not serialize attestation report into file.")?;

    // Extended report requested
    } else {
        // Get attestation report path
        let att_report_path = match args.att_report_path {
            Some(path) => path,
            None => PathBuf::from_str("./attestation_report.bin")
                .context("unable to create attestation report default path")?,
        };

        // Request extended report
        let (att_report, certificates) = sev_fw
            .get_ext_report(None, Some(request_data), vmpl)
            .context("Failed to get extended report.")?;

        // Write attestation report into file
        let mut attestation_file =
            File::create(att_report_path).context("Failed to create Attestation Report File")?;
        bincode::serialize_into(&mut attestation_file, &att_report)
            .context("Could not serialize attestation report into file.")?;

        // Check for certificates
        if certificates.is_empty() {
            return Err(anyhow::anyhow!(
                "The certificate chain is empty! Certificates probably not loaded by the host."
            ));
        }

        // If default path is being used, make sure certs folder is created if missing
        if args.certs_path.is_none() {
            if !Path::new("./certs").is_dir() {
                fs::create_dir("./certs").context("Could not create certs folder")?;
            }
        }

        // Cycle throgh certs and write them into the passed file path.
        // If default path is being used, then check for cert type first to write it into correct file type
        for cert in certificates.iter() {
            // Generate path from provided certs path
            let mut path = match args.certs_path.clone() {
                Some(path) => path,
                None => PathBuf::from("./certs"),
            };

            // Create file for certipicate depeninding on its type and format
            let mut f = match cert.cert_type {
                CertType::ARK => {
                    match identify_cert(&cert.data[0..27]) {
                        CertFormat::PEM => path.push("ark.pem"),
                        CertFormat::DER => path.push("ark.der"),
                    };
                    fs::File::create(path).context("unable to create/open ARK file")?
                }

                CertType::ASK => {
                    match identify_cert(&cert.data[0..27]) {
                        CertFormat::PEM => path.push("ask.pem"),
                        CertFormat::DER => path.push("ask.der"),
                    };
                    fs::File::create(path).context("unable to create/open VCEK file")?
                }

                CertType::VCEK => {
                    match identify_cert(&cert.data[0..27]) {
                        CertFormat::PEM => path.push("vcek.pem"),
                        CertFormat::DER => path.push("vcek.der"),
                    };
                    fs::File::create(path).context("unable to create/open VCEK file")?
                }

                _ => continue,
            };

            f.write(&cert.data)
                .context(format!("unable to write data to file {:?}", f))?;
        }
    }

    Ok(())
}
