// SPDX-License-Identifier: Apache-2.0
// This file contains code related to managing certificates. It defines a structure for managing certificate paths (`CertPaths`) and functions for obtaining extended certificates from the AMD Secure Processor.

use super::*;

use std::{
    fs,
    io::{ErrorKind, Read, Write},
    path::PathBuf,
    str::FromStr,
};

use sev::{
    certs::snp::{ca, Certificate, Chain},
    firmware::{guest::Firmware, host::CertType},
};

use openssl::x509::X509;

pub struct CertPaths {
    pub ark_path: PathBuf,
    pub ask_path: PathBuf,
    pub vek_path: PathBuf,
}
#[derive(StructOpt, Clone, Copy)]
pub enum CertFormat {
    #[structopt(about = "Certificates are encoded in PEM format.")]
    Pem,

    #[structopt(about = "Certificates are encoded in DER format.")]
    Der,
}

impl FromStr for CertFormat {
    type Err = anyhow::Error;
    fn from_str(input: &str) -> Result<CertFormat, anyhow::Error> {
        match input.to_lowercase().as_str() {
            "pem" => Ok(CertFormat::Pem),
            "der" => Ok(CertFormat::Der),
            _ => Err(anyhow::anyhow!("Invalid Cert Format!")),
        }
    }
}

// Function to check if certificate is in .der or .pem depending on its contents
fn identify_cert(buf: &[u8]) -> CertFormat {
    // Pem certificates will start with this byte content
    const PEM_START: &[u8] = &[
        45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45,
        45, 45, 45, 45,
    ];

    match buf {
        PEM_START => CertFormat::Pem,
        _ => CertFormat::Der,
    }
}

// Function that will convert a cert path into a snp Certificate
pub fn convert_path_to_cert(
    cert_path: &PathBuf,
    cert_type: &str,
) -> Result<Certificate, anyhow::Error> {
    let mut buf = vec![];

    let mut current_file = if cert_path.as_os_str().is_empty() {
        match fs::File::open(format!("./certs/{cert_type}.pem")) {
            Ok(file) => file,
            Err(err) => match err.kind() {
                ErrorKind::NotFound => match fs::File::open(format!("./certs/{cert_type}.der")) {
                    Ok(file) => file,
                    Err(e) => {
                        return Err(anyhow::anyhow!("Problem opening {cert_type} file {:?}", e))
                    }
                },
                other_error => {
                    return Err(anyhow::anyhow!(
                        "Problem opening {cert_type} file {:?}",
                        other_error
                    ));
                }
            },
        }
    } else {
        fs::File::open(cert_path).context(format!("Could not open provided {cert_type} file"))?
    };

    current_file
        .read_to_end(&mut buf)
        .context(format!("Could not read contents of {cert_type} file"))?;

    let cert = match identify_cert(&buf[0..27]) {
        CertFormat::Pem => Certificate::from_pem(&buf)
            .context(format!("Could not convert {cert_type} data into X509"))?,
        CertFormat::Der => Certificate::from_der(&buf)
            .context(format!("Could not convert {cert_type} data into X509"))?,
    };

    Ok(cert)
}

// Tryfrom function that takes in 3 certificate paths returns a snp Certificate Chain
impl TryFrom<CertPaths> for Chain {
    type Error = anyhow::Error;
    fn try_from(content: CertPaths) -> Result<Self, Self::Error> {
        let ark_cert: Certificate = convert_path_to_cert(&content.ark_path, "ark")?;
        let ask_cert: Certificate = convert_path_to_cert(&content.ask_path, "ask")?;
        let vek_cert: Certificate = if content
            .vek_path
            .to_string_lossy()
            .to_lowercase()
            .contains("vlek")
        {
            convert_path_to_cert(&content.vek_path, "vlek")?
        } else {
            convert_path_to_cert(&content.vek_path, "vcek")?
        };

        let ca_chain = ca::Chain {
            ark: ark_cert,
            ask: ask_cert,
        };

        Ok(Chain {
            ca: ca_chain,
            vek: vek_cert,
        })
    }
}

fn translate_cert(data: &[u8], cert_encoding: CertFormat) -> Vec<u8> {
    match (identify_cert(&data[0..27]), cert_encoding) {
        (CertFormat::Pem, CertFormat::Der) => X509::from_pem(data)
            .expect("Failed to parse the certificate")
            .to_der()
            .expect("Failed to convert to DER encoding"),
        (CertFormat::Der, CertFormat::Pem) => X509::from_der(data)
            .expect("Failed to parse the certificate")
            .to_pem()
            .expect("Failed to convert to PEM encoding"),
        _ => Vec::from(data),
    }
}

// Function used to write provided cert into desired directory.
pub fn write_cert(
    mut path: PathBuf,
    cert_type: &CertType,
    data: &[u8],
    encoding: CertFormat,
) -> Result<()> {
    // Get cert type into str
    let cert_str = match cert_type {
        CertType::ARK => "ark",
        CertType::ASK => "ask",
        CertType::VCEK => "vcek",
        _ => return Err(anyhow::anyhow!("Invalid cert type")),
    };

    let file_ext: &str = match encoding {
        CertFormat::Pem => "pem",
        CertFormat::Der => "der",
    };

    path.push(format!("{}.{}", cert_str, file_ext));

    let bytes: Vec<u8> = translate_cert(data, encoding);

    // Write cert into directory
    let mut file = if path.exists() {
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .context(format!("Unable to overwrite {} cert contents", cert_str))?
    } else {
        fs::File::create(path).context(format!("Unable to create {} certificate", cert_str))?
    };

    file.write(&bytes)
        .context(format!("unable to write data to file {:?}", file))?;

    Ok(())
}

#[derive(StructOpt)]
pub struct CertificatesArgs {
    #[structopt(help = "Specify encoding to use for certificates. [PEM | DER]")]
    pub encoding: CertFormat,

    #[structopt(
        help = "Directory to store certificates in. Required if requesting an extended-report."
    )]
    pub certs_dir: PathBuf,
}

pub fn get_ext_certs(args: CertificatesArgs) -> Result<()> {
    let mut sev_fw: Firmware = Firmware::open().context("failed to open SEV firmware device.")?;

    // Generate random request data
    let request_data = report::create_random_request();

    // Request extended attestation report
    let (_, certificates) = sev_fw
        .get_ext_report(None, Some(request_data), None)
        .context("Failed to get extended report.")?;

    // Create certificate directory if missing
    if !args.certs_dir.exists() {
        fs::create_dir(args.certs_dir.clone()).context("Could not create certs folder")?;
    };

    // If certificates are present, write certs into directory
    if let Some(ref certificates) = certificates {
        for cert in certificates.iter() {
            let path = args.certs_dir.clone();

            write_cert(path, &cert.cert_type, &cert.data, args.encoding)?;
        }
    } else {
        eprintln!("No certificates were loaded by the host...");
    }

    Ok(())
}
