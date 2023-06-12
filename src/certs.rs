// SPDX-License-Identifier: Apache-2.0

use super::*;

use std::{
    fs,
    io::{ErrorKind, Read, Write},
    path::PathBuf,
};

use sev::{
    certs::snp::{ca, Certificate, Chain},
    firmware::host::CertType,
};

pub struct CertPaths {
    pub ark_path: PathBuf,
    pub ask_path: PathBuf,
    pub vcek_path: PathBuf,
}
pub enum CertFormat {
    PEM,
    DER,
}

// Function to check if certificate is in .der or .pem depending on its contents
fn identify_cert(buf: &[u8]) -> CertFormat {
    // Pem certificates will start with this byte content
    const PEM_START: &[u8] = &[
        45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 45,
        45, 45, 45, 45,
    ];

    match buf {
        PEM_START => CertFormat::PEM,
        _ => CertFormat::DER,
    }
}

// Function that will convert a cert path into a snp Certificate
pub fn convert_path_to_cert(
    cert_path: &PathBuf,
    cert_type: &str,
) -> Result<Certificate, anyhow::Error> {
    let mut buf = vec![];

    let mut current_file = if cert_path.as_os_str().is_empty() {
        let temp_file = match fs::File::open(format!("./certs/{cert_type}.pem")) {
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
        };
        temp_file
    } else {
        fs::File::open(cert_path).context(format!("Could not open provided {cert_type} file"))?
    };

    current_file
        .read_to_end(&mut buf)
        .context(format!("Could not read contents of {cert_type} file"))?;

    let cert = match identify_cert(&buf[0..27]) {
        CertFormat::PEM => Certificate::from_pem(&buf)
            .context(format!("Could not convert {cert_type} data into X509"))?,
        CertFormat::DER => Certificate::from_der(&buf)
            .context(format!("Could not convert {cert_type} data into X509"))?,
    };

    Ok(cert)
}

// Tryfrom function that takes in 3 certificate paths returns a snp Certificate Chain
impl TryFrom<CertPaths> for Chain {
    type Error = anyhow::Error;
    fn try_from(content: CertPaths) -> Result<Self, Self::Error> {
        let ark_cert = convert_path_to_cert(&content.ark_path, "ark")?;
        let ask_cert = convert_path_to_cert(&content.ask_path, "ask")?;
        let vcek_cert = convert_path_to_cert(&content.vcek_path, "vcek")?;

        let ca_chain = ca::Chain {
            ark: ark_cert,
            ask: ask_cert,
        };

        Ok(Chain {
            ca: ca_chain,
            vcek: vcek_cert,
        })
    }
}

// Function used to write provided cert into desired directory.
pub fn write_cert(mut path: PathBuf, cert_type: &CertType, data: &Vec<u8>) -> Result<()> {
    // Get cert type into str
    let cert_str = match cert_type {
        CertType::ARK => "ark",
        CertType::ASK => "ask",
        CertType::VCEK => "vcek",
        _ => return Err(anyhow::anyhow!("Invalid cert type")),
    };

    // Identify cert as either pem or der
    match identify_cert(&data[0..27]) {
        CertFormat::PEM => path.push(format!("{}.pem", cert_str)),
        CertFormat::DER => path.push(format!("{}.der", cert_str)),
    };

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

    file.write(&data)
        .context(format!("unable to write data to file {:?}", file))?;

    Ok(())
}
