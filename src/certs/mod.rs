use super::*;
use sev::certs::snp::{ca, Certificate, Chain};
use std::{
    fs,
    io::{ErrorKind, Read},
    path::PathBuf,
};

// Structure of 3 paths meant for cert-chain
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
pub fn identify_cert(buf: &[u8]) -> CertFormat {
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
    // Will contain cert data
    let mut buf = vec![];

    // If path string is empty, check for cert in default path directory
    // If path is not empty, use provided path
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

    // Read certificate contents
    current_file
        .read_to_end(&mut buf)
        .context(format!("Could not read contents of {cert_type} file"))?;

    // Convert to Certificate from data, depending on encoding type
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
