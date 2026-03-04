// SPDX-License-Identifier: Apache-2.0

//! Requests certificates from Host.
//!
//! This module provides the `certificate` subcommand which retrieves certificates
//! cached in hypervisor memory via the AMD Secure Processor (`SNP_GET_EXT_REPORT` ioctl),
//! converting certificate formats (PEM/DER).
//!
//! ## `certificates`
//!
//! ```bash
//! snpguest report $ATT_REPORT_PATH $REQUEST_FILE [OPTIONS]
//! ```
//!
//! The output depends on which certificates are cached in the hypervisor memory.
//! Before executing this command, the host (platform owner) must fetch certificates
//! from AMD KDS and load them into the extended configuration.
//!
//! ## Note
//!
//! In principle, the host can cache any certificate. However, in practice, it
//! typically caches only the leaf certificate (VCEK or VLEK) or the entire
//! certificate chain.
//!
//! Note that this feature is *not* supported in the current upstream kernels.
//! Actual behavior also depends on the kernel version. For example, behavior
//! when executed without loading certificates.
//!
//! ## Arguments
//!
//! | Argument | Description | Default |
//! | :--      | :--        | :--    |
//! | `$ENCODING` | The certificate encoding to store the certificates in (PEM or DER). All certificates will be in the same encoding. | *required* |
//! | `$CERTS_DIR` | The directory to store the certificates in. If certificates already exist in the provided directory, they will be overwritten. | *required* |
//!
//! ## Example
//!
//! ```bash
//! snpguest certificates pem ./certs
//! ```

use crate::fetch::Endorsement;

use super::*;

use std::{
    fs,
    io::{ErrorKind, Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

use sev::{
    certs::snp::{ca, Certificate, Chain},
    firmware::{guest::Firmware, host::CertType},
};

/// Paths to the three certificates that form an SNP certificate chain:
/// ARK (AMD Root Key), ASK (AMD SEV Key) or ASVK (AMD SEV-VLEK Key),
/// and VCEK (Versioned Chip Endorsement Key) or VLEK (Versioned Loaded Endorsement Key).
pub struct CertPaths {
    /// Path to the AMD Root Key certificate.
    pub ark_path: PathBuf,
    /// Path to the AMD SEV Key (or ASVK for VLEK chains) certificate.
    pub ask_path: PathBuf,
    /// Path to the VCEK or VLEK certificate.
    pub vek_path: PathBuf,
}

/// Supported certificate encoding formats.
#[derive(ValueEnum, Clone, Copy)]
pub enum CertFormat {
    /// PEM (Privacy-Enhanced Mail) encoding.
    Pem,

    /// DER (Distinguished Encoding Rules) binary encoding.
    Der,
}

impl std::fmt::Display for CertFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertFormat::Pem => write!(f, "pem"),
            CertFormat::Der => write!(f, "der"),
        }
    }
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

/// Read a certificate file and convert it into an SNP [`Certificate`].
///
/// If `cert_path` is empty, falls back to looking in `./certs/` for
/// `{cert_type}.pem` or `{cert_type}.der`.
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

    Ok(Certificate::from_bytes(&buf)?)
}

/// Build an SNP [`Chain`] from three certificate file paths (ARK, ASK/ASVK, VCEK/VLEK).
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

/// Write a certificate to a file in the specified encoding format.
///
/// The filename is derived from the certificate type and encoding
/// (e.g., `vcek.pem`, `ark.der`). For VLEK endorsement with an ASK
/// cert type, the file is named `asvk`.
pub fn write_cert(
    path: &Path,
    cert_type: &CertType,
    data: &[u8],
    encoding: CertFormat,
    endorser: &Endorsement,
) -> Result<()> {
    // Get cert type into str
    let cert: Certificate = Certificate::from_bytes(data)?;

    let cert_str: String = match (cert_type, endorser) {
        (CertType::ASK, Endorsement::Vlek) => "asvk".to_string(),
        (_, _) => match cert_type {
            CertType::Empty => "empty".to_string(),
            CertType::ARK => "ark".to_string(),
            CertType::ASK => "ask".to_string(),
            CertType::VCEK => "vcek".to_string(),
            CertType::VLEK => "vlek".to_string(),
            CertType::CRL => "crl".to_string(),
            CertType::OTHER(uuid) => format!("other-{uuid}"),
        },
    };

    let bytes: Vec<u8> = match encoding {
        CertFormat::Pem => cert.to_pem()?,
        CertFormat::Der => cert.to_der()?,
    };

    let cert_path: PathBuf = path.join(format!("{cert_str}.{encoding}"));

    // Write cert into directory
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&cert_path)
        .context(format!(
            "unable to create or overwrite {cert_str} certificate"
        ))?;

    file.write(&bytes)
        .context(format!("unable to write data to file {:?}", file))?;

    Ok(())
}

/// CLI arguments for the `certificates` subcommand.
///
/// Requests certificates from the hypervisor extended memory via the AMD
/// Secure Processor and stores them in the specified directory.
#[derive(Parser)]
pub struct CertificatesArgs {
    /// Certificate encoding format (PEM or DER).
    #[arg(value_name = "encoding", required = true, ignore_case = true)]
    pub encoding: CertFormat,

    /// Directory to store the certificates in. Created if it does not exist.
    #[arg(value_name = "certs-dir", required = true)]
    pub certs_dir: PathBuf,
}

/// Request extended certificates from the AMD Secure Processor and write them to disk.
///
/// Uses `SNP_GET_EXT_REPORT` to obtain certificates cached in the hypervisor
/// extended memory. Each certificate is written to the specified directory in the
/// chosen encoding format.
pub fn get_ext_certs(args: CertificatesArgs) -> Result<()> {
    let mut sev_fw: Firmware = Firmware::open().context("failed to open SEV firmware device.")?;

    // Generate random request data
    let request_data: [u8; 64] = report::create_random_request();

    // Request extended attestation report
    let (_, mut certificates) = sev_fw
        .get_ext_report(None, Some(request_data), None)
        .context("Failed to get extended report.")?;

    // Create certificate directory if missing
    if !args.certs_dir.exists() {
        fs::create_dir(&args.certs_dir).context("Could not create certs folder")?;
    };

    // If certificates are present, write certs into directory
    if let Some(ref mut certificates) = certificates {
        // Unless VLEK is encountered, assume VCEK style endorsement with ASK.
        let mut endorsement: Endorsement = Endorsement::Vcek;

        certificates.iter().try_for_each(|cert| {
            if cert.cert_type == CertType::VLEK {
                endorsement = Endorsement::Vlek;
            }
            write_cert(
                &args.certs_dir,
                &cert.cert_type,
                &cert.data,
                args.encoding,
                &endorsement,
            )
        })?;
    } else {
        eprintln!("No certificates were loaded by the host...");
    }

    Ok(())
}
