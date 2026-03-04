// SPDX-License-Identifier: Apache-2.0

//! Fetches certificates and CRL from AMD KDS.
//!
//! This module provides the following subcommands, which request certificates
//! and CRLs from the AMD Key Distribution Service (KDS).
//!
//! - `fetch ca` — Fetch the AMD Root Key (ARK) and AMD SEV Key (ASK/ASVK)
//! - `fetch vcek` — Fetch the Versioned Chip Endorsement Key (VCEK)
//! - `fetch crl` — Fetch the Certificate Revocation List (CRL)
//!
//! Certificates are fetched over HTTPS from `kdsintf.amd.com` and written
//! to disk in the user-specified encoding (PEM or DER).
//!
//! ## `fetch ca`
//!
//! ```bash
//! snpguest fetch ca $ENCODING $CERTS_DIR $PROCESSOR_MODEL [OPTIONS]
//! ```
//!
//! Fetches the AMD root CA certificate (ARK) and the AMD intermediate certificate
//! (ASK for VCEK or ASVK for VLEK) from the AMD KDS, and writes them in PEM or
//! DER format.
//!
//! ### Arguments and Options
//!
//! | Argument/Option | Description | Default |
//! | :--      | :--        | :--    |
//! | `$ENCODING` | The certificate encoding to store the certificates in (PEM or DER). | *required* |
//! | `$CERTS_DIR` | The directory to store the certificates in. | *required* |
//! | `$PROCESSOR_MODEL` | The host processor model (`milan`, `genoa`, `bergano`, `sienna`, `turin`). (Conflicts with `--report`) | required |
//! | `-r, --report` | Path to the attestation report to detect the host processor model. (Conflicts with `$PROCESSOR_MODEL`) | - |
//! | `-e, --endorser` | The endorser type (`vcek` or `vlek`). | `vcek` |
//!
//! The user must specify either the host processor model `$PROCESSOR_MODEL`
//! (`milan`, `genoa`, `bergano`, `sienna`, `turin`) or the path to an attestation
//! report using the `-r, --report` option. When the report is provided, the
//! command attempts to infer the host processor model from the report.
//! Autodetection succeeds only under the following conditions:
//!
//! 1. **Report Version 3 or later**
//!    - both `CPU_FAM_ID` and `CPU_MOD_ID` are present (i.e. not missing)
//! 2. **Report Version 2**
//!    - the host processor model is Turin
//!    - the `CHIP_ID` is not masked, i.e. `MASK_CHIP_ID` is zero-filled
//!
//! In the latter case, automatic detection is based on heuristics: whereas
//! pre-Turin's `CHIP_ID` utilises the full 64 bytes, Turin's `CHIP_ID` uses
//! only the first 8 bytes. This heuristics may not remain valid for future
//! processors.
//!
//! ### Example
//!
//! ```bash
//! # Fetch CA cert chain in DER encoding for with milan with VLEK
//! # ark.der and asvk.der will be stored in ./certs
//! snpguest fetch ca der ./certs milan -e vlek
//!
//! # Fetch CA cert chain in PEM encoding associated with V3+ report and VCEK
//! # ark.pem and ask.pem will be stored in ./certs
//! snpguest fetch ca pem ./certs -r report.bin -e vcek
//! ```
//!
//! ## `fetch vcek`
//!
//! ```bash
//! snpguest fetch vcek $ENCODING $CERTS_DIR $ATT_REPORT_PATH [OPTIONS]
//! ```
//!
//! Fetches the VCEK certificate from the AMD KDS, and write it in PEM or DER
//! format.
//!
//! ### Arguments and Options
//!
//! | Argument/Option | Description | Default |
//! | :--      | :--        | :--    |
//! | `$ENCODING` | The certificate encoding to store the certificates in (PEM or DER). | *required* |
//! | `$CERTS_DIR` | The directory to store the certificates in. | *required* |
//! | `$ATT_REPORT_PATH` | The path of the stored attestation report. | *required* |
//! | `-p, --processor-model` | The host processor model (`milan`, `genoa`, `bergano`, `sienna`, `turin`). If the report is *older than version 3*, this option must be specified. | - |
//!
//! The user must provide the path to an attestation report `$ATT_REPORT_PATH`
//! to get the REPORTED_TCB and CHIP_ID.
//!
//! The user can specify the host processor model using the `--processor-model`
//! option. If the processor model is not specified, the command attempts to infer
//! the host processor model from the report contents. Autodetection follows the
//! same rules and limitations as the `ca` subcommand.
//!
//! ### Example
//!
//! ```bash
//! # Fetch VCEK certificate in PEM encoding associated with V3+ report from AMD KDS
//! # vcek.pem will be stored in ./certs
//! snpguest fetch vcek pem ./certs report.bin
//!
//! # If the report is older than V3, manually specify the processor model
//! snpguest fetch vcek pem ./certs report.bin -p milan
//! ```
//!
//! ## `fetch crl`
//!
//! ```bash
//! snpguest fetch crl $ENCODING $CERTS_DIR $PROCESSOR_MODEL [OPTIONS]
//! ```
//!
//! Fetches the Certificate Revocation List (CRL) from the AMD KDS, and writes
//! it in PEM or DER format. This subcommand has completely the same API as the
//! `ca` subcommand.
//!
//! ### Arguments and Options
//!
//! | Argument/Option | Description | Default |
//! | :--      | :--        | :--    |
//! | `$ENCODING` | The CRL encoding to store the CRL in (PEM or DER). | *required* |
//! | `$CERTS_DIR` | The directory to store the CRL in. | *required* |
//! | `$PROCESSOR_MODEL` | The host processor model (`milan`, `genoa`, `bergano`, `sienna`, `turin`). (Conflicts with `--report`) | required |
//! | `-r, --report` | Path to the attestation report to detect the host processor model. (Conflict with `$PROCESSOR_MODEL`) | - |
//! | `-e, --endorser` | The endorser type (`vcek` or `vlek`). | `vcek` |
//!
//! ### Example
//!
//! ```bash
//! # Fetch CRL in DER encoding for milan with VLEK
//! # crl.der will be stored in ./certs
//! snpguest fetch crl der ./certs milan -e vlek
//!
//! # Fetch CRL in PEM encoding associated with V3+ report and VCEK
//! # ark.pem and ask.pem will be stored in ./certs
//! snpguest fetch crl pem ./certs -r report.bin -e vcek
//! ```

use super::*;

use core::fmt;

use std::{fs, path::PathBuf, str::FromStr};

use reqwest::blocking::{get, Response};

use sev::{
    certs::snp::ca::Chain,
    firmware::{guest::AttestationReport, host::CertType},
};

use certs::{write_cert, CertFormat};

/// Subcommands for fetching certificates and CRLs from the AMD KDS.
#[derive(Subcommand)]
pub enum FetchCmd {
    /// Fetch the AMD Root Key (ARK) and AMD SEV Key (ASK/ASVK) from the KDS.
    CA(cert_authority::Args),

    /// Fetch the Versioned Chip Endorsement Key (VCEK) from the KDS.
    Vcek(vcek::Args),

    /// Fetch the Certificate Revocation List (CRL) from the KDS.
    Crl(crl::Args),
}

/// The type of attestation signing key (endorsement key).
#[derive(ValueEnum, Debug, Clone, PartialEq, Eq)]
pub enum Endorsement {
    /// Versioned Chip Endorsement Key — unique per chip, derived from fused secrets.
    Vcek,

    /// Versioned Loaded Endorsement Key — provisioned by the platform owner.
    Vlek,
}

impl fmt::Display for Endorsement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endorsement::Vcek => write!(f, "VCEK"),
            Endorsement::Vlek => write!(f, "VLEK"),
        }
    }
}

impl FromStr for Endorsement {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "vcek" => Ok(Self::Vcek),
            "vlek" => Ok(Self::Vlek),
            _ => Err(anyhow::anyhow!("Endorsement type not found!")),
        }
    }
}

/// AMD EPYC processor model used to select the correct KDS endpoint.
///
/// Bergamo and Siena share the same KDS endpoint as Genoa.
#[derive(ValueEnum, Debug, Clone, PartialEq, Eq)]
pub enum ProcType {
    /// 3rd Gen AMD EPYC Processor (Standard).
    Milan,

    /// 4th Gen AMD EPYC Processor (Standard).
    Genoa,

    /// 4th Gen AMD EPYC Processor (Performance). Uses the Genoa KDS endpoint.
    Bergamo,

    /// 4th Gen AMD EPYC Processor (Edge). Uses the Genoa KDS endpoint.
    Siena,

    /// 5th Gen AMD EPYC Processor (Standard).
    Turin,
}

impl ProcType {
    fn to_kds_url(&self) -> String {
        match self {
            ProcType::Genoa | ProcType::Siena | ProcType::Bergamo => &ProcType::Genoa,
            _ => self,
        }
        .to_string()
    }
}

impl FromStr for ProcType {
    type Err = anyhow::Error;
    fn from_str(input: &str) -> Result<ProcType, anyhow::Error> {
        match input.to_lowercase().as_str() {
            "milan" => Ok(ProcType::Milan),
            "genoa" => Ok(ProcType::Genoa),
            "bergamo" => Ok(ProcType::Bergamo),
            "siena" => Ok(ProcType::Siena),
            "turin" => Ok(ProcType::Turin),
            _ => Err(anyhow::anyhow!("Processor type not found!")),
        }
    }
}

impl fmt::Display for ProcType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProcType::Milan => write!(f, "Milan"),
            ProcType::Genoa => write!(f, "Genoa"),
            ProcType::Bergamo => write!(f, "Bergamo"),
            ProcType::Siena => write!(f, "Siena"),
            ProcType::Turin => write!(f, "Turin"),
        }
    }
}

/// Determine the processor model from an attestation report.
///
/// For report version 3+, uses the CPU family and model IDs. For version 2,
/// attempts heuristic detection based on the CHIP_ID field (only succeeds
/// for Turin, where CHIP_ID uses only the first 8 bytes).
pub fn get_processor_model(att_report: AttestationReport) -> Result<ProcType> {
    if att_report.version < 3 {
        if [0u8; 64] == att_report.chip_id {
            return Err(anyhow::anyhow!(
                "Attestation report version is lower than 3 and Chip ID is all 0s. Make sure MASK_CHIP_ID is set to 0 or update firmware."
            ));
        } else {
            let chip_id = att_report.chip_id;
            if chip_id[8..64] == [0; 56] {
                return Ok(ProcType::Turin);
            } else {
                return Err(anyhow::anyhow!(
                    "Attestation report could be either Milan or Genoa. Update firmware to get a new version of the report."
                ));
            }
        }
    }

    let cpu_fam = att_report
        .cpuid_fam_id
        .ok_or_else(|| anyhow::anyhow!("Attestation report version 3+ is missing CPU family ID"))?;

    let cpu_mod = att_report
        .cpuid_mod_id
        .ok_or_else(|| anyhow::anyhow!("Attestation report version 3+ is missing CPU model ID"))?;

    match cpu_fam {
        0x19 => match cpu_mod {
            0x0..=0xF => Ok(ProcType::Milan),
            0x10..=0x1F | 0xA0..0xAF => Ok(ProcType::Genoa),
            _ => Err(anyhow::anyhow!("Processor model not supported")),
        },
        0x1A => match cpu_mod {
            0x0..=0x11 => Ok(ProcType::Turin),
            _ => Err(anyhow::anyhow!("Processor model not supported")),
        },
        _ => Err(anyhow::anyhow!("Processor family not supported")),
    }
}

/// Dispatch to the appropriate fetch subcommand handler.
pub fn cmd(cmd: FetchCmd) -> Result<()> {
    match cmd {
        FetchCmd::CA(args) => cert_authority::fetch_ca(args),
        FetchCmd::Vcek(args) => vcek::fetch_vcek(args),
        FetchCmd::Crl(args) => crl::fetch_crl(args),
    }
}

mod cert_authority {
    use super::*;
    use reqwest::StatusCode;

    /// CLI arguments for `fetch ca`.
    ///
    /// Fetches the ARK and ASK (or ASVK for VLEK) from the AMD KDS.
    /// Either `processor_model` or `att_report` must be specified (mutually exclusive).
    #[derive(Parser)]
    pub struct Args {
        /// Certificate encoding format (PEM or DER).
        #[arg(value_name = "encoding", required = true, ignore_case = true)]
        pub encoding: CertFormat,

        /// Directory to store the certificates in. Created if it does not exist.
        #[arg(value_name = "certs-dir", required = true)]
        pub certs_dir: PathBuf,

        /// Host processor model (milan, genoa, bergamo, siena, turin).
        /// Conflicts with `--report`.
        #[arg(
            value_name = "processor-model",
            required_unless_present = "att_report",
            conflicts_with = "att_report",
            ignore_case = true
        )]
        pub processor_model: Option<ProcType>,

        /// Path to an attestation report to auto-detect the processor model.
        /// Requires report version 3+, or version 2 with a Turin processor.
        /// Conflicts with the positional `processor-model` argument.
        #[arg(
            short = 'r',
            long = "report",
            value_name = "att-report",
            conflicts_with = "processor_model",
            ignore_case = true
        )]
        pub att_report: Option<PathBuf>,

        /// Endorser type: VCEK (fetches ARK + ASK) or VLEK (fetches ARK + ASVK).
        #[arg(short, long, value_name = "endorser", default_value_t = Endorsement::Vcek, ignore_case = true)]
        pub endorser: Endorsement,
    }

    /// Fetch the CA certificate chain (ARK + ASK/ASVK) from the AMD KDS.
    pub fn request_ca_kds(
        processor_model: ProcType,
        endorser: &Endorsement,
    ) -> Result<Chain, anyhow::Error> {
        const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
        const KDS_CERT_CHAIN: &str = "cert_chain";

        // Should make -> https://kdsintf.amd.com/vcek/v1/{SEV_PROD_NAME}/cert_chain
        let url: String = format!(
            "{KDS_CERT_SITE}/{}/v1/{}/{KDS_CERT_CHAIN}",
            endorser.to_string().to_lowercase(),
            processor_model.to_kds_url()
        );

        let rsp: Response = get(url).context("Unable to send request for certs to URL")?;

        match rsp.status() {
            StatusCode::OK => {
                // Parse the request
                let body = rsp
                    .bytes()
                    .context("Unable to parse AMD certificate chain")?
                    .to_vec();

                let certificates = Chain::from_pem_bytes(&body)?;

                Ok(certificates)
            }
            status => Err(anyhow::anyhow!("Unable to fetch certificate: {:?}", status)),
        }
    }

    /// Fetch the CA certificates from the KDS and write them to the specified directory.
    pub fn fetch_ca(args: Args) -> Result<()> {
        let proc_model = if let Some(processor_model) = args.processor_model {
            processor_model
        } else if let Some(att_report) = args.att_report {
            let report =
                report::read_report(att_report).context("Could not open attestation report")?;
            get_processor_model(report)?
        } else {
            return Err(anyhow::anyhow!("Attestation report is missing or invalid, or the user did not specify a processor model"));
        };
        // Get certs from kds
        let certificates = request_ca_kds(proc_model, &args.endorser)?;

        // Create certs directory if missing
        if !args.certs_dir.exists() {
            fs::create_dir(&args.certs_dir).context("Could not create certs folder")?;
        }

        let ark_cert = certificates.ark;
        let ask_cert = certificates.ask;

        write_cert(
            &args.certs_dir,
            &CertType::ARK,
            &ark_cert.to_pem()?,
            args.encoding,
            &args.endorser,
        )?;
        write_cert(
            &args.certs_dir,
            &CertType::ASK,
            &ask_cert.to_pem()?,
            args.encoding,
            &args.endorser,
        )?;

        Ok(())
    }
}

mod vcek {
    use asn1_rs::nom::AsBytes;
    use reqwest::StatusCode;

    use super::*;

    /// CLI arguments for `fetch vcek`.
    ///
    /// Fetches the VCEK certificate from the AMD KDS using the REPORTED_TCB
    /// and CHIP_ID from a stored attestation report.
    #[derive(Parser)]
    pub struct Args {
        /// Certificate encoding format (PEM or DER).
        #[arg(value_name = "encoding", required = true, ignore_case = true)]
        pub encoding: CertFormat,

        /// Directory to store the certificate in. Created if it does not exist.
        #[arg(value_name = "certs-dir", required = true)]
        pub certs_dir: PathBuf,

        /// Path to the attestation report (used to extract CHIP_ID and REPORTED_TCB).
        #[arg(value_name = "att-report-path", required = true)]
        pub att_report: PathBuf,

        /// Host processor model. If not specified, auto-detected from the report.
        #[arg(short, long, value_name = "processor-model", ignore_case = true)]
        pub processor_model: Option<ProcType>,
    }

    /// Fetch the VCEK certificate from the AMD KDS in DER format.
    pub fn request_vcek_kds(
        processor_model: ProcType,
        att_report_path: PathBuf,
    ) -> Result<Vec<u8>, anyhow::Error> {
        // KDS URL parameters
        const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
        const KDS_VCEK: &str = "/vcek/v1";

        // Grab attestation report if path provided, request report if no path is provided
        let att_report = if !att_report_path.exists() {
            return Err(anyhow::anyhow!("No attestation report in provided path."));
        } else {
            report::read_report(att_report_path).context("Could not open attestation report")?
        };

        // Get hardware id
        let hw_id: String = if att_report.chip_id.as_bytes() != [0; 64] {
            match processor_model {
                ProcType::Turin => {
                    let shorter_bytes: &[u8] = &att_report.chip_id[0..8];
                    hex::encode(shorter_bytes)
                }
                _ => hex::encode(att_report.chip_id),
            }
        } else {
            return Err(anyhow::anyhow!(
                "Hardware ID is 0s on attestation report. Confirm that MASK_CHIP_ID is set to 0."
            ));
        };

        // Request VCEK from KDS
        let vcek_url: String = match processor_model {
            ProcType::Turin => {
                let fmc = if let Some(fmc) = att_report.reported_tcb.fmc {
                    fmc
                } else {
                    return Err(anyhow::anyhow!("A Turin processor must have a fmc value"));
                };
                format!(
                    "{KDS_CERT_SITE}{KDS_VCEK}/{}/\
                    {hw_id}?fmcSPL={:02}&blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                    processor_model.to_kds_url(),
                    fmc,
                    att_report.reported_tcb.bootloader,
                    att_report.reported_tcb.tee,
                    att_report.reported_tcb.snp,
                    att_report.reported_tcb.microcode
                )
            }
            _ => {
                format!(
                    "{KDS_CERT_SITE}{KDS_VCEK}/{}/\
                    {hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                    processor_model.to_kds_url(),
                    att_report.reported_tcb.bootloader,
                    att_report.reported_tcb.tee,
                    att_report.reported_tcb.snp,
                    att_report.reported_tcb.microcode
                )
            }
        };

        // VCEK in DER format
        let vcek_rsp: Response = get(vcek_url).context("Unable to send request for VCEK")?;

        match vcek_rsp.status() {
            StatusCode::OK => {
                let vcek_rsp_bytes: Vec<u8> =
                    vcek_rsp.bytes().context("Unable to parse VCEK")?.to_vec();
                Ok(vcek_rsp_bytes)
            }
            status => Err(anyhow::anyhow!("Unable to fetch VCEK from URL: {status:?}")),
        }
    }

    /// Fetch the VCEK from the KDS and write it to the specified directory.
    pub fn fetch_vcek(args: Args) -> Result<()> {
        let proc_model = if let Some(proc_model) = args.processor_model {
            proc_model
        } else {
            let att_report = report::read_report(args.att_report.clone())
                .context("Could not open attestation report")?;
            get_processor_model(att_report)?
        };

        // Request vcek
        let vcek = request_vcek_kds(proc_model, args.att_report)?;

        if !args.certs_dir.exists() {
            fs::create_dir(&args.certs_dir).context("Could not create certs folder")?;
        }

        write_cert(
            &args.certs_dir,
            &CertType::VCEK,
            &vcek,
            args.encoding,
            &Endorsement::Vcek,
        )?;

        Ok(())
    }
}

mod crl {
    use super::*;
    use openssl::x509::X509Crl;
    use reqwest::StatusCode;
    use std::io::Write;

    /// CLI arguments for `fetch crl`.
    ///
    /// Fetches the Certificate Revocation List from the AMD KDS.
    /// Has the same interface as `fetch ca`: either `processor_model` or
    /// `att_report` must be specified (mutually exclusive).
    #[derive(Parser)]
    pub struct Args {
        /// CRL encoding format (PEM or DER).
        #[arg(value_name = "encoding", required = true, ignore_case = true)]
        pub encoding: CertFormat,

        /// Directory to store the CRL in. Created if it does not exist.
        #[arg(value_name = "certs-dir", required = true)]
        pub certs_dir: PathBuf,

        /// Host processor model (milan, genoa, bergamo, siena, turin).
        /// Conflicts with `--report`.
        #[arg(
            value_name = "processor-model",
            required_unless_present = "att_report",
            conflicts_with = "att_report",
            ignore_case = true
        )]
        pub processor_model: Option<ProcType>,

        /// Path to an attestation report to auto-detect the processor model.
        /// Conflicts with the positional `processor-model` argument.
        #[arg(
            short = 'r',
            long = "report",
            value_name = "att-report",
            conflicts_with = "processor_model",
            ignore_case = true
        )]
        pub att_report: Option<PathBuf>,

        /// Endorser type: VCEK or VLEK.
        #[arg(short, long, value_name = "endorser", default_value_t = Endorsement::Vcek, ignore_case = true)]
        pub endorser: Endorsement,
    }

    /// Fetch the CRL from the AMD KDS in DER format.
    pub fn request_crl_kds(
        processor_model: ProcType,
        endorser: &Endorsement,
    ) -> Result<Vec<u8>, anyhow::Error> {
        const KDS_CRL_SITE: &str = "https://kdsintf.amd.com";
        const KDS_CRL: &str = "crl";

        // Should make -> https://kdsintf.amd.com/vcek/v1/{SEV_PROD_NAME}/crl
        let url: String = format!(
            "{KDS_CRL_SITE}/{}/v1/{}/{KDS_CRL}",
            endorser.to_string().to_lowercase(),
            processor_model.to_kds_url()
        );

        // CRL in DER format
        let crl_rsp: Response = get(url).context("unable to send request for CRL to URL")?;

        match crl_rsp.status() {
            StatusCode::OK => {
                let crl_rsp_bytes: Vec<u8> =
                    crl_rsp.bytes().context("unable to parse CRL")?.to_vec();
                Ok(crl_rsp_bytes)
            }
            status => Err(anyhow::anyhow!("unable to fetch CRL from URL: {status:?}")),
        }
    }

    /// Fetch the CRL from the KDS and write it to the specified directory.
    pub fn fetch_crl(args: Args) -> Result<()> {
        let proc_model = if let Some(processor_model) = args.processor_model {
            processor_model
        } else if let Some(att_report) = args.att_report {
            let report =
                report::read_report(att_report).context("could not open attestation report")?;
            get_processor_model(report)?
        } else {
            return Err(anyhow::anyhow!("attestation report is missing or invalid, or the user did not specify a processor model"));
        };

        // Request CRL
        let crl_der = request_crl_kds(proc_model, &args.endorser)?;
        let crl = X509Crl::from_der(&crl_der)?;

        // Convert encoding
        let bytes: Vec<u8> = match args.encoding {
            CertFormat::Pem => crl.to_pem()?,
            CertFormat::Der => crl.to_der()?,
        };

        // Write CRL into directory
        if !args.certs_dir.exists() {
            fs::create_dir(&args.certs_dir).context("could not create certs folder")?;
        }

        let crl_path: PathBuf = args.certs_dir.join(format!("crl.{}", args.encoding));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&crl_path)
            .context("unable to create or overwrite CRL")?;

        file.write(&bytes)
            .context(format!("unable to write data to file {:?}", file))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sev::firmware::guest::KeyInfo;

    #[test]
    fn test_kds_prod_name_milan_base() {
        let milan_proc: ProcType = ProcType::Milan;
        assert_eq!(milan_proc.to_kds_url(), ProcType::Milan.to_string());
    }

    #[test]
    fn test_kds_prod_name_genoa_base() {
        assert_eq!(ProcType::Genoa.to_kds_url(), ProcType::Genoa.to_string());
        assert_eq!(ProcType::Siena.to_kds_url(), ProcType::Genoa.to_string());
        assert_eq!(ProcType::Bergamo.to_kds_url(), ProcType::Genoa.to_string());
    }

    #[test]
    fn test_get_processor_model_milan() {
        let att_report = AttestationReport {
            version: 3,
            cpuid_fam_id: Some(0x19),
            cpuid_mod_id: Some(0x0),
            ..Default::default()
        };
        let proc_model = get_processor_model(att_report).unwrap();
        assert_eq!(proc_model, ProcType::Milan);
    }

    #[test]
    fn test_get_processor_model_genoa() {
        let att_report = AttestationReport {
            version: 3,
            cpuid_fam_id: Some(0x19),
            cpuid_mod_id: Some(0x10),
            ..Default::default()
        };
        let proc_model = get_processor_model(att_report).unwrap();
        assert_eq!(proc_model, ProcType::Genoa);
    }

    #[test]
    fn test_get_processor_model_turin() {
        let att_report = AttestationReport {
            version: 3,
            cpuid_fam_id: Some(0x1A),
            cpuid_mod_id: Some(0x0),
            ..Default::default()
        };
        let proc_model = get_processor_model(att_report).unwrap();
        assert_eq!(proc_model, ProcType::Turin);
    }

    #[test]
    fn test_get_processor_model_unsupported_family() {
        let att_report = AttestationReport {
            version: 3,
            cpuid_fam_id: Some(0x1B),
            cpuid_mod_id: Some(0x0),
            ..Default::default()
        };
        let result = get_processor_model(att_report);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_processor_model_unsupported_model() {
        let att_report = AttestationReport {
            version: 3,
            cpuid_fam_id: Some(0x19),
            cpuid_mod_id: Some(0x20),
            ..Default::default()
        };
        let result = get_processor_model(att_report);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_processor_model_version_too_low() {
        let att_report = AttestationReport {
            version: 2,
            chip_id: [1; 64],
            ..Default::default()
        };
        let result = get_processor_model(att_report);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_processor_model_mask_chip_key_set() {
        let key_info = KeyInfo(0b10);
        let att_report = AttestationReport {
            version: 2,
            key_info,
            ..Default::default()
        };
        let result = get_processor_model(att_report);
        assert!(result.is_err());
    }
}
