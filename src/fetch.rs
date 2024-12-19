// SPDX-License-Identifier: Apache-2.0
// This file contains subcommands for fetching various types of certificates from the AMD Secure Processor.

use super::*;

use core::fmt;

use std::{fs, path::PathBuf, str::FromStr};

use reqwest::blocking::{get, Response};

use sev::{certs::snp::ca::Chain, firmware::host::CertType};

use certs::{write_cert, CertFormat};

#[derive(Subcommand)]
pub enum FetchCmd {
    /// Fetch the certificate authority (ARK & ASK) from the KDS.
    CA(cert_authority::Args),

    /// Fetch the VCEK from the KDS.
    Vcek(vcek::Args),
}

#[derive(ValueEnum, Debug, Clone, PartialEq, Eq)]
pub enum Endorsement {
    /// Versioned Chip Endorsement Key
    Vcek,

    /// Versioned Loaded Endorsement Key
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
#[derive(ValueEnum, Debug, Clone)]
pub enum ProcType {
    /// 3rd Gen AMD EPYC Processor (Standard)
    Milan,

    /// 4th Gen AMD EPYC Processor (Standard)
    Genoa,

    /// 4th Gen AMD EPYC Processor (Performance)
    Bergamo,

    /// 4th Gen AMD EPYC Processor (Edge)
    Siena,

    /// 5th Gen AMD EPYC Processor (Standard)
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

pub fn cmd(cmd: FetchCmd) -> Result<()> {
    match cmd {
        FetchCmd::CA(args) => cert_authority::fetch_ca(args),
        FetchCmd::Vcek(args) => vcek::fetch_vcek(args),
    }
}

mod cert_authority {
    use super::*;
    use reqwest::StatusCode;

    #[derive(Parser)]
    pub struct Args {
        /// Specify encoding to use for certificates.
        #[arg(value_name = "encoding", required = true, ignore_case = true)]
        pub encoding: CertFormat,

        /// Specify the processor model for the certificate chain.
        #[arg(value_name = "processor-model", required = true, ignore_case = true)]
        pub processor_model: ProcType,

        /// Directory to store the certificates in.
        #[arg(value_name = "certs-dir", required = true)]
        pub certs_dir: PathBuf,

        /// Specify which endorsement certificate chain to pull, either VCEK or VLEK.
        #[arg(short, long, value_name = "endorser", default_value_t = Endorsement::Vcek, ignore_case = true)]
        pub endorser: Endorsement,
    }

    // Function to build kds request for ca chain and return a vector with the 2 certs (ASK & ARK)
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

    // Fetch the ca from the kds and write it into the certs directory
    pub fn fetch_ca(args: Args) -> Result<()> {
        // Get certs from kds
        let certificates = request_ca_kds(args.processor_model, &args.endorser)?;

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
    use reqwest::StatusCode;

    use super::*;

    #[derive(Parser)]
    pub struct Args {
        /// Specify encoding to use for certificates.
        #[arg(value_name = "encoding", required = true, ignore_case = true)]
        pub encoding: CertFormat,

        /// Specify the processor model for the certificate chain.
        #[arg(value_name = "processor-model", required = true, ignore_case = true)]
        pub processor_model: ProcType,

        /// Directory to store the certificates in.
        #[arg(value_name = "certs-dir", required = true)]
        pub certs_dir: PathBuf,

        /// Path to attestation report to use to request VCEK.
        #[arg(value_name = "att-report-path", required = true)]
        pub att_report_path: PathBuf,
    }

    // Function to request vcek from KDS. Return vcek in der format.
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

        let hw_id: String = match processor_model {
            ProcType::Turin => {
                let shorter_bytes: &[u8] = &att_report.chip_id[0..8];
                hex::encode(shorter_bytes)
            }
            _ => hex::encode(att_report.chip_id),
        };

        let vcek_url: String = format!(
            "{KDS_CERT_SITE}{KDS_VCEK}/{}/\
            {hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            processor_model.to_kds_url(),
            att_report.reported_tcb.bootloader,
            att_report.reported_tcb.tee,
            att_report.reported_tcb.snp,
            att_report.reported_tcb.microcode
        );

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

    // Function to request vcek from kds and write it into file
    pub fn fetch_vcek(args: Args) -> Result<()> {
        // Request vcek
        let vcek = request_vcek_kds(args.processor_model, args.att_report_path)?;

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
#[cfg(test)]
mod tests {
    use super::ProcType;

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
}
