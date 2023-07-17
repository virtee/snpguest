// SPDX-License-Identifier: Apache-2.0

use super::*;

use core::fmt;

use std::{fs, path::PathBuf, str::FromStr};

use reqwest::blocking::{get, Response};

use sev::firmware::host::CertType;

use certs::{write_cert, CertFormat};

#[derive(StructOpt)]
pub enum FetchCmd {
    #[structopt(about = "Fetch the certificate authority (ARK & ASK) from the KDS.")]
    CA(cert_authority::Args),

    #[structopt(about = "Fetch the VCEK from the KDS.")]
    VCEK(vcek::Args),
}

#[derive(Debug, Clone)]
pub enum ProcType {
    Milan,
    Genoa,
}

impl FromStr for ProcType {
    type Err = anyhow::Error;
    fn from_str(input: &str) -> Result<ProcType, anyhow::Error> {
        match input.to_lowercase().as_str() {
            "milan" => Ok(ProcType::Milan),
            "genoa" => Ok(ProcType::Genoa),
            _ => Err(anyhow::anyhow!("Processor type not found!")),
        }
    }
}

impl fmt::Display for ProcType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProcType::Milan => write!(f, "Milan"),
            ProcType::Genoa => write!(f, "Genoa"),
        }
    }
}

pub fn cmd(cmd: FetchCmd) -> Result<()> {
    match cmd {
        FetchCmd::CA(args) => cert_authority::fetch_ca(args),
        FetchCmd::VCEK(args) => vcek::fetch_vcek(args),
    }
}

mod cert_authority {
    use super::*;
    use openssl::x509::X509;

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(help = "Specify encoding to use for certificates. [PEM | DER]")]
        pub encoding: CertFormat,

        #[structopt(
            help = "Specify the processor model for the certificate chain. [Milan | Genoa]"
        )]
        pub processor_model: ProcType,

        #[structopt(help = "Directory to store the certificates in.")]
        pub certs_dir: PathBuf,
    }

    // Function to build kds request for ca chain and return a vector with the 2 certs (ASK & ARK)
    pub fn request_ca_kds(processor_model: ProcType) -> Result<Vec<X509>, anyhow::Error> {
        const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
        const KDS_VCEK: &str = "/vcek/v1";
        const KDS_CERT_CHAIN: &str = "cert_chain";

        // Should make -> https://kdsintf.amd.com/vcek/v1/{SEV_PROD_NAME}/cert_chain
        let url: String = format!("{KDS_CERT_SITE}{KDS_VCEK}/{processor_model}/{KDS_CERT_CHAIN}");

        let rsp: Response = get(&url).context("Could not get certs from URL")?;

        // Parse response
        let body = rsp
            .bytes()
            .context("Unable to parse AMD certificate chain")?
            .to_vec();

        let certificates = X509::stack_from_pem(&body)?;

        Ok(certificates)
    }

    // Fetch the ca from the kds and write it into the certs directory
    pub fn fetch_ca(args: Args) -> Result<()> {
        // Get certs from kds
        let certificates = request_ca_kds(args.processor_model)?;

        // Create certs directory if missing
        if !args.certs_dir.exists() {
            fs::create_dir(args.certs_dir.clone()).context("Could not create certs folder")?;
        }

        let ark_cert = &certificates[1];
        let ask_cert = &certificates[0];

        write_cert(
            args.certs_dir.clone(),
            &CertType::ARK,
            &ark_cert.to_pem()?,
            args.encoding.clone(),
        )?;
        write_cert(
            args.certs_dir.clone(),
            &CertType::ASK,
            &ask_cert.to_pem()?,
            args.encoding.clone(),
        )?;

        Ok(())
    }
}

mod vcek {
    use super::*;

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(help = "Specify encoding to use for certificates. [PEM | DER]")]
        pub encoding: CertFormat,

        #[structopt(
            help = "Specify the processor model for the certificate chain. [Milan | Genoa]"
        )]
        pub processor_model: ProcType,

        #[structopt(help = "Directory to store the certificates in.")]
        pub certs_dir: PathBuf,

        #[structopt(help = "Path to attestation report to use to request VCEK.")]
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

        // Use attestation report to get data for URL
        let hw_id: String = hex::encode(&att_report.chip_id);

        let vcek_url: String = format!(
            "{KDS_CERT_SITE}{KDS_VCEK}/{processor_model}/\
            {hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            att_report.reported_tcb.bootloader,
            att_report.reported_tcb.tee,
            att_report.reported_tcb.snp,
            att_report.reported_tcb.microcode
        );

        // VCEK in DER format
        let vcek_rsp = get(&vcek_url).context("Could not get VCEK from URL")?;

        let vcek_rsp_bytes = vcek_rsp.bytes().context("Unable to parse VCEK")?.to_vec();

        Ok(vcek_rsp_bytes)
    }

    // Function to request vcek from kds and write it into file
    pub fn fetch_vcek(args: Args) -> Result<()> {
        // Request vcek
        let vcek = request_vcek_kds(args.processor_model, args.att_report_path)?;

        if !args.certs_dir.exists() {
            fs::create_dir(args.certs_dir.clone()).context("Could not create certs folder")?;
        }

        let vcek_path = args.certs_dir.clone();

        write_cert(vcek_path, &CertType::VCEK, &vcek, args.encoding)?;

        Ok(())
    }
}
