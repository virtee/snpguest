// SPDX-License-Identifier: Apache-2.0

use super::*;

use core::fmt;

use std::{fs, path::PathBuf, str::FromStr};

use reqwest::blocking::{get, Response};

use sev::firmware::host::CertType;

use certs::write_cert;

#[derive(StructOpt)]
pub enum FetchCmd {
    #[structopt(about = "Fetch the certificate authority (ARK & ASK) from the KDS.")]
    CA(cert_authority::Args),

    #[structopt(about = "Fetch the VCEK from the KDS.")]
    VCEK(vcek::Args),

    #[structopt(
        about = "Fetch the complete certificate chain from either the KDS or extended-report (Host Memory)."
    )]
    CERTS(certificates::Args),

    #[structopt(about = "Fetch a unique encryption key from the hardware root of trust.")]
    KEY(key::Args),
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
        FetchCmd::CERTS(args) => certificates::fetch_certs(args),
        FetchCmd::KEY(args) => key::fetch_key(args),
    }
}

mod cert_authority {
    use super::*;
    use openssl::x509::X509;

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(help = "Directory to store the certificates in.")]
        pub certs_dir: PathBuf,

        #[structopt(
            help = "Specify the processor model for the certificate chain. [Milan | Genoa]"
        )]
        pub processor_model: ProcType,
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

        write_cert(args.certs_dir.clone(), &CertType::ARK, &ark_cert.to_pem()?)?;
        write_cert(args.certs_dir.clone(), &CertType::ASK, &ask_cert.to_pem()?)?;

        Ok(())
    }
}

mod vcek {
    use super::*;

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(help = "Directory to store the VCEK in.")]
        pub certs_dir: PathBuf,

        #[structopt(help = "Specify the processor model for the VCEK. [Milan | Genoa]")]
        pub processor_model: ProcType,

        #[structopt(
            long = "att-report",
            short,
            help = "Optional: path to attestation report to use to request VCEK."
        )]
        pub att_report_path: Option<PathBuf>,
    }

    // Function to request vcek from KDS. Return vcek in der format.
    pub fn request_vcek_kds(
        processor_model: ProcType,
        att_report_path: Option<PathBuf>,
    ) -> Result<Vec<u8>, anyhow::Error> {
        // KDS URL parameters
        const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
        const KDS_VCEK: &str = "/vcek/v1";

        // Grab attestation report if path provided, request report if no path is provided
        let att_report = match att_report_path {
            Some(path) => {
                // Check that provided path contains an attestation report
                if !path.exists() {
                    return Err(anyhow::anyhow!("No attestation report in provided path."));
                }
                report::read_report(path).context("Could not open attestation report")?
            }
            None => report::request_default_report()?,
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

        write_cert(vcek_path, &CertType::VCEK, &vcek)?;

        Ok(())
    }
}

mod certificates {
    use super::*;
    use report::create_random_request;
    use sev::firmware::{
        guest::Firmware,
        host::{CertTableEntry, CertType},
    };
    use std::{fs, path::PathBuf};

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(long, short = "e", help = "Fetch certificates from extended report.")]
        pub extended_report: bool,

        #[structopt(help = "Directory to store certificates")]
        pub certs_dir: PathBuf,

        #[structopt(
            help = "Specify the processor model for the certificates [Milan | Genoa] (KDS only)",
            required_unless("extended-report")
        )]
        pub processor_model: Option<ProcType>,

        #[structopt(
            long = "att-report",
            short,
            help = "Optional: path to attestation report to use to request VCEK (KDS only)"
        )]
        pub att_report_path: Option<PathBuf>,
    }

    pub fn fetch_certs(args: Args) -> Result<()> {
        // If an attestation report will be requested, open the SEV firmware and create a random request
        let (sev_fw, request_data) = if args.att_report_path.is_none() {
            (
                Some(Firmware::open().context("failed to open SEV firmware device.")?),
                Some(create_random_request()),
            )
        } else {
            (None, None)
        };

        // Create certificate directory if missing
        if !args.certs_dir.exists() {
            fs::create_dir(args.certs_dir.clone()).context("Could not create certs folder")?;
        }

        // Depending on request type, get certificate chain
        let certificates = match args.extended_report {
            true => {
                let (_, memory_certs) = sev_fw
                    .unwrap()
                    .get_ext_report(None, Some(request_data.unwrap()), None)
                    .context("Failed to get extended report.")?;

                if memory_certs.is_empty() {
                    return Err(anyhow::anyhow!(
                        "The certificate chain is empty! Certificates probably not loaded by the host."
                    ));
                }
                memory_certs
            }
            false => {
                let mut kds_certs: Vec<CertTableEntry> = Vec::new();
                let ca_chain = cert_authority::request_ca_kds(
                    args.processor_model
                        .clone()
                        .context("Processor model not provided")?,
                )?;
                let kds_ark = ca_chain[1].to_pem()?;
                let kds_ask = ca_chain[0].to_pem()?;
                let kds_vcek = vcek::request_vcek_kds(
                    args.processor_model
                        .clone()
                        .context("Processor model not provided")?,
                    args.att_report_path,
                )?;

                kds_certs.push(CertTableEntry::new(CertType::ARK, kds_ark));
                kds_certs.push(CertTableEntry::new(CertType::ASK, kds_ask));
                kds_certs.push(CertTableEntry::new(CertType::VCEK, kds_vcek));

                kds_certs
            }
        };

        // Write certificate chain into files
        for cert in certificates.iter() {
            // Generate path from provided certs path
            let path = args.certs_dir.clone();

            write_cert(path, &cert.cert_type, &cert.data)?;
        }

        Ok(())
    }
}

mod key {
    use super::*;
    use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(
            long = "key-location",
            short,
            help = "Optional: path to attestation report to use to request VCEK (KDS only)"
        )]
        pub key_path: Option<PathBuf>,
    }
    pub fn fetch_key(args: Args) -> Result<()> {
        let request = DerivedKey::new(false, GuestFieldSelect(1), 0, 0, 0);
        let mut sev_fw = Firmware::open().context("failed to open SEV firmware device.")?;
        let derived_key: [u8; 32] = sev_fw
            .get_derived_key(None, request)
            .context("failed to request derived key")?;

        // Create attestation report path
        let key_path = match args.key_path {
            Some(path) => path,
            None => {
                PathBuf::from_str("./derived_key.bin").context("unable to create default path")?
            }
        };

        // Write attestation report into desired file
        let mut key_file = if key_path.exists() {
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(key_path)
                .context("Unable to overwrite derived key file contents")?
        } else {
            fs::File::create(key_path)
                .context("Unable to create attestation report file contents")?
        };

        bincode::serialize_into(&mut key_file, &derived_key)
            .context("Could not serialize attestation report into file.")?;

        Ok(())
    }
}
