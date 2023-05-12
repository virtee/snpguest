use super::*;

use reqwest::blocking::{get, Response};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

// Fetch command structure
#[derive(StructOpt)]
pub enum FetchCmd {
    #[structopt(about = "Fetch the certificate authority (ARK & ASK) from the KDS.")]
    CA(cert_authority::Args),

    #[structopt(about = "Fetch the VCEK from the KDS.")]
    VCEK(vcek::Args),
}

// Fetch Subcommands
pub fn cmd(cmd: FetchCmd) -> Result<()> {
    match cmd {
        FetchCmd::CA(args) => cert_authority::request_ca_chain(args),
        FetchCmd::VCEK(args) => vcek::request_vcek(args),
    }
}

// Module to request certificate authority from kds (ask & ark)
mod cert_authority {
    use super::*;
    use openssl::x509::X509;

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(
            long = "processor",
            short,
            help = "Specify processor version for the certificate chain"
        )]
        pub processor_type: String,

        #[structopt(
            long = "certs",
            short,
            help = "Directory to store certificates. Defaults to ./certs"
        )]
        pub certs_path: Option<PathBuf>,
    }

    // Function to request certificate chain
    pub fn request_ca_chain(args: Args) -> Result<()> {
        // KDS URL parameters
        const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
        const KDS_VCEK: &str = "/vcek/v1";
        const KDS_CERT_CHAIN: &str = "cert_chain";

        // Get the processor type
        let sev_prod_name = match args.processor_type.to_lowercase().as_str() {
            "milan" => "Milan",
            "genoa" => "Genoa",
            _ => return Err(anyhow::anyhow!("Processor type not found!")),
        };

        // Should make -> https://kdsintf.amd.com/vcek/v1/{SEV_PROD_NAME}/cert_chain
        let url: String = format!("{KDS_CERT_SITE}{KDS_VCEK}/{sev_prod_name}/{KDS_CERT_CHAIN}");

        //Get response from url
        let rsp: Response = get(&url).context("Could not get certs from URL")?;

        // Put the response into vector
        let body = rsp
            .bytes()
            .context("Unable to parse AMD certificate chain")?
            .to_vec();

        // Create a stack from the vector
        let certificates = X509::stack_from_pem(&body)?;

        // If default path is being used, make sure certs folder is created if missing
        if args.certs_path.is_none() {
            if !Path::new("./certs").is_dir() {
                fs::create_dir("./certs").context("Could not create certs folder")?;
            }
        }

        // Cycle through certs in stack
        for i in 0..2 {
            // Grab cert. 0 is ask and 1 is ark
            let cert = &certificates[i];

            // Create path
            let mut cert_dir = match args.certs_path.clone() {
                Some(path) => path,
                None => PathBuf::from("./certs"),
            };
            let cert_type = if i.eq(&0) {
                cert_dir.push("ask.pem");
                "ASK"
            } else {
                cert_dir.push("ark.pem");
                "ARK"
            };

            // Create cert file
            let mut cert_file = fs::File::create(cert_dir)
                .context(format!("Unable to create {} file", cert_type))?;

            // Write cert contents
            cert_file
                .write(&cert.to_pem()?)
                .context(format!("unable to write data to file {:?}", cert_file))?;
        }

        Ok(())
    }
}

// Module to request vcek from KDS
mod vcek {
    use super::*;

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(
            long = "processor",
            short,
            help = "Specify processor version for the certificate chain"
        )]
        pub processor_type: String,

        #[structopt(
            long = "certs",
            short,
            help = "Directory to store VCEK in. Defaults to ./certs"
        )]
        pub certs_path: Option<PathBuf>,

        #[structopt(
            long = "att-report",
            short,
            help = "File to read attestation report from. Defaults to ./attestation_report.bin"
        )]
        pub att_report_path: Option<PathBuf>,
    }

    // Function to request vcek from KDS
    pub fn request_vcek(args: Args) -> Result<()> {
        // KDS URL parameters
        const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
        const KDS_VCEK: &str = "/vcek/v1";

        // Get the processor type
        let sev_prod_name = match args.processor_type.to_lowercase().as_str() {
            "milan" => "Milan",
            "genoa" => "Genoa",
            _ => return Err(anyhow::anyhow!("Processor type not found!")),
        };

        // Get attestation report path
        let att_report_path = match args.att_report_path {
            Some(path) => path,
            None => PathBuf::from_str("./attestation_report.bin")
                .context("unable to create default path")?,
        };

        // Check that provided path contains an attestation report
        if !att_report_path.exists() {
            return Err(anyhow::anyhow!("No attestation report was found. Provide an attestation report to request VCEK from the KDS."));
        }

        // Grab attestation report
        let att_report = report::read_report(att_report_path)
            .context("Could not read attestation report contents.")?;

        //Convert chip id into hex
        let hw_id: String = hex::encode(&att_report.chip_id);

        // Create the vcek url
        let vcek_url: String = format!(
            "{KDS_CERT_SITE}{KDS_VCEK}/{sev_prod_name}/\
            {hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            att_report.reported_tcb.bootloader,
            att_report.reported_tcb.tee,
            att_report.reported_tcb.snp,
            att_report.reported_tcb.microcode
        );

        // Get VCEK contents from URL (already in der format)
        let vcek_rsp = get(&vcek_url).context("Could not get VCEK from URL")?;

        // Make vcek into byte vector
        let vcek_rsp_bytes = vcek_rsp.bytes().context("Unable to parse VCEK")?.to_vec();

        // Check to see if default path is being used.
        // If default path is being used, and certs directory is missing, create it.
        if args.certs_path.is_none() {
            if !Path::new("./certs").exists() {
                fs::create_dir("./certs").context("Could not create certs folder")?;
            }
        }

        // Grab vcek path or use default
        let mut vcek_path = match args.certs_path {
            Some(path) => path,
            None => PathBuf::from_str("./certs").context("unable to create default certs path")?,
        };
        vcek_path.push("vcek.der");

        // Create Vcek file and write contents into it.
        let mut vcek_file =
            fs::File::create(vcek_path).context("unable to create/open VCEK file")?;
        vcek_file
            .write(&vcek_rsp_bytes)
            .context(format!("unable to write data to file {:?}", vcek_file))?;

        Ok(())
    }
}
