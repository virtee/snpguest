use super::*;

use reqwest::blocking::{get, Response};
use std::{
    fs,
    io::Write,
    path::PathBuf,
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
            help = "Specify the processor model for the certificate chain"
        )]
        pub processor_model: String,

        #[structopt(
            help = "Directory to store the certificates in"
        )]
        pub certs_dir: PathBuf,
    }

    // Function to request certificate chain
    pub fn request_ca_chain(args: Args) -> Result<()> {
        // KDS URL parameters
        const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
        const KDS_VCEK: &str = "/vcek/v1";
        const KDS_CERT_CHAIN: &str = "cert_chain";

        // Get the processor type
        let sev_prod_name = match args.processor_model.to_lowercase().as_str() {
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

        // Create certs folder if missing
        if !args.certs_dir.exists() {
            fs::create_dir(args.certs_dir.clone()).context("Could not create certs folder")?;
        }

        // Cycle through certs in stack
        for i in 0..2 {
            // Grab cert. 0 is ask and 1 is ark
            let cert = &certificates[i];

            // Create path to cert
            let mut curr_path = args.certs_dir.clone();
            let cert_type = if i.eq(&0) {
                curr_path.push("ask.pem");
                "ASK"
            } else {
                curr_path.push("ark.pem");
                "ARK"
            };

            // Create or open current cert and write contents into it
            let mut cert_file = if curr_path.exists(){
                std::fs::OpenOptions::new().write(true).truncate(true).open(curr_path).context(format!("Unable to overwrite {} cert contents", cert_type))?
            } else {
                fs::File::create(curr_path).context(format!("Unable to create {} file", cert_type))?
            };
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
            help = "Specify the processor model for the VCEK"
        )]
        pub processor_model: String,

        #[structopt(
            help = "Directory to store the VCEK in"
        )]
        pub certs_dir: PathBuf,

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
        let sev_prod_name = match args.processor_model.to_lowercase().as_str() {
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

        // Create certs folder if missing
        if !args.certs_dir.exists() {
            fs::create_dir(args.certs_dir.clone()).context("Could not create certs folder")?;
        }

        // Create vcek path
        let mut vcek_path = args.certs_dir.clone();
        vcek_path.push("vcek.der");

        // Create or open Vcek file and write contents into it.
        let mut vcek_file = if vcek_path.exists(){
            std::fs::OpenOptions::new().write(true).truncate(true).open(vcek_path).context("Unable to overwrite VCEK cert contents")?
        } else {
            fs::File::create(vcek_path).context("Unable to create VCEK cert")?
        };
        vcek_file
            .write(&vcek_rsp_bytes)
            .context(format!("unable to write data to file {:?}", vcek_file))?;

        Ok(())
    }
}
