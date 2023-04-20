use super::*;

use bincode;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::{Path,PathBuf};
use reqwest::blocking::{get,Response};

use sev::firmware::{
    guest::{
        types::SnpReportReq,
        Firmware,
    },
    host::types::SnpCertType,
};

use certs::identify_cert;

// Request command structure
#[derive(StructOpt)]
pub enum RequestCmd {

    #[structopt(about = "Request an attestation report from the PSP.")]
    Report(report::Args),

    #[structopt(
        about = "Request an extended attestation report from the PSP. (Attestation Report + certificate chain)"
    )]
    ExtendedReport(extended_report::Args),

    #[structopt(about = "Request the certificate chain from the KDS.")]
    CertificateChain(cert_chain::Args),

    #[structopt(about = "Request the VCEK from the KDS.")]
    VCEK(vcek::Args),
}

// Diffrent request options
pub fn cmd(cmd: RequestCmd) -> Result<()> {
    match cmd {
        RequestCmd::Report(args) => report::get_report(args),
        RequestCmd::ExtendedReport(args) => extended_report::get_extended_report(args),
        RequestCmd::CertificateChain(args) => cert_chain::request_cert_chain(args),
        RequestCmd::VCEK(args) => vcek::request_vcek(args),
    }
}

// Module to request a regular report
mod report {

    use super::*;

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(
            long,
            help = "(Optional) Used for the SnpGuestRequest, specifies the message version number defaults to 1."
        )]
        pub message_version: Option<u8>,

        #[structopt(long, help = "SNP Report data to pass in. Must be 64 bytes in any format.")]
        pub request_file: PathBuf,

        #[structopt(
            long,
            default_value = "0",
            help = "VMPL level the Guest is running on."
        )]
        pub vmpl: u32,

        #[structopt(
            long,
            default_value = "./attestation_report.bin",
            help = "File to write the attestation report to."
        )]
        pub att_report_path: PathBuf,
    }

    // Request report function
    pub fn get_report(args: Args) -> Result<()> {
        
        // Open SEV firmware device
        let mut sev_fw: Firmware =
            Firmware::open().context("failed to open SEV firmware device.")?;

        // Read the report request file
        let mut request_file = File::open(args.request_file.clone())
            .context("Could not open the report request file.")?;
        let mut request_data: [u8; 64] = [0; 64];
        request_file
            .read(&mut request_data)
            .context("Could not read report request file.")?;

        // Create an SNP Report Request structure
        let snp_data: SnpReportReq = SnpReportReq::new(Some(request_data), args.vmpl);

        // Request attestation rerport
        let att_report = sev_fw
            .snp_get_report(args.message_version, snp_data)
            .context("Failed to get report.")?;

        // Write attestation report into a bin file
        let mut attestation_file = File::create(args.att_report_path.clone())
            .context("Failed to create Attestation Report File")?;
        bincode::serialize_into(&mut attestation_file, &att_report)
            .context("Could not serialize attestation report into file.")?;

        Ok(())
    }
}

// Module to request extended-report
mod extended_report {
    use super::*;

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(
            long,
            help = "(Optional) Used for the SnpGuestRequest, specifies the message version number defaults to 1."
        )]
        pub message_version: Option<u8>,

        #[structopt(long, help = "SNP Report data to pass in. Must be 64 bytes in any format.")]
        pub request_file: PathBuf,

        #[structopt(
            long,
            default_value = "0",
            help = "VMPL level the Guest is running on."
        )]
        pub vmpl: u32,

        #[structopt(
            long,
            default_value = "./attestation_report.bin",
            help = "File to write the attestation report to."
        )]
        pub att_report_path: PathBuf,

        #[structopt(
            long,
            default_value = "",
            help = "File to write the AMD Root Key (ARK) to. Will default to ./certs/ark.pem or ./certs/ark.der"
        )]
        pub ark_path: PathBuf,

        #[structopt(
            long,
            default_value = "",
            help = "File to write the AMD Signing Key (ASK) to. Will default to ./certs/ask.pem or ./certs/ask.der"
        )]
        pub ask_path: PathBuf,

        #[structopt(
            long,
            default_value = "",
            help = "File to write the he Versioned Chip Endorsement Key (VCEK) to. Will default to ./certs/vcek.pem or ./certs/vcek.der"
        )]
        pub vcek_path: PathBuf,
    }

    //Request extended report function
    pub fn get_extended_report(args: Args) -> Result<()> {
        
        // Open sev firmware device
        let mut sev_fw: Firmware =
            Firmware::open().context("failed to open SEV firmware device.")?;

        // Read request file contents
        let mut request_file = File::open(args.request_file.clone())
            .context("Could not open the report request file.")?;
        let mut request_data: [u8; 64] = [0; 64];
        request_file
            .read(&mut request_data)
            .context("Could not read report request file.")?;
        
        // Create snp request structure
        let snp_data: SnpReportReq = SnpReportReq::new(Some(request_data), args.vmpl);

        // Request extended report
        let (att_report, certificates) = sev_fw
            .snp_get_ext_report(args.message_version, snp_data)
            .context("Failed to get extended report.")?;

        // Write attestation report into file
        let mut attestation_file = File::create(args.att_report_path.clone())
            .context("Failed to create Attestation Report File")?;
        bincode::serialize_into(&mut attestation_file, &att_report)
            .context("Could not serialize attestation report into file.")?;

        // Check for certificates
        if certificates.is_empty() {
            panic!("The certicate chain was not loaded by the host")
        }
        
        // If default path is being used, make sure certs folder is created if missing
        if args.ark_path.as_os_str().is_empty() | args.ask_path.as_os_str().is_empty() | args.vcek_path.as_os_str().is_empty() {
            if !Path::new("./certs").is_dir() {
                fs::create_dir("./certs").context("Could not create certs folder")?;
            }
        }

        // Cycle throgh certs and write them into the passed file path.
        // If default path is being used, then check for cert type first to write it into correct file type
        for cert in certificates.iter() {
            let mut f = match cert.cert_type {

                SnpCertType::ARK => {
                    let mut path = args.ark_path.clone();

                    if path.as_os_str().is_empty() {
                        path = PathBuf::from("./certs");
                        let encode_type = identify_cert(&cert.data[0..27]);
                        if encode_type.eq("pem") {
                            path.push("ark.pem")
                        } else {
                            path.push("ark.der")
                        }
                    }

                    fs::File::create(path).context("unable to create/open ARK file")?
                },

                SnpCertType::ASK => {
                    let mut path = args.ask_path.clone();

                    if path.as_os_str().is_empty(){
                        path = PathBuf::from("./certs");
                        let encode_type = identify_cert(&cert.data[0..27]);
                        if encode_type.eq("pem") {
                            path.push("ask.pem")
                        } else {
                            path.push("ask.der")
                        }
                    }

                    fs::File::create(path).context("unable to create/open ASK file")?
                },

                SnpCertType::VCEK => {
                    let mut path = args.vcek_path.clone();

                    if path.as_os_str().is_empty(){
                        path = PathBuf::from("./certs");
                        let encode_type = identify_cert(&cert.data[0..27]);
                        if encode_type.eq("pem") {
                            path.push("vcek.pem")
                        } else {
                            path.push("vcek.der")
                        }
                    }

                    fs::File::create(path).context("unable to create/open VCEK file")?
                },
                
                _ => continue,
            };

            f.write(&cert.data)
                .context(format!("unable to write data to file {:?}", f))?;
        }

        Ok(())
    }
}

// Module to request cert-chain from kds (ask & ark)
mod cert_chain {
    use super::*;
    use openssl::x509::X509;

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(
            long = "processor",
            help = "Specify processor version for the certificate chain",
            default_value = "Milan"
        )]
        pub processor_type: String,

        #[structopt(
            long,
            default_value = "./certs/ark.pem",
            help = "File to write the AMD Root Key (ARK) to "
        )]
        pub ark_path: PathBuf,

        #[structopt(
            long,
            default_value = "./certs/ask.pem",
            help = "File to write the AMD Signing Key (ASK) to"
        )]
        pub ask_path: PathBuf,
    }

    // Function to request certificate chain
    pub fn request_cert_chain(args: Args) -> Result<()> {
        
        // KDS URL parameters
        const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
        const KDS_VCEK: &str = "/vcek/v1";
        const KDS_CERT_CHAIN: &str = "cert_chain";
        let sev_prod_name: &str = &args.processor_type;

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

        // Grab the ask and ark individually
        let ask = &certificates[0];
        let ark = &certificates[1];

        // If default path is being used, make sure that certs folder exists
        // If missing create it
        if args.ark_path.as_os_str().eq("./certs/ark.pem") | args.ask_path.as_os_str().eq("./certs/ask.pem") {
            if !Path::new("./certs").exists() {
                fs::create_dir("./certs").context("Could not create certs folder")?;
            }
        }

        // Write ark into file
        let mut ark_file =
            fs::File::create(args.ark_path.clone()).context("unable to create/open ARK file")?;
        ark_file
            .write(&ark.to_pem()?)
            .context(format!("unable to write data to file {:?}", ark_file))?;

        // Write ask into file
        let mut ask_file =
            fs::File::create(args.ask_path.clone()).context("unable to create/open ASK file")?;
        ask_file
            .write(&ask.to_pem()?)
            .context(format!("unable to write data to file {:?}", ask_file))?;

        Ok(())
    }
}

// Module to request vcek from KDS
mod vcek {
    use super::*;
    use guest::open_att_report;

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(
            long = "processor",
            help = "Specify processor version for the certificate chain",
            default_value = "Milan"
        )]
        pub processor_type: String,

        #[structopt(
            long,
            default_value = "./certs/vcek.der",
            help = "File to write the he Versioned Chip Endorsement Key (VCEK) to"
        )]
        pub vcek_path: PathBuf,

        #[structopt(
            long,
            default_value = "./attestation_report.bin",
            help = "File to read attestation report from"
        )]
        pub att_report_path: PathBuf,
    }

    // Function to request vcek from KDS
    pub fn request_vcek(args: Args) -> Result<()> {

        // KDS URL parameters
        const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
        const KDS_VCEK: &str = "/vcek/v1";
        let sev_prod_name: &str = &args.processor_type;

        // Open existing attestation report to get needed parameters for URL
        let att_report = open_att_report(args.att_report_path)
            .context("Could not open attestation report file.")?;

        //Convert chip id into hex
        let hw_id: String = hex::encode(&att_report.chip_id);

        // Create the vcek url
        let vcek_url: String = format!(
            "{KDS_CERT_SITE}{KDS_VCEK}/{sev_prod_name}/\
            {hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            att_report.reported_tcb.boot_loader,
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
        if args.vcek_path.as_os_str().eq("./certs/vcek.der") {
            if !Path::new("./certs").exists() {
                fs::create_dir("./certs").context("Could not create certs folder")?;
            }
        }

        // Create Vcek file and write contents into it.
        let mut vcek_file =
            fs::File::create(args.vcek_path.clone()).context("unable to create/open VCEK file")?;
        vcek_file
        .write(&vcek_rsp_bytes)
        .context(format!("unable to write data to file {:?}", vcek_file))?;

         Ok(())
    }
}
