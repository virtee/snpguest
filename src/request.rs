use super::*;

use std::{
    fs, 
    fs::File,
    io,
    io::{Read, Write, BufWriter}, 
    path::{Path, PathBuf},
    str::FromStr
};

use bincode;
use reqwest::blocking::{get,Response};
use rand::{RngCore, thread_rng};

use sev::firmware::{
    guest::{Firmware,AttestationReport},
    host::CertType
};

use certs::identify_cert;

// Create 64 random bytes of data
pub fn create_random_request() -> [u8; 64] {
    let mut data = [0u8; 64];
    thread_rng().fill_bytes(&mut data);
    return data
}

// Write data into given file
pub fn write_hex<W: Write>(file: &mut BufWriter<W>, data: &[u8]) -> Result<()> {
    let mut line_counter = 0;
    for val in data {
        // Make it blocks for easier read
        if line_counter.eq(&16){
            write!(file,"\n").context("Failed to write data to file")?;
            line_counter = 0;
        }
        // Write byte into file
        write!(file, "{:02x} ", val).context("Failed to write data to file")?;
        line_counter += 1;
    }
    Ok(())
}

// Request command structure
#[derive(StructOpt)]
pub enum RequestCmd {

    #[structopt(about = "Request an attestation report from the PSP.")]
    Report(report::Args),

    #[structopt(about = "Request the certificate chain (ARK & ASK) from the KDS.")]
    CertificateChain(cert_chain::Args),

    #[structopt(about = "Request the VCEK from the KDS.")]
    VCEK(vcek::Args),
}

// Diffrent request options
pub fn cmd(cmd: RequestCmd) -> Result<()> {
    match cmd {
        RequestCmd::Report(args) => report::get_report(args),
        RequestCmd::CertificateChain(args) => cert_chain::request_cert_chain(args),
        RequestCmd::VCEK(args) => vcek::request_vcek(args),
    }
} 

// Module to request an attestation report
mod report {

use super::*;

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(
            long = "extended",
            short,
            help = "Request an extended report instead of the regular report"
        )]
        pub extended_report: bool,
        
        #[structopt(
            long = "message-version",
            short,
            help = "Used for the SnpGuestRequest, specifies the message version number. Defaults to 1"
        )]
        pub message_version: Option<u8>,

        #[structopt(
            long = "vmpl",
            short,
            help = "VMPL level the Guest is running on. Defaults to 1"
        )]
        pub vmpl: Option<u32>,

        #[structopt(
            long = "random",
            short,
            help = "Generate a random request file for the attestation report. Defaults to ./random-request-file.txt"
        )]
        pub random: bool,

        #[structopt(
            long = "request",
            help = "Path pointing to were the request-file location. If provided with random flag, then a random request file will be generated at that location"
        )]
        pub request_file: Option<PathBuf>,

        #[structopt(
            long = "attestation-report",
            short,
            help = "File to write the attestation report to. Defaults to ./attestation_report.bin"
        )]
        pub att_report_path: Option<PathBuf>,

        #[structopt(
            long = "ark",
            help = "File to write the AMD Root Key (ARK) to. Defaults to ./certs/ark.pem or ./certs/ark.der"
        )]
        pub ark_path: Option<PathBuf>,

        #[structopt(
            long = "ask",
            help = "File to write the AMD Signing Key (ASK) to. Defaults to ./certs/ask.pem or ./certs/ask.der"
        )]
        pub ask_path: Option<PathBuf>,

        #[structopt(
            long = "vcek",
            help = "File to write the he Versioned Chip Endorsement Key (VCEK) to. Defaults to ./certs/vcek.pem or ./certs/vcek.der"
        )]
        pub vcek_path: Option<PathBuf>,
    }

    // Request report function
    pub fn get_report(args: Args) -> Result<()> {

        let mut sev_fw: Firmware =
            Firmware::open().context("failed to open SEV firmware device.")?;

        
        // Get Request data
        let request_data = match args.request_file{
            
            // Request path provided
            Some(path) => {
                
                // Generate random request data and place in specified path
                let request_data = if args.random {
                    let request_buf = create_random_request();
                    let file = File::create(path).context("Failed to create a random request file for report request")?;
                    write_hex(&mut BufWriter::new(file),&request_buf).context("Failed to write request data in request file")?;
                    request_buf
                
                // Open and read data on specified file
                } else {
                    let mut request_file = File::open(path)
                        .context("Could not open the report request file.")?;
                    let mut request_buf: [u8; 64] = [0; 64];
                    request_file
                        .read(&mut request_buf)
                        .context("Could not read report request file.")?;
                    request_buf
                };

                request_data
            },

            // No request path was provided
            None => {

                // random flag was passed, generate random buffer and place in default path
                let request_data = if args.random {
                    let request_buf = create_random_request();
                    let file = File::create("./random-request-file.txt").context("Failed to create a random request file for report request")?;
                    write_hex(&mut BufWriter::new(file),&request_buf).context("Failed to write request data in request file")?;
                    request_buf
                
                // Random flag was not passed, return error         
                    } else {
                        return Err(anyhow::anyhow!("Please provide a request-file or use --random flag to create one in order request attestation report."));
                    };

                request_data

            },

        };

        // Get VMPL level from arg
        let vmpl = match args.vmpl{
            Some(level) =>  if level > 3 {
                return Err(anyhow::anyhow!("Invalid VMPL level"));
            } else {
                level
            },
            None => 1
        };

        // Regular report requested
        if !args.extended_report {

            // Get attestation report path
            let att_report_path = match args.att_report_path {
                Some(path) => path,
                None => PathBuf::from_str("./attestation_report.bin").context("unable to create default path")?
            };

            // Request attestation rerport
            let att_report = sev_fw
                .get_report(args.message_version, Some(request_data), vmpl)
                .context("Failed to get report.")?;

            // Write attestation report into bin file
            let mut attestation_file = File::create(att_report_path)
                .context("Failed to create Attestation Report File")?;
            bincode::serialize_into(&mut attestation_file, &att_report)
                .context("Could not serialize attestation report into file.")?;
        
        // Extended report requested
        } else {

            // Get attestation report path
            let att_report_path = match args.att_report_path {
                Some(path) => path,
                None => PathBuf::from_str("./attestation_report.bin").context("unable to create attestation report default path")?
            };

            // Request extended report
            let (att_report, certificates) = sev_fw
                .get_ext_report(args.message_version, Some(request_data), vmpl)
                .context("Failed to get extended report.")?;

            // Write attestation report into file
            let mut attestation_file = File::create(att_report_path)
                .context("Failed to create Attestation Report File")?;
            bincode::serialize_into(&mut attestation_file, &att_report)
                .context("Could not serialize attestation report into file.")?;

            // Check for certificates
            if certificates.is_empty() {
                panic!("The certicate chain was not loaded by the host")
            }
    
            // If default path is being used, make sure certs folder is created if missing
            if args.ark_path.is_none() | args.ask_path.is_none() | args.vcek_path.is_none() {
                if !Path::new("./certs").is_dir() {
                    fs::create_dir("./certs").context("Could not create certs folder")?;
                }
            }

            // Cycle throgh certs and write them into the passed file path.
            // If default path is being used, then check for cert type first to write it into correct file type
            for cert in certificates.iter() {
                let mut f = match cert.cert_type {

                    CertType::ARK => {

                        // Check for path, if none is provided use default value
                        match args.ark_path {
                            Some(ref path) => fs::File::create(path).context("unable to create/open ARK file")?,
                            None => {
                                let mut path = PathBuf::from("./certs");
                                let encode_type = identify_cert(&cert.data[0..27]);
                                if encode_type.eq("pem") {
                                    path.push("ark.pem")
                                } else {
                                    path.push("ark.der")
                                }
                                fs::File::create(path).context("unable to create/open ARK file")?
                            }
                        }
                    },

                    CertType::ASK => {
                        // Check for path, if none is provided use default value
                        match args.ask_path {
                            Some(ref path) => fs::File::create(path).context("unable to create/open ASK file")?,
                            None => {
                                let mut path = PathBuf::from("./certs");
                                let encode_type = identify_cert(&cert.data[0..27]);
                                if encode_type.eq("pem") {
                                    path.push("ask.pem")
                                } else {
                                    path.push("ask.der")
                                }
                                fs::File::create(path).context("unable to create/open VCEK file")?
                            }
                        }
                    },

                    CertType::VCEK => {
                        // Check for path, if none is provided use default value
                        match args.vcek_path {
                            Some(ref path) => fs::File::create(path).context("unable to create/open VCEK file")?,
                            None => {
                                let mut path = PathBuf::from("./certs");
                                let encode_type = identify_cert(&cert.data[0..27]);
                                if encode_type.eq("pem") {
                                    path.push("vcek.pem")
                                } else {
                                    path.push("vcek.der")
                                }
                                fs::File::create(path).context("unable to create/open VCEK file")?
                            }
                        }
                    },
            
                    _ => continue,
                };

                f.write(&cert.data)
                    .context(format!("unable to write data to file {:?}", f))?;
            } 
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
            short,
            help = "Specify processor version for the certificate chain",
        )]
        pub processor_type: String,

        #[structopt(
            long = "ark",
            help = "File to write the AMD Root Key (ARK) to. Defaults to ./certs/ark.pem"
        )]
        pub ark_path: Option<PathBuf>,

        #[structopt(
            long = "ask",
            help = "File to write the AMD Signing Key (ASK) to. Defaults to ./certs/ask.pem"
        )]
        pub ask_path: Option<PathBuf>,
    }

    // Function to request certificate chain
    pub fn request_cert_chain(args: Args) -> Result<()> {
        
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

        // Grab the ask and ark individually
        let ask = &certificates[0];
        let ark = &certificates[1];

        // If default path is being used, make sure that certs folder exists
        // If missing create it
        // If default path is being used, make sure certs folder is created if missing
        if args.ark_path.is_none() | args.ask_path.is_none(){
            if !Path::new("./certs").is_dir() {
                fs::create_dir("./certs").context("Could not create certs folder")?;
            }
        }

        // Write ark into file
        let mut ark_file = match args.ark_path {
            Some(ref path) => fs::File::create(path).context("unable to create ARK file")?,
            None => fs::File::create("./certs/ark.pem").context("unable to create ARK file")?
        };
        ark_file
            .write(&ark.to_pem()?)
            .context(format!("unable to write data to file {:?}", ark_file))?;
        
        
        // Write ask into file
        let mut ask_file = match args.ask_path {
            Some(ref path) => fs::File::create(path).context("unable to create ASK file")?,
            None => fs::File::create("./certs/ask.pem").context("unable to create ASK file")?
        };
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
            short,
            help = "Specify processor version for the certificate chain",
        )]
        pub processor_type: String,

        #[structopt(
            long = "vcek",
            help = "File to write the he Versioned Chip Endorsement Key (VCEK) to"
        )]
        pub vcek_path: Option<PathBuf>,

        #[structopt(
            long = "attestation-report",
            short,
            help = "File to read attestation report from"
        )]
        pub att_report_path: Option<PathBuf>,
    }

    // Request an attestation report with default values and place into provided path if any.
    fn request_default_att(report_path: Option<PathBuf>) -> Result<AttestationReport, anyhow::Error> {
        let mut sev_fw: Firmware = Firmware::open().context("failed to open SEV firmware device.")?;

        // Get attestation report path
        let att_report_path = match report_path {
            Some(path) => path,
            None => PathBuf::from_str("./attestation_report.bin").context("unable to create default path")?
        };

        // Generate random data buffer
        let request_data = create_random_request();
        let file = File::create("./random-request-file.txt").context("Failed to create a random request file for report request")?;
        write_hex(&mut BufWriter::new(file),&request_data).context("Failed to write request data in request file")?;
        
        // Get attestation report
        let att_report = sev_fw.get_report(None, Some(request_data),1).context("Failed to get report.")?;

        // Write attestation report into a bin file
        let mut attestation_file = File::create(att_report_path)
            .context("Failed to create Attestation Report File")?;
        bincode::serialize_into(&mut attestation_file, &att_report)
            .context("Could not serialize attestation report into file.")?;

        Ok(att_report)
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
            None => PathBuf::from_str("./attestation_report.bin").context("unable to create default path")?
        };

        // Report doesn't exist in provided path, ask for user input, defaults to yes
        let att_report = if !att_report_path.exists() {
            println!("Attestation Report in provided path was not found.");
            println!("Would you like to request report with random data and default values? [Y|n]");
            
            // Read user input
            let mut rsp = String::new();
            io::stdin().read_line(&mut rsp).expect("failed to readline");
            match rsp.trim().to_lowercase().as_str() {
                
                // user said approved, put attestation report into provided path, continue with request
                "yes" | "y" | "" => request_default_att(Some(att_report_path)),
                
                // user declined, or wrong input
                "no" | "n" => return Err(anyhow::anyhow!("Please provide an attestation report to request a VCEK certificate from the KDS.")),
                _ => return Err(anyhow::anyhow!("Invalid response. Please provide an attestation report to request a VCEK certificate from the KDS.")),
            }?

        } else {

        // Open existing attestation report to get needed parameters for URL
            let att_report = open_att_report(att_report_path)
                .context("Could not open attestation report file.")?;

            att_report
        };

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
        if args.vcek_path.is_none() {
            if !Path::new("./certs").exists() {
                fs::create_dir("./certs").context("Could not create certs folder")?;
            }
        }

        // Grab vcek path or use default
        let vcek_path = match args.vcek_path {
            Some(path) => path,
            None => PathBuf::from_str("./certs/vcek.der").context("unable to create VCEK default path")?
        };

        // Create Vcek file and write contents into it.
        let mut vcek_file =
            fs::File::create(vcek_path).context("unable to create/open VCEK file")?;
        vcek_file
        .write(&vcek_rsp_bytes)
        .context(format!("unable to write data to file {:?}", vcek_file))?;

         Ok(())
    }
}
