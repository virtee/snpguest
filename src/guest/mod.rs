use super::*;
use anyhow;
use std::io::Read;
use std::path::PathBuf;
use std::fs;
use std::io::ErrorKind;

use sev::firmware::guest::types::AttestationReport;

use openssl::x509::X509;

use certs::identify_cert;

// Function used to read contents of an attestation report file. Returns AttestationReport.
pub fn open_att_report(att_report_path: PathBuf) -> Result<AttestationReport, anyhow::Error> {

    // Open file from specified path
    let attestation_file = fs::File::open(att_report_path)?;

    // Deserialize content into AttestationReport
    let attestation_report = bincode::deserialize_from(attestation_file)
        .context("Could not parse attestation report.")?;

    Ok(attestation_report)
}

// Structure of 3 paths meant for cert-chain
// Should always keep order (ark,ask,vcek)
struct CertPaths(PathBuf,PathBuf,PathBuf);


// Tryfrom function that takes in 3 certificate paths, returns 3 x509 objects
impl TryFrom<CertPaths> for (X509, X509, X509) {
    type Error = anyhow::Error;
    fn try_from(content: CertPaths) -> Result<Self, Self::Error> {

        // Tracks current cert
        let mut i = 0;

        // Intitalize to first cert path (ARK)
        let mut current_cert = "ark";

        // Initialize to first cert content
        let mut current_path = &content.0;

        // Empty vector that will contain x509 objects
        let mut cert_chain = vec![];

        // Loop through certs
        while i <= 3 {
            
            // Get second cert values (ASK)
            if i.eq(&1) {
                current_cert = "ask";
                current_path =  &content.1;
            }
            // Get third cert values (VCEK)
            else if i.eq(&2)  {
                current_cert = "vcek";
                current_path =  &content.2;
            }

            // Will contain cert data
            let mut buf = vec![];

            // If path string is empty, check for cert in default path directory
            // If path is not empty, use provided path
            let mut current_file = if current_path.as_os_str().is_empty() {
                let temp_file = match fs::File::open(format!("./certs/{current_cert}.pem")) {
                    Ok(file) => file,
                    Err(err) => match err.kind() {
                        ErrorKind::NotFound => match fs::File::open(format!("./certs/{current_cert}.der")) {
                            Ok(file) => file,
                            Err(e) => panic!("Problem opening {current_cert} file {:?}", e),
                        },
                        other_error => {
                            panic!("Problem opening {current_cert} file {:?}", other_error)
                        }
                    },
                };
                temp_file
            } else {
                fs::File::open(current_path).context(format!("Could not open provided {current_cert} file"))?
            };

            // Read certificate contents
            current_file.read_to_end(&mut buf).context(format!("Could not read contents of {current_cert} file"))?;

            // Convert to x509 from data, check to see if in der or pem format
            let x509_cert = if identify_cert(&buf[0..27]).eq("pem") {
                X509::from_pem(&buf).context(format!("Could not convert {current_cert} data into X509"))?
            } else {
                X509::from_der(&buf).context(format!("Could not convert {current_cert} data into X509"))?
            };

            cert_chain.push(x509_cert);

            i += 1;
        };

        Ok((cert_chain[0].clone(), cert_chain[1].clone(), cert_chain[2].clone()))

        }
    }        


// Function to get cert-chain from provided paths as x509 certs.
pub fn grab_cert_chain(
    ark_path: PathBuf,
    ask_path: PathBuf,
    vcek_path: PathBuf,
) -> Result<(X509, X509, X509), anyhow::Error> {
    let cert_paths = CertPaths(ark_path, ask_path, vcek_path);

    Ok(cert_paths.try_into()?)
}

// Guest command options
#[derive(StructOpt)]
pub enum GuestCmd {
    #[structopt(about = "Display attestation report from a given file.")]
    DisplayAttestation(display_attestation::Args),

    #[structopt(about = "Verify the root of trust using the certificate chain")]
    VerifyRootOfTrust(verify_rot::Args),
}

pub fn cmd(cmd: GuestCmd) -> Result<()> {
    match cmd {
        GuestCmd::DisplayAttestation(args) => display_attestation::display_attestation_report(args),
        GuestCmd::VerifyRootOfTrust(args) => verify_rot::validate_rot(args),
    }
}


// Module to verify root of trust
mod verify_rot {
    use super::*;

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(
            long,
            default_value = "",
            help = "AMD Root Key (ARK) location"
        )]
        pub ark_path: PathBuf,

        #[structopt(
            long,
            default_value = "",
            help = "AMD Signing Key (ASK) location"
        )]
        pub ask_path: PathBuf,

        #[structopt(
            long,
            default_value = "",
            help = "Versioned Chip Endorsement Key (VCEK) location"
        )]
        pub vcek_path: PathBuf,
    }

 
    // Verify root of trust function
    pub fn validate_rot(args: Args) -> Result<()> {

        // Get x509 certs from cert paths
        let (ark, ask, vcek) = grab_cert_chain(args.ark_path, args.ask_path, args.vcek_path)
            .context("Could not get cert chain from provided files")?;

        // get ark and ask public keys
        let ark_pubkey = ark
            .public_key()
            .context("Could not get the ark public key.")?;
        let ask_pubkey = ask
            .public_key()
            .context("Could not get the ask public key")?;

        // Verify root of trust using public keys
        if !ark
            .verify(&ark_pubkey)
            .context("Failed to verify with ark certificate")?
        {
            return Err(anyhow::anyhow!("The AMD ARK is not self-signed!"));
        }

        if !ask
            .verify(&ark_pubkey)
            .context("Failed to verify ask certificate")?
        {
            return Err(anyhow::anyhow!("The AMD ASK ws not signed by the AMD ARK!"));
        }

        if vcek
            .verify(&ask_pubkey)
            .context("Failed to verify vcek certificate")?
        {
            return Err(anyhow::anyhow!("The VCEK was not signed by the AMD ASK!"));
        }

        Ok(())
    }
}

// Module to display an attestation report
mod display_attestation {
    use super::*;

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(
            long,
            default_value = "./attestation_report.bin",
            help = "File to write the attestation report to."
        )]
        pub report_file: PathBuf,
    }

    // Function to display attestation report
    pub fn display_attestation_report(args: Args) -> Result<()> {
        // Open attestation report using deserialize and print contents
        let att_report =
            open_att_report(args.report_file).context("Could not open attestation report")?;

        println!("{}", att_report);

        Ok(())
    }
}
