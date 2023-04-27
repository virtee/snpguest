use super::*;
use anyhow;
use std::io::Read;
use std::path::PathBuf;
use std::fs;
use std::io::ErrorKind;

use sev::firmware::guest::AttestationReport;

use openssl::{
    ecdsa::EcdsaSig,
    x509::X509,
    sha::Sha384
};

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

// Function that will convert a cert path into an openssl x509 object
pub fn convert_path_to_cert(cert_path: &PathBuf, cert_type: &str) -> Result<X509, anyhow::Error> {
    
    // Will contain cert data
    let mut buf = vec![];

    // If path string is empty, check for cert in default path directory
    // If path is not empty, use provided path
    let mut current_file = if cert_path.as_os_str().is_empty() {
        let temp_file = match fs::File::open(format!("./certs/{cert_type}.pem")) {
            Ok(file) => file,
            Err(err) => match err.kind() {
                ErrorKind::NotFound => match fs::File::open(format!("./certs/{cert_type}.der")) {
                    Ok(file) => file,
                    Err(e) => panic!("Problem opening {cert_type} file {:?}", e),
                },
                other_error => {
                    panic!("Problem opening {cert_type} file {:?}", other_error)
                }
            },
        };
        temp_file
    } else {
        fs::File::open(cert_path).context(format!("Could not open provided {cert_type} file"))?
    };

    // Read certificate contents
    current_file.read_to_end(&mut buf).context(format!("Could not read contents of {cert_type} file"))?;

    // Convert to x509 from data, check to see if in der or pem format
    let x509_cert = if identify_cert(&buf[0..27]).eq("pem") {
        X509::from_pem(&buf).context(format!("Could not convert {cert_type} data into X509"))?
    } else {
        X509::from_der(&buf).context(format!("Could not convert {cert_type} data into X509"))?
    };

    Ok(x509_cert)

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

            // Get x509 cert object from path
            let x509_cert = convert_path_to_cert(current_path, current_cert)?;

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

    #[structopt(about = "Verify the trusted computing based (TCB)")]
    VerifyTCB(verify_tcb::Args),

    #[structopt(about = "Verify the Attestation Report Signature with the VCEK")]
    VerifyAttestationSignature(verify_attestation_signature::Args),
}

pub fn cmd(cmd: GuestCmd, quiet: bool) -> Result<()> {
    match cmd {
        GuestCmd::DisplayAttestation(args) => display_attestation::display_attestation_report(args),
        GuestCmd::VerifyRootOfTrust(args) => verify_rot::validate_rot(args, quiet),
        GuestCmd::VerifyTCB(args) => verify_tcb::validate_cert_metadata(args, quiet),
        GuestCmd::VerifyAttestationSignature(args) => verify_attestation_signature::verify_attestation_signature(args, quiet),
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
    pub fn validate_rot(args: Args, quiet:bool) -> Result<()> {
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
        if ark.verify(&ark_pubkey).context("Failed to verify with ark certificate")? {
            if !quiet {
                println!("The AMD ARK was self-signed!");
            }
            if ask.verify(&ark_pubkey).context("Failed to verify ask certificate")? {
                if !quiet {
                    println!("The AMD ASK was signed by the AMD ARK!");
                }
                if vcek.verify(&ask_pubkey).context("Failed to verify vcek certificate")? {
                    if !quiet {
                        println!("The VCEK was signed by the AMD ASK!");
                    }
                } else {
                    return Err(anyhow::anyhow!("The VCEK was not signed by the AMD ASK!"));
                }
            } else {
                return Err(anyhow::anyhow!("The AMD ASK ws not signed by the AMD ARK!"));
            }
        } else {
            return Err(anyhow::anyhow!("The AMD ARK is not self-signed!"));
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
            help = "Requested Attestation Report Location"
        )]
        pub att_report_path: PathBuf,
    }

    // Function to display attestation report
    pub fn display_attestation_report(args: Args) -> Result<()> {
        // Open attestation report using deserialize and print contents
        let att_report =
            open_att_report(args.att_report_path).context("Could not open attestation report")?;

        println!("{}", att_report);

        Ok(())
    }
}

// Module to verify Trusted Compute Base information
mod verify_tcb{
    use super::*;

    use asn1_rs::{oid, Oid, FromDer};

    use x509_parser::{
    self,
    certificate::X509Certificate,
    prelude::X509Extension,
    };

    enum SnpOid {
        BootLoader,
        Tee,
        Snp,
        Ucode,
        HwId,
    }

    // OID extensions for the VCEK, will be used to verify attestation report
    impl SnpOid {
        fn oid(&self) -> Oid {
            match self {
                SnpOid::BootLoader => oid!(1.3.6.1.4.1.3704.1.3.1),
                SnpOid::Tee => oid!(1.3.6.1.4.1.3704.1.3.2),
                SnpOid::Snp => oid!(1.3.6.1.4.1.3704.1.3.3),
                SnpOid::Ucode => oid!(1.3.6.1.4.1.3704.1.3.8),
                SnpOid::HwId => oid!(1.3.6.1.4.1.3704.1.4),
            }
        }
    }

    // Implement display for OID
    impl std::fmt::Display for SnpOid {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.oid().to_id_string())
        }
    }

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(
            long,
            default_value = "./attestation_report.bin",
            help = "File to write the attestation report to."
        )]
        pub att_report_path: PathBuf,

        #[structopt(
            long,
            default_value = "",
            help = "Versioned Chip Endorsement Key (VCEK) location"
        )]
        pub vcek_path: PathBuf,
    }

    // Check if the certificate extension matches provided value
    fn check_cert_ext_byte(ext: &X509Extension, val: u8) -> bool {
        if ext.value[0] != 0x2 {
            panic!("Invalid type encountered!");
        }
        if ext.value[1] != 0x1 && ext.value[1] != 0x2 {
            panic!("Invalid octet length encountered");
        }
        if let Some(byte_value) = ext.value.last() {
            *byte_value == val
        } else {
            false
        }
    }

    // Check if certificate extension bytes match provided bytes
    fn check_cert_ext_bytes(ext: &X509Extension, val: &[u8]) -> bool {
        ext.value == val
       }
    
    // Function to validate the vcek metadata with the TCB
    pub fn validate_cert_metadata(args: Args, quiet: bool) -> Result<()> {
        // Open attestation report from given path
        let attestation_report = open_att_report(args.att_report_path)?;

        // Open VCEK as an openssl x509 and convert it into der format
        let vcek_der = convert_path_to_cert(&args.vcek_path, "vcek")?.to_der().context("Could not convert VCEK to der.")?;

        // Convert der format VCEK into a x509Certificate (Different from openssl x509)
        let (_,vcek_x509) = X509Certificate::from_der(&vcek_der).context("Could not create X509Certificate from der")?;

        // Create Hashmap of the VCEK extensions
        let extensions: std::collections::HashMap<Oid, &X509Extension> = vcek_x509.extensions_map().context("Failed getting VCEK oids.")?;
        
        // Grab BootLoader information from VCEK and compare with attestation report
        if let Some(cert_bl) = extensions.get(&SnpOid::BootLoader.oid()) {
            if !check_cert_ext_byte(cert_bl, attestation_report.reported_tcb.boot_loader) {
                return Err(anyhow::anyhow!("Report TCB Boot Loader and Certificate Boot Loader mismatch encountered."));
            }
            if !quiet {
                println!("Reported TCB Boot Loader from certificate matches the attestation report.");
            }
        }
        
        // Grab Tee information from VCEK and compare with attestation report
        if let Some(cert_tee) = extensions.get(&SnpOid::Tee.oid()) {
            if !check_cert_ext_byte(cert_tee, attestation_report.reported_tcb.tee) {
                return Err(anyhow::anyhow!("Report TCB TEE and Certificate TEE mismatch encountered."));    
            }
            if !quiet {
                println!("Reported TCB TEE from certificate matches the attestation report.");
            }
        }
    
        // Grab SNP information from VCEK and compare with attestation report
        if let Some(cert_snp) = extensions.get(&SnpOid::Snp.oid()) {
            if !check_cert_ext_byte(cert_snp, attestation_report.reported_tcb.snp) {
                return Err(anyhow::anyhow!("Report TCB SNP and Certificate SNP mismatch encountered."));    
            }
            if !quiet {
                println!("Reported TCB SNP from certificate matches the attestation report.");
            }
        }
       
        // Grab Microcode information from VCEK and compare with attestation report
        if let Some(cert_ucode) = extensions.get(&SnpOid::Ucode.oid()) {
            if !check_cert_ext_byte(cert_ucode, attestation_report.reported_tcb.microcode) {
                return Err(anyhow::anyhow!("Report TCB Microcode and Certificate Microcode mismatch encountered."));
            }
            if !quiet {
                println!("Reported TCB Microcode from certificate matches the attestation report.");
            }
        }   

        // Grab HW ID information from VCEK and compare it with attestation report
        if let Some(cert_hwid) = extensions.get(&SnpOid::HwId.oid()) {
            if !check_cert_ext_bytes(cert_hwid, &attestation_report.chip_id) {
                return Err(anyhow::anyhow!("Report TCB Microcode and Certificate Microcode mismatch encountered."));
            }
            if !quiet {
                println!("Chip ID from certificate matches the attestation report.");
            }
        }

        Ok(())
    }
}

// Module to verify the attestation report signature
mod verify_attestation_signature{
    use super::*;

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(
            long,
            default_value = "./attestation_report.bin",
            help = "File to write the attestation report to."
        )]
        pub att_report_path: PathBuf,

        #[structopt(
            long,
            default_value = "",
            help = "Versioned Chip Endorsement Key (VCEK) location"
        )]
        pub vcek_path: PathBuf,
    }

    // Function to verify attestation report signature
    pub fn verify_attestation_signature(args: Args, quiet:bool) -> Result<()> {

        // Open Attestation Report
        let attestation_report = open_att_report(args.att_report_path)?;

        // Get ECDSASIG from the attestation report
        let ar_signature = EcdsaSig::try_from(&attestation_report.signature).context("Failed to get ECDSA Signature from attestation report.")?;

        // Make the attestation report bytes and grab the signed bytes
        let signed_bytes = &bincode::serialize(&attestation_report).context("Failed to get the signed bytes from the attestation report.")?[0x0..0x2A0];

        // Open VCEK from path
        let vcek = convert_path_to_cert(&args.vcek_path, "vcek")?;

        // Get public key from VCEK
        let vcek_pubkey = vcek.public_key().context("Failed to get the public key from the VCEK.")?.ec_key().context("Failed to convert VCEK public key into ECkey.")?;
        
        // Create a hash
        let mut hasher: Sha384 = Sha384::new();

        // Update hash with the signed bytes of the attestation report
        hasher.update(signed_bytes);

        // Get Hash digest
        let base_message_digest: [u8; 48] = hasher.finish();

        // Verify attestation report signatture with digest and VCEK public key
        if ar_signature.verify(base_message_digest.as_ref(), vcek_pubkey.as_ref()).context("Failed to verify attestation report signature with VCEK public key.")? {
            if !quiet{
                println!("VCEK signed the Attestation Report!");
            }
        } else {
            return Err(anyhow::anyhow!("VCEK did NOT sign the Attestation Report!"));
        }

        Ok(())
    }

}