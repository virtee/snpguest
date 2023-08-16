// SPDX-License-Identifier: Apache-2.0

use super::*;

use certs::{convert_path_to_cert, CertPaths};

use std::{io::ErrorKind, path::PathBuf};

use openssl::{ecdsa::EcdsaSig, sha::Sha384};
use sev::certs::snp::Chain;

#[derive(StructOpt)]
pub enum VerifyCmd {
    #[structopt(about = "Verify the certificate chain.")]
    Certs(certificate_chain::Args),

    #[structopt(about = "Verify the attestation report.")]
    Attestation(attestation::Args),
}

pub fn cmd(cmd: VerifyCmd, quiet: bool) -> Result<()> {
    match cmd {
        VerifyCmd::Certs(args) => certificate_chain::validate_cc(args, quiet),
        VerifyCmd::Attestation(args) => attestation::verify_attesation(args, quiet),
    }
}

// Find a certificate in specified directory according to its extension
pub fn find_cert_in_dir(dir: PathBuf, cert: &str) -> Result<PathBuf, anyhow::Error> {
    if dir.join(format!("{cert}.pem")).exists() {
        Ok(dir.join(format!("{cert}.pem")))
    } else if dir.join(format!("{cert}.der")).exists() {
        Ok(dir.join(format!("{cert}.der")))
    } else {
        return Err(anyhow::anyhow!("{cert} certificate not found in directory"));
    }
}

mod certificate_chain {
    use sev::certs::snp::Verifiable;

    use super::*;

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(help = "Path to directory containing certificate chain")]
        pub certs_dir: PathBuf,
    }

    // Function to validate certificate chain
    pub fn validate_cc(args: Args, quiet: bool) -> Result<()> {
        let ark_path = find_cert_in_dir(args.certs_dir.clone(), "ark")?;
        let ask_path = find_cert_in_dir(args.certs_dir.clone(), "ask")?;
        let vcek_path = find_cert_in_dir(args.certs_dir, "vcek")?;

        // Get a cert chain from directory
        let cert_chain: Chain = CertPaths {
            ark_path,
            ask_path,
            vcek_path,
        }
        .try_into()?;

        let ark = cert_chain.ca.ark;
        let ask = cert_chain.ca.ask;
        let vcek = cert_chain.vcek;

        // Verify each signature and print result in console
        match (&ark, &ark).verify() {
            Ok(()) => {
                if !quiet {
                    println!("The AMD ARK was self-signed!");
                }
            }
            Err(e) => match e.kind() {
                ErrorKind::Other => return Err(anyhow::anyhow!("The AMD ARK is not self-signed!")),
                _ => {
                    return Err(anyhow::anyhow!(
                        "Failed to verify the ARK cerfificate: {:?}",
                        e
                    ))
                }
            },
        }

        match (&ark, &ask).verify() {
            Ok(()) => {
                if !quiet {
                    println!("The AMD ASK was signed by the AMD ARK!");
                }
            }
            Err(e) => match e.kind() {
                ErrorKind::Other => {
                    return Err(anyhow::anyhow!("The AMD ASK ws not signed by the AMD ARK!"))
                }
                _ => return Err(anyhow::anyhow!("Failed to verify ASK certificate: {:?}", e)),
            },
        }

        match (&ask, &vcek).verify() {
            Ok(()) => {
                if !quiet {
                    println!("The VCEK was signed by the AMD ASK!");
                }
            }
            Err(e) => match e.kind() {
                ErrorKind::Other => {
                    return Err(anyhow::anyhow!("The VCEK was not signed by the AMD ASK!"))
                }
                _ => {
                    return Err(anyhow::anyhow!(
                        "Failed to verify VCEK certificate: {:?}",
                        e
                    ))
                }
            },
        }
        Ok(())
    }
}

mod attestation {
    use super::*;

    use asn1_rs::{oid, FromDer, Oid};

    use x509_parser::{self, certificate::X509Certificate, prelude::X509Extension};

    use sev::{certs::snp::Certificate, firmware::guest::AttestationReport};

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
                SnpOid::BootLoader => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .1),
                SnpOid::Tee => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .2),
                SnpOid::Snp => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .3),
                SnpOid::Ucode => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .8),
                SnpOid::HwId => oid!(1.3.6 .1 .4 .1 .3704 .1 .4),
            }
        }
    }

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(help = "Path to directory containing VCEK.")]
        pub certs_dir: PathBuf,

        #[structopt(help = "Path to attestation report to use for validation.")]
        pub att_report_path: PathBuf,

        #[structopt(long = "tcb", short, help = "Run the tcb verification only.")]
        pub tcb: bool,

        #[structopt(
            long = "signature",
            short,
            help = "Run the signature verification only."
        )]
        pub signature: bool,
    }

    fn verify_attestation_signature(
        vcek: Certificate,
        att_report: AttestationReport,
        quiet: bool,
    ) -> Result<()> {
        let vcek_pubkey = vcek
            .public_key()
            .context("Failed to get the public key from the VCEK.")?
            .ec_key()
            .context("Failed to convert VCEK public key into ECkey.")?;

        // Get the attestation report signature
        let ar_signature = EcdsaSig::try_from(&att_report.signature)
            .context("Failed to get ECDSA Signature from attestation report.")?;
        let signed_bytes = &bincode::serialize(&att_report)
            .context("Failed to get the signed bytes from the attestation report.")?[0x0..0x2A0];

        let mut hasher: Sha384 = Sha384::new();

        hasher.update(signed_bytes);

        let base_message_digest: [u8; 48] = hasher.finish();

        // Verify signature
        if ar_signature
            .verify(base_message_digest.as_ref(), vcek_pubkey.as_ref())
            .context("Failed to verify attestation report signature with VCEK public key.")?
        {
            if !quiet {
                println!("VCEK signed the Attestation Report!");
            }
        } else {
            return Err(anyhow::anyhow!("VCEK did NOT sign the Attestation Report!"));
        }

        Ok(())
    }

    // Check the cert extension byte to value
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

    // Check cert extension bytes to data
    fn check_cert_ext_bytes(ext: &X509Extension, val: &[u8]) -> bool {
        // Patching for a bug found in the VCEK where the raw bytes
        // were provided instead of a DER encoded Octet String. Now
        // this function will handle both.
        if ext.value.len() > 0x40 {
            if ext.value[0] != 0x4 {
                panic!("Invalid type encountered!");
            } else if ext.value[1] != 0x40 {
                panic!("Invalid octet length encountered");
            }
            &ext.value[2..] == val
        } else {
            ext.value == val
        }
    }

    fn verify_attestation_tcb(
        vcek: Certificate,
        att_report: AttestationReport,
        quiet: bool,
    ) -> Result<()> {
        let vcek_der = vcek.to_der().context("Could not convert VCEK to der.")?;
        let (_, vcek_x509) = X509Certificate::from_der(&vcek_der)
            .context("Could not create X509Certificate from der")?;

        // Collect extensions from VCEK
        let extensions: std::collections::HashMap<Oid, &X509Extension> = vcek_x509
            .extensions_map()
            .context("Failed getting VCEK oids.")?;

        // Compare bootloaders
        if let Some(cert_bl) = extensions.get(&SnpOid::BootLoader.oid()) {
            if !check_cert_ext_byte(cert_bl, att_report.reported_tcb.bootloader) {
                return Err(anyhow::anyhow!(
                    "Report TCB Boot Loader and Certificate Boot Loader mismatch encountered."
                ));
            }
            if !quiet {
                println!(
                    "Reported TCB Boot Loader from certificate matches the attestation report."
                );
            }
        }

        // Compare TEE information
        if let Some(cert_tee) = extensions.get(&SnpOid::Tee.oid()) {
            if !check_cert_ext_byte(cert_tee, att_report.reported_tcb.tee) {
                return Err(anyhow::anyhow!(
                    "Report TCB TEE and Certificate TEE mismatch encountered."
                ));
            }
            if !quiet {
                println!("Reported TCB TEE from certificate matches the attestation report.");
            }
        }

        // Compare SNP information
        if let Some(cert_snp) = extensions.get(&SnpOid::Snp.oid()) {
            if !check_cert_ext_byte(cert_snp, att_report.reported_tcb.snp) {
                return Err(anyhow::anyhow!(
                    "Report TCB SNP and Certificate SNP mismatch encountered."
                ));
            }
            if !quiet {
                println!("Reported TCB SNP from certificate matches the attestation report.");
            }
        }

        // Compare Microcode information
        if let Some(cert_ucode) = extensions.get(&SnpOid::Ucode.oid()) {
            if !check_cert_ext_byte(cert_ucode, att_report.reported_tcb.microcode) {
                return Err(anyhow::anyhow!(
                    "Report TCB Microcode and Certificate Microcode mismatch encountered."
                ));
            }
            if !quiet {
                println!("Reported TCB Microcode from certificate matches the attestation report.");
            }
        }

        // Compare HWID information
        if let Some(cert_hwid) = extensions.get(&SnpOid::HwId.oid()) {
            if !check_cert_ext_bytes(cert_hwid, &att_report.chip_id) {
                return Err(anyhow::anyhow!(
                    "Report TCB ID and Certificate ID mismatch encountered."
                ));
            }
            if !quiet {
                println!("Chip ID from certificate matches the attestation report.");
            }
        }

        Ok(())
    }

    pub fn verify_attesation(args: Args, quiet: bool) -> Result<()> {
        // Get attestation report
        let att_report = if !args.att_report_path.exists() {
            return Err(anyhow::anyhow!("No attestation report was found. Provide an attestation report to request VCEK from the KDS."));
        } else {
            report::read_report(args.att_report_path)
                .context("Could not open attestation report")?
        };

        // Get VCEK and grab its public key
        let vcek_path = find_cert_in_dir(args.certs_dir, "vcek")?;
        let vcek = convert_path_to_cert(&vcek_path, "vcek")?;

        if args.tcb || args.signature {
            if args.tcb {
                verify_attestation_tcb(vcek.clone(), att_report, quiet)?;
            }
            if args.signature {
                verify_attestation_signature(vcek, att_report, quiet)?;
            }
        } else {
            verify_attestation_tcb(vcek.clone(), att_report, quiet)?;
            verify_attestation_signature(vcek, att_report, quiet)?;
        }

        Ok(())
    }
}
