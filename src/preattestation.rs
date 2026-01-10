// SPDX-License-Identifier: Apache-2.0
// This file defines the CLI for pre-attestation related processes, such as calculating the measurement or generating an ID-BLOCK

use super::*;
use base64::{engine::general_purpose, Engine as _};
use clap_num::maybe_hex;
use sev::{
    firmware::guest::GuestPolicy,
    measurement::{
        idblock::{generate_key_digest, snp_calculate_id},
        idblock_types::{FamilyId, ImageId},
        snp::{calc_snp_ovmf_hash, snp_calc_launch_digest, SnpLaunchDigest, SnpMeasurementArgs},
        vcpu_types::{cpu_sig, CpuType},
        vmsa::{GuestFeatures, VMMType},
    },
    parser::ByteParser,
};
use std::{fs::OpenOptions, io::Write, path::PathBuf};

#[derive(Subcommand)]
pub enum PreAttestationCmd {
    /// Calculate the Measurement of a confidential VM with the supplied parameters
    Measurement(measurement::Args),

    /// Calculated the hash of an OVMF file
    OvmfHash(ovmf_hash::Args),

    /// Generate an ID-Block and Auth-Block for a confidential VM with the supplied parameters
    IdBlock(idblock::Args),

    /// Generate a SEV key digest for the provided openssl key.
    KeyDigest(keydigest::Args),
}

pub fn cmd(cmd: PreAttestationCmd, quiet: bool) -> Result<()> {
    match cmd {
        PreAttestationCmd::Measurement(args) => measurement::generate_measurement(args, quiet),
        PreAttestationCmd::OvmfHash(args) => ovmf_hash::generate_ovmf_hash(args, quiet),
        PreAttestationCmd::IdBlock(args) => idblock::generate_id_block(args, quiet),
        PreAttestationCmd::KeyDigest(args) => keydigest::calculate_key_digest(args, quiet),
    }
}

mod measurement {

    use std::str::FromStr;

    use super::*;

    #[derive(Parser, Debug)]
    pub struct Args {
        /// Number of guest vcpus
        #[arg(short, long, default_value = "1")]
        pub vcpus: u32,

        /// Type of guest vcpu (EPYC, EPYC-v1, EPYC-v2, EPYC-IBPB, EPYC-v3, EPYC-v4,
        /// EPYC-Rome, EPYC-Rome-v1, EPYC-Rome-v2, EPYC-Rome-v3, EPYC-Milan, EPYC-
        /// Milan-v1, EPYC-Milan-v2, EPYC-Genoa, EPYC-Genoa-v1)
        #[arg(long, value_name = "vcpu-type", 
            conflicts_with_all = ["vcpu_sig", "vcpu_family", "vcpu_model", "vcpu_stepping"], 
            required_unless_present_any(["vcpu_sig", "vcpu_family", "vcpu_model", "vcpu_stepping"],
        ), ignore_case = true)]
        pub vcpu_type: Option<String>,

        /// Guest vcpu signature value
        #[arg(long, value_name = "vcpu-sig", conflicts_with_all = ["vcpu_type", "vcpu_family", "vcpu_model", "vcpu_stepping"])]
        pub vcpu_sig: Option<i32>,

        /// Guest vcpu family
        #[arg(long, value_name = "vcpu-family", conflicts_with_all = ["vcpu_type", "vcpu_sig"], requires_all = ["vcpu_model", "vcpu_stepping"])]
        pub vcpu_family: Option<i32>,

        /// Guest vcpu model
        #[arg(long, value_name = "vcpu-model", conflicts_with_all = ["vcpu_type", "vcpu_sig"], requires_all = ["vcpu_family", "vcpu_stepping"])]
        pub vcpu_model: Option<i32>,

        /// Guest vcpu stepping.
        #[arg(long, value_name = "vcpu-stepping", conflicts_with_all = ["vcpu_type", "vcpu_sig"], requires_all = ["vcpu_family", "vcpu_model"])]
        pub vcpu_stepping: Option<i32>,

        /// Type of guest vmm (QEMU, ec2, KRUN)
        #[arg(long, short = 't', value_name = "vmm-type", ignore_case = true)]
        pub vmm_type: Option<String>,

        /// OVMF file to calculate measurement from
        #[arg(short, long, value_name = "ovmf", required = true)]
        pub ovmf: PathBuf,

        /// Kernel file to calculate measurement from
        #[arg(short, long, value_name = "kernel")]
        pub kernel: Option<PathBuf>,

        /// Initrd file to calculate measurement from
        #[arg(short, long, value_name = "initrd", requires = "kernel")]
        pub initrd: Option<PathBuf>,

        /// Kernel command line to calculate measurement from
        #[arg(short, long, value_name = "append", requires = "kernel")]
        pub append: Option<String>,

        /// Hex representation of the guest kernel features expected to be included, defaults to 0x1
        #[arg(short, long, value_name = "guest-features", value_parser=maybe_hex::<u64>)]
        pub guest_features: Option<u64>,

        /// Precalculated hash of the OVMF binary
        #[arg(
            long,
            value_name = "ovmf-hash",
            conflicts_with = "ovmf",
            required_unless_present = "ovmf"
        )]
        pub ovmf_hash: Option<String>,

        ///Choose output format (base64, hex).
        #[arg(
            long,
            short = 'f',
            value_name = "output-format",
            default_value = "hex",
            ignore_case = true
        )]
        pub output_format: String,

        /// Optional file path where measurement value can be stored in
        #[arg(short = 'm', long, value_name = "measurement-file")]
        pub measurement_file: Option<PathBuf>,
    }

    pub fn generate_measurement(args: Args, quiet: bool) -> Result<()> {
        // Get VCPU type from either string, signature or family, model and step.
        let vcpu_type = if let Some(v_type) = args.vcpu_type {
            CpuType::try_from(v_type.as_str())?
        } else if let Some(sig) = args.vcpu_sig {
            CpuType::try_from(sig)?
        } else if let Some(family) = args.vcpu_family {
            let sig = cpu_sig(
                family,
                args.vcpu_model.unwrap(),
                args.vcpu_stepping.unwrap(),
            );
            CpuType::try_from(sig)?
        } else {
            return Err(anyhow::anyhow!("No VCPU Type provided"));
        };

        let guest_features = match args.guest_features {
            Some(gf) => GuestFeatures(gf),
            None => GuestFeatures::default(),
        };

        let append: Option<&str> = args.append.as_deref();

        let ovmf_hash_str: Option<&str> = args.ovmf_hash.as_deref();

        let vmm_type = match args.vmm_type {
            Some(vmm_type) => Some(VMMType::from_str(vmm_type.as_str())?),
            None => None,
        };

        let collected_args = SnpMeasurementArgs {
            vcpus: args.vcpus,
            vcpu_type,
            ovmf_file: args.ovmf,
            guest_features,
            kernel_file: args.kernel,
            initrd_file: args.initrd,
            append,
            ovmf_hash_str,
            vmm_type,
        };

        let launch_digest = match snp_calc_launch_digest(collected_args) {
            Ok(ld) => {
                if args.output_format == "hex" {
                    format!("0x{}", ld.get_hex_ld())
                } else {
                    general_purpose::STANDARD.encode(ld.get_hex_ld().as_bytes())
                }
            }
            Err(e) => return Err(anyhow::anyhow!("Error calculating the measurement:{e}")),
        };

        // If measurement file is provided, store measurement value in the file
        if let Some(measurement_file) = args.measurement_file {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(measurement_file)?;

            file.write_all(launch_digest.as_bytes())
                .expect("Unable to write data");
        }

        // Print measurement
        if !quiet {
            println!("{}", launch_digest);
        }

        Ok(())
    }
}

mod ovmf_hash {
    use super::*;

    #[derive(Parser)]
    pub struct Args {
        /// Path to OVMF file to calculate hash from
        #[arg(short, long, value_name = "ovmf", required = true)]
        pub ovmf: PathBuf,

        /// Choose output format (base64, hex). Defaults to hex
        #[arg(
            short = 'f',
            long,
            value_name = "output-format",
            default_value = "hex",
            ignore_case = true
        )]
        pub output_format: String,

        /// Optional file where hash value can be stored in
        #[arg(long, value_name = "hash-file")]
        pub hash_file: Option<PathBuf>,
    }
    pub fn generate_ovmf_hash(args: Args, quiet: bool) -> Result<()> {
        let ovmf_hash = match calc_snp_ovmf_hash(args.ovmf) {
            Ok(ld) => {
                if args.output_format == "hex" {
                    ld.get_hex_ld()
                } else {
                    general_purpose::STANDARD.encode(ld.get_hex_ld().as_bytes())
                }
            }
            Err(e) => return Err(anyhow::anyhow!("Error calculating the measurement:{e}")),
        };

        if let Some(hash_file) = args.hash_file {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(hash_file)?;

            file.write_all(ovmf_hash.as_bytes())
                .expect("Unable to write data");
        }

        if !quiet {
            println!("{}", ovmf_hash);
        }

        Ok(())
    }
}

mod idblock {
    use hex::FromHex;

    use super::*;

    #[derive(Parser)]
    pub struct Args {
        /// Path to the Id-Block key
        #[arg(value_name = "id-block-key", required = true)]
        pub id_block_key: PathBuf,

        /// Path to the Auth-Block key
        #[arg(value_name = "auth-key", required = true)]
        pub auth_key: PathBuf,

        /// Guest launch measurement in either Base64 encoding or hex (if hex prefix with 0x)
        #[arg(value_name = "launch-digest", required = true)]
        pub launch_digest: String,

        /// Family ID of the guest provided by the guest owner in hex. Has to be 32 characters (16 bytes).
        #[arg(short, long, value_name = "family-id")]
        pub family_id: Option<String>,

        /// Image ID of the guest provided by the guest owner in hex. Has to be 32 characters (16 bytes).
        #[arg(short = 'm', long, value_name = "image-id")]
        pub image_id: Option<String>,

        /// Id-Block version. Currently only version 1 is available
        #[arg(short, long, value_name = "version")]
        pub version: Option<u32>,

        /// SVN of the guest
        #[arg(short, long, value_name = "svn")]
        pub svn: Option<u32>,

        /// Launch policy of the guest. Can provide in decimal or hex format.
        #[arg(short, long, value_name = "policy", value_parser=maybe_hex::<u64>)]
        pub policy: Option<u64>,

        /// Optional file where the Id-Block value can be stored in
        #[arg(short, long, value_name = "id-block-file")]
        pub id_file: Option<PathBuf>,

        /// Optional file where the Auth-Block value can be stored in
        #[arg(short, long, value_name = "auth-info-file")]
        pub auth_file: Option<PathBuf>,
    }

    pub fn generate_id_block(args: Args, quiet: bool) -> Result<()> {
        let ld =
            if &args.launch_digest[..args.launch_digest.char_indices().nth(2).unwrap().0] == "0x" {
                SnpLaunchDigest::from_bytes(Vec::from_hex(&args.launch_digest[2..])?.as_slice())?
            } else {
                SnpLaunchDigest::from_bytes(
                    general_purpose::STANDARD
                        .decode(args.launch_digest)?
                        .as_slice(),
                )?
            };

        let family_id = match args.family_id {
            Some(s) => {
                if s.len() != 32 {
                    return Err(anyhow::anyhow!("Family ID must be 32 hex chars"));
                }
                let bytes: [u8; 16] =
                    <[u8; 16]>::from_hex(&s).map_err(|_| anyhow::anyhow!("Invalid hex"))?;
                Some(FamilyId::new(bytes))
            }
            None => None,
        };

        let image_id = match args.image_id {
            Some(s) => {
                if s.len() != 32 {
                    return Err(anyhow::anyhow!("Image ID must be 32 hex chars"));
                }
                let bytes: [u8; 16] =
                    <[u8; 16]>::from_hex(&s).map_err(|_| anyhow::anyhow!("Invalid hex"))?;
                Some(ImageId::new(bytes))
            }
            None => None,
        };

        let policy = args.policy.map(GuestPolicy);

        let measurements = snp_calculate_id(
            Some(ld),
            family_id,
            image_id,
            args.svn,
            policy,
            args.id_block_key,
            args.auth_key,
        )?;

        // Formatted in Base-64 since it's the format QEMU takes.
        let id_block_string = general_purpose::STANDARD.encode(measurements.id_block.to_bytes()?);
        let id_auth_string = general_purpose::STANDARD.encode(measurements.id_auth.to_bytes()?);

        // If Id-Block file is provided, store Id-Block value in the file
        if let Some(id_file) = args.id_file {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(id_file)?;

            file.write_all(id_block_string.as_bytes())
                .expect("Unable to write data");
        }

        // If Auth-Block file is provided, store Auth-Block value in the file
        if let Some(auth_file) = args.auth_file {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(auth_file)?;

            file.write_all(id_auth_string.as_bytes())
                .expect("Unable to write data");
        }

        if !quiet {
            println!("ID-BLOCK:");
            println!("{}", id_block_string);
            println!("AUTH-BLOCK:");
            println!("{}", id_auth_string);
        }
        Ok(())
    }
}

mod keydigest {
    use super::*;

    #[derive(Parser)]
    pub struct Args {
        /// Path to key to generate hash for
        #[arg(value_name = "key", required = true)]
        pub key: PathBuf,

        /// File to store the key digest in
        #[arg(short = 'd', long, value_name = "key-digest-file")]
        pub key_digest_file: Option<PathBuf>,
    }

    pub fn calculate_key_digest(args: Args, quiet: bool) -> Result<()> {
        let kd = generate_key_digest(args.key)?;

        let key_digest_string = hex::encode::<Vec<u8>>(kd.try_into().unwrap());

        if let Some(key_digest_file) = args.key_digest_file {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(key_digest_file)?;

            file.write_all(key_digest_string.as_bytes())
                .expect("Unable to write data");
        }

        if !quiet {
            println!("Key Digest:");
            println!("{}", key_digest_string);
        }
        Ok(())
    }
}
