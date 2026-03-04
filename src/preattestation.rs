// SPDX-License-Identifier: Apache-2.0

//! Pregenerates reference values.
//!
//! This module provides the following subcommands, which calculate pre-attestation
//! reference value.
//!
//! - `generate measurement` — Calculate the expected launch measurement digest.
//! - `generate ovmf-hash` — Calculate the hash of an OVMF binary.
//! - `generate id-block` — Generate an ID block and auth block for guest launch.
//! - `generate key-digest` — Generate an SEV key digest for an EC P-384 key.
//!
//! ## `generate measurement`
//!
//! ```bash
//! snpguest generate measurement [OPTIONS]
//! ```
//!
//! Calculates an expected launch digest measurement of secure guest, and prints
//! it into the terminal or stores it into the specified path.
//!
//! ### Options
//!
//! | Option | Description | Default |
//! | :--      | :--        | :--    |
//! | `-v, --vcpus` | Number of guest vCPUs. | 1 |
//! | `--vcpu-type` | Type of guest vCPU. Either this parameter, `--vcpu-sig`, or the triplet (`--vcpu-family`, `--vcpu-model`, `--vcpu-stepping`) must be specified. (Conflicts with the other `--vcpu-*` parameters) | *required* |
//! | `--vcpu-sig` | Guest vCPU signature value. (Conflicts with the other `--vcpu-*` options) | - |
//! | `--vcpu-family`, `--vcpu-model`, `--vcpu-stepping` | Guest vCPU family, model, and stepping. When specifying the vCPU type using these options, all three options must be specified. (Conflicts with `--vcpu-type` and `--vcpu-sig`) | - |
//! | `--vmm-type` | Guest VMM type (QEMU, EC2, KRUN). | - |
//! | `-o, --ovmf` | OVMF file path to calculate measurement from. Either this option or `--ovmf-hash` must be specified. (Conflicts with `--ovmf-hash`) | *required* |
//! | `-k, --kernel` | Kernel file path to calculate measurement from. | - |
//! | `-i, --initrd` | Initrd file path to calculate measurement from. (Requires `--kernel`) | - |
//! | `-a, --append` | Kernel command line to calculate measurement from. (Requires `--kernel`) | - |
//! | `-g, --guest-features` | Decimal or prefixed-hex representation of the guest kernel features expected to be included. | `0x1` |
//! | `--ovmf-hash` | Precalculated hash of the OVMF binary. (Conflicts with `--ovmf`) | - |
//! | `-f, --output-format` | Output format (`base64` or `hex`). | `hex` |
//! | `-m, --measurement-file` | Optional file path where measurement value can be stored in. | stdout |
//!
//! Every parameter passed in is used to calculate this measurement, but the user
//! does not need to provide every parameter.
//!
//! The only mandatory parameters are the `-o, --ovmf` parameter which is a path
//! to the ovmf file used to launch the secure guest, and provide the guest vCPU
//! type.
//!
//! There are 3 ways to provide the vCPU type, and the 3 of them are mutually
//! exclusive (will get an error if the user tries to use more than one method):
//!
//! - `--vcpu-type` A string with the vcpu-type used to launch the secure guest
//! - `--vcpu-sig` The signature of the vcpu-type used to launch the secure guest
//! - `--vcpu-family, --vcpu-model, --vcpu-stepping` The family, model and
//!   stepping of the vcpu used to launch the secure guest. Family, model and
//!   stepping have to be used together, if they are not all provided together
//!   an error will be raised.
//!
//! If the user specifies the `-k, --kernel` parameter to calculate measurements,
//! they can also specify `-i, --initrd` and `-a, --append`. These parameters
//! are unnecessary if the kernel file already contains initrd and append.
//!
//! There were kernel features added that affect the result of the measurement
//! if those are enabled. With the `-g, --guest-features` parameter the user can
//! provide which of this features are enabled in their kernel.
//!
//! The `-g, --guest-features` can be a hex or decimal number that cover the
//! features enabled. For information on the guest-features bitfield checkout
//! [virtee/sev/src/measurement/vmsa.rs](https://github.com/virtee/sev/blob/main/src/measurement/vmsa.rs).
//!
//! A user can use a pre-calculated ovmf-hash using `--ovmf-hash`, but the ovmf
//! file still has to be provided.
//!
//! The calculated measurement will be printed in the console. If the user
//! wishes to store the measurement value they can provide a file path with
//! `-m, --measurement-file` and the measurement will get written there.
//!
//! If the global `-q, --quiet` flag is used, nothing will be printed out.
//!
//! ### List of vCPU types
//!
//! Currently the following vCPU types are available. The vCPU signature value
//! can be calculated from the cprresponding vCPU (family, model, stepping).
//! For details, see [AMD's CPUID Specification](https://www.amd.com/content/dam/amd/en/documents/archived-tech-docs/design-guides/25481.pdf).
//!
//! | vcpu_type | vcpu_family | vcpu_model | vcpu_stepping |
//! | :-- | :-- | :-- | :-- |
//! | `epyc` | 23 | 1 | 2 |
//! | `epyc-v1` | | | |
//! | `epyc-v2` | | | |
//! | `epyc-ibpb` | | | |
//! | `epyc-v3` | | | |
//! | `epyc-v4` | | | |
//! | `epyc-rome` | 23 | 49 | 0 |
//! | `epyc-rome-v1` | | | |
//! | `epyc-rome-v2` | | | |
//! | `epyc-rome-v3` | | | |
//! | `epyc-milan` | 25 | 1 | 1 |
//! | `epyc-milan-v1` | | | |
//! | `epyc-milan-v2` | | | |
//! | `epyc-genoa` | 25 | 17 | 0 |
//! | `epyc-genoa-v1` | | | |
//!
//! ## `generate ovmf-hash`
//!
//! ```bash
//! snpguest generate ovmf-hash [OPTIONS]
//! ```
//!
//! Calculates the hash of an ovmf file.
//!
//! ### Options
//!
//! | Option | Description | Default |
//! | :--      | :--        | :--    |
//! | `-o, --ovmf` | Path to OVMF file to calculate hash from | *required* |
//! | `-f, --output-format` | Output format (`hex` or `base64`) | `hex` |
//! | `--hash-file` | Optional file where hash value can be stored in | stdout |
//!
//! The user must specify the OVMF file using the `-o, --ovmf` option.
//!
//! The user can specify the output format using the `-f, --output-format`
//! option: "hex" or "base64" (default: "hex").
//!
//! The hash will be printed in the console, if the user wishes to store the
//! hash value they can provide a file path with `--hash-file` and the hash
//! will get written there.
//!
//! If the global `-q, --quiet` flag is used, nothing will be printed out.
//!
//! ## `generate id-block`
//!
//! ```bash
//! snpguest generate id-block $ID_BLOCK_KEY $AUTH_KEY $LAUNCH_DIGEST [OPTIONS]
//! ```
//!
//! Calculates an id-block and auth-block for a secure guest.
//!
//! ### Arguments and Options
//!
//! | Argument/Option | Description | Default |
//! | :--      | :--        | :--    |
//! | `$ID_BLOCK_KEY` | Path to the Id-Block key | *required* |
//! | `$AUTH_KEY` | Path to the Auth-Block key | *required* |
//! | `$LAUNCH_DIGEST` | Guest launch measurement in either Base64 encoding or hex (if hex prefix with 0x) | *required* |
//! | `-f, --family-id` | Family ID of the guest provided by the guest owner (16 bytes) | 0s |
//! | `-m, --image-id` | Image ID of the guest provided by the guest owner (16 bytes) | 0s |
//! | `-v, --version` | Id-Block version. Currently only version 1 is available | 1 |
//! | `-s, --svn` | SVN of the guest | 0 |
//! | `-p, --policy` | Launch policy of the guest. Can provide in decimal or hex format. | 0x30000 |
//! | `-i, --id-file` | Optional file where the Id-Block value can be stored in | stdout |
//! | `-a, --auth-info-file` | Optional file where the Auth-Block value can be stored in | stdout |
//!
//! The user needs to provide a path to two different EC P-384 keys
//! `$ID_BLOCK_KEY` and `$AUTH_KEY` in PEM or DER format. One will be for the
//! id-block the other for the auth-block.
//!
//! The user also needs to provide the launch digest `$LAUNCH_DIGEST` (in either
//! hex or base64 format) of the secure guest. The user can generate the launch
//! digest using the `generate measurement` command.
//!
//! The user can provide optional id's for further verification using the
//! `-f, --family-id` and `-m, image-id` paramerters. Each parameter is 16 raw
//! bytes (default: 0s).
//!
//! The user can provide the security version number of the guest using
//! `-s, --svn` (default: 0).
//!
//! The user can specify the launch policy of the guest using the `-p, --policy`
//! parameter. The policy can be provided in either hex or decimal format. It
//! will default to 0x30000. For more information on the guest-policy, see
//! [SEV-SNP Firmware ABI Specification](https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf).
//!
//! The blocks will be printed in the console, if the user wishes to store the
//! blocks values they can provide a file path with `-i, --id-file` for the
//! id-block and `-a, --auth-file` for the auth-block.
//!
//! If the global `-q, --quiet` flag is used, nothing will be printed out.
//!
//! ## `generate key-digest`
//!
//! ```bash
//! snpguest generate key-digest $KEY_PATH [-d, --key-digest-file]
//! ```
//!
//! Generates an SEV key digest for a provided EC P-384 key.
//!
//! ### Arguments and Options
//!
//! | Argument/Option | Description | Default |
//! | :--      | :--        | :--    |
//! | `$KEY_PATH` | Path to key to generate hash for | *required* |
//! | `-d, --key-digest-file` | File to store the key digest in | stdout |
//!
//! User needs to provide a path to the key `$KEY_PATH`. The key has to be an
//! EC P-384 key in either PEM or DER format.
//!
//! The digest will be printed in the console. If the user wishes to store the
//! digest value they can provide a file path with `-d, --key-digest-file`.
//!
//! If the global `-q, --quiet` flag is used, nothing will be printed out.

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

/// Subcommands for generating pre-attestation reference values.
#[derive(Subcommand)]
pub enum PreAttestationCmd {
    /// Calculate the expected launch measurement digest of a confidential VM.
    Measurement(measurement::Args),

    /// Calculate the hash of an OVMF binary.
    OvmfHash(ovmf_hash::Args),

    /// Generate an ID block and auth block for a confidential VM.
    IdBlock(idblock::Args),

    /// Generate an SEV key digest for an EC P-384 key.
    KeyDigest(keydigest::Args),
}

/// Dispatch to the appropriate generate subcommand handler.
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

    /// CLI arguments for `generate measurement`.
    ///
    /// Calculates the expected launch measurement digest of a confidential VM.
    /// The vCPU type must be specified using one of three mutually exclusive
    /// methods: `--vcpu-type`, `--vcpu-sig`, or the triplet
    /// (`--vcpu-family`, `--vcpu-model`, `--vcpu-stepping`).
    #[derive(Parser, Debug)]
    pub struct Args {
        /// Number of guest vCPUs.
        #[arg(short, long, default_value = "1")]
        pub vcpus: u32,

        /// Type of guest vCPU (e.g., EPYC, EPYC-v1, EPYC-Rome, EPYC-Milan, EPYC-Genoa).
        /// Conflicts with `--vcpu-sig` and the family/model/stepping triplet.
        #[arg(long, value_name = "vcpu-type",
            conflicts_with_all = ["vcpu_sig", "vcpu_family", "vcpu_model", "vcpu_stepping"],
            required_unless_present_any(["vcpu_sig", "vcpu_family", "vcpu_model", "vcpu_stepping"],
        ), ignore_case = true)]
        pub vcpu_type: Option<String>,

        /// Guest vCPU signature value. Conflicts with `--vcpu-type` and the
        /// family/model/stepping triplet.
        #[arg(long, value_name = "vcpu-sig", conflicts_with_all = ["vcpu_type", "vcpu_family", "vcpu_model", "vcpu_stepping"])]
        pub vcpu_sig: Option<i32>,

        /// Guest vCPU family. Must be used together with `--vcpu-model` and `--vcpu-stepping`.
        #[arg(long, value_name = "vcpu-family", conflicts_with_all = ["vcpu_type", "vcpu_sig"], requires_all = ["vcpu_model", "vcpu_stepping"])]
        pub vcpu_family: Option<i32>,

        /// Guest vCPU model. Must be used together with `--vcpu-family` and `--vcpu-stepping`.
        #[arg(long, value_name = "vcpu-model", conflicts_with_all = ["vcpu_type", "vcpu_sig"], requires_all = ["vcpu_family", "vcpu_stepping"])]
        pub vcpu_model: Option<i32>,

        /// Guest vCPU stepping. Must be used together with `--vcpu-family` and `--vcpu-model`.
        #[arg(long, value_name = "vcpu-stepping", conflicts_with_all = ["vcpu_type", "vcpu_sig"], requires_all = ["vcpu_family", "vcpu_model"])]
        pub vcpu_stepping: Option<i32>,

        /// Guest VMM type (QEMU, ec2, KRUN).
        #[arg(long, short = 't', value_name = "vmm-type", ignore_case = true)]
        pub vmm_type: Option<String>,

        /// Path to the OVMF file to calculate measurement from.
        #[arg(short, long, value_name = "ovmf", required = true)]
        pub ovmf: PathBuf,

        /// Path to the kernel file to include in measurement calculation.
        #[arg(short, long, value_name = "kernel")]
        pub kernel: Option<PathBuf>,

        /// Path to the initrd file to include in measurement calculation.
        /// Requires `--kernel`.
        #[arg(short, long, value_name = "initrd", requires = "kernel")]
        pub initrd: Option<PathBuf>,

        /// Kernel command line to include in measurement calculation.
        /// Requires `--kernel`.
        #[arg(short, long, value_name = "append", requires = "kernel")]
        pub append: Option<String>,

        /// Guest kernel features value (decimal or `0x`-prefixed hex). Defaults to 0x1.
        #[arg(short, long, value_name = "guest-features", value_parser=maybe_hex::<u64>)]
        pub guest_features: Option<u64>,

        /// Precalculated hash of the OVMF binary. Conflicts with `--ovmf`.
        #[arg(
            long,
            value_name = "ovmf-hash",
            conflicts_with = "ovmf",
            required_unless_present = "ovmf"
        )]
        pub ovmf_hash: Option<String>,

        /// Output format (`base64` or `hex`).
        #[arg(
            long,
            short = 'f',
            value_name = "output-format",
            default_value = "hex",
            ignore_case = true
        )]
        pub output_format: String,

        /// Optional file path to store the measurement value.
        #[arg(short = 'm', long, value_name = "measurement-file")]
        pub measurement_file: Option<PathBuf>,
    }

    /// Calculate and output the expected launch measurement digest.
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

    /// CLI arguments for `generate ovmf-hash`.
    #[derive(Parser)]
    pub struct Args {
        /// Path to the OVMF file to calculate the hash from.
        #[arg(short, long, value_name = "ovmf", required = true)]
        pub ovmf: PathBuf,

        /// Output format (`hex` or `base64`).
        #[arg(
            short = 'f',
            long,
            value_name = "output-format",
            default_value = "hex",
            ignore_case = true
        )]
        pub output_format: String,

        /// Optional file path to store the hash value.
        #[arg(long, value_name = "hash-file")]
        pub hash_file: Option<PathBuf>,
    }

    /// Calculate and output the OVMF hash.
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

    /// CLI arguments for `generate id-block`.
    ///
    /// Generates an ID block and auth block for a confidential VM using
    /// two EC P-384 keys (one for the ID block, one for the auth block)
    /// and a launch digest. Output is in Base64 (the format QEMU accepts).
    #[derive(Parser)]
    pub struct Args {
        /// Path to the ID block signing key (EC P-384, PEM or DER).
        #[arg(value_name = "id-block-key", required = true)]
        pub id_block_key: PathBuf,

        /// Path to the auth block signing key (EC P-384, PEM or DER).
        #[arg(value_name = "auth-key", required = true)]
        pub auth_key: PathBuf,

        /// Guest launch measurement in Base64 or `0x`-prefixed hex.
        #[arg(value_name = "launch-digest", required = true)]
        pub launch_digest: String,

        /// Family ID of the guest (32 hex characters = 16 bytes).
        #[arg(short, long, value_name = "family-id")]
        pub family_id: Option<String>,

        /// Image ID of the guest (32 hex characters = 16 bytes).
        #[arg(short = 'm', long, value_name = "image-id")]
        pub image_id: Option<String>,

        /// ID block version (currently only version 1).
        #[arg(short, long, value_name = "version")]
        pub version: Option<u32>,

        /// Security Version Number (SVN) of the guest.
        #[arg(short, long, value_name = "svn")]
        pub svn: Option<u32>,

        /// Launch policy of the guest (decimal or `0x`-prefixed hex).
        #[arg(short, long, value_name = "policy", value_parser=maybe_hex::<u64>)]
        pub policy: Option<u64>,

        /// Optional file path to store the ID block value (Base64).
        #[arg(short, long, value_name = "id-block-file")]
        pub id_file: Option<PathBuf>,

        /// Optional file path to store the auth block value (Base64).
        #[arg(short, long, value_name = "auth-info-file")]
        pub auth_file: Option<PathBuf>,
    }

    /// Generate ID block and auth block, outputting as Base64.
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

    /// CLI arguments for `generate key-digest`.
    #[derive(Parser)]
    pub struct Args {
        /// Path to the EC P-384 key (PEM or DER) to generate the digest for.
        #[arg(value_name = "key", required = true)]
        pub key: PathBuf,

        /// Optional file path to store the key digest (hex encoded).
        #[arg(short = 'd', long, value_name = "key-digest-file")]
        pub key_digest_file: Option<PathBuf>,
    }

    /// Calculate and output the SEV key digest for the given key.
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
