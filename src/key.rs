// SPDX-License-Identifier: Apache-2.0

//! Requests derived keys from AMD-SP.
//!
//! This module provides the `key` subcommand which requests derived keys from
//! the AMD-SP via the `SNP_GUEST_REQUEST(MSG_KEY_REQ)` ioctl. The derived key
//! is computed from a root key (VCEK or VMRK) mixed with configurable parameters
//! such as VMPL, Guest Field Select bits, guest SVN, TCB version, and launch
//! mitigation vector.
//!
//! ## `key`
//!
//! ```bash
//! snpguest key $KEY_PATH $ROOT_KEY_SELECT [OPTIONS]
//! ```
//!
//! ## Arguments and Options
//!
//! | :--      | :--        | :--    |
//! | `$KEY_PATH` | The path to store the derived key. | *required* |
//! | `$ROOT_KEY_SELECT` | The root key from which to derive the key (either `vcek` or `vmrk`). | *required* |
//! | `-v, --vmpl` | The VMPL value to mix into the key (0-3). Must be greater than or equal to the current VMPL. | 1 |
//! | `-g, --guest_field_select` | Guest Field Select bits to enable as a 64-bit integer (decimal, `0x`-prefixed hex or `0b`-prefixed bin). | 0 |
//! | `-s, --guest_svn` | Specifies the guest SVN to mix into the key (decimal, prefixed hex or prefixed bin). | 0 |
//! | `-t, --tcb_version` | Specifies the TCB version to mix into the derived key (decimal, prefixed hex or prefixed bin). Must not exceed the commited TCB. | 0 |
//! | `-l, --launch_mit_vector` | Specifies the launch mitigation vector value to mix into the derived key (decimal, prefixed hex or prefixed bin). Only available for `MSG_KEY_REQ` message version ≥ 2. | — |
//!
//! ## Structure of Guest Field Select
//!
//! | Bit      | Field             | Note |
//! | :--      | :--               | :--  |
//! | 63:7     | (Reserved)        | Currently unused. |
//! | 6 (MSB)  | Launch MIT Vector | Set to 0 if not specified; supported for `MSG_KEY_REQ` message version ≥ 2. |
//! | 5        | TCB Version       |      |
//! | 4        | SVN               |      |
//! | 3        | Measurement       |      |
//! | 2        | Family ID         |      |
//! | 1        | Image ID          |      |
//! | 0 (LSB)  | Guest Policy      |      |
//!
//! For example, all of
//!
//! - `--guest_field_select 49`
//! - `--guest_field_select 0x31`
//! - `--guest_field_select 0b110001`
//!
//! denote the following selection:
//!
//! ```plaintext
//! Guest Policy: On (1),
//! Image ID: Off (0),
//! Family ID: Off (0),
//! Measurement: Off (0),
//! SVN: On (1),
//! TCB Version: On (1),
//! Launch MIT Vector: Off or None (0).
//! ```
//!
//! ## Example
//!
//! ```bash
//! # Creating and storing a derived key
//! snpguest key derived-key.bin vcek --guest_field_select 0b110001 --guest_svn 2 --tcb_version 1 --vmpl 3
//! ```

use super::*;
use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};
use std::io::Read;
use std::{fs, path::PathBuf};

/// CLI arguments for the `key` subcommand.
///
/// Requests a derived key from the AMD-SP and stores it in a file.
/// The key is derived from a root key (VCEK or VMRK) mixed with the
/// specified parameters.
#[derive(Parser)]
pub struct KeyArgs {
    /// Path where the derived key will be stored.
    #[arg(value_name = "key-path", required = true)]
    pub key_path: PathBuf,

    /// Root key from which to derive the key (`vcek` or `vmrk`).
    #[arg(value_name = "root-key-select", required = true, ignore_case = true)]
    pub root_key_select: String,

    /// VMPL (Virtual Machine Privilege Level) to mix into the key (0-3).
    /// Must be greater than or equal to the current VMPL. Default is 1.
    #[arg(short, long, value_name = "vmpl", default_value = "1")]
    pub vmpl: u32,

    /// Guest Field Select bits to enable as a 64-bit integer. Only the
    /// least-significant 6 bits (message version 1) or 7 bits (message
    /// version 2) are defined; higher bits must be zero. Bits (LSB to MSB):
    /// 0=Guest Policy, 1=Image ID, 2=Family ID, 3=Measurement, 4=SVN,
    /// 5=TCB Version, 6=Launch Mitigation Vector (version 2 only).
    /// Accepts decimal, `0x`-prefixed hex, or `0b`-prefixed binary.
    #[arg(short, long = "guest_field_select", value_name = "gfs", value_parser = clparser::parse_int_auto_radix::<u64>, default_value = "0")]
    pub gfs: u64,

    /// Guest SVN to mix into the key. Must not exceed the guest SVN
    /// provided at launch in the ID block. Accepts decimal, `0x`-prefixed
    /// hex, or `0b`-prefixed binary.
    #[arg(short = 's', long = "guest_svn", value_name = "gsvn", value_parser = clparser::parse_int_auto_radix::<u32>, default_value = "0")]
    pub gsvn: u32,

    /// TCB version to mix into the derived key. Must not exceed the
    /// committed TCB. Accepts decimal, `0x`-prefixed hex, or `0b`-prefixed
    /// binary.
    #[arg(short, long = "tcb_version", value_name = "tcbv", value_parser = clparser::parse_int_auto_radix::<u64>, default_value = "0")]
    pub tcbv: u64,

    /// Launch mitigation vector to mix into the derived key. Only available
    /// for `MSG_KEY_REQ` message version 2. When provided, the message version
    /// is automatically set to 2. Accepts decimal, `0x`-prefixed hex, or
    /// `0b`-prefixed binary.
    #[arg(short, long = "launch_mit_vector", value_name = "lmv", value_parser = clparser::parse_int_auto_radix::<u64>)]
    pub lmv: Option<u64>,
}

/// Request a derived key from the AMD-SP and write it to a file.
///
/// Validates arguments, constructs a `DerivedKey` request, sends it to the
/// firmware via `/dev/sev-guest`, and serializes the resulting 32-byte key
/// to the specified path.
pub fn get_derived_key(args: KeyArgs) -> Result<()> {
    let root_key_select = match args.root_key_select.as_str() {
        "vcek" => false,
        "vmrk" => true,
        _ => return Err(anyhow::anyhow!("Invalid input. Enter either vcek or vmrk")),
    };

    if args.vmpl > 3 {
        return Err(anyhow::anyhow!(
            "Invalid Virtual Machine Privilege Level. Must betwee"
        ));
    }

    if args.gfs > 0b1111111 {
        return Err(anyhow::anyhow!("Invalid Guest Field Select option."));
    }

    // Automatically set message version 2 when launch mitigation vector is provided
    let msg_ver = if args.lmv.is_some() { 2 } else { 1 };

    let request = DerivedKey::new(
        root_key_select,
        GuestFieldSelect(args.gfs),
        args.vmpl,
        args.gsvn,
        args.tcbv,
        args.lmv,
    );
    let mut sev_fw = Firmware::open().context("failed to open SEV firmware device.")?;
    let derived_key: [u8; 32] = sev_fw
        .get_derived_key(Some(msg_ver), request)
        .context("Failed to request derived key")?;

    let key_path: PathBuf = args.key_path;

    let mut key_file = if key_path.exists() {
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(key_path)
            .context("Unable to overwrite derived key file contents")?
    } else {
        fs::File::create(key_path).context("Unable to create derived key file contents")?
    };

    bincode::serialize_into(&mut key_file, &derived_key)
        .context("Could not serialize derived key into file.")?;

    Ok(())
}

/// Read a derived key file and return its contents as a byte vector.
pub fn read_key(key_path: PathBuf) -> Result<Vec<u8>, anyhow::Error> {
    let mut key_file = fs::File::open(key_path)?;
    let mut key = Vec::new();
    key_file.read_to_end(&mut key)?;
    Ok(key)
}
