// SPDX-License-Identifier: Apache-2.0
// This file contains code for fetching derived keys from root keys. It also includes functions for requesting and saving derived keys.

use super::*;
use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};
use std::io::Read;
use std::{fs, path::PathBuf};

#[derive(Parser)]
pub struct KeyArgs {
    /// This is the path where the derived key will be saved.
    #[arg(value_name = "key-path", required = true)]
    pub key_path: PathBuf,

    /// This is the root key from which to derive the key. Input either VCEK or VMRK.
    #[arg(value_name = "root-key-select", required = true, ignore_case = true)]
    pub root_key_select: String,

    /// Specify an integer VMPL level between 0 and 3 that the Guest is running on.
    #[arg(short, long, value_name = "vmpl", default_value = "1")]
    pub vmpl: u32,

    /// Specify which Guest Field Select bits to enable. It is 64-bit wide but only the least-significant 6 bits (Message Version 1) or 7 bits (Message Version 2) are currently defined; all higher bits must be zero. The bits (LSB->MSB) are: 0 = Guest Policy, 1 = Image ID, 2 = Family ID, 3 = Measurement, 4 = SVN, 5 = TCB Version, 6 = Launch Mitigation Vector (only available for Message Version 2). Accepts an integer in decimal (e.g. `63`), prefixed hex (e.g. `0x3f`) or prefixed bin (e.g. `0b111111`).
    #[arg(short, long = "guest_field_select", value_name = "gfs", value_parser = clparser::parse_int_auto_radix::<u64>, default_value = "0")]
    pub gfs: u64,

    /// Specify the guest SVN to mix into the key. Must not exceed the guest SVN provided at launch in the ID block. Accepts an integer in decimal, prefixed hex or prefixed bin.
    #[arg(short = 's', long = "guest_svn", value_name = "gsvn", value_parser = clparser::parse_int_auto_radix::<u32>, default_value = "0")]
    pub gsvn: u32,

    /// Specify the TCB version to mix into the derived key. Must not exceed CommittedTcb. Accepts an integer in decimal, prefixed hex or prefixed bin.
    #[arg(short, long = "tcb_version", value_name = "tcbv", value_parser = clparser::parse_int_auto_radix::<u64>, default_value = "0")]
    pub tcbv: u64,

    /// Specify the launch mitigation vector to mix into the derived key (only available for Message Version 2). Accepts an integer in decimal, hexadecimal or binary string.
    #[arg(short, long = "launch_mit_vector", value_name = "lmv", value_parser = clparser::parse_int_auto_radix::<u64>)]
    pub lmv: Option<u64>,
}

pub fn get_derived_key(args: KeyArgs) -> Result<()> {
    // Validate arguments
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

    // Switch message version of MSG_KEY_REQ
    let msg_ver = if args.lmv.is_some() { 2 } else { 1 };

    // Request derived key
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

    // Create derived key path
    let key_path: PathBuf = args.key_path;

    // Write derived key into desired file
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

pub fn read_key(key_path: PathBuf) -> Result<Vec<u8>, anyhow::Error> {
    let mut key_file = fs::File::open(key_path)?;
    let mut key = Vec::new();
    // read the whole file
    key_file.read_to_end(&mut key)?;
    Ok(key)
}
