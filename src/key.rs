// SPDX-License-Identifier: Apache-2.0

use super::*;
use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};
//use std::{fs, path::PathBuf, str::FromStr};
use std::{fs, path::PathBuf};

#[derive(StructOpt)]
pub struct KeyArgs {
#[structopt(help = "This is the directory where the derived key will be saved")]
pub key_path: PathBuf,

#[structopt(help = "This is the root key from which to derive the key. Input either VCEK or VMRK. VLEK is not supported yet.")]
pub rks: String,

#[structopt(
    long = "vmpl",
    short,
    help = "Specify VMPL level the Guest is running on. Defaults to 1."
)]
pub vmpl: Option<u32>,

#[structopt(
    long = "guest_field_select",
    short = "gfs",
    help = "Specify which Guest Field Select bits to enable. Value of N for Guest Policy:0, Image ID:1, Family ID:2, Measurement:3, SVN:4, TCB Version:5 where Guest Field Select bit = 10^N"
)]
pub gfs: Option<String>,

#[structopt(
    long = "guest_svn",
    short = "gs",
    help = "Specify the guest SVN to mix into the key. Must not exceed the guest SVN provided at launch in the ID block."
)]
pub gsvn: Option<u32>,

#[structopt(
    long = "tcb_version",
    short,
    help = "Specify the TCB version to mix into the derived key. Must not exceed CommittedTcb"
)]
pub tcbv: Option<u64>,
}

pub fn get_derived_key(args: KeyArgs) -> Result<()> {

let rks = match args.rks.as_str(){
    "vcek" => false,
    "vmrk" => true,
    _ => return Err(anyhow::anyhow!("Invalid input. Enter either vcek or vmrk"))
};

let vmpl = match args.vmpl {
    Some(level) => {
        if level <= 3 {
            level
        } else {
            return Err(anyhow::anyhow!("Invalid vmpl."));
        }
    }
    None => 1,
};

let gfs = match args.gfs {
    Some(gfs) => {
        let value: u64 = u64::from_str_radix(gfs.as_str(), 2).unwrap();
        if value <= 63 {
            value
        } else {
            return Err(anyhow::anyhow!("Invalid gfs."));
        }
    }
    None => 0,
};

let gsvn:u32 = match args.gsvn {
    Some(ret_gsvn) => ret_gsvn,
    None => 0,
};

let tcbv:u64 = match args.tcbv {
    Some(ret_tcbv) => ret_tcbv,
    None => 0,
};

let request = DerivedKey::new(rks, GuestFieldSelect(gfs), vmpl, gsvn,tcbv );
let mut sev_fw = Firmware::open().context("failed to open SEV firmware device.")?;
let derived_key: [u8; 32] = sev_fw
    .get_derived_key(None, request)
    .context("failed to request derived key")?;

// Create attestation report path
let key_path: PathBuf = args.key_path;

// Write attestation report into desired file
let mut key_file = if key_path.exists() {
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(key_path)
        .context("Unable to overwrite derived key file contents")?
} else {
    fs::File::create(key_path).context("Unable to create attestation report file contents")?
};

bincode::serialize_into(&mut key_file, &derived_key)
    .context("Could not serialize attestation report into file.")?;

Ok(())
}
