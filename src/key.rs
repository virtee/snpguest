// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::{fs, path::PathBuf, str::FromStr};
use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};

#[derive(StructOpt)]
pub struct KeyArgs {
    #[structopt(
        long = "key-location",
        short,
        help = "Optional: path to attestation report to use to request VCEK (KDS only)"
    )]
    pub key_path: Option<PathBuf>,
}
pub fn get_derived_key(args: KeyArgs) -> Result<()> {
    let request = DerivedKey::new(false, GuestFieldSelect(1), 0, 0, 0);
    let mut sev_fw = Firmware::open().context("failed to open SEV firmware device.")?;
    let derived_key: [u8; 32] = sev_fw
        .get_derived_key(None, request)
        .context("failed to request derived key")?;

    // Create attestation report path
    let key_path = match args.key_path {
        Some(path) => path,
        None => {
            PathBuf::from_str("./derived_key.bin").context("unable to create default path")?
        }
    };

    // Write attestation report into desired file
    let mut key_file = if key_path.exists() {
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(key_path)
            .context("Unable to overwrite derived key file contents")?
    } else {
        fs::File::create(key_path)
            .context("Unable to create attestation report file contents")?
    };

    bincode::serialize_into(&mut key_file, &derived_key)
        .context("Could not serialize attestation report into file.")?;

    Ok(())
}
