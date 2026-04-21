// SPDX-License-Identifier: Apache-2.0

//! Prints attestation reports andderived keys.
//!
//! This module provides the following subcommands, which display artifacts
//! in human-readable form.
//!
//! - `display report` — Print an attestation report's contents to the terminal.
//! - `display key` — Print a derived key in hex format to the terminal.
//!
//! ## `display report`
//!
//! ```bash
//! snpguest display report $ATT_REPORT_PATH
//! ```
//!
//! Prints the attestation report contents into the terminal.
//!
//! ### Arguments
//!
//! | Argument | Description | Default |
//! | :--      | :--        | :--    |
//! | `$ATT_REPORT_PATH` | The path of the stored attestation report to display. | *required* |
//!
//! ### Example
//!
//! ```bash
//! snpguest display report report.bin
//! ```
//!
//! ## `display key`
//!
//! ```bash
//! snpguest display key $KEY_PATH
//! ```
//!
//! Prints the derived key in hex format into the terminal.
//!
//! ### Arguments
//!
//! | Argument | Description | Default |
//! | :--      | :--        | :--    |
//! | `$KEY_PATH` | The path of the stored derived key to display. | *required* |
//!
//! ### Example
//!
//! ```bash
//! snpguest display key derived-key.bin
//! ```

use super::*;
use std::path::PathBuf;

/// Subcommands for displaying attestation data in human-readable form.
#[derive(Subcommand)]
pub enum DisplayCmd {
    /// Print the contents of an attestation report to the terminal.
    Report(report_display::Args),

    /// Print a derived key in hex format to the terminal.
    Key(key_display::Args),
}

/// Dispatch to the appropriate display subcommand handler.
pub fn cmd(cmd: DisplayCmd, quiet: bool) -> Result<()> {
    match cmd {
        DisplayCmd::Report(args) => report_display::display_attestation_report(args, quiet),
        DisplayCmd::Key(args) => key_display::display_derived_key(args, quiet),
    }
}
mod report_display {
    use super::*;

    /// CLI arguments for `display report`.
    #[derive(Parser)]
    pub struct Args {
        /// Path to the attestation report file to display.
        #[arg(value_name = "att-report-path", required = true)]
        pub att_report_path: PathBuf,
    }

    /// Read and print an attestation report to the console.
    pub fn display_attestation_report(args: Args, quiet: bool) -> Result<()> {
        let att_report = report::read_report(args.att_report_path)
            .context("Could not open attestation report")?;

        if !quiet {
            println!("{}", att_report);
        };

        Ok(())
    }
}

mod key_display {
    use super::*;

    /// CLI arguments for `display key`.
    #[derive(Parser)]
    pub struct Args {
        /// Path to the derived key file to display.
        #[arg(value_name = "key-path", required = true)]
        pub key_path: PathBuf,
    }

    /// Read and print a derived key in hex format (16 bytes per line).
    pub fn display_derived_key(args: Args, quiet: bool) -> Result<()> {
        let key_report = key::read_key(args.key_path).context("Could not open key")?;

        if !quiet {
            let mut keydata: String = String::new();
            for (i, byte) in key_report.iter().enumerate() {
                if (i % 16) == 0 {
                    keydata.push('\n');
                }
                keydata.push_str(&format!("{byte:02x} "));
            }
            keydata.push('\n');
            println!("{}", keydata);
        };

        Ok(())
    }
}
