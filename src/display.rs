// SPDX-License-Identifier: Apache-2.0
// This file contains the subcommands for displaying attestation reports and derived keys.

use super::*;
use std::path::PathBuf;

#[derive(StructOpt)]
pub enum DisplayCmd {
    #[structopt(about = "Display an attestation report in console.")]
    Report(report_display::Args),

    #[structopt(about = "Display the derived key in console.")]
    Key(key_display::Args),
}

pub fn cmd(cmd: DisplayCmd, quiet: bool) -> Result<()> {
    match cmd {
        DisplayCmd::Report(args) => report_display::display_attestation_report(args, quiet),
        DisplayCmd::Key(args) => key_display::display_derived_key(args, quiet),
    }
}
mod report_display {
    use super::*;

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(help = "Path to attestation report to display.")]
        pub att_report_path: PathBuf,
    }

    // Print attestation report in console
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

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(help = "Path of key to be displayed.")]
        pub key_path: PathBuf,
    }

    // Print derived key in console
    pub fn display_derived_key(args: Args, quiet: bool) -> Result<()> {
        let key_report = key::read_key(args.key_path).context("Could not open key")?;

        if !quiet {
            let mut keydata: String = String::new();
            for (i, byte) in key_report.iter().enumerate() {
                if (i % 16) == 0 {
                    keydata.push('\n');
                }
                //Displaying key in Hex format
                keydata.push_str(&format!("{byte:02x} "));
            }
            keydata.push('\n');
            println!("{}", keydata);
        };

        Ok(())
    }
}
