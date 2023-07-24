// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::path::PathBuf;

#[derive(StructOpt)]
pub enum DisplayCmd {
    #[structopt(about = "Display an attestation report in console.")]
    Report(report_display::Args),
}

pub fn cmd(cmd: DisplayCmd, quiet: bool) -> Result<()> {
    match cmd {
        DisplayCmd::Report(args) => report_display::display_attestation_report(args, quiet),
    }
}
mod report_display {
    use super::*;

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(
            help = "Path to attestation report to display."
        )]
        pub att_report_path: PathBuf,
    }

    // Print attestation report in console
    pub fn display_attestation_report(args: Args, quiet: bool) -> Result<()> {
        let att_report = report::read_report(args.att_report_path).context("Could not open attestation report")?;

        if !quiet {
            println!("{}", att_report);
        };

        Ok(())
    }
}
