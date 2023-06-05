// SPDX-License-Identifier: Apache-2.0

use super::*;

use report;
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
            long = "att-report",
            short,
            help = "Optional: path to attestation report to display."
        )]
        pub att_report_path: Option<PathBuf>,
    }

    // Print attestation report in console
    pub fn display_attestation_report(args: Args, quiet: bool) -> Result<()> {
        let att_report = match args.att_report_path {
            Some(path) => {
                // Check that provided path contains an attestation report
                if !path.exists() {
                    return Err(anyhow::anyhow!("No attestation report was found. Provide an attestation report to request VCEK from the KDS."));
                }
                report::read_report(path).context("Could not open attestation report")?
            }
            // No path provieded, request an attestation report with default values and random data
            None => report::request_default_report()?,
        };

        if !quiet {
            println!("{}", att_report);
        };

        Ok(())
    }
}
