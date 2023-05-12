use super::*;

use std::path::PathBuf;

// Guest command options
#[derive(StructOpt)]
pub enum DisplayCmd {
    #[structopt(about = "Display attestation report from a given file.")]
    Report(report_display::Args),
}

pub fn cmd(cmd: DisplayCmd, quiet: bool) -> Result<()> {
    match cmd {
        DisplayCmd::Report(args) => report_display::display_attestation_report(args, quiet),
    }
}
// // Module to display an attestation report
mod report_display {
    use super::*;

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(
            long = "att-report",
            short,
            help = "File to write the attestation report to. Defaults to ./attestation_report.bin"
        )]
        pub att_report_path: Option<PathBuf>,
    }

    // Function to display attestation report
    pub fn display_attestation_report(args: Args, quiet: bool) -> Result<()> {
        let report_path = match args.att_report_path {
            Some(path) => path,
            None => PathBuf::from("./attestation_report.bin"),
        };

        // Open attestation report using deserialize and print contents
        let att_report =
            report::read_report(report_path).context("Could not open attestation report")?;

        if !quiet {
            println!("{}", att_report);
        };

        Ok(())
    }
}
