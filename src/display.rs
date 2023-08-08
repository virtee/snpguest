// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::{
    fs,
    str,
    fs::File,
    io::{BufWriter, Read, Write},
    path::PathBuf,
};

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
        let att_report = report::read_report(args.att_report_path).context("Could not open attestation report")?;

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
        #[structopt(help = "Path to display key.")]
        pub key_path: PathBuf,
    }

    // Print derived key in console
    pub fn display_derived_key(args: Args, quiet: bool) -> Result<()> {
        let key_report = key::read_key(args.key_path)
            .context("Could not open key")?;

        if !quiet {
            println!("{:?}", key_report);
        };

        Ok(())
    }
}

pub fn key_hex<W: Write>(file: &mut BufWriter<W>, data: &[u8]) -> Result<()> {
    let mut line_counter = 0;
    for val in data {
        // Make it blocks for easier read
        if line_counter.eq(&16) {
            writeln!(file).context("Failed to write data to file")?;
            line_counter = 0;
        }
        // Write byte into file
        write!(file, "{:02x}", val).context("Failed to write data to file")?;
        line_counter += 1;
    }
    Ok(())
}
/* 
pub fn hexdump(bytes: &[u8]) -> String {
    let mut retval: String = String::new();
    for (i, byte) in bytes.iter().enumerate() {
        if (i % 16) == 0 {
            retval.push('\n');
        }
        retval.push_str(&format!("{byte:02x} "));
    }
    retval.push('\n');
    retval
}

*/