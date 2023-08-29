// SPDX-License-Identifier: Apache-2.0

mod certs;
mod display;
mod fetch;
mod key;
mod report;
mod verify;

#[cfg(feature = "hyperv")]
mod hyperv;

use certs::CertificatesArgs;
use display::DisplayCmd;
use fetch::FetchCmd;
use key::KeyArgs;
use report::ReportArgs;
use verify::VerifyCmd;

use anyhow::{Context, Result};
use structopt::StructOpt;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

#[derive(StructOpt)]
struct SnpGuest {
    #[structopt(subcommand)]
    pub cmd: SnpGuestCmd,

    #[structopt(short, long, help = "Don't print anything to the console")]
    pub quiet: bool,
}

#[allow(clippy::large_enum_variant)]
#[derive(StructOpt)]
#[structopt(author = AUTHORS, version = VERSION, about = "Utilities for managing the SNP Guest environment")]
enum SnpGuestCmd {
    #[structopt(about = "Report command to request an attestation report.")]
    Report(ReportArgs),

    #[structopt(about = "Certificates command to request cached certificates from the AMD PSP")]
    Certificates(CertificatesArgs),

    #[structopt(about = "Fetch command to request certificates.")]
    Fetch(FetchCmd),

    #[structopt(about = "Verify command to verify certificates and attestation report.")]
    Verify(VerifyCmd),

    #[structopt(about = "Display command to display files in human readable form.")]
    Display(DisplayCmd),

    #[structopt(about = "Key command to generate derived key.")]
    Key(KeyArgs),
}

fn main() -> Result<()> {
    env_logger::init();

    let snpguest = SnpGuest::from_args();

    #[cfg(feature = "hyperv")]
    let hv = hyperv::present;

    #[cfg(not(feature = "hyperv"))]
    let hv = false;

    let status = match snpguest.cmd {
        SnpGuestCmd::Report(args) => report::get_report(args, hv),
        SnpGuestCmd::Certificates(args) => certs::get_ext_certs(args),
        SnpGuestCmd::Fetch(subcmd) => fetch::cmd(subcmd),
        SnpGuestCmd::Verify(subcmd) => verify::cmd(subcmd, snpguest.quiet),
        SnpGuestCmd::Display(subcmd) => display::cmd(subcmd, snpguest.quiet),
        SnpGuestCmd::Key(args) => key::get_derived_key(args),
    };

    if let Err(ref e) = status {
        if !snpguest.quiet {
            eprintln!("ERROR: {}", e);
            e.chain()
                .skip(1)
                .for_each(|cause| eprintln!("because: {}", cause));
        }
    }

    status
}
