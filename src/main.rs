// SPDX-License-Identifier: Apache-2.0
// This is the main entry point of the snpguest utility. The CLI includes subcommands for requesting and managing certificates, displaying information, fetching derived keys, and verifying certificates and attestation reports.

mod certs;
mod display;
mod fetch;
mod key;
mod ok;
mod preattestation;
mod report;
mod verify;

mod clparser;

#[cfg(feature = "hyperv")]
mod hyperv;

use certs::CertificatesArgs;
use display::DisplayCmd;
use fetch::FetchCmd;
use key::KeyArgs;
use preattestation::PreAttestationCmd;
use report::ReportArgs;
use verify::VerifyCmd;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct SnpGuest {
    #[command(subcommand)]
    pub cmd: SnpGuestCmd,

    /// Don't print anything to the console
    #[arg(short, long, default_value_t = false)]
    pub quiet: bool,
}

#[allow(clippy::large_enum_variant)]
/// Utilities for managing the SNP Guest environment
#[derive(Subcommand)]
enum SnpGuestCmd {
    /// Report command to request an attestation report.
    Report(ReportArgs),

    /// Certificates command to request cached certificates from the AMD PSP.
    Certificates(CertificatesArgs),

    /// Fetch command to request certificates.
    #[command(subcommand)]
    Fetch(FetchCmd),

    /// Verify command to verify certificates and attestation report.
    #[command(subcommand)]
    Verify(VerifyCmd),

    /// Display command to display files in human readable form.
    #[command(subcommand)]
    Display(DisplayCmd),

    /// Key command to generate derived key.
    Key(KeyArgs),

    /// Probe system for SEV-SNP support.
    Ok,

    /// Generate Pre-Attestation components
    #[command(subcommand)]
    Generate(PreAttestationCmd),
}

fn main() -> Result<()> {
    env_logger::init();

    let snpguest = SnpGuest::parse();

    #[cfg(feature = "hyperv")]
    let azcvm_present = hyperv::check::present();

    #[cfg(not(feature = "hyperv"))]
    let azcvm_present = false;

    let status = match snpguest.cmd {
        SnpGuestCmd::Report(args) => report::get_report(args, azcvm_present),
        SnpGuestCmd::Certificates(args) => certs::get_ext_certs(args),
        SnpGuestCmd::Fetch(subcmd) => fetch::cmd(subcmd),
        SnpGuestCmd::Verify(subcmd) => verify::cmd(subcmd, snpguest.quiet),
        SnpGuestCmd::Display(subcmd) => display::cmd(subcmd, snpguest.quiet),
        SnpGuestCmd::Key(args) => key::get_derived_key(args),
        SnpGuestCmd::Ok => ok::cmd(snpguest.quiet),
        SnpGuestCmd::Generate(subcmd) => preattestation::cmd(subcmd, snpguest.quiet),
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
