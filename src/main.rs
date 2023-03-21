use anyhow::{Context, Result};
use structopt::StructOpt;

mod guest;
mod request;
mod certs;

// Request and guest command options
use request::RequestCmd;
use guest::GuestCmd;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

// Guest command structure
#[derive(StructOpt)]
struct SnpGuest {
    #[structopt(subcommand)]
    pub cmd: SnpGuestCmd,

    #[structopt(short, long, help = "Don't print anything to the console")]
    pub quiet: bool,
}

// Enum with different Guest command options
#[allow(clippy::large_enum_variant)]
#[derive(StructOpt)]
#[structopt(author = AUTHORS, version = VERSION, about = "Utilities for managing the SNP Guest environment")]
enum SnpGuestCmd {
    #[structopt(
        about = "Request a report or extended report from the PSP. Can also request the certificate chain and VCEK from the KDS."
    )]
    Request(RequestCmd),
    #[structopt(about = "Different guest tools to manage your secure guest.")]
    Guest(GuestCmd),
}

fn main() -> Result<()> {
    env_logger::init();

    // Secure guest command passed from command line
    let snpguest = SnpGuest::from_args();

    let status = match snpguest.cmd {
        SnpGuestCmd::Request(subcmd) => request::cmd(subcmd),
        SnpGuestCmd::Guest(subcmd) => guest::cmd(subcmd),
    };

    // Show caught error if quiet is not enabled.
    if let Err(ref e) = status {
        if !snpguest.quiet {
            eprintln!("ERROR: {}", e);
            e.chain()
                .skip(1)
                .for_each(|cause| eprintln!("because: {}", cause));
        }
    }

    // Return status
    status
}
