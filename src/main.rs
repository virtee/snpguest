// SPDX-License-Identifier: Apache-2.0

//! # snpguest
//!
//! `snpguest` is a Command Line Interface utility for managing an AMD SEV-SNP
//! enabled guest. This tool allows users to interact with the AMD SEV-SNP guest
//! firmware device (`/dev/sev-guest`) enabling various operations such as:
//!
//! - **Attestation**: Request attestation reports from the AMD Secure Processor.
//! - **Certificate management**:Get cached certificates from the hypervisor,
//!   or fetch certificates from the AMD Key Distribution Service (KDS).
//! - **Verification**: Verify certificate chains and attestation report.
//! - **Derived key generation**: Request derived keys from the AMD-SP.
//! - **Pre-attestation**: Calculate expected/reference values of launch
//!   measurements, OVMF hashes, ID blocks, and key digests for use in
//!   confidential VM provisioning.
//!
//! ## Basic Usage
//!
//! ```sh
//! snpguest [GLOBAL_OPTIONS] [COMMAND] [COMMAND_ARGS] [SUBCOMMAND] [SUBCOMMAND_ARGS]
//! ```
//!
//! Every `snpguest` (sub)command comes with a `-h, --help` option for a
//! description of its use.
//!
//! ## Subcommands
//!
//! | Command | Subcommand | Description |
//! |---------|------------|-------------|
//! | [`ok`] | — | Quick local check if SEV-SNP is enabled in the guest environment |
//! | [`report`] | — | Requests an attestation report from AMD-SP (or vTPM) |
//! | [`certificates`](certs) | — | Requests certificates from the hypervisor memory via AMD-SP |
//! | [`fetch`] | `ca`, `vcek`, `crl` | Fetches certificates/CRLs from AMD KDS |
//! | [`verify`] | `certs`, `attestation` | Verifies certificates / attestation report |
//! | [`key`] | — | Requests the derived key from AMD-SP based on input parameters |
//! | [`display`] | `report`, `key` | Displays files in human-readable form |
//! | [`generate`](preattestation) | `measurement`, `ovmf-hash`, `id-block`, `key-digest` | Calculates reference values |
//!
//! ## [Extended Attestation Workflow](#extended-attestation-flowchart)
//!
//! ![Extended attestation diagram](https://github.com/virtee/snpguest/blob/main/docs/extended.PNG?raw=true)
//!
//! **Step 1.** Request the attestation report by providing the two mandatory
//! parameters - `$ATT_REPORT_PATH` which is the path pointing to where the
//! user wishes to store the attestation report and `$REQUEST_FILE` which is
//! the path pointing to where the request file used to request the attestation
//! report is stored. The optional parameter `-v, --vmpl` specifies the vmpl
//! level for the attestation report and is set to 1 by default. The flag
//! `-r, --random` generates random data to be used as request data for the
//! attestation report. Lastly, the flag `-p, --platform` obtains both the
//! attestation report and the request data from the platform (only available
//! for a Microsoft Azure CVM where Hyper-V guest is enabled).
//!
//! ```bash
//! snpguest report $ATT_REPORT_PATH $REQUEST_FILE [-v, --vmpl] $VMPL [-r, --random] [-p, --platform]
//! ```
//!
//! **Step 2.** Request certificates from the extended memory by providing the
//! two mandatory parameters - `$ENCODING` which specifies whether to use PEM
//! or DER encoding to store the certificates and $CERTS_DIR which specifies
//! the path in the user's directory where the certificates will be saved.
//!
//! ```bash
//! snpguest certificates $ENCODING $CERTS_DIR
//! ```
//!
//! In some environments, only the VCEK/VLEK certificate can be obtained. In
//! this case, you must follow the procedure described in
//! [Regular Attestation Workflow](#regular-attestation-workflow) to obtain an
//! AMD CA certificates.
//!
//! **Step 3.** Verify the certificates obtained from the extended memory by
//! providing `$CERTS_DIR` which specifies the path in the user's directory
//! where the certificates were saved from Step 2.
//!
//! ```bash
//! snpguest verify certs $CERTS_DIR
//! ```
//!
//! **Step 4.** Verify the attestation by providing the two mandatory
//! parameters - `$CERTS_DIR` which specifies the path in the user's directory
//! where the certificates were saved from Step 2 and `$ATT_REPORT_PATH` which
//! is the path pointing to the stored attestation report which the user
//! wishes to verify. The optional parameters `-t, --tcb` is used to verify
//! just the Reported TCB contents of the attestaion report and
//! `-s, --signature` is used to verify just the signature of the attestaion
//! report.
//!
//! ```bash
//! snpguest verify attestation $CERTS_DIR $ATT_REPORT_PATH [-t, --tcb] [-s, --signature]
//! ```
//!
//! ## [Regular Attestation Workflow](#regular-attestation-flowchart)
//!
//! ![Regular attestation diagram](https://github.com/virtee/snpguest/blob/main/docs/regular.PNG?raw=true)
//!
//! **Step 1.** Request the attestation report by providing the two mandatory
//! parameters - `$ATT_REPORT_PATH` which is the path pointing to where the
//! user wishes to store the attestation report and `$REQUEST_FILE` which is
//! the path pointing to where the request file used to request the attestation
//! report is stored. The optional parameter `-v, --vmpl` specifies the vmpl
//! level for the attestation report and is set to 1 by default. The flag
//! `-r, --random` generates random data to be used as request data for the
//! attestation report. Lastly, the flag `-p, --platform` obtains both the
//! attestation report and the request data from the platform (only available
//! for a Microsoft Azure CVM where Hyper-V guest is enabled).
//!
//! ```bash
//! snpguest report $ATT_REPORT_PATH $REQUEST_FILE [-v, --vmpl] $VMPL [-r, --random] [-p, --platform]
//! ```
//!
//! **Step 2.** Request AMD Root Key (ARK) and AMD SEV Key (ASK) (or AMD
//! SEV-VLEK Key (ASVK) for VLEK) from the AMD Key Distribution Service (KDS)
//! by providing the three mandatory parameters - `$ENCODING` which specifies
//! whether to use PEM or DER encoding to store the certificates, `$CERTS_DIR`
//! which specifies the path in the user's directory where the certificates
//! will be saved, and `$PROCESSOR_MODEL` - which specifies the AMD Processor
//! model for which the certificates are to be fetched. The optional
//! `-e, --endorser` argument specifies the type of attestation signing key
//! (defaults to VCEK).
//!
//! ```bash
//! snpguest fetch ca $ENCODING $CERTS_DIR $PROCESSOR_MODEL [-e, --endorser] $ENDORSER
//! ```
//!
//! **Step 3.** Request the Versioned Chip Endorsement Key (VCEK) from the AMD
//! Key Distribution Service (KDS) by providing the three mandatory
//! parameters - `$ENCODING` which specifies whether to use PEM or DER
//! encoding to store the certificates, `$CERTS_DIR` which specifies the path
//! in the user's directory where the certificates will be saved, and
//! `$ATT_REPORT_PATH` which is the path pointing to the stored attestation
//! report for detecting Chip ID and Reported TCB Version. The optional
//! `-p, --processor-model` argument specifies the AMD Processor model for
//! which the certificates are to be fetched.
//!
//! ```bash
//! snpguest fetch vcek $ENCODING $CERTS_DIR $ATT_REPORT_PATH [-p, --processor-model] $PROCESSOR_MODEL
//! ```
//!
//! **Step 4.** Verify the certificates obtained by providing `$CERTS_DIR`
//! which specifies the path in the user's directory where the certificates
//! were saved from Step 2.
//!
//! ```bash
//! snpguest verify certs $CERTS_DIR
//! ```
//!
//! **Step 5.** Verify the attestation by providing the two mandatory
//! parameters - `$CERTS_DIR` which specifies the path in the user's directory
//! where the certificates were saved from Step 2 and `$ATT_REPORT_PATH` which
//! is the path pointing to the stored attestation report which the user
//! wishes to verify. The optional parameters `-t, --tcb` is used to verify
//! just the Reported TCB contents of the attestaion report and
//! `-s, --signature` is used to verify just the signature of the attestaion
//! report.
//!
//! ```bash
//! snpguest verify attestation $CERTS_DIR $ATT_REPORT_PATH [-t, --tcb] [-s, --signature]
//! ```
//!
//! ## Build
//!
//! ### For Standard CVMs
//!
//! ```bash
//! # Build
//! git clone https://github.com/virtee/snpguest
//! cd snpguest
//! cargo build -r
//!
//! # Install from the repository
//! cargo install --git https://github.com/virtee/snpguest
//!
//! # Install from crate.io
//! cargo install snpguest
//! ```
//!
//! ### For Azure CVMs
//!
//! On Azure CVMs, all communication between the guest OS and AMD-SP is proxied
//! by the OpenHCL paravisor. The native `/dev/sev-guest` interface is hidden
//! from the guest OS. The user must specify the `--platform` flag to get an
//! attestation report; this flag is available only in builds compiled with the
//! `hyperv` feature.
//!
//! ```bash
//! # Install additional dependencies
//! sudo apt update
//! sudo apt install -y pkg-config libtss2-dev
//!
//! # Build
//! git clone https://github.com/virtee/snpguest
//! cd snpguest
//! cargo build -r --features hyperv
//!
//! # Install from the repository
//! cargo install --git https://github.com/virtee/snpguest --features hyperv
//!
//! # Install from crate.io
//! cargo install snpguest --features hyperv
//! ```
//!
//! ### Build Dependencies
//!
//! Some packages may need to be installed on the guest system in order to
//! build `snpguest`.
//!
//! #### Rust
//!
//! ```bash
//! curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
//! source "$HOME/.cargo/env"
//! ```
//!
//! #### Ubuntu Dependencies
//!
//! ```bash
//! sudo apt install build-essential
//! ```
//!
//! #### RHEL and its compatible distributions Dependencies
//!
//! ```bash
//! sudo dnf groupinstall "Development Tools" "Development Libraries"
//! ```
//!
//! #### openSUSE and its compatible distributions Dependencies
//!
//! ```bash
//! sudo zypper in -t pattern "devel_basis"
//! ```
//!
//! ### Load sev-guest module
//!
//! In some guest environments, the device `/dev/sev-guest` does not created
//! by default. In such cases, make sure that the kernel supports SEV-SNP,
//! then load the sev-guest module.
//!
//! ```bash
//! modprobe sev-guest
//! ls -l /dev/sev-guest
//! ```
//!
//! ## Reporting Bugs
//!
//! Please report all bugs to the [Github snpguest](https://github.com/virtee/snpguest/issues) repository.

#![deny(missing_docs)]

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

/// Top-level CLI structure for `snpguest`.
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct SnpGuest {
    #[command(subcommand)]
    pub cmd: SnpGuestCmd,

    /// Suppress console output.
    #[arg(short, long, default_value_t = false)]
    pub quiet: bool,
}

/// Available subcommands for managing the SEV-SNP guest environment.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum SnpGuestCmd {
    /// Request an attestation report from the AMD Secure Processor (or vTPM).
    Report(ReportArgs),

    /// Request cached certificates from the hypervisor memory via the AMD Secure Processor.
    Certificates(CertificatesArgs),

    /// Fetch certificates or CRLs from the AMD Key Distribution Service (KDS).
    #[command(subcommand)]
    Fetch(FetchCmd),

    /// Verify certificate chains or attestation reports.
    #[command(subcommand)]
    Verify(VerifyCmd),

    /// Display attestation reports or derived keys in human-readable form.
    #[command(subcommand)]
    Display(DisplayCmd),

    /// Request a derived key from the AMD Secure Processor.
    Key(KeyArgs),

    /// Quick local check if SEV-SNP is enabled in the guest environment.
    Ok,

    /// Calculate pre-attestation reference values (measurements, OVMF hashes, ID blocks, key digests).
    #[command(subcommand)]
    Generate(PreAttestationCmd),
}

/// Entry point: parses CLI arguments and dispatches to the appropriate subcommand handler.
fn main() -> Result<()> {
    env_logger::init();

    let snpguest = SnpGuest::parse();

    #[cfg(feature = "hyperv")]
    let hv = hyperv::present();

    #[cfg(not(feature = "hyperv"))]
    let hv = false;

    let status = match snpguest.cmd {
        SnpGuestCmd::Report(args) => report::get_report(args, hv),
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
