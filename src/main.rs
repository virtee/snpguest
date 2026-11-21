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
//! Every `snpguest` (sub)command provides a `-h, --help` option for a
//! description of its use.
//!
//! ## Subcommands
//!
//! | Command | Subcommand | Description |
//! |---------|------------|-------------|
//! | `ok` | — | Quick local check if SEV-SNP is enabled in the guest environment |
//! | `report` | — | Requests an attestation report from AMD-SP (or vTPM) |
//! | `certificates` | — | Requests certificates from the hypervisor memory via AMD-SP |
//! | `fetch` | `ca`, `vcek`, `crl` | Fetches certificates/CRLs from AMD KDS |
//! | `verify` | `certs`, `attestation` | Verifies certificates / attestation report |
//! | `key` | — | Requests the derived key from AMD-SP based on input parameters |
//! | `display` | `report`, `key` | Displays files in human-readable form |
//! | `generate` | `measurement`, `ovmf-hash`, `id-block`, `key-digest` | Calculates reference values |
//!
//! ## Build
//!
//! ### For Standard CVMs
//!
//! ```bash
//! # Clone and build
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
//! by the [OpenHCL](https://github.com/microsoft/openvmm) paravisor. The native
//! `/dev/sev-guest` interface is hidden from the guest OS. The user must specify
//! the `--platform` flag to get an attestation report; this flag is available
//! only in builds compiled with the `hyperv` feature.
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
//! ### Generate manpages
//!
//! ```bash
//! # Generate the manpages
//! cargo xtask manpages
//!
//! # View the main page or a subcommand page
//! man -l target/man/snpguest.1
//! man -l target/man/snpguest-fetch-ca.1
//! ```
//!
//! The default output directory is `target/man` at the workspace root. Use
//! `cargo xtask manpages --out-dir ./man` to choose another directory. Generation
//! requires the same build dependencies as `snpguest`, but no SEV-SNP hardware.
//!
//! ## Reporting Bugs
//!
//! Please report all bugs to the [Github snpguest](https://github.com/virtee/snpguest/issues) repository.

fn main() -> anyhow::Result<()> {
    snpguest::run()
}
