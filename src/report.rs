// SPDX-License-Identifier: Apache-2.0
// This file defines the CLI for requesting attestation reports. It contains functions for requesting attestation reports and saving them to files. Additionally, it includes code for reading and parsing attestation reports.

use super::*;

use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Result};
use rand::{thread_rng, RngCore};

use sev::{
    firmware::guest::{AttestationReport, Firmware},
    parser::{ByteParser, Encoder},
};

const TSM_REPORT_PATH: &str = "/sys/kernel/config/tsm/report";

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ServiceProvider {
    Svsm,
}

struct SvsmReport {
    report: Vec<u8>,
    manifest: Vec<u8>,
}

// Read a bin-formatted attestation report.
pub fn read_report(att_report_path: PathBuf) -> Result<AttestationReport, anyhow::Error> {
    let mut attestation_file = fs::File::open(att_report_path)?;

    let mut report_bytes = Vec::new();
    attestation_file
        .read_to_end(&mut report_bytes)
        .context("Failed to read the report bytes.")?;

    let attestation_report = AttestationReport::from_bytes(&report_bytes)
        .context("Failed to build report from the raw bytes. Report could be malformed.")?;

    Ok(attestation_report)
}

// Create 64 random bytes of data for attestation report request
pub fn create_random_request() -> [u8; 64] {
    let mut data = [0u8; 64];
    thread_rng().fill_bytes(&mut data);
    data
}

/// Report command to request an attestation report.
#[derive(Parser)]
pub struct ReportArgs {
    /// File to write the attestation report to.
    #[arg(value_name = "att-report-path", required = true)]
    pub att_report_path: PathBuf,

    /// Provide file with data for attestation-report request. If provided
    /// with random flag, then the random data will be written in the
    /// provided path.
    #[arg(value_name = "request-file", required = true)]
    pub request_file: PathBuf,

    /// Use random data for attestation report request and write it to the request file.
    #[arg(short, long, default_value_t = false)]
    pub random: bool,

    /// Specify an integer VMPL level between 0 and 3 that the Guest is running on.
    /// Ignored with --openhcl or --service-provider svsm, which request VMPL 0.
    #[arg(short, long, default_value = "1", value_name = "vmpl")]
    pub vmpl: Option<u32>,

    /// Request attestation report on Confidential VM with OpenHCL paravisor
    #[arg(long, default_value_t = false)]
    pub openhcl: bool,

    /// Request an SVSM attestation report through configfs TSM at VMPL 0.
    #[arg(
        long,
        value_enum,
        ignore_case = true,
        requires = "manifest_path",
        conflicts_with = "openhcl"
    )]
    pub service_provider: Option<ServiceProvider>,

    /// File to write the raw SVSM manifest blob to; requires --service-provider svsm.
    #[arg(long, value_name = "manifest-path", requires = "service_provider")]
    pub manifest_path: Option<PathBuf>,
}

fn create_tsm_report_dir(root: &Path) -> Result<PathBuf> {
    for _ in 0..8 {
        let path = root.join(format!(
            "snpguest-{}-{:016x}",
            std::process::id(),
            thread_rng().next_u64()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "unable to create TSM report in {}; configfs must be mounted and the SEV-SNP TSM driver available with write permission",
                        root.display()
                    )
                });
            }
        }
    }
    Err(anyhow!("unable to create a unique TSM report directory"))
}

fn read_svsm_report(path: &Path, data: &[u8; 64]) -> Result<SvsmReport> {
    let provider = fs::read_to_string(path.join("provider"))
        .context("unable to read the TSM report provider")?;
    if provider.trim() != "sev_guest" {
        return Err(anyhow!(
            "expected TSM provider sev_guest, found {}",
            provider.trim()
        ));
    }

    for (attribute, value) in [
        ("service_provider", b"svsm".as_slice()),
        (
            "service_guid",
            b"00000000-0000-0000-0000-000000000000".as_slice(),
        ),
        ("inblob", data.as_slice()),
    ] {
        OpenOptions::new()
            .write(true)
            .open(path.join(attribute))
            .with_context(|| {
                format!("unable to open TSM attribute {attribute}; SVSM attestation support is required")
            })?
            .write_all(value)
            .with_context(|| format!("unable to write TSM attribute {attribute}"))?;
    }

    let report =
        fs::read(path.join("outblob")).context("unable to read the SVSM report outblob")?;
    AttestationReport::from_bytes(&report).context("invalid SNP report in TSM outblob")?;
    let manifest =
        fs::read(path.join("manifestblob")).context("unable to read the SVSM manifestblob")?;

    Ok(SvsmReport { report, manifest })
}

fn request_svsm_report(root: &Path, data: &[u8; 64]) -> Result<SvsmReport> {
    let path = create_tsm_report_dir(root)?;
    let result = read_svsm_report(&path, data);
    let cleanup = fs::remove_dir(&path)
        .with_context(|| format!("unable to remove TSM report directory {}", path.display()));
    let report = result?;
    cleanup?;
    Ok(report)
}

fn request_hardware_report(
    data: [u8; 64],
    vmpl: Option<u32>,
    _openhcl: bool,
) -> Result<AttestationReport> {
    #[cfg(feature = "hyperv")]
    if _openhcl {
        if vmpl.unwrap_or(0) > 0 {
            eprintln!("Warning: --vmpl argument was ignored because attestation report is requested by the paravisor at VMPL 0.");
        }
        return hyperv::report::get(data);
    }

    let mut fw = Firmware::open().context("unable to open /dev/sev-guest")?;
    Ok(AttestationReport::from_bytes(
        fw.get_report(None, Some(data), vmpl)
            .context("unable to get attestation report")?
            .as_slice(),
    )?)
}

// Request attestation report and write it into a file
pub fn get_report(args: ReportArgs, hyperv_present: bool) -> Result<()> {
    if args.openhcl && !hyperv_present {
        #[cfg(feature = "hyperv")]
        let msg =
            "--openhcl enabled yet Hyper-V guest with SEV-SNP isolation not detected (not allowed).";
        #[cfg(not(feature = "hyperv"))]
        let msg =
            "--openhcl requires a binary built with --features hyperv. Please rebuild with --features hyperv.";
        return Err(anyhow!(msg));
    }

    if let Some(manifest_path) = &args.manifest_path {
        if manifest_path == &args.att_report_path || manifest_path == &args.request_file {
            return Err(anyhow!(
                "--manifest-path must differ from the attestation report and request file paths"
            ));
        }
    }

    let data: [u8; 64] = if args.random {
        create_random_request()
    } else {
        /*
         * Read from the request file.
         */
        let mut bytes = [0u8; 64];
        let mut file = File::open(&args.request_file)?;
        file.read_exact(&mut bytes)
            .context("unable to read 64 bytes from REQUEST_FILE")?;

        bytes
    };

    let (report, manifest) = match args.service_provider {
        Some(ServiceProvider::Svsm) => {
            if args.vmpl.unwrap_or(0) > 0 {
                eprintln!("Warning: --vmpl argument was ignored because SVSM requests the attestation report at VMPL 0.");
            }
            let report = request_svsm_report(Path::new(TSM_REPORT_PATH), &data)?;
            (report.report, Some(report.manifest))
        }
        None => {
            let report = request_hardware_report(data, args.vmpl, args.openhcl)?;
            let mut bytes = Vec::new();
            report.encode(&mut bytes, ())?;
            (bytes, None)
        }
    };

    /*
     * Serialize and write attestation report.
     */
    fs::write(&args.att_report_path, &report).context("unable to write the attestation report")?;

    if let (Some(path), Some(manifest)) = (&args.manifest_path, manifest) {
        fs::write(path, manifest).context("unable to write the SVSM manifest blob")?;
    }

    /*
     * Write reports report data (only for --random or --platform).
     */
    if args.random {
        reqdata_write(args.request_file, &data)
            .context("unable to write random request data to specified file")?;
    }

    Ok(())
}

fn reqdata_write(name: PathBuf, report_data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(name)
        .context("unable to create or write to request data file")?;

    file.write_all(report_data)
        .context("unable to write report data to REQUEST_FILE")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind as ClapErrorKind;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            Self(create_tsm_report_dir(&std::env::temp_dir()).unwrap())
        }

        fn report() -> Self {
            let directory = Self::new();
            fs::write(directory.0.join("provider"), "sev_guest\n").unwrap();
            for attribute in ["service_provider", "service_guid", "inblob"] {
                fs::write(directory.0.join(attribute), []).unwrap();
            }
            let report = AttestationReport {
                version: 2,
                chip_id: [1; 64],
                ..Default::default()
            };
            let mut report_bytes = Vec::new();
            report.encode(&mut report_bytes, ()).unwrap();
            fs::write(directory.0.join("outblob"), report_bytes).unwrap();
            fs::write(directory.0.join("manifestblob"), b"\x00\xffmanifest\n").unwrap();
            directory
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn report_options_preserve_default_behavior() {
        let args = ReportArgs::try_parse_from(["report", "report.bin", "request.bin"]).unwrap();
        assert!(args.service_provider.is_none());
        assert!(args.manifest_path.is_none());
        assert_eq!(args.vmpl, Some(1));
    }

    #[test]
    fn svsm_options_accept_random_requests_and_case_insensitive_provider() {
        let args = ReportArgs::try_parse_from([
            "report",
            "report.bin",
            "request.bin",
            "--service-provider",
            "SVSM",
            "--manifest-path",
            "manifest.bin",
            "--random",
        ])
        .unwrap();
        assert_eq!(args.service_provider, Some(ServiceProvider::Svsm));
        assert_eq!(args.manifest_path, Some(PathBuf::from("manifest.bin")));
        assert!(args.random);
    }

    #[test]
    fn svsm_options_require_provider_and_manifest_together() {
        for options in [
            ["--service-provider", "svsm"],
            ["--manifest-path", "manifest.bin"],
        ] {
            let error = ReportArgs::try_parse_from(
                ["report", "report.bin", "request.bin"]
                    .into_iter()
                    .chain(options),
            )
            .err()
            .unwrap();
            assert_eq!(error.kind(), ClapErrorKind::MissingRequiredArgument);
        }
    }

    #[test]
    fn svsm_options_reject_openhcl_and_unknown_providers() {
        for (provider, extra, expected) in [
            ("svsm", "--openhcl", ClapErrorKind::ArgumentConflict),
            ("unknown", "--random", ClapErrorKind::InvalidValue),
        ] {
            let error = ReportArgs::try_parse_from([
                "report",
                "report.bin",
                "request.bin",
                "--service-provider",
                provider,
                "--manifest-path",
                "manifest.bin",
                extra,
            ])
            .err()
            .unwrap();
            assert_eq!(error.kind(), expected);
        }
    }

    #[test]
    fn manifest_path_cannot_overwrite_report_or_request() {
        for path in ["report.bin", "request.bin"] {
            let args = ReportArgs::try_parse_from([
                "report",
                "report.bin",
                "request.bin",
                "--service-provider",
                "svsm",
                "--manifest-path",
                path,
            ])
            .unwrap();
            let error = get_report(args, false).unwrap_err();
            assert!(error.to_string().contains("--manifest-path must differ"));
        }
    }

    #[test]
    fn svsm_request_writes_nonce_and_preserves_both_blobs() {
        let directory = TestDirectory::report();
        let data = [0xa5; 64];
        let report = read_svsm_report(&directory.0, &data).unwrap();
        assert_eq!(
            report.report,
            fs::read(directory.0.join("outblob")).unwrap()
        );
        assert_eq!(report.manifest, b"\x00\xffmanifest\n");
        assert_eq!(fs::read(directory.0.join("inblob")).unwrap(), data);
        assert_eq!(
            fs::read(directory.0.join("service_provider")).unwrap(),
            b"svsm"
        );
        assert_eq!(
            fs::read(directory.0.join("service_guid")).unwrap(),
            b"00000000-0000-0000-0000-000000000000"
        );
        assert!(!directory.0.join("privlevel").exists());
    }

    #[test]
    fn svsm_request_rejects_wrong_tsm_provider() {
        let directory = TestDirectory::report();
        fs::write(directory.0.join("provider"), "tdx_guest\n").unwrap();
        let error = read_svsm_report(&directory.0, &[0; 64]).err().unwrap();
        assert!(error
            .to_string()
            .contains("expected TSM provider sev_guest"));
        assert!(fs::read(directory.0.join("inblob")).unwrap().is_empty());
    }

    #[test]
    fn svsm_request_does_not_create_missing_configfs_attributes() {
        let directory = TestDirectory::report();
        fs::remove_file(directory.0.join("service_provider")).unwrap();
        let error = read_svsm_report(&directory.0, &[0; 64]).err().unwrap();
        assert!(error.to_string().contains("TSM attribute service_provider"));
        assert!(!directory.0.join("service_provider").exists());
    }

    #[test]
    fn svsm_request_rejects_malformed_reports_and_missing_manifests() {
        let directory = TestDirectory::report();
        fs::remove_file(directory.0.join("manifestblob")).unwrap();
        let error = read_svsm_report(&directory.0, &[0; 64]).err().unwrap();
        assert!(error.to_string().contains("manifestblob"));

        fs::write(directory.0.join("outblob"), b"invalid report").unwrap();
        let error = read_svsm_report(&directory.0, &[0; 64]).err().unwrap();
        assert!(error.to_string().contains("invalid SNP report"));
    }

    #[test]
    fn svsm_request_preserves_empty_manifests() {
        let directory = TestDirectory::report();
        fs::write(directory.0.join("manifestblob"), []).unwrap();
        let report = read_svsm_report(&directory.0, &[0; 64]).unwrap();
        assert!(report.manifest.is_empty());
    }

    #[test]
    fn failed_svsm_requests_clean_up_their_directory() {
        let root = TestDirectory::new();
        assert!(request_svsm_report(&root.0, &[0; 64]).is_err());
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
    }

    #[test]
    fn tsm_requests_use_distinct_directories() {
        let root = TestDirectory::new();
        let first = create_tsm_report_dir(&root.0).unwrap();
        let second = create_tsm_report_dir(&root.0).unwrap();
        assert_ne!(first, second);
        fs::remove_dir(first).unwrap();
        fs::remove_dir(second).unwrap();
    }
}
