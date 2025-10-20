# snpguest

`snpguest` is a Command Line Interface utility for managing an AMD SEV-SNP enabled guest. This tool allows users to interact with the AMD SEV-SNP guest firmware device enabling various operations such as: attestation, certificate management, derived key fetching, and more.

- [Usage](#usage)
  - [1. help](#1-help)
  - [2. certificates](#2-certificates)
  - [3. display](#3-display)
  - [4. fetch](#4.fetch)
  - [5. key](#5-key)
  - [6. report](#6-report)
  - [7. verify](#7-verify)
  - [Global Options](#global-options)
- [Extended Attestation Workflow](#extended-attestation-workflow)
- [Regular Attestation Workflow](#regular-attestation-workflow)
- [Extended Attestation Flowchart](#extended-attestation-flowchart)
- [Regular Attestation Flowchart](#regular-attestation-flowchart)
- [Building](#building)
  - [Ubuntu Dependencies](#ubuntu-dependencies)
  - [RHEL and its compatible distributions dependencies](#rhel-and-its-compatible-distributions-dependencies)
  - [openSUSE and its compatible distributions dependencies](#opensuse-and-its-compatible-distributions-dependencies)
  - [Building for Azure Confidential VMs](#building-for-azure-confidential-vms)
- [Reporting Bugs](#reporting-bugs)

## Usage

### 1. `help`

Every `snpguest` (sub)command comes with a `--help` option for a description on its use. 

**Usage**
```bash
snpguest --help
```

### 2. `certificates` 

Requests the VEK certificate chain (ARK, ASK/ASVK and VCEK/VLEK) from host memory (requests extended-config). The user needs to specify the certificate encoding to store the certificates in (PEM or DER). Currently, only PEM and DER encodings are supported. All certificates will be in the same encoding. The user also needs to provide the path to the directory where the certificates will be stored. If certificates already exist in the provided directory, they will be overwritten.

**Usage**
```bash
snpguest certificates $ENCODING $CERTS_DIR
```

**Arguments**

- `$ENCODING` : Specifies the certificate encoding to store the certificates in (PEM or DER).

- `$CERTS_DIR` : Specifies the directory to store the certificates in. This is required only when requesting an extended attestation report.

**Example**
```bash
snpguest certificates pem ./certs
```

### 3. `display` 

Displays files in human readable form. 

**Usage**
```bash
snpguest display <SUBCOMMAND>
```

**Subcommands**

1. `report`

    When used for displaying a report, it prints the attestation report contents into the terminal. The user has to provide the path of the stored attestation report to display.

    **Usage**
    ```bash
    snpguest display report $ATT_REPORT_PATH
    ```

    **Argument**

    - `$ATT_REPORT_PATH` : Specifies the path of the stored attestation report to display.

    **Example**
    ```bash
    snpguest display report attestation-report.bin
    ```

2. `key`

    When used for displaying the fetched derived key's contents, it prints the derived key in hex format into the terminal. The user has to provide the path of a stored derived key to display.

    **Usage**

    ```bash
    snpguest display key $KEY_PATH
    ```
    **Argument**

    - `$KEY_PATH` : Specifies the path of the stored derived key to display.

    **Example**
    ```bash
    snpguest display key derived-key.bin
    ```

### 4. `fetch`

Command to Requests certificates from the KDS.

**Usage**
```bash
snpguest fetch <SUBCOMMAND>
```

**Subcommands**
1. `ca`

    Requests the certificate authority chain (ARK & ASK/ASVK) from the KDS. The user needs to specify the certificate encoding to store the certificates in (PEM or DER). Currently, only PEM and DER encodings are supported. Both certificates will be in the same encoding. The user must specify their host processor model. The user also needs to provide the path to the directory where the certificates will be stored. If the certificates already exist in the provided directory, they will be overwritten. The `--endorser` argument specifies the type of attestation signing key (defaults to VCEK).

    **Usage**
    ```bash
    # Fetch CA chain of the user-provided processor model
    snpguest fetch ca $ENCODING $CERTS_DIR $PROCESSOR_MODEL --endorser $ENDORSER
    # Fetch CA chain of the processor-model written in the attestation report
    snpguest fetch ca $ENCODING $CERTS_DIR --report $ATT_REPORT_PATH --endorser $ENDORSER
    ```
    
    **Arguments**
    | Argument | Description | Default |
    | :--      | :--        | :--    |
    | `$ENCODING` | Specifies the certificate encoding to store the certificates in (PEM or DER). | required |
    | `$CERTS_DIR` | Specifies the directory to store the certificates in. | required |
    | `$PROCESSOR_MODEL` | Specifies the host processor model (conflict with `$ATT_REPORT_PATH`). | required |
    | `-r, --report $ATT_REPORT_PATH` | Specifies the attestation report to detect the host processor model (conflict with `$PROCESSOR_MODEL`) | — |
    | `-e, --endorser $ENDORSER` | Specifies the endorser type, possible values: "vcek", "vlek". | "vcek" |

    **Example**
    ```bash
    snpguest fetch ca der ./certs-kds milan -e vlek
    ```
    ```bash
    snpguest fetch ca pem ./certs-kds -r attestation-report.bin -e vcek
    ```

2. `vcek`

    Requests the VCEK certificate from the KDS. The user needs to specify the certificate encoding to store the certificate in (PEM or DER). Currently, only PEM and DER encodings are supported. The user must specify their host processor model. The user also needs to provide the path to the directory where the VCEK will be stored and the path to a stored attestation report that will be used to request the VCEK. If the certificate already exists in the provided directory, it will be overwritten.

    **Usage**
    ```bash
    snpguest fetch vcek $ENCODING $CERTS_DIR $ATT_REPORT_PATH --processor-model $PROCESSOR_MODEL
    ```

    **Arguments**
    | Argument | Description | Default |
    | :--      | :--        | :--    |
    | `$ENCODING` | Specifies the certificate encoding to store the certificates in (PEM or DER). | required |
    | `$CERTS_DIR` | Specifies the directory to store the certificates in. | required |
    | `$ATT_REPORT_PATH` | Specifies the path of the stored attestation report. | required |
    | `-p, --processor-model $PROCESSOR_MODEL` | Specifies the host processor model. | — |

    **Example**
    ```bash
    snpguest fetch vcek pem ./certs-kds attestation-report.bin
    ```

3. `crl`

    Requests the Certificate Revocation List (CRL) from the KDS. It takes the same set of arguments as `snpguest fetch ca`. The user needs to specify the encoding to store the CRL in (PEM or DER). Currently, only PEM and DER encodings are supported. The user must specify their host processor model. The user also needs to provide the path to the directory where the CRL will be stored. If the CRL already exists in the provided directory, it will be overwritten. The `--endorser` argument specifies the type of attestation signing key (defaults to VCEK).

    **Usage**
    ```bash
    # Fetch CRL of the user-provided processor model
    snpguest fetch crl $ENCODING $CERTS_DIR $PROCESSOR_MODEL --endorser $ENDORSER
    # Fetch CRL of the processor-model written in the attestation report
    snpguest fetch crl $ENCODING $CERTS_DIR --report $ATT_REPORT_PATH --endorser $ENDORSER
    ```
    
    **Arguments**
    | Argument | Description | Default |
    | :--      | :--        | :--    |
    | `$ENCODING` | Specifies the encoding to store the CRL in (PEM or DER). | required |
    | `$CERTS_DIR` | Specifies the directory to store the CRL in. | required |
    | `$PROCESSOR_MODEL` | Specifies the host processor model (conflict with `--report`). | required |
    | `-r, --report $ATT_REPORT_PATH` | Specifies the attestation report to detect the host processor model (conflict with `$PROCESSOR_MODEL`) | — |
    | `-e, --endorser $ENDORSER` | Specifies the endorser type, possible values: "vcek", "vlek". | "vcek" |

    Example
    ```bash
    snpguest fetch crl der ./certs-kds milan -e vlek
    ```
    ```bash
    snpguest fetch crl pem ./certs-kds -r attestation-report.bin -e vcek
    ```

### 5. `key` 

Creates the derived key based on input parameters and stores it. `$KEY_PATH` is the path to store the derived key. `$ROOT_KEY_SELECT` is the root key from which to derive the key (either "vcek" or "vmrk"). The `--guest_field_select` option specifies which Guest Field Select bits to enable as a 64-bit integer. Only the least-significant 6 bits (Message Version 1) or 7 bits (Message Version 2) are currently defined. Each of the bits from *right to left* correspond to Guest Policy, Image ID, Family ID, Measurement, SVN and TCB Version, Launch Mitigation Vector, respectively. For each bit, 0 denotes off, and 1 denotes on. The `--guest_svn` option specifies the guest SVN to mix into the key, the `--tcb_version` option specifies the TCB version to mix into the derived key, and the `--launch_mit_vector` option specifies the launch mitigation vector value to mix into the derived key. The `--vmpl` option specifies the VMPL level the Guest is running on and defaults to 1.

**Usage**
```bash
snpguest key $KEY_PATH $ROOT_KEY_SELECT [-v, --vmpl] [-g, --guest_field_select] [-s, --guest_svn] [-t, --tcb_version]
```

**Arguments**
| Argument | Description | Default |
| :--      | :--        | :--    |
| `$KEY_PATH` | The path to store the derived key. | required |
| `$ROOT_KEY_SELECT` | is the root key from which to derive the key (either "vcek" or "vmrk"). | required |
| `-v, --vmpl $VMPL` | option specifies the VMPL level the Guest is running on. | 1 |
| `-g, --guest_field_select $GFS` | option specifies which Guest Field Select bits to enable as a 64-bit integer (decimal, prefixed hex or prefixed bin). | 0 |
| `-s, --guest_svn $GSVN` | option specifies the guest SVN to mix into the key (decimal, prefixed hex or prefixed bin). | 0 |
| `-t, --tcb_version $TCBV` | option specifies the TCB version to mix into the derived key (decimal, prefixed hex or prefixed bin). | 0 |
| `-l, --launch_mit_vector $LMV` | option specifies the launch mitigation vector value to mix into the derived key (decimal, prefixed hex or prefixed bin). Only available for `MSG_KEY_REQ` message version ≥ 2. | — |

**Guest Field Select**

| Bit      | Field             | Note |
| :--      | :--               | :--  |
| 63:7     | (Reserved)        | Currently not supported. |
| 6 (MSB)  | Launch MIT Vector | Set to 0 if not specified; supported for `MSG_KEY_REQ` message version ≥ 2. |
| 5        | TCB Version       |      |
| 4        | SVN               |      |
| 3        | Measurement       |      |
| 2        | Family ID         |      |
| 1        | Image ID          |      |
| 0 (LSB)  | Guest Policy      |      |

For example, all of
- `--guest_field_select 49`
- `--guest_field_select 0x31`
- `--guest_field_select 0b110001`

denote the following specification:
```
Guest Policy:On (1), 
Image ID:Off (0), 
Family ID: Off (0), 
Measurement: Off (0), 
SVN:On (1), 
TCB Version:On (1),
Launch MIT Vector: Off (none).
```

**Example**
```bash
# Creating and storing a derived key
snpguest key derived-key.bin vcek --guest_field_select 0b110001 --guest_svn 2 --tcb_version 1 --vmpl 3
```

### 6. `report` 

Requests an attestation report from the host and writes it to a file with the provided request data and VMPL. The attestation report is written in binary format to the specified report path. The user can pass 64 bytes of data in any file format into `$REQUEST_FILE` to request the attestation report. This data will be bound to the REPORT_DATA field of the attestation report. The `--random` flag can be used to generate and use random data for the request, which will be written into `$REQUEST_FILE`. For Microsoft Azure Confidential VM, the `--platform` flag is required to get an attestation report from the vTPM. With this flag, the request data provided by the hypervisor will be written into the `$REQUEST_FILE`. `VMPL` is an optional parameter that defaults to 1.

**Usage**
```bash
snpguest report $ATT_REPORT_PATH $REQUEST_FILE [-v, --vmpl] [-r, --random] [-p, --platform]
```

**Arguments**
| Argument | Description | Default |
| :--      | :--        | :--    |
| `$ATT_REPORT_PATH` | Specifies the path where the attestation report would be stored. | required |
| `$REQUEST_FILE` | Specifies the path to the 64-byte request file. <br>• With `-r` flag, 64 random bytes will be written. <br>• With `-p` flag, writes 64 bytes provided by the hypervisor will be written. <br>• Without flags, the existing file contents are read as-is. | required |
| `-v, --vmpl $VMPL` | option specifies the VMPL level the Guest is running on.| 1 |
| `-r, --random` | Generate 64 random bytes of data for the report request. | false |
| `-p, --platform` | Fetch an attestation report from the vTPM NV index (Only available for Azure CVMs). | false |

**Example**
```bash
# Requesting Attestation Report with user-generated data
snpguest report attestation-report.bin request-file.bin
# Requesting Attestation Report using random data
snpguest report attestation-report.bin random-request-file.bin --random
# Get Pregenerated Attestation Report and Request Data from vTPM
snpguest report attestation-report.bin platform-request-file.bin --platform
```

### 7. `verify` 

Verifies certificates and the attestation report.

**Usage**
```bash
snpguest verify <SUBCOMMAND>
```

**Subcommands**
1. `certs`

    Verifies that the provided certificate chain has been properly signed by each certificate. The user needs to provide a directory where all three certificates (ARK, ASK/ASVK and VCEK/VLEK) are stored. An error will be raised if any of the certificates fail verification.

    **Usage**
    ```bash
    snpguest verify certs $CERTS_DIR
    ```
    **Argument**

    - `$CERTS_DIR` : Specifies the directory where the certificates are stored in. 

    **Example**
    ```bash
    snpguest verify certs ./certs
    ```

2. `attestation`

    Verifies the contents of the Attestation Report using the VCEK/VLEK certificate. The user needs to provide the path to the directory containing the VCEK/VLEK certificate and the path to a stored attestation report to be verified. An error will be raised if the attestation verification fails at any point. The user can use the `-t, --tcb` flag to only validate the TCB contents of the report and the `-s, --signature` flag to only validate the report's signature.

    **Usage**
    ```bash
    snpguest verify attestation $CERTS_DIR $ATT_REPORT_PATH [-t, --tcb] [-s, --signature] [-m, --measurement] [-d, --host-data] [-r, --report-data]
    ```
    **Arguments**

    - `$CERTS_DIR` : Specifies the directory where the certificates are stored in. 

    - `$ATT_REPORT_PATH` : Specifies the path of the stored attestation report.

    **Options**

    - `-t, --tcb`: Verify the Reported TCB section of the report only.
    - `-s, --signature`: Verify the signature of the report only.
    - `-m, --measurement`: Verify the measurement from the attestation report.
    - `-d, --host-data`: Verify the host-data from the attestation report.
    - `-r, --report-data`: Verify the report-data from the attestation report. 

    **Example**
    ```bash
    # Verify Attestation
    snpguest verify attestation ./certs attestation-report.bin
    # Verify Attestation Reported TCB only
    snpguest verify attestation ./certs attestation-report.bin --tcb
    # Verify Attestation Signature only
    snpguest verify attestation ./certs attestation-report.bin --signature
    # Verify Attestation Measurement only
    snpguest verify attestation --measurement 0xf28aac58964258d8ae0b2e88a706fc7afd0bb524f6a291ac3eedeccb73f89d7cfcf2e4fb6045e7d5201e41d1726afa02 /home/amd/certs /home/amd/report.bin
    # Verify Attestation host-data only
    snpguest verify attestation --host-data 0x7e4a3f9c1b82a056d39f0d44e5c8a7b1f02394de6b58ac0d7e3c11af0042bd59 /home/amd/certs /home/amd/report.bin
    # Verify Attestation report-data only
    snpguest verify attestation --report-data 0x5482c1ffe29145d47cf678f7681e3b64a89909d6cf8ec0104cfacb0b0418f005f564ad14f5c1381c99b74903a780ea340e887c9b445e9c760bf0b74115b26d45 /home/amd/certs /home/amd/report.bin 
    ```

### Global Options

- **-q, --quiet**: Suppress console output.

**Usage**
```bash
snpguest -q <SUBCOMMAND>
```

### [Extended Attestation Workflow](#extended-attestation-flowchart)

**Step 1.** Request the attestation report by providing the two mandatory parameters - `$ATT_REPORT_PATH` which is the path pointing to where the user wishes to store the attestation report and `$REQUEST_FILE` which is the path pointing to where the request file used to request the attestation report is stored. The optional parameter \[`-v, --vmpl`\] specifies the vmpl level for the attestation report and is set to 1 by default. The flag \[`-r, --random`\] generates random data to be used as request data for the attestation report. Lastly, the flag \[`-p, --platform`\] obtains both the attestation report and the request data from the platform (only available for a Microsoft Azure CVM where Hyper-V guest is enabled).

```bash
snpguest report $ATT_REPORT_PATH $REQUEST_FILE [-v, --vmpl] [-r, --random] [-p, --platform]
```

**Step 2.** Request certificates from the extended memory by providing the two mandatory parameters - `$ENCODING` which specifies whether to use PEM or DER encoding to store the certificates and $CERTS_DIR which specifies the path in the user's directory where the certificates will be saved.

```bash
snpguest certificates $ENCODING $CERTS_DIR
```

In some environments, only the VCEK/VLEK certificate can be obtained. In this case, you must follow the procedure described in [Regular Attestation Workflow](#regular-attestation-workflow) to obtain an AMD CA certificates.

**Step 3.** Verify the certificates obtained from the extended memory by providing `$CERTS_DIR` which specifies the path in the user's directory where the certificates were saved from Step 2.

```bash
snpguest verify certs $CERTS_DIR
```

**Step 4.** Verify the attestation by providing the two mandatory parameters - `$CERTS_DIR` which specifies the path in the user's directory where the certificates were saved from Step 2 and `$ATT_REPORT_PATH` which is the path pointing to the stored attestation report which the user wishes to verify. The optional parameters \[`-t, --tcb`\] is used to verify just the Reported TCB contents of the attestaion report and \[`-s, --signature`\] is used to verify just the signature of the attestaion report.

```bash
snpguest verify attestation $CERTS_DIR $ATT_REPORT_PATH [-t, --tcb] [-s, --signature]
```

### [Regular Attestation Workflow](#regular-attestation-flowchart)

**Step 1.** Request the attestation report by providing the two mandatory parameters - `$ATT_REPORT_PATH` which is the path pointing to where the user wishes to store the attestation report and `$REQUEST_FILE` which is the path pointing to where the request file used to request the attestation report is stored. The optional parameter \[`-v, --vmpl`\] specifies the vmpl level for the attestation report and is set to 1 by default. The flag \[`-r, --random`\] generates random data to be used as request data for the attestation report. Lastly, the flag \[`-p, --platform`\] obtains both the attestation report and the request data from the platform (only available for a Microsoft Azure CVM where Hyper-V guest is enabled).

```bash
snpguest report $ATT_REPORT_PATH $REQUEST_FILE [-v, --vmpl] [-r, --random] [-p, --platform]
```

**Step 2.** Request AMD Root Key (ARK) and AMD SEV Key (ASK) (or AMD SEV-VLEK Key (ASVK) for VLEK) from the AMD Key Distribution Service (KDS) by providing the three mandatory parameters - `$ENCODING` which specifies whether to use PEM or DER encoding to store the certificates, `$CERTS_DIR` which specifies the path in the user's directory where the certificates will be saved, and `$PROCESSOR_MODEL` - which specifies the AMD Processor model for which the certificates are to be fetched. The optional `-e, --endorser` argument specifies the type of attestation signing key (defaults to VCEK).

```bash
snpguest fetch ca $ENCODING $CERTS_DIR $PROCESSOR_MODEL [-e, --endorser] $ENDORSER
```

**Step 3.** Request the Versioned Chip Endorsement Key (VCEK) from the AMD Key Distribution Service (KDS) by providing the three mandatory parameters - `$ENCODING` which specifies whether to use PEM or DER encoding to store the certificates, `$CERTS_DIR` which specifies the path in the user's directory where the certificates will be saved, and `$ATT_REPORT_PATH` which is the path pointing to the stored attestation report for detecting Chip ID and Reported TCB Version. The optional \[`-p, --processor-model`\] argument specifies the AMD Processor model for which the certificates are to be fetched.

```bash
snpguest fetch vcek $ENCODING $CERTS_DIR $ATT_REPORT_PATH [-p, --processor-model] $PROCESSOR_MODEL
```

**Step 4.** Verify the certificates obtained by providing `$CERTS_DIR` which specifies the path in the user's directory where the certificates were saved from Step 2.

```bash
snpguest verify certs $CERTS_DIR
```

**Step 5.** Verify the attestation by providing the two mandatory parameters - `$CERTS_DIR` which specifies the path in the user's directory where the certificates were saved from Step 2 and `$ATT_REPORT_PATH` which is the path pointing to the stored attestation report which the user wishes to verify. The optional parameters \[`-t, --tcb`\] is used to verify just the Reported TCB contents of the attestaion report and \[`-s, --signature`\] is used to verify just the signature of the attestaion report.

```bash
snpguest verify attestation $CERTS_DIR $ATT_REPORT_PATH [-t, --tcb] [-s, --signature]
```

## Extended Attestation Flowchart
![alt text](https://github.com/virtee/snpguest/blob/main/docs/extended.PNG?raw=true)
## Regular Attestation Flowchart
![alt text](https://github.com/virtee/snpguest/blob/main/docs/regular.PNG?raw=true)

## Building

Some packages may need to be installed on the host system in order to build `snpguest`.

```bash
#Rust Installation
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

#Building snpguest after cloning
cargo build -r
```
### Ubuntu Dependencies

```bash
sudo apt install build-essential
```

### RHEL and its compatible distributions Dependencies

```bash
sudo dnf groupinstall "Development Tools" "Development Libraries"
```

### openSUSE and its compatible distributions Dependencies

```bash
sudo zypper in -t pattern "devel_basis"
```

### Building for Azure Confidential VMs
On Azure CVMs with AMD SEV-SNP, the paravisor fetches the report from AMD-SP once at VM boot time, and stores it in the vTPM NV index. The native `/dev/sev-guest` interface is hidden from the guest OS, so the guest OS must retrieve the report from the vTPM NV index using the `--platform` flag, which is available only in builds compiled with the `hyperv` feature.

```bash
git clone https://github.com/virtee/snpguest
cd ./snpguest
cargo build -r --features hyperv
```

## Reporting Bugs

Please report all bugs to the [Github snpguest](https://github.com/virtee/snpguest/issues) repository.
