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
- [Extended Attestation Workflow](#extended-attestation-workflow)
- [Regular Attestation Workflow](#regular-attestation-workflow)
- [Global Options](#global-options)
- [Extended Attestation Flowchart](#extended-attestation-flowchart)
- [Regular Attestation Flowchart](#regular-attestation-flowchart)
- [Building](#building)
  - [Ubuntu Dependencies](#ubuntu-dependencies)
  - [RHEL and its compatible distributions dependencies](#rhel-and-its-compatible-distributions-dependencies)
- [Reporting Bugs](#reporting-bugs)

## Usage

### 1. `help`

Every `snpguest` (sub)command comes with a `--help` option for a description on its use. 

Usage
```bash
snpguest --help
```

### 2. `certificates` 

Requests the certificate chain (ASK, ARK & VCEK) from host memory (requests extended-config). The user needs to specify the certificate encoding to store the certificates in (PEM or DER). Currently, only PEM and DER encodings are supported. All certificates will be in the same encoding. The user also needs to provide the path to the directory where the certificates will be stored. If certificates already exist in the provided directory, they will be overwritten.

Usage 
```bash
snpguest certificates $ENCODING $CERTS_DIR
```
Arguments

- `$ENCODING` : Specifies the certificate encoding to store the certificates in (PEM or DER).

- `$CERTS_DIR` : Specifies the directory to store the certificates in. This is required only when requesting an extended attestation report.

Example
```bash
snpguest certificates pem ./certs
```

### 3. `display` 

Displays files in human readable form. 

Usage
```bash
snpguest display <SUBCOMMAND>
```
Subcommands

1. `report`

    When used for displaying a report, it prints the attestation report contents into the terminal. The user has to provide the path of the stored attestation report to display.

    Usage
    ```bash
    snpguest display report $ATT_REPORT_PATH
    ```

    Argument

    - `$ATT_REPORT_PATH` : Specifies the path of the stored attestation report to display.

    Example
    ```bash
    snpguest display report attestation-report.bin
    ```

2. `key`

    When used for displaying the fetched derived key's contents, it prints the derived key in hex format into the terminal. The user has to provide the path of a stored derived key to display.

    Usage

    ```bash
    snpguest display key $KEY_PATH
    ```
    Argument

    - `$KEY_PATH` : Specifies the path of the stored derived key to display.

    Example
    ```bash
    snpguest display key derived-key.bin
    ```

### 4. `fetch`

Command to Requests certificates from the KDS.

Usage
```bash
snpguest fetch <SUBCOMMAND>
```

Subcommands
1. `ca`

    Requests the certificate authority chain (ARK & ASK) from the KDS. The user needs to specify the certificate encoding to store the certificates in (PEM or DER). Currently, only PEM and DER encodings are supported. Both certificates will be in the same encoding. The user must specify their host processor model. The user also needs to provide the path to the directory where the certificates will be stored. If the certificates already exist in the provided directory, they will be overwritten.

    Usage
    ```bash
    snpguest fetch ca $ENCODING $PROCESSOR_MODEL $CERTS_DIR
    ```
    Arguments
    
    - `$ENCODING` : Specifies the certificate encoding to store the certificates in (PEM or DER).

    - `$PROCESSOR_MODEL` : Specifies the host processor model. 
    
    - `$CERTS_DIR` : Specifies the directory to store the certificates in.

    Example
    ```bash
    snpguest fetch ca der milan ./certs-kds
    ```

2. `vcek`

    Requests the VCEK certificate from the KDS. The user needs to specify the certificate encoding to store the certificate in (PEM or DER). Currently, only PEM and DER encodings are supported. The user must specify their host processor model. The user also needs to provide the path to the directory where the VCEK will be stored and the path to a stored attestation report that will be used to request the VCEK. If the certificate already exists in the provided directory, it will be overwritten.

    Usage
    ```bash
    snpguest fetch vcek $ENCODING $PROCESSOR_MODEL $CERTS_DIR $ATT_REPORT_PATH
    ```
    Arguments
    
    - `$ENCODING` : Specifies the certificate encoding to store the certificates in (PEM or DER).

    - `$PROCESSOR_MODEL` : Specifies the host processor model. 
    
    - `$CERTS_DIR` : Specifies the directory to store the certificates in. 

    - `$ATT_REPORT_PATH` : Specifies the path of the stored attestation report.

    Example
    ```bash
    snpguest fetch vcek der milan ./certs-kds attestation-report.bin
    ```

### 5. `key` 

Creates the derived key based on input parameters and stores it. `$KEY_PATH` is the path to store the derived key. `$ROOT_KEY_SELECT` is the root key from which to derive the key (either "vcek" or "vmrk"). The `--guest_field_select` option specifies which Guest Field Select bits to enable as a 6-digit binary string. Each of the 6 bits from left to right correspond to Guest Policy, Image ID, Family ID, Measurement, SVN and TCB Version respectively. For each bit, 0 denotes off, and 1 denotes on. The `--guest_svn` option specifies the guest SVN to mix into the key, and the `--tcb_version` option specifies the TCB version to mix into the derived key. The `--vmpl` option specifies the VMPL level the Guest is running on and defaults to 1.


Usage
```bash
snpguest key $KEY_PATH $ROOT_KEY_SELECT [-g, --guest_field_select] [-s, --guest_svn] [-t, --tcb_version] [-v, --vmpl]
```
Arguments

- `$KEY_PATH` : The path to store the derived key. 

- `$ROOT_KEY_SELECT` : is the root key from which to derive the key (either "vcek" or "vmrk").

Options

- `--guest_field_select` : option specifies which Guest Field Select bits to enable as a 6-digit binary string. For each bit, 0 denotes off, and 1 denotes on. 

      For example, `--guest_field_select 100001` denotes 

      Guest Policy:On (1), 

      Image ID:Off (0), 

      Family ID:Off (0), 

      Measurement:Off (0), 

      SVN:Off (0), 

      TCB Version:On (1). 

- `--guest_svn` : option specifies the guest SVN to mix into the key,

- `--tcb_version` : option specifies the TCB version to mix into the derived key. 

- `--vmpl` : option specifies the VMPL level the Guest is running on and defaults to 1.

Example
```bash
# Creating and storing a derived key
snpguest key derived-key.bin vcek --guest_field_select 100001 --guest_svn 2 --tcb_version 1 --vmpl 3
```

### 6. `report` 

Requests an attestation report from the host and writes it to a file with the provided request data and VMPL. The attestation report is written in binary format to the specified report path. The user can pass 64 bytes of data in any file format into `$REQUEST_FILE` to request the attestation report. The `--random` flag can be used to generate and use random data for the request, and for Microsoft Hyper-V guests, the `--platform` flag is required to use pre-generated request data. The data already generated from the hypervisor will be written into the file provided in `$REQUEST_FILE`. `VMPL` is an optional parameter that defaults to 1. `--random` is not available in Hyper-V, as the request data is pre-generated.

Usage
```bash
snpguest report $ATT_REPORT_PATH $REQUEST_FILE [-v, --vmpl] [-r, --random] [-p, --platform]
```

Arguments

- `$ATT_REPORT_PATH` : Specifies the path where the attestation report would be stored.

- `$REQUEST_FILE` : File where the data generated from the hypervisor will be written into.

Options

- `-r, --random`: Generate 64 random bytes of data for the report request (Not available for in Hyper-V).
- `-p, --platform` : Use platform provided 64 bytes of data for the request report (Only available for Hyper-V).
- `-v, --vmpl` : option specifies the VMPL level the Guest is running on and defaults to 1.

Example
```bash
# Requesting Attestation Report with user-generated data
snpguest report attestation-report.bin request-file.txt
# Requesting Attestation Report using random data
snpguest report attestation-report.bin random-request-file.txt --random
# Requesting Attestation Report using platform data
snpguest report attestation-report.bin platform-request-file.txt --platform
```

### 7. `verify` 

Verifies certificates and the attestation report.

Usage
```bash
snpguest verify <SUBCOMMAND>
```

Subcommands
1. `certs`

    Verifies that the provided certificate chain has been properly signed by each certificate. The user needs to provide a directory where all three certificates (ARK, ASK, and VCEK) are stored. An error will be raised if any of the certificates fail verification.

    Usage
    ```bash
    snpguest verify certs $CERTS_DIR
    ```
    Argument

    - `$CERTS_DIR` : Specifies the directory where the certificates are stored in. 

    Example
    ```bash
    snpguest verify certs ./certs
    ```

2. `attestation`

    Verifies the contents of the Attestation Report using the VCEK certificate. The user needs to provide the path to the directory containing the VCEK certificate and the path to a stored attestation report to be verified. An error will be raised if the attestation verification fails at any point. The user can use the `-t, --tcb` flag to only validate the TCB contents of the report and the `-s, --signature` flag to only validate the report's signature.

    Usage
    ```bash
    snpguest verify attestation $CERTS_DIR $ATT_REPORT_PATH [-t, --tcb] [-s, --signature]
    ```
    Arguments

    - `$CERTS_DIR` : Specifies the directory where the certificates are stored in. 

    - `$ATT_REPORT_PATH` : Specifies the path of the stored attestation report.

    Options

    - `-t, --tcb`: Verify the TCB section of the report only.
    - `-s, --signature`: Verify the signature of the report only.

    Example
    ```bash
    # Verify Attestation
    snpguest verify attestation ./certs attestation-report.bin
    # Verify Attestation Signature only
    snpguest verify attestation ./certs attestation-report.bin --signature
    ```

### [Extended Attestation Workflow](#extended-attestation-flowchart)

**Step 1.** Request the attestation report by providing the two mandatory parameters - $ATT_REPORT_PATH which is the path pointing to where the user wishes to store the attestation report and $REQUEST_FILE which is the path pointing to where the request file used to request the attestation report is stored. The optional parameters [-v, --vmpl] specifies the vmpl level for the attestation report and is set to 1 by default. [-r, --random] generates random data to be used as request data for the attestation report. Lastly, [-p, --platform] obtains the request data from the platform. Microsoft Hyper-V is mandatory when the user is expecting the platform to provide the request data for the attestaion report.

```bash
snpguest report $ATT_REPORT_PATH $REQUEST_FILE [-v, --vmpl] [-r, --random] [-p, --platform]
```

**Step 2.** Request certificates from the extended memory by providing the two mandatory parameters - $ENCODING whichspecifies whether to use PEM or DER encoding to store the certificates and $CERTS_DIR which specifies the path in the user's directory where the certificates will be saved.

```bash
snpguest certificates $ENCODING $CERTS_DIR
```

**Step 3.** Verify the certificates obtained from the extended memory by providing $CERTS_DIR which specifies the path in the user's directory where the certificates were saved from Step 2.

```bash
snpguest verify certs $CERTS_DIR
```

**Step 4.** Verify the attestation by providing the two mandatory parameters - $CERTS_DIR which specifies the path in the user's directory where the certificates were saved from Step 2 and $ATT_REPORT_PATH which is the path pointing to the stored attestation report which the user wishes to verify. The optional parameters [-t, --tcb] is used to verify just the TCB contents of the attestaion report and [-s, --signature] is used to verify just the signature of the attestaion report.

```bash
snpguest verify attestation $CERTS_DIR $ATT_REPORT_PATH [-t, --tcb] [-s, --signature]
```

### [Regular Attestation Workflow](#regular-attestation-flowchart)

**Step 1.** Request the attestation report by providing the two mandatory parameters - $ATT_REPORT_PATH which is the path pointing to where the user wishes to store the attestation report and $REQUEST_FILE which is the path pointing to where the request file used to request the attestation report is stored. The optional parameters [-v, --vmpl] specifies the vmpl level for the attestation report and is set to 1 by default. [-r, --random] generates random data to be used as request data for the attestation report. Lastly, [-p, --platform] obtains the request data from the platform. Microsoft Hyper-V is mandatory when the user is expecting the platform to provide the request data for the attestation report.

```bash
snpguest report $ATT_REPORT_PATH $REQUEST_FILE [-v, --vmpl] [-r, --random] [-p, --platform]
```

**Step 2.** Request AMD Root Key (ARK) and AMD SEV Key (ASK) from the AMD Key Distribution Service (KDS) by providing the three mandatory parameters - $ENCODING whichspecifies whether to use PEM or DER encoding to store the certificates, $PROCESSOR_MODEL - which specifies the AMD Processor model for which the certificates are to be fetched and $CERTS_DIR which specifies the path in the user's directory where the certificates will be saved.

```bash
snpguest fetch ca $ENCODING $PROCESSOR_MODEL $CERTS_DIR
```

**Step 3.** Request the Versioned Chip Endorsement Key (VCEK) from the AMD Key Distribution Service (KDS) by providing the three mandatory parameters - $ENCODING whichspecifies whether to use PEM or DER encoding to store the certificates, $PROCESSOR_MODEL - which specifies the AMD Processor model for which the certificates are to be fetched and $CERTS_DIR which specifies the path in the user's directory where the certificates will be saved.


```bash
snpguest fetch vcek $ENCODING $PROCESSOR_MODEL $CERTS_DIR $ATT_REPORT_PATH
```

**Step 4.** Verify the certificates obtained by providing $CERTS_DIR which specifies the path in the user's directory where the certificates were saved from Step 2.

```bash
snpguest verify certs $CERTS_DIR
```

**Step 5.** Verify the attestation by providing the two mandatory parameters - $CERTS_DIR which specifies the path in the user's directory where the certificates were saved from Step 2 and $ATT_REPORT_PATH which is the path pointing to the stored attestation report which the user wishes to verify. The optional parameters [-t, --tcb] is used to verify just the TCB contents of the attestaion report and [-s, --signature] is used to verify just the signature of the attestaion report.

```bash
snpguest verify attestation $CERTS_DIR $ATT_REPORT_PATH [-t, --tcb] [-s, --signature]
```

### Global Options

- **-q, --quiet**: Suppress console output.

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


## Reporting Bugs

Please report all bugs to the [Github snpguest](https://github.com/virtee/snpguest/issues) repository.
