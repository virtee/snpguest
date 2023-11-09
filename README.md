# snpguest

`snpguest` is a Command Line Interface utility for managing an AMD SEV-SNP enabled guest. This tool allows users to interact with the AMD SEV-SNP guest firmware device enabling various operations such as: attestation, certificate management, derived key fetching, and more.

- [Usage](#usage)
  - [Extended Attestation Workflow](#extended-attestation-workflow)
  - [Regular Attestation Workflow](#regular-attestation-workflow)
  - [Global Options](#global-options)
  - [Commands](#commands)
    - [snpguest report](#snpguest-report)
    - [snpguest certificates](#snpguest-certificates)
    - [snpguest fetch ca](#snpguest-fetch-ca)
    - [snpguest fetch vcek](#snpguest-fetch-vcek)
    - [snpguest guest verify certs](#snpguest-guest-verify-certs)
    - [snpguest guest verify attestation](#snpguest-guest-verify-attestation)
    - [snpguest key](#snpguest-key)
    - [snpguest guest display report](#snpguest-guest-display-report)
    - [snpguest guest display key](#snpguest-guest-display-key)
- [SNP Examples](#snp-examples)
- [Extended Attestation Flowchart](#extended-attestation-flowchart)
- [Regular Attestation Flowchart](#regular-attestation-flowchart)
- [Building](#building)
- [Reporting Bugs](#reporting-bugs)


## Usage
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

**Step 2.** Request AMD Root Key (ARK) and AMD SEV Key (ASK) from the AMD Key Distribution Service (KDS) by providing the three mandatory parameters - $ENCODING whichspecifies whether to use PEM or DER encoding to store the certificates, $PROCESSOR_MODEL - which specifies the AMD Processor model (Milan, Genoa) for which the certificates are to be fetched and $CERTS_DIR which specifies the path in the user's directory where the certificates will be saved.

```bash
snpguest fetch ca $ENCODING $PROCESSOR_MODEL $CERTS_DIR
```

**Step 3.** Request the Versioned Chip Endorsement Key (VCEK) from the AMD Key Distribution Service (KDS) by providing the three mandatory parameters - $ENCODING whichspecifies whether to use PEM or DER encoding to store the certificates, $PROCESSOR_MODEL - which specifies the AMD Processor model (Milan, Genoa) for which the certificates are to be fetched and $CERTS_DIR which specifies the path in the user's directory where the certificates will be saved.


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

### Commands

### snpguest report

```bash
snpguest report $ATT_REPORT_PATH $REQUEST_FILE [-v, --vmpl] [-r, --random] [-p, --platform]
```

Requests an attestation report from the host and writes it to a file with the provided request data and VMPL. The attestation report is written in binary format to the specified report path. The user can pass 64 bytes of data in any file format into `$REQUEST_FILE` to request the attestation report. The `--random` flag can be used to generate and use random data for the request, and for Microsoft Hyper-V guests, the `--platform` flag is required to use pre-generated request data. The data already generated from the hypervisor will be written into the file provided in `$REQUEST_FILE`. `VMPL` is an optional parameter that defaults to 1. `--random` is not available in Hyper-V, as the request data is pre-generated.

Options:
- `-h, --help`: Show a help message.
- `-r, --random`: Generate 64 random bytes of data for the report request. (Not used in Hyper-V)
- `-v, --vmpl`: Specify a different VMPL level for the attestation report (defaults to 1).

Example usage:
```bash
# Requesting Attestation Report with user-generated data
snpguest report attestation-report.bin request-file.txt
# Requesting Attestation Report using random data
snpguest report attestation-report.bin random-request-file.txt --random
# Requesting Attestation Report using platform data
snpguest report attestation-report.bin platform-request-file.txt --platform
```

### snpguest certificates

```bash
snpguest certificates $ENCODING $CERTS_DIR
```

Requests the certificate chain (ASK, ARK & VCEK) from host memory (requests extended-config). The user needs to specify the certificate encoding to store the certificates in (PEM or DER). Currently, only PEM and DER encodings are supported. All certificates will be in the same encoding. The user also needs to provide the path to the directory where the certificates will be stored. If certificates already exist in the provided directory, they will be overwritten.

Options:
- `-h, --help`: Show a help message.

Example usage:
```bash
# Requesting certificates
snpguest certificates pem ./certificates
```

### snpguest fetch ca

```bash
snpguest fetch ca $ENCODING $PROCESSOR_MODEL $CERTS_DIR
```

Requests the certificate authority chain (ARK & ASK) from the KDS. The user needs to specify the certificate encoding to store the certificates in (PEM or DER). Currently, only PEM and DER encodings are supported. Both certificates will be in the same encoding. The user must specify their host processor model (Milan or Genoa). The user also needs to provide the path to the directory where the certificates will be stored. If the certificates already exist in the provided directory, they will be overwritten.

Options:
- `-h, --help`: Show a help message.

Example usage:
```bash
# Requesting ARK & ASK certificates from KDS
snpguest fetch ca der milan ./certs-kds
```

### snpguest fetch vcek

```bash
snpguest fetch vcek $ENCODING $PROCESSOR_MODEL $CERTS_DIR $ATT_REPORT_PATH
```

Requests the VCEK certificate from the KDS. The user needs to specify the certificate encoding to store the certificate in (PEM or DER). Currently, only PEM and DER encodings are supported. The user must specify their host processor model (Milan or Genoa). The user also needs to provide the path to the directory where the VCEK will be stored and the path to a stored attestation report that will be used to request the VCEK. If the certificate already exists in the provided directory, it will be overwritten.

Options:
- `-h, --help`: Show a help message.

Example usage:
```bash
# Requesting VCEK
snpguest fetch vcek der milan ./certs-kds attestation-report.bin
```

### snpguest verify certs

```bash
snpguest verify certs $CERTS_DIR
```

Verifies that the provided certificate chain has been properly signed by each certificate. The user needs to provide a directory where all three certificates (ARK, ASK, and VCEK) are stored. An error will be raised if any of the certificates fail verification.

Options:
- `-h, --help`: Show a help message.

Example usage:
```bash
# Verifying Certs
snpguest verify certs ./certs
```

### snpguest verify attestation

```bash
snpguest verify attestation $CERTS_DIR $ATT_REPORT_PATH [-t, --tcb] [-s, --signature]
```

Verifies the contents of the Attestation Report using the VCEK certificate. The user needs to provide the path to the directory containing the VCEK certificate and the path to a stored attestation report to be verified. An error will be raised if the attestation verification fails at any point. The user can use the `-t, --tcb` flag to only validate the TCB contents of the report and the `-s, --signature` flag to only validate the report's signature.

Options:
- `-h, --help`: Show a help message.
- `-t, --tcb`: Verify the TCB section of the report only

.
- `-s, --signature`: Verify the signature of the report only.

Example usage:
```bash
# Verify Attestation
snpguest verify attestation ./certs attestation-report.bin
# Verify Attestation Signature only
snpguest verify attestation ./certs attestation-report.bin --signature
```

### snpguest key

```bash
snpguest key $KEY_PATH $ROOT_KEY_SELECT [-g, --guest_field_select] [-s, --guest_svn] [-t, --tcb_version] [-v, --vmpl]
```

Creates the derived key based on input parameters and stores it. `$KEY_PATH` is the path to store the derived key. `$ROOT_KEY_SELECT` is the root key from which to derive the key (either "vcek" or "vmrk"). The `--guest_field_select` option specifies which Guest Field Select bits to enable as a 6-digit binary string. For each bit, 0 denotes off, and 1 denotes on (e.g., `--guest_field_select 100001` denotes Guest Policy:On, Image ID:Off, Family ID:Off, Measurement:Off, SVN:Off, TCB Version:On). The `--guest_svn` option specifies the guest SVN to mix into the key, and the `--tcb_version` option specifies the TCB version to mix into the derived key. The `--vmpl` option specifies the VMPL level the Guest is running on and defaults to 1.

Options:
- `-h, --help`: Show a help message.

Example usage:
```bash
# Creating and storing a derived key
snpguest key derived-key.bin vcek --guest_field_select 100001 --guest_svn 2 --tcb_version 1 --vmpl 3
```

### snpguest guest display report

```bash
snpguest display report $ATT_REPORT_PATH
```

Prints the attestation report contents into the terminal. The user has to provide a path to a stored attestation report to display.

Options:
- `-h, --help`: Show a help message.

Example usage:
```bash
# Displaying an attestation report
snpguest display report attestation-report.bin
```

### snpguest guest display key

```bash
snpguest display key $KEY_PATH
```

Prints the derived key contents in hex format into the terminal. The user has to provide the path of a stored derived key to display.

Options:
- `-h, --help`: Show a help message.

Example usage:
```bash
# Displaying a derived key
snpguest display key derived-key.bin
```
---

# SNP Examples

## Requesting a report:

```bash
snpguest report <attestation-report-path> <request-file-path> [-v, --vmpl] [-r, --random] [-p, --platform]
```

- `<attestation-report-path>`: Path pointing to where the user wants to store the attestation report (stored in binary format).
- `<request-file-path>`: Path pointing to the request file to be used to request the attestation report.
- `-v, --vmpl`: Specify a VMPL level for the attestation report (defaults to 1).
- `-r, --random`: Generate random data to use as request data for the attestation report. The data will be stored at `<request-file-path>` location.
- `-p, --platform`: Get request data from the platform. The user expects that the platform will provide the request data for the attestation report (mandatory for Microsoft Hyper-V).

### Requesting Attestation Report with user-generated data:

```bash
snpguest report attestation-report.bin request-file.txt
```

**Note**: `request-file.txt` must contain 64 bytes of data.

### Requesting Attestation Report using random data:

```bash
snpguest report attestation-report.bin random-request-file.txt --random
```

### Requesting Attestation Report using platform data:

```bash
snpguest report attestation-report.bin platform-request-file.txt --platform
```

## Requesting Certificates:

### Requesting certificates from extended memory (extended report use case):

```bash
snpguest certificates <encoding> <certs-directory>
```

- `<encoding>`: Specify whether to store certificates in either PEM or DER encoding.
- `<certs-directory>`: Specify the path to a directory where the certificates will be stored.

Example:

```bash
snpguest certificates pem ./certificates
```

### Requesting ARK & ASK certificates from KDS:

```bash
snpguest fetch ca <encoding> <processor-model> <certs-directory>
```

- `<encoding>`: Specify whether to store certificates in either PEM or DER encoding.
- `<processor-model>`: Specify the processor model to get the certificates for (Milan, Genoa).
- `<certs-directory>`: Specify the path to a directory where the certificates will be stored.

Example:

```bash
snpguest fetch ca der milan ./certs-kds
```

### Requesting VCEK from KDS:

```bash
snpguest fetch vcek <encoding> <processor-model> <certs-directory> <attestation-report-path>
```

- `<encoding>`: Specify whether to store certificates in either PEM or DER encoding.
- `<processor-model>`: Specify the processor model to get the certificates for (Milan, Genoa).
- `<certs-directory>`: Specify the path to a directory where the VCEK will be stored.
- `<attestation-report-path>`: Specify the path to an attestation report to be used to request the VCEK.

Example:

```bash
snpguest fetch vcek der milan ./certs-kds attestation-report.bin
```

## Verifying Attestation

### Verifying certificate chain:

```bash
snpguest verify certs <certs-directory>
```

- `<certs-directory>`: Specify the path to a directory where the certificates are stored. A full certificate chain is required (ASK, ARK, and VCEK).

Example:

```bash
snpguest verify certs ./certs
```

### Verifying Attestation Report:

```bash
snpguest verify attestation <certs-directory> <attestation-report-path> [-t, --tcb] [-s, --signature]
```

- `<certs-directory>`: Specify the path to a directory where the certificates are stored.
- `<attestation-report-path>`: Specify the path to an attestation report to be verified.
- `-t, --tcb`: Just verify the TCB contents of the attestation report.
- `-s, --signature`: Just verify the signature of the attestation report.

Example:

```bash
# Verify Attestation
snpguest verify attestation ./certs attestation-report.bin
# Verify Attestation Signature only
snpguest verify attestation ./certs attestation-report.bin --signature
```

---
## Extended Attestation Flowchart
![alt text](https://github.com/AdithyaKrishnan/adi-snpguest/blob/main/docs/extended.PNG?raw=true)
## Regular Attestation Flowchart
![alt text](https://github.com/AdithyaKrishnan/adi-snpguest/blob/main/docs/regular.PNG?raw=true)

## Building

Some packages may need to be installed on the host system in order to build `snpguest`.

```console
#Rust Installation
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

#Building snpguest after cloning
cargo build -r
```
### Ubuntu Dependencies

```console
sudo apt install build-essential
```

### RHEL and its compatible distributions Dependencies

```console
sudo dnf groupinstall "Development Tools" "Development Libraries"
```


## Reporting Bugs

Please report all bugs to the [Github snpguest](https://github.com/virtee/snpguest/issues) repository.
