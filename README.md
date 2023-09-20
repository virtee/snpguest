**SNPguest** is a Command Line Interface utility for managing the AMD SEV-SNP guest environment. This tool allows users to interact with the AMD SEV-SNP guest firmware device enabling various operations related to attestation, certificate management, key generation, and more.

## Table of Contents

- [Summary](#summary)
- [File Structure](#file-structure)
- [Usage](#usage)
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
- [Reporting Bugs](#reporting-bugs)
- [Extended Attestation Flowchart](#extended-attestation-flowchart)
- [Regular Attestation Flowchart](#regular-attestation-flowchart)

## Summary

The "src" directory in the `snpguest` GitHub repository contains several Rust source code files that collectively implement the functionality of the SNP Guest utility. Here's a summary of the functionality of each of these files:

1. **`certs.rs`**:

- This file contains code related to managing certificates.

- It defines a structure for managing certificate paths (`CertPaths`) and functions for obtaining extended certificates from the AMD PSP.

2. **`display.rs`**:

- This file defines the CLI for displaying attestation reports and derived keys.

- It contains subcommands for displaying attestation reports and derived keys.

- Submodules `report_display` and `key_display` handle the respective display functionalities.

3. **`fetch.rs`**:

- This file defines the CLI for fetching certificates.

- It contains subcommands for fetching various types of certificates from the AMD PSP.

4. **`key.rs`**:

- This file contains code for generating derived keys.

- It defines the CLI for generating derived keys from root keys.

- It includes functions for requesting and saving derived keys.

5. **`report.rs`**:

- This file defines the CLI for requesting attestation reports.

- It contains functions for requesting attestation reports and saving them to files.

- Additionally, it includes code for reading and parsing attestation reports.

6. **`verify.rs`**:

- This file defines the CLI for verifying certificates and attestation reports.

- It includes subcommands for verifying certificate chains and attestation reports.

- Submodules `certificate_chain` and `attestation` contain the verification logic for certificates and attestation reports, respectively.

7. **`hyperv.rs`** (conditional compilation with the "hyperv" feature):

- This file contains code related to Hyper-V integration (Hypervisor).

- It provides a flag (`hyperv::present`) indicating whether the SNP Guest is running within a Hyper-V guest environment.

8. **`main.rs`**:

- This is the main entry point of the SNP Guest utility.

- It initializes the CLI using the `structopt` crate.

- The CLI includes subcommands for requesting and managing certificates, displaying information, generating keys, and verifying certificates and attestation reports.

- It also handles command execution based on the selected subcommand and manages error handling.

Each of these files contributes to the overall functionality of the SNP Guest utility, allowing users to interact with and manage security-related features such as certificates, attestation reports, derived keys, and verification within a Secure Nested Paging (SNP) Guest environment.

## File Structure

Main.rs:
This code serves as a CLI utility for managing and interacting with the SNP Guest environment in virtualization scenarios. It offers various operations related to certificates, attestation reports, key generation, and verification, making it a versatile tool for SNP Guest management. The choice of specific operations is determined by the selected subcommand.

1. **Module Imports**:

- The code imports several modules that provide functionality for certificates, display, fetching data, key generation, reporting, and verification.

2. **Feature Flags**:

- Conditional compilation is used based on a feature flag named `hyperv`. Depending on whether this feature is enabled or not, it is used to support different virtualization platforms.

3. **Command-Line Interface (CLI)**:

- The main program defines a CLI interface using the `structopt` crate.

- It has subcommands for different operations, including reporting, certificate management, fetching, verification, displaying, and key generation.

- The `quiet` flag is provided to suppress console output if set.

4. **Main Function** (`main`):

- The main function initializes the `env_logger` for logging.

- It parses command-line arguments into the `snpguest` structure.

- Depending on the selected subcommand, it sets the `hv` (Hyper-V) flag based on feature flag conditions.

- It then executes the corresponding subcommand by calling functions from the respective modules.

- Any errors encountered during subcommand execution are handled and printed to the console, including error chains.

Certs.rs:  
This code manages certificates in the context of AMD SEV-SNP technology, including reading, writing, converting between PEM and DER formats, requesting certificates from SEV firmware, and saving them to a directory. It serves as a crucial component for certificate management.

1. **Imports and Dependencies**: The code imports various external dependencies, including Rust's standard library (`std`), the `sev` crate for SEV-related functionality, and the `openssl` crate for OpenSSL bindings.

2. **Certificate Path Representation**: It defines a `CertPaths` struct to represent paths to three types of certificates: `ark`, `ask`, and `vcek`.

3. **Certificate Encoding Format**: An enumeration called `CertFormat` is defined to represent certificate encoding formats, specifically PEM or DER.

4. **Parsing Certificate Format**: The code implements the `FromStr` trait for `CertFormat` to parse a string into the corresponding enum variant (`Pem` or `Der`).

5. **Identifying Certificate Format**: There's a function called `identify_cert` that determines whether a certificate is in PEM or DER format based on its content.

6. **Converting Certificates**: The code defines a function named `convert_path_to_cert` that reads a certificate file and converts it into an `snp Certificate` object. This function supports both PEM and DER formats.

7. **Chaining Certificates**: It implements the `TryFrom` trait for `CertPaths`, allowing the conversion of a `CertPaths` struct into an `snp Chain` object, which represents a chain of certificates.

8. **Converting Certificate Formats**: There's a function called `translate_cert` that converts a certificate from one encoding format to another, such as PEM to DER or vice versa.

9. **Writing Certificates**: Another function named `write_cert` is defined to write a certificate to a specified directory, allowing for different encoding formats (PEM or DER). The encoding format is determined based on the provided data and format.

10. **Handling Command-Line Arguments**: The code defines a `CertificatesArgs` struct to represent command-line arguments for requesting and saving certificates.

11. **Requesting and Saving Certificates**: The primary function, `get_ext_certs`, requests extended attestation reports and saves the associated certificates to a specified directory. It uses the `sev` crate to communicate with the SEV firmware. The function generates random request data, fetches the certificates, and writes them to the specified directory.

Display.rs:  
This code provides console-based functionality for displaying attestation reports and derived keys. It also defines a module for displaying information. The code provides two main subcommands for displaying attestation reports and derived keys, each with its own set of options and functionality. 

1. **Module Structure**:
   - This module contains two submodules: `report_display` and `key_display`. Each submodule handles the display of a specific type of information.

2. **Command-Line Interface (CLI)**:
   - The code uses the `structopt` crate to define a CLI.
   - It defines two subcommands within the `DisplayCmd` enum:
     - `Report`: Used for displaying attestation reports.
     - `Key`: Used for displaying derived keys.

3. **Command Execution Function** (`cmd`):
   - The `cmd` function takes a `DisplayCmd` enum and a `quiet` flag as parameters.
   - It matches the provided `DisplayCmd` and calls the appropriate submodule's display function based on the selected subcommand.

4. **Submodule `report_display`**:
   - This submodule handles the display of attestation reports.
   - It defines a `display_attestation_report` function that takes an `Args` struct as input.
   - The `display_attestation_report` function reads an attestation report from the specified file path and prints it to the console.
   - If the `quiet` flag is not set, the attestation report is printed.

5. **Submodule `key_display`**:
   - This submodule handles the display of derived keys.
   - It defines a `display_derived_key` function that takes an `Args` struct as input.
   - The `display_derived_key` function reads a derived key from the specified file path, formats it as a hexadecimal string, and prints it to the console.
   - The key is displayed in a human-readable format with 16 bytes per line.
   - If the `quiet` flag is not set, the derived key is printed.

Fetch.rs:  
This code defines a CLI for fetching certificates from a Key Distribution Service (KDS). The code aims to provide a convenient CLI interface for users to fetch certificates from a KDS, supporting different processor models and certificate formats. It also handles directory creation and certificate writing. It includes the following functionality:

1. **Command-Line Interface (CLI) Definition**: The code defines a CLI with two subcommands:

- `CA`: Fetches the certificate authority chain (ARK & ASK) from the KDS.

- `Vcek`: Fetches the VCEK (Virtualization Code Execution Key) from the KDS.

2. **Enumeration and Parsing**: It defines an enumeration called `ProcType` to represent processor types ("Milan" or "Genoa"). It also implements the `FromStr` trait for parsing processor types and the `fmt::Display` trait for displaying them.

3. **Command Handling**: The `cmd` function is responsible for handling the selected subcommand and performing the corresponding action. It calls either the `cert_authority::fetch_ca` function or the `vcek::fetch_vcek` function based on the selected subcommand.

4. **Subcommand Modules**:

- `cert_authority`: This module contains functionality for fetching the certificate authority chain (ARK & ASK) from the KDS. It defines a structure `Args` to represent the command-line arguments required for this operation. The `request_ca_kds` function constructs a URL to the KDS, fetches the certificates, and writes them to the specified directory in either PEM or DER format.

- `vcek`: This module contains functionality for fetching the VCEK from the KDS. It defines a structure `Args` to represent the command-line arguments required for this operation. The `request_vcek_kds` function constructs a URL using an attestation report, fetches the VCEK in DER format, and writes it to the specified directory in either PEM or DER format.

Key.rs:  
This code defines a module for working with derived keys. A CLI interface is used for generating and reading derived keys, allowing users to specify various parameters for key derivation. The generated keys are saved to files for later use. Here's a summary of its functionality:

1. **Command-Line Interface (CLI) Argument Parsing**: The code defines a `KeyArgs` struct to represent the command-line arguments required for key generation. It includes fields for specifying the key file path, root key selection (VCEK or VMRK), Virtual Machine Privilege Level (VMPL), Guest Field Select bits (GFS), Guest SVN, and TCB version.

2. **Derived Key Generation**: The `get_derived_key` function takes the parsed command-line arguments and generates a derived key based on SEV parameters. It performs the following steps:

- Validates the input for root key selection, VMPL, GFS, Guest SVN, and TCB version.

- Constructs a `DerivedKey` request object based on the input.

- Opens the SEV firmware device.

- Requests the derived key from the SEV firmware using the constructed request.

- Writes the derived key to the specified file path in binary format using the `bincode` crate.

3. **Derived Key Reading**: The `read_key` function reads a derived key from a file and returns it as a vector of bytes.

Reports.rs: This code provides functionality for handling attestation reports. It provides functionality for verifying certificate chains and attestation reports. It offers command-line interface options for running specific verification tasks, making it a useful tool for ensuring the security and integrity of SEV-based virtualization systems. Here's a summary of its key features:

1. **Reading Attestation Reports**:

- The `read_report` function reads a binary-formatted attestation report from a file and deserializes it into an `AttestationReport` object.

2. **Generating Random Attestation Report Data**:

- The `create_random_request` function generates 64 random bytes of data that can be used as a request for attestation reports.

3. **Command-Line Interface (CLI) Argument Parsing**:

- The code defines a `ReportArgs` struct for parsing CLI arguments related to attestation reports.

- It includes options to specify the output file for the attestation report, whether to use random data for the request, VMPL level, request file, and platform mode.

4. **Argument Verification**:

- The `ReportArgs` struct includes a `verify` method that checks the validity of command-line arguments, such as disallowing the combination of `--random` and `--platform` options.

5. **Requesting Hardware Attestation Reports**:

- The `request_hardware_report` function requests attestation reports based on the provided data and VMPL level.

- It uses conditional compilation to handle attestation report requests differently depending on whether the `hyperv` feature is enabled or not.

6. **Getting and Writing Attestation Reports**:

- The `get_report` function orchestrates the process of requesting attestation reports based on CLI arguments, verifying arguments, and writing the obtained report to a file.

- It also writes the request data to a file, either for random or platform modes.

7. **Writing Hexadecimal Data to Files**:

- The `write_hex` function writes hexadecimal data to a file, making it more readable with 16 values per line.


Verify.rs: This code is for verifying certificate chains and attestation reports. Here's a summary of its key components:

1. **Imports and Dependencies**:

- The code includes various import statements to bring in necessary dependencies and modules, such as `std` for standard library modules, `openssl` for cryptography-related operations, and `sev` for SEV-specific functionality.

2. **Command-Line Interface (CLI)**:

- The module defines a CLI interface using the `structopt` crate. It has two subcommands: `Certs` for certificate chain verification and `Attestation` for attestation report verification.

3. **Command Execution**:

- The `cmd` function takes a `VerifyCmd` enum and a `quiet` flag and executes the appropriate verification based on the subcommand provided.

4. **Certificate Chain Verification** (Inside `certificate_chain` module):

- The `validate_cc` function verifies a certificate chain consisting of ARK (AMD Root Key), ASK (AMD Signing Key), and VCEK (Virtualization Code Encryption Key).

- It reads these certificates from a specified directory, validates their signatures, and ensures the certificates are properly chained.

- The result of each verification step is printed to the console unless the `quiet` flag is set.

5. **Attestation Report Verification** (Inside `attestation` module):

- The `verify_attesation` function verifies an attestation report's contents.

- It reads an attestation report from a file and compares the reported values with those in the VCEK certificate extensions.

- The verification includes checking Boot Loader, TEE (Trusted Execution Environment), SNP (Secure Nested Paging), Microcode, and Hardware ID values.

- The function also allows for separate verification of the TCB (Trusted Computing Base) and the digital signature.

- Verification results are printed to the console.

6. **Helper Functions**:

- Several helper functions are defined within the modules to facilitate various tasks, including locating certificates in a directory, comparing certificate values, and verifying attestation report signatures.

## Usage

### Global Options

- **-q, --quiet**: Suppress console output.

### Commands

#### snpguest report

```bash
snpguest report $ATT_REPORT_PATH $REQUEST_FILE [-v, --vmpl] [-r, --random] [-p, --platform]
```

Requests an attestation report from the host and writes it to a file with the provided request data and VMPL. The attestation report is written in binary format to the specified report path. The user can pass 64 bytes of data in any file format into `$REQUEST_FILE` to request the attestation report. The `--random` flag can be used to generate and use random data for the request, and for Microsoft Hyper-V guests, the `--platform` flag is required to use pre-generated request data. If the `--random` flag is used, the data will be written into the file provided in `$REQUEST_FILE`. `VMPL` is an optional parameter that defaults to 1.

Options:
- `-h, --help`: Show a help message.
- `-r, --random`: Generate 64 random bytes of data for the report request.
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

#### snpguest certificates

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

#### snpguest fetch ca

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

#### snpguest fetch vcek

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

#### snpguest guest verify certs

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

#### snpguest guest verify attestation

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

#### snpguest key

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

#### snpguest guest display report

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

#### snpguest guest display key

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
![alt text](https://github.com/virtee/snpguest/blob/main/docs/extended.png?raw=true)
## Regular Attestation Flowchart
![alt text](https://github.com/virtee/snpguest/blob/main/docs/regular.png?raw=true)

## Reporting Bugs

Please report all bugs to [the SNPguest GitHub repository](https://github.com/virtee/snpguest/issues).
