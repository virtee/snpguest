# snpguest

`snpguest` is a Command Line Interface utility for managing an AMD SEV-SNP enabled guest. This tool allows users to interact with the AMD SEV-SNP guest firmware device enabling various operations such as: attestation, certificate management, derived key fetching, and more.

- [Basic Usage](#basic-usage)
  - [List of (Sub)commands](#list-of-subcommands)
  - [Global Options](#global-options)
- [Subcommand Details](#subcommand-details)
  - [ok](#ok)
  - [report](#report)
  - [certificates](#certificates)
  - [fetch ca](#fetch-ca)
  - [fetch vcek](#fetch-vcek)
  - [fetch crl](#fetch-crl)
  - [verify certs](#verify-certs)
  - [verify attestation](#verify-attestation)
  - [key](#key)
  - [display report](#display-report)
  - [display key](#display-key)
  - [generate measurement](#generate-measurement)
  - [generate ovmf-hash](#generate-ovmf-hash)
  - [generate id-block](#generate-id-block)
  - [generate key-digest](#generate-key-digest)
- [Extended Attestation Workflow](#extended-attestation-workflow)
- [Regular Attestation Workflow](#regular-attestation-workflow)
- [Extended Attestation Flowchart](#extended-attestation-flowchart)
- [Regular Attestation Flowchart](#regular-attestation-flowchart)
- [Build](#build)
  - [For Standard CVMs](#for-standard-cvms)
  - [For Azure CVMs](#for-azure-cvms)
  - [Build Dependencies](#build-dependencies)
  - [Load sev-guest module](#load-sev-guest-module)
- [Reporting Bugs](#reporting-bugs)

## Basic Usage

```bash
snpguest [GLOBAL_OPTIONS] [COMMAND] [COMMAND_ARGS] [SUBCOMMAND] [SUBCOMMAND_ARGS]
```

Every `snpguest` (sub)command comes with a `-h, --help` option for a description on its use.

### List of (Sub)commands

| Command | Subcommand | Description |
| :------ | :--------- | :---------- |
| `ok` | - | Quick local check if SEV-SNP is enabled in the guest environment. |
| `report` | - | Requests an attestation report from AMD-SP (or vTPM) |
| `certificates` | - | Requests certificates from the hypervisor memory via AMD-SP |
| `fetch` | `ca`, `vcek`, `crl` | Fetches certificates/CRLs from AMD KDS |
| `verify` | `certs`, `attestation` | Verifies certificates / attestation report |
| `key`   | - | Requests the derived key from AMD-SP based on input parameters |
| `display` | `report`, `key` | Displays files in human-readable form |
| `generate` | `measurement`, `ovmf-hash`, `id-block`, `key-digest` | Calculates reference values |

### Global Options


| Option | Description | Default |
| :----- | :---------- | :------ |
| `-q, --quiet` | Suppresses console output. | - |

## Subcommand Details

### `ok`

```bash
snpguest ok
```

Performs a quick local check of the guest using features such as CPUID and MSRs (Model-Specific Registers) to determine whether SEV-SNP appears to be enabled in the guest environment.

Note that this command is only a sanity check and does not provide a cryptographic guarantee that the SEV-SNP is definitely valid. To obtain strict cryptographic assurance for the SEV-SNP, the user must perform remote attestation.

This command requires that the `msr` module is loaded.

### `report`

```bash
snpguest report $ATT_REPORT_PATH $REQUEST_FILE [OPTIONS]
```

Requests an attestation report from the AMD Secure Processor (ASP), and writes it to `$ATT_REPORT_PATH` as raw binary. This command is a wrapper of the `SNP_GUEST_REQUEST(MSG_REPORT_REQ)` ioctl.

Without `-p, --platform` or `-r, --random`, the user can pass 64 bytes of data in any file format into `$REQUEST_FILE` to request an attestation report. The request file is interpreted as raw binary, and the first 64 bytes of the binary are sent to the AMD-SP as the request data. The request data will be bound to the REPORT_DATA field in the attestation report.

With the `-r, --random` flag, this command generates a random data for the request, which will be written into `$REQUEST_FILE`.

The `-v, --vmpl` option specifies the Virtual Machine Privilege Level (VMPL) to request an attestation report (0 to 3). The default value is 1. This value must be greater than or equal to the current VMPL. Specifying a privilege level higher than the actual level (smaller VMPL value) will result in a firmware error.

With the `-p, --platform` flag, this command retrieves an attestation report from vTPM NV index `0x01400001` instead of the ASP, and writes the Report Data field in the retrieved report into `$REQUEST_FILE`. This attestation route is available (and mandatory) on Microsoft Azure Confidential VMs with SEV-SNP isolation. This flag requires the `hyperv` feature (see [Install on Azure CVMs](#install-on-azure-cvms)). Currently, only the pre-generated attestation report can be retrieved. To request a (fresh) report with the user-provided request data, use any TPM2 tool to write the request data to vTPM NV index `0x01400002`, then execute this command.

#### Arguments and Options

| Argument/Option | Description | Default |
| :--      | :--        | :--    |
| `$ATT_REPORT_PATH` | The path where the attestation report would be stored. | *required* |
| `$REQUEST_FILE` | The path to the 64-byte request file. | *required* |
| `-v, --vmpl $VMPL` | The VMPL value to put in the attestation report (0-3). Must be greater than or equal to the current VMPL. | 1 |
| `-r, --random` | Generate 64 random bytes of data for the report request. | - |
| `-p, --platform` | Get an attestation report from the vTPM NV index (Only available for Azure CVMs). | - |

#### Example

```bash
# Request attestation report with user-provided data
snpguest report report.bin request-file.bin

# Request attestation report with randomly generated data
snpguest report report.bin request-file.bin --random

# Get attestation report and request data from vTPM
snpguest report report.bin request-file.bin --platform
```

### `certificates`

```bash
snpguest certificates $ENCODING $CERTS_DIR
```

Requests the certificates from the hypervisor memory via the ASP, and writes it into `$CERTS_DIR` as `$ENCODING` format (PEM or DER). This command uses the `SNP_GET_EXT_REPORT` ioctl of the ASP.

The output depends on which certificates are cached in the hypervisor memory. Before executing this command, the host (platform owner) must fetch certificates from AMD KDS and load them into the extended configuration.

In principle, the host can cache any certificate. However, in practice, it typically caches only the leaf certificate (VCEK or VLEK) or the entire certificate chain.

Note that this feature is *not* supported in upstream kernels. Actual behavior also depends on the kernel version. For example, behavior when executed without loading certificates.

#### Arguments

| Argument | Description | Default |
| :--      | :--        | :--    |
| `$ENCODING` | The certificate encoding to store the certificates in (PEM or DER). All certificates will be in the same encoding. | *required* |
| `$CERTS_DIR` | The directory to store the certificates in. If certificates already exist in the provided directory, they will be overwritten. | *required* |

#### Example

```bash
snpguest certificates pem ./certs
```

### `fetch ca`

```bash
snpguest fetch ca $ENCODING $CERTS_DIR $PROCESSOR_MODEL [OPTIONS]
```

Fetches the AMD root CA certificate (ARK) and the AMD intermediate certificate (ASK for VCEK or ASVK for VLEK) from the AMD KDS, and writes them into `$CERTS_DIR` in `$ENCODING` format (PEM or DER).

The user must specify either the host processor model `$PROCESSOR_MODEL` (`milan`, `genoa`, `bergano`, `sienna`, `turin`) or the path to an attestation report using the `-r, --report` option. When the report is provided, the command attempts to infer the host processor model from the report. Autodetection succeeds only under the following conditions:

1. **Report Version 3 or later**
   - both `CPU_FAM_ID` and `CPU_MOD_ID` are present (i.e. not missing)
2. **Report Version 2**
   - the host processor model is Turin
   - the `CHIP_ID` is not masked, i.e. `MASK_CHIP_ID` is zero-filled

In the latter case, automatic detection is based on heuristics: whereas pre-Turin's `CHIP_ID` utilises the full 64 bytes, Turin's `CHIP_ID` uses only the first 8 bytes. This heuristics may not remain valid for future processors.

The `--endorser` option specifies the type of  attestation signing key (VCEK or VLEK). The default value is VCEK.

#### Arguments and Options

| Argument/Option | Description | Default |
| :--      | :--        | :--    |
| `$ENCODING` | The certificate encoding to store the certificates in (PEM or DER). | *required* |
| `$CERTS_DIR` | The directory to store the certificates in. | *required* |
| `$PROCESSOR_MODEL` | The host processor model (`milan`, `genoa`, `bergano`, `sienna`, `turin`). (Conflicts with `--report`) | required |
| `-r, --report` | Path to the attestation report to detect the host processor model. (Conflicts with `$PROCESSOR_MODEL`) | - |
| `-e, --endorser` | The endorser type (`vcek` or `vlek`). | `vcek` |

#### Example

```bash
# Fetch CA cert chain in DER encoding for with milan with VLEK
# ark.der and asvk.der will be stored in ./certs
snpguest fetch ca der ./certs milan -e vlek

# Fetch CA cert chain in PEM encoding associated with V3+ report and VCEK
# ark.pem and ask.pem will be stored in ./certs
snpguest fetch ca pem ./certs -r report.bin -e vcek
```

### `fetch vcek`

```bash
snpguest fetch vcek $ENCODING $CERTS_DIR $ATT_REPORT_PATH [OPTIONS]
```

Fetches the VCEK certificate from the AMD KDS, and write it into `$CERTS_DIR` in `$ENCODING` format (PEM or DER).

The user must provide the path to an attestation report `$ATT_REPORT_PATH` to get the REPORTED_TCB and CHIP_ID.

The user can specify the host processor model using the `--processor-model` option. If the processor model is not specified, the command attempts to infer the host processor model from the report contents. Autodetection follows the same rules and limitations as the [fetch ca](#fetch-ca) command.

#### Arguments and Options

| Argument/Option | Description | Default |
| :--      | :--        | :--    |
| `$ENCODING` | The certificate encoding to store the certificates in (PEM or DER). | *required* |
| `$CERTS_DIR` | The directory to store the certificates in. | *required* |
| `$ATT_REPORT_PATH` | The path of the stored attestation report. | *required* |
| `-p, --processor-model` | The host processor model (`milan`, `genoa`, `bergano`, `sienna`, `turin`). If the report is *older than version 3*, this option must be specified. | - |

#### Example

```bash
# Fetch VCEK certificate in PEM encoding associated with V3+ report from AMD KDS
# vcek.pem will be stored in ./certs
snpguest fetch vcek pem ./certs report.bin

# If the report is older than V3, manually specify the processor model
snpguest fetch vcek pem ./certs report.bin -p milan
```

### `fetch crl`

```bash
snpguest fetch crl $ENCODING $CERTS_DIR $PROCESSOR_MODEL [OPTIONS]
```

Fetches the Certificate Revocation List (CRL) from the AMD KDS, and writes it into `$CERTS_DIR` in `$ENCODING` format (PEM or DER). This command has completely the same interface as the [fetch ca](#fetch-ca) command.

#### Arguments and Options

| Argument/Option | Description | Default |
| :--      | :--        | :--    |
| `$ENCODING` | The CRL encoding to store the CRL in (PEM or DER). | *required* |
| `$CERTS_DIR` | The directory to store the CRL in. | *required* |
| `$PROCESSOR_MODEL` | The host processor model (`milan`, `genoa`, `bergano`, `sienna`, `turin`). (Conflicts with `--report`) | required |
| `-r, --report` | Path to the attestation report to detect the host processor model. (Conflict with `$PROCESSOR_MODEL`) | - |
| `-e, --endorser` | The endorser type (`vcek` or `vlek`). | `vcek` |

#### Example

```bash
# Fetch CRL in DER encoding for milan with VLEK
# crl.der will be stored in ./certs
snpguest fetch crl der ./certs milan -e vlek

# Fetch CRL in PEM encoding associated with V3+ report and VCEK
# ark.pem and ask.pem will be stored in ./certs
snpguest fetch crl pem ./certs -r report.bin -e vcek
```

### `verify certs`

```bash
snpguest verify certs $CERTS_DIR
```

Verifies that the provided certificate chain in `$CERTS_DIR` has been properly signed by each certificate.

The user need to provide all three certificates in `$CERTS_DIR`, namely, the VCEK chain (`ark.*`, `ask.*` and `vcek.*`) or the VLEK chain (`ark.*`, `asvk.*` and `vlek.*`).

This command then verifies that
- ARK is self-signed
- ASK (or ASVK) is signed by ARK
- VCEK (or VLEK) is signed by ASK (or ASVK)

An error will be raised if any of the certificates fail verification.

#### Arguments

| Argument | Description | Default |
| :--      | :--        | :--    |
| `$CERTS_DIR` | The directory where the certificates are stored in. | *required* |

#### Example

```bash
# Verify cert chain stored in ./certs
snpguest verify certs ./certs
```

### `verify attestation`

```bash
snpguest verify attestation $CERTS_DIR $ATT_REPORT_PATH [OPTIONS]
```

Verifies the attestation report contents and signature using the VCEK/VLEK certificate and the given parameters. More precisely, this command performs the following verification steps:

- Verify that the REPORTED_TCB and CHIP_ID fields in the report matches the given certificate. The `-s, --signature` option skips this step.
- Verify the report signature using the given certificate. The `-t, --tcb` option skips this step.
- (Option) Verify that each report field matches the user-provided reference value. Reference values must be provided in `0x`-prefixed hex string. Currently, the following options are supported:

  - `-r, --report-data` (64 bytes = 128 hex characters)
  - `-m, --measurement` (48 bytes = 96 hex characters)
  - `-d, --host-data` (32 bytes = 64 hex characters)

The user can specify the host processor model using the `--processor-model` option. If the processor model is not specified, the command attempts to infer the host processor model from the report contents. Processor model autodetection follows the same rules and limitations as described in
[fetch ca](#3-fetch-ca).

#### Arguments and Options

| Argument/Option | Description | Default |
| :--      | :--        | :--    |
| `$CERTS_DIR` | The directory where the leaf certificate is stored in. | *required* |
| `$ATT_REPORT_PATH` | The path of the stored attestation report. | *required* |
| `-p, --processor-model $PROCESSOR_MODEL` | The host processor model (`milan`, `genoa`, `bergano`, `sienna`, `turin`). | - |
| `-t, --tcb` | Skip signature check. | - |
| `-s, --signature` | Skip TCB check. | - |
| `-r, --report-data` | Verify that the REPORT_DATA field in the report matches the given 64-byte data (`0x`-prefixed hex string). | - |
| `-m, --measurement` | Verify that the MEASUREMENT field in the report matches the given 48-byte data (`0x`-prefixed hex string). | - |
| `-d, --host-data` | Verify that the MEASUREMENT field in the report matches the given 32-byte data (`0x`-prefixed hex string). | - |

#### Example

```bash
# Verify Attestation (TCB and signature)
snpguest verify attestation ./certs report.bin

# Verify TCB only
snpguest verify attestation ./certs report.bin --tcb

# Verify Signature only
snpguest verify attestation ./certs report.bin --signature

# Verify TCB, Signature and Report Data
snpguest verify attestation ./certs report.bin --report-data 0x5482c1ffe29145d47cf678f7681e3b64a89909d6cf8ec0104cfacb0b0418f005f564ad14f5c1381c99b74903a780ea340e887c9b445e9c760bf0b74115b26d45

# Verify TCB, Signature and Measurement
snpguest verify attestation ./certs report.bin --measurement 0xf28aac58964258d8ae0b2e88a706fc7afd0bb524f6a291ac3eedeccb73f89d7cfcf2e4fb6045e7d5201e41d1726afa02
    
# Verify TCB, Signature and Host Data
snpguest verify attestation ./certs report.bin --host-data 0x7e4a3f9c1b82a056d39f0d44e5c8a7b1f02394de6b58ac0d7e3c11af0042bd59
```

### `key`

```bash
snpguest key $KEY_PATH $ROOT_KEY_SELECT [OPTIONS]
```

Requests the derived key from the AMD-SP based on input parameters, and stores it into `$KEY_PATH`. This command is a wrapper of the `SNP_GUEST_REQUEST(MSG_KEY_REQ)` ioctl of the AMD-SP.

The user must specifies the root key `$ROOT_KEY_SELECT` from which to derive the key (either `vcek` or `vmrk`).

The `--guest_field_select` option is a bit field of length 64, which specifies which data field will be mixed into the derived key. Each of the bits from *right to left* correspond to Guest Policy, Image ID, Family ID, Measurement, SVN and TCB Version, Launch Mitigation Vector, respectively. For each bit, 0 denotes off, and 1 denotes on. See also [Structure of Guest Field Select](#structure-of-guest-field-select).

The `--vmpl` option specifies the VMPL value to mix into the key (0-3). The default value is 1. This value must be greater than or equal to the current VMPL. Specifying a privilege level higher than the actual level (smaller VMPL value) will result in a firmware error.

The `--guest_svn` option specifies the guest SVN to mix into the key.

The `--tcb_version` option specifies the TCB version to mix into the derived key (must not exceed the committed TCB)

The `--launch_mit_vector` option specifies the launch mitigation vector value to mix into the derived key.

Note that the launch mitigation vector is only available for `MSG_KEY_REQ` message version ≥ 2.

#### Arguments and Options

| Argument/Option | Description | Default |
| :--      | :--        | :--    |
| `$KEY_PATH` | The path to store the derived key. | *required* |
| `$ROOT_KEY_SELECT` | The root key from which to derive the key (either `vcek` or `vmrk`). | *required* |
| `-v, --vmpl` | The VMPL value to mix into the key (0-3). Must be greater than or equal to the current VMPL. | 1 |
| `-g, --guest_field_select` | Guest Field Select bits to enable as a 64-bit integer (decimal, `0x`-prefixed hex or `0b`-prefixed bin). | 0 |
| `-s, --guest_svn` | Specifies the guest SVN to mix into the key (decimal, prefixed hex or prefixed bin). | 0 |
| `-t, --tcb_version` | Specifies the TCB version to mix into the derived key (decimal, prefixed hex or prefixed bin). Must not exceed the commited TCB. | 0 |
| `-l, --launch_mit_vector` | Specifies the launch mitigation vector value to mix into the derived key (decimal, prefixed hex or prefixed bin). Only available for `MSG_KEY_REQ` message version ≥ 2. | — |

#### Structure of Guest Field Select

| Bit      | Field             | Note |
| :--      | :--               | :--  |
| 63:7     | (Reserved)        | Currently unused. |
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

denote the following selection:

```plaintext
Guest Policy: On (1), 
Image ID: Off (0), 
Family ID: Off (0), 
Measurement: Off (0), 
SVN: On (1), 
TCB Version: On (1),
Launch MIT Vector: Off or None (0).
```

#### Example

```bash
# Creating and storing a derived key
snpguest key derived-key.bin vcek --guest_field_select 0b110001 --guest_svn 2 --tcb_version 1 --vmpl 3
```

### `display report`

```bash
snpguest display report $ATT_REPORT_PATH
```

Prints the attestation report contents into the terminal. The user has to provide the path of a stored attestation report `$ATT_REPORT_PATH` to display.

#### Arguments

| Argument | Description | Default |
| :--      | :--        | :--    |
| `$ATT_REPORT_PATH` | The path of the stored attestation report to display. | *required* |

#### Example

```bash
snpguest display report report.bin
```

### `display key`

```bash
snpguest display key $KEY_PATH
```

Prints the derived key in hex format into the terminal. The user has to provide the path of a stored derived key `$KEY_PATH` to display.

#### Arguments

| Argument | Description | Default |
| :--      | :--        | :--    |
| `$KEY_PATH` | The path of the stored derived key to display. | *required* |

#### Example

```bash
snpguest display key derived-key.bin
```

### `generate measurement`

```bash
snpguest generate measurement [OPTIONS]
```

Calculates an expected launch digest measurement of secure guest, and prints it into the terminal or stores it into the specified path.

Every parameter passed in is used to calculate this measurement, but the user does not need to provide every parameter.

The only mandatory parameters are the `-o, --ovmf` parameter which is a path to the ovmf file used to launch the secure guest, and provide the guest vCPU type.

There are 3 ways to provide the vCPU type, and the 3 of them are mutually exclusive (will get an error if the user tries to use more than one method):
- `--vcpu-type` A string with the vcpu-type used to launch the secure guest
- `--vcpu-sig` The signature of the vcpu-type used to launch the secure guest
- `--vcpu-family, --vcpu-model, --vcpu-stepping` The family, model and stepping of the vcpu used to launch the secure guest. Family, model and stepping have to be used together, if they are not all provided together an error will be raised.

If the user specifies the `-k, --kernel` parameter to calculate measurements, they can also specify `-i, --initrd` and `-a, --append`. These parameters are unnecessary if the kernel file already contains initrd and append.

There were kernel features added that affect the result of the measurement if those are enabled. With the `-g, --guest-features` parameter the user can provide which of this features are enabled in their kernel.

The `-g, --guest-features` can be a hex or decimal number that cover the features enabled. For information on the guest-features bitfield checkout [virtee/sev/src/measurement/vmsa.rs](https://github.com/virtee/sev/blob/main/src/measurement/vmsa.rs).

A user can use a pre-calculated ovmf-hash using `--ovmf-hash`, but the ovmf file still has to be provided.

The calculated measurement will be printed in the console. If the user wishes to store the measurement value they can provide a file path with `-m, --measurement-file` and the measurement will get written there.

If the global `-q, --quiet` flag is used, nothing will be printed out.

#### Options

| Option | Description | Default |
| :--      | :--        | :--    |
| `-v, --vcpus` | Number of guest vCPUs. | 1 |
| `--vcpu-type` | Type of guest vCPU. Either this parameter, `--vcpu-sig`, or the triplet (`--vcpu-family`, `--vcpu-model`, `--vcpu-stepping`) must be specified. (Conflicts with the other `--vcpu-*` parameters) | *required* |
| `--vcpu-sig` | Guest vCPU signature value. (Conflicts with the other `--vcpu-*` options) | - |
| `--vcpu-family`, `--vcpu-model`, `--vcpu-stepping` | Guest vCPU family, model, and stepping. When specifying the vCPU type using these options, all three options must be specified. (Conflicts with `--vcpu-type` and `--vcpu-sig`) | - |
| `--vmm-type` | Guest VMM type (QEMU, EC2, KRUN). | - |
| `-o, --ovmf` | OVMF file path to calculate measurement from. Either this option or `--ovmf-hash` must be specified. (Conflicts with `--ovmf-hash`) | *required* |
| `-k, --kernel` | Kernel file path to calculate measurement from. | - |
| `-i, --initrd` | Initrd file path to calculate measurement from. (Requires `--kernel`) | - |
| `-a, --append` | Kernel command line to calculate measurement from. (Requires `--kernel`) | - |
| `-g, --guest-features` | Decimal or prefixed-hex representation of the guest kernel features expected to be included. | `0x1` |
| `--ovmf-hash` | Precalculated hash of the OVMF binary. (Conflicts with `--ovmf`) | - |
| `-f, --output-format` | Output format (`base64` or `hex`). | `hex` |
| `-m, --measurement-file` | Optional file path where measurement value can be stored in. | stdout |

#### List of vCPU types

Currently the following vCPU types are available. The vCPU signature value can be calculated from the cprresponding vCPU (family, model, stepping). For details, see [AMD's CPUID Specification](https://www.amd.com/content/dam/amd/en/documents/archived-tech-docs/design-guides/25481.pdf).

| vcpu_type | vcpu_family | vcpu_model | vcpu_stepping |
| :-- | :-- | :-- | :-- |
| `epyc` | 23 | 1 | 2 |
| `epyc-v1` | | | |
| `epyc-v2` | | | |
| `epyc-ibpb` | | | |
| `epyc-v3` | | | |
| `epyc-v4` | | | |
| `epyc-rome` | 23 | 49 | 0 |
| `epyc-rome-v1` | | | |
| `epyc-rome-v2` | | | |
| `epyc-rome-v3` | | | |
| `epyc-milan` | 25 | 1 | 1 |
| `epyc-milan-v1` | | | |
| `epyc-milan-v2` | | | |
| `epyc-genoa` | 25 | 17 | 0 |
| `epyc-genoa-v1` | | | |

### `generate ovmf-hash`

```bash
snpguest generate ovmf-hash [OPTIONS]
```

Calculates the hash of an ovmf file.

The user must specify the OVMF file using the `-o, --ovmf` option.

The user can specify the output format using the `-f, --output-format` option: "hex" or "base64" (default: "hex").

The hash will be printed in the console, if the user wishes to store the hash value they can provide a file path with `--hash-file` and the hash will get written there.

If the global `-q, --quiet` flag is used, nothing will be printed out.

#### Options

| Option | Description | Default |
| :--      | :--        | :--    |
| `-o, --ovmf` | Path to OVMF file to calculate hash from | *required* |
| `-f, --output-format` | Output format (`hex` or `base64`) | `hex` |
| `--hash-file` | Optional file where hash value can be stored in | stdout |

### `generate id-block`

```bash
snpguest generate id-block $ID_BLOCK_KEY $AUTH_KEY $LAUNCH_DIGEST [OPTIONS]
```

Calculates an id-block and auth-block for a secure guest.

The user needs to provide a path to two different EC P-384 keys `$ID_BLOCK_KEY` and `$AUTH_KEY` in PEM or DER format. One will be for the id-block the other for the auth-block.

The user also needs to provide the launch digest `$LAUNCH_DIGEST` (in either hex or base64 format) of the secure guest. The user can generate the launch digest using the `generate measurement` command.

The user can provide optional id's for further verification using the `-f, --family-id` and `-m, image-id` paramerters. Each parameter is 16 raw bytes (default: 0s).

The user can provide the security version number of the guest using `-s, --svn` (default: 0).

The user can specify the launch policy of the guest using the `-p, --policy` parameter. The policy can be provided in either hex or decimal format. It will default to 0x30000. For more information on the guest-policy, see [SEV-SNP Firmware ABI Specification](https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf).

The blocks will be printed in the console, if the user wishes to store the blocks values they can provide a file path with `-i, --id-file` for the id-block and `-a, --auth-file` for the auth-block.

If the global `-q, --quiet` flag is used, nothing will be printed out.

The digest will be printed in the console. If the user wishes to store the digest value they can provide a file path with [-d, --key-digest-file].

#### Arguments and Options

| Argument/Option | Description | Default |
| :--      | :--        | :--    |
| `$ID_BLOCK_KEY` | Path to the Id-Block key | *required* |
| `$AUTH_KEY` | Path to the Auth-Block key | *required* |
| `$LAUNCH_DIGEST` | Guest launch measurement in either Base64 encoding or hex (if hex prefix with 0x) | *required* |
| `-f, --family-id` | Family ID of the guest provided by the guest owner (16 bytes) | 0s |
| `-m, --image-id` | Image ID of the guest provided by the guest owner (16 bytes) | 0s |
| `-v, --version` | Id-Block version. Currently only version 1 is available | 1 |
| `-s, --svn` | SVN of the guest | 0 |
| `-p, --policy` | Launch policy of the guest. Can provide in decimal or hex format. | 0x30000 |
| `-i, --id-file` | Optional file where the Id-Block value can be stored in | stdout |
| `-a, --auth-info-file` | Optional file where the Auth-Block value can be stored in | stdout |

### `generate key-digest`

```bash
snpguest generate key-digest $KEY_PATH [-d, --key-digest-file]
```

Generates an SEV key digest for a provided EC P-384 key.

User needs to provide a path to the key `$KEY_PATH`. The key has to be an EC P-384 key in either PEM or DER format.

The digest will be printed in the console. If the user wishes to store the digest value they can provide a file path with `-d, --key-digest-file`.

If the global `-q, --quiet` flag is used, nothing will be printed out.

#### Arguments and Options

| Argument/Option | Description | Default |
| :--      | :--        | :--    |
| `$KEY_PATH` | Path to key to generate hash for | *required* |
| `-d, --key-digest-file` | File to store the key digest in | stdout |

## [Extended Attestation Workflow](#extended-attestation-flowchart)

**Step 1.** Request the attestation report by providing the two mandatory parameters - `$ATT_REPORT_PATH` which is the path pointing to where the user wishes to store the attestation report and `$REQUEST_FILE` which is the path pointing to where the request file used to request the attestation report is stored. The optional parameter `-v, --vmpl` specifies the vmpl level for the attestation report and is set to 1 by default. The flag `-r, --random` generates random data to be used as request data for the attestation report. Lastly, the flag `-p, --platform` obtains both the attestation report and the request data from the platform (only available for a Microsoft Azure CVM where Hyper-V guest is enabled).

```bash
snpguest report $ATT_REPORT_PATH $REQUEST_FILE [-v, --vmpl] $VMPL [-r, --random] [-p, --platform]
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

**Step 4.** Verify the attestation by providing the two mandatory parameters - `$CERTS_DIR` which specifies the path in the user's directory where the certificates were saved from Step 2 and `$ATT_REPORT_PATH` which is the path pointing to the stored attestation report which the user wishes to verify. The optional parameters `-t, --tcb` is used to verify just the Reported TCB contents of the attestaion report and `-s, --signature` is used to verify just the signature of the attestaion report.

```bash
snpguest verify attestation $CERTS_DIR $ATT_REPORT_PATH [-t, --tcb] [-s, --signature]
```

## [Regular Attestation Workflow](#regular-attestation-flowchart)

**Step 1.** Request the attestation report by providing the two mandatory parameters - `$ATT_REPORT_PATH` which is the path pointing to where the user wishes to store the attestation report and `$REQUEST_FILE` which is the path pointing to where the request file used to request the attestation report is stored. The optional parameter `-v, --vmpl` specifies the vmpl level for the attestation report and is set to 1 by default. The flag `-r, --random` generates random data to be used as request data for the attestation report. Lastly, the flag `-p, --platform` obtains both the attestation report and the request data from the platform (only available for a Microsoft Azure CVM where Hyper-V guest is enabled).

```bash
snpguest report $ATT_REPORT_PATH $REQUEST_FILE [-v, --vmpl] $VMPL [-r, --random] [-p, --platform]
```

**Step 2.** Request AMD Root Key (ARK) and AMD SEV Key (ASK) (or AMD SEV-VLEK Key (ASVK) for VLEK) from the AMD Key Distribution Service (KDS) by providing the three mandatory parameters - `$ENCODING` which specifies whether to use PEM or DER encoding to store the certificates, `$CERTS_DIR` which specifies the path in the user's directory where the certificates will be saved, and `$PROCESSOR_MODEL` - which specifies the AMD Processor model for which the certificates are to be fetched. The optional `-e, --endorser` argument specifies the type of attestation signing key (defaults to VCEK).

```bash
snpguest fetch ca $ENCODING $CERTS_DIR $PROCESSOR_MODEL [-e, --endorser] $ENDORSER
```

**Step 3.** Request the Versioned Chip Endorsement Key (VCEK) from the AMD Key Distribution Service (KDS) by providing the three mandatory parameters - `$ENCODING` which specifies whether to use PEM or DER encoding to store the certificates, `$CERTS_DIR` which specifies the path in the user's directory where the certificates will be saved, and `$ATT_REPORT_PATH` which is the path pointing to the stored attestation report for detecting Chip ID and Reported TCB Version. The optional `-p, --processor-model` argument specifies the AMD Processor model for which the certificates are to be fetched.

```bash
snpguest fetch vcek $ENCODING $CERTS_DIR $ATT_REPORT_PATH [-p, --processor-model] $PROCESSOR_MODEL
```

**Step 4.** Verify the certificates obtained by providing `$CERTS_DIR` which specifies the path in the user's directory where the certificates were saved from Step 2.

```bash
snpguest verify certs $CERTS_DIR
```

**Step 5.** Verify the attestation by providing the two mandatory parameters - `$CERTS_DIR` which specifies the path in the user's directory where the certificates were saved from Step 2 and `$ATT_REPORT_PATH` which is the path pointing to the stored attestation report which the user wishes to verify. The optional parameters `-t, --tcb` is used to verify just the Reported TCB contents of the attestaion report and `-s, --signature` is used to verify just the signature of the attestaion report.

```bash
snpguest verify attestation $CERTS_DIR $ATT_REPORT_PATH [-t, --tcb] [-s, --signature]
```

## Extended Attestation Flowchart
![alt text](https://github.com/virtee/snpguest/blob/main/docs/extended.PNG?raw=true)
## Regular Attestation Flowchart
![alt text](https://github.com/virtee/snpguest/blob/main/docs/regular.PNG?raw=true)

## Build

### For Standard CVMs

```bash
# Build
git clone https://github.com/virtee/snpguest
cd snpguest
cargo build -r

# Install from the repository
cargo install --git https://github.com/virtee/snpguest

# Install from crate.io
cargo install snpguest
```

### For Azure CVMs

On Azure CVMs, all communication between the guest OS and AMD-SP is proxied by the OpenHCL paravisor. The native `/dev/sev-guest` interface is hidden from the guest OS. The user must specify the `--platform` flag to get an attestation report; this flag is available only in builds compiled with the `hyperv` feature.

```bash
# Install additional dependencies
sudo apt update
sudo apt install -y pkg-config libtss2-dev

# Build
git clone https://github.com/virtee/snpguest
cd snpguest
cargo build -r --features hyperv

# Install from the repository
cargo install --git https://github.com/virtee/snpguest --features hyperv

# Install from crate.io
cargo install snpguest --features hyperv
```

### Build Dependencies

Some packages may need to be installed on the guest system in order to build `snpguest`.

#### Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

#### Ubuntu Dependencies

```bash
sudo apt install build-essential
```

#### RHEL and its compatible distributions Dependencies

```bash
sudo dnf groupinstall "Development Tools" "Development Libraries"
```

#### openSUSE and its compatible distributions Dependencies

```bash
sudo zypper in -t pattern "devel_basis"
```

### Load sev-guest module

In some guest environments, the device `/dev/sev-guest` does not created by default. In such cases, make sure that the kernel supports SEV-SNP, then load the sev-guest module.

```bash
modprobe sev-guest
ls -l /dev/sev-guest
```

## Reporting Bugs

Please report all bugs to the [Github snpguest](https://github.com/virtee/snpguest/issues) repository.
