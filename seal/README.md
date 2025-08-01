# Encrypt (tvault-core)

## Description

The `encrypt` package is a core component of the TVault Core system that provides encryption functionality for folders and files. 
It compresses data, encrypts it using secure cryptographic methods, and generates access tokens using various integrity protection mechanisms.

## Features

- Folder compression with configurable compression algorithms
- AES encryption of compressed data
- Token generation for secure access
- Shamir's Secret Sharing support for distributed key management
- Multiple integrity providers for ensuring data authenticity

## Usage

The encrypt package can be used programmatically or through the command-line interface:

### Command-Line Usage

```shell
tvault seal \
  --container-path=/path/to/output.tvlt \
  --folder-path=/path/to/folder \
  --passphrase="your-secure-passphrase" \
  --token-save-type=file \
  --token-save-path=/path/to/token/file
```

## Configuration Options

| Option | Description | Default | Required |
| --- | --- | --- | --- |
| ContainerPath | Path to save the encrypted container file | - | Yes |
| FolderPath | Path to the folder to be encrypted | - | Yes |
| CompressionType | Type of compression to use | `zip` | No |
| Passphrase | Passphrase for encrypting the container | - | Yes |
| TokenSaveType | Method to save the token(s): `file` or `stdout` | `stdout` | No |
| TokenSavePath | Path to save token(s) | - | Yes (for `file` TokenSaveType) |
| IsShamirEnabled | Enable Shamir's Secret Sharing | `true` | No |
| NumberOfShares | Number of shares to generate (Shamir) | 5 | No |
| Threshold | Minimum shares required to reconstruct the secret (Shamir) | 3 | No |
| IntegrityProvider | Type of integrity provider: `none` or `hmac` | `hmac` | No |
| AdditionalPassword | Additional password for the integrity provider | - | Yes (for `hmac` IntegrityProvider) |

## Supported Compression Types

- `zip`: Standard ZIP compression

## Supported Token Save Types

- `file`: Save tokens to a file
- `stdout`: Print tokens to standard output

## Supported Integrity Providers

- `none`: No integrity verification
- `hmac`: HMAC-based integrity verification (requires an additional password)
- `ed25519`: Ed25519 signature-based integrity verification (not implemented yet)

## Shamir's Secret Sharing

When `IsShamirEnabled` is set to `true`, the master key is split into multiple shares using Shamir's Secret Sharing algorithm. 
This allows the key to be distributed among multiple parties, where a subset (defined by the `Threshold` parameter) is required to reconstruct the original key

## Error Handling

The method checks all configuration parameters for correctness before proceeding with encryption: `Validate()`
- Required fields must be provided
- Compression type must be supported
- Token save type must be valid
- If HMAC integrity provider is used, an additional password must be provided
- If token save type is set to file, a token save path must be provided

## Example Flow

1. Compress the folder using the specified compression algorithm
2. Create an encrypted container with the compressed data
3. Apply integrity protection to the master key
4. Generate token(s) for later access
5. Save the token(s) according to the specified method
