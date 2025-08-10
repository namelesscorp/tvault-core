# Seal (tvault-core)

## Description

The `seal` package is a core component of the TVault Core system that provides encryption functionality for folders and files. 
It compresses data, encrypts it using secure cryptographic methods, and generates access tokens using various integrity protection mechanisms.

## Features

- Folder compression with configurable compression algorithms
- Data encryption using secure cryptographic techniques
- Token generation for secure access
- Shamir's Secret Sharing support for distributed key management
- Multiple integrity providers for ensuring data authenticity

## Usage

The seal package can be used programmatically or through the command-line interface:

### Command-Line Usage

```shell
tvault seal \
container \
  -name="container-name" \
  -new-path="/path/to/output.tvlt" \
  -folder-path="/path/to/folder" \
  -passphrase="your-secure-passphrase" \
  -comment="container-comment" \
  -tags="container-tag-1,container-tag-2,container-tag-3"
compression \
  -type="zip" \
token \
  -type="share" \
token-writer \
  -type="file" \
  -format="json" \
  -path="/path/to/token/file" \
integrity-provider \
  -type="hmac" \
  -new-passphrase="your-integrity-password" \
shamir \
  -is-enabled=true \
  -shares=5 \
  -threshold=3 \
log-writer \
  -type="stdout" \
  -format="json"
```

## Configuration Options

### Container Options

| Option     | Description                               | Default             | Required |
|------------|-------------------------------------------|---------------------|----------|
| Name       | Container name                            | Container file name | No       |
| NewPath    | Path to save the encrypted container file | -                   | Yes      |
| FolderPath | Path to the folder to be encrypted        | -                   | Yes      |
| Passphrase | Passphrase for encrypting the container   | -                   | Yes      |
| Comment    | Container comment                         | -                   | No       |
| Tags       | Container tags                            | -                   | No       |

### Compression Options

| Option | Description | Default | Required |
| --- | --- | --- | --- |
| Type | Type of compression to use: `zip` or `none` | `zip` | No |

### Token Options

| Option | Description | Default | Required |
| --- | --- | --- | --- |
| Type | Type of token to generate: `none`, `share` or `master` | `share` | No |

### Token Writer Options

| Option | Description | Default | Required |
| --- | --- | --- | --- |
| Type | Method to save tokens: `file` or `stdout` | `stdout` | No |
| Path | Path to save tokens | - | Yes (for `file` type) |
| Format | Format for token output: `plaintext` or `json` | `plaintext` | No |

### Integrity Provider Options

| Option | Description | Default | Required |
| --- | --- | --- | --- |
| Type | Type of integrity provider: `none` or `hmac` | `hmac` | No |
| NewPassphrase | Password for the integrity provider | - | Yes (for `hmac` type) |

### Shamir Options

| Option | Description | Default | Required |
| --- | --- | --- | --- |
| IsEnabled | Enable Shamir's Secret Sharing | `true` | No |
| Shares | Number of shares to generate | 5 | No |
| Threshold | Minimum shares required to reconstruct the secret | 3 | No |

### Log Writer Options

| Option | Description | Default | Required |
| --- | --- | --- | --- |
| Type | Method to write logs: `file` or `stdout` | `stdout` | No |
| Format | Format of logs: `plaintext` or `json` | `plaintext` | No |
| Path | Path to write logs | - | Yes (for `file` type) |

## Supported Token Types

- `none`: Passphrase will be used without a token wrapper
- `share`: Split master key wrapped in tokens
- `master`: Master key wrapped in a token

## Supported Compression Types

- `zip`: Standard ZIP compression
- `none`: No compression (not yet implemented)

## Supported Token Save Types

- `file`: Save tokens to a file
- `stdout`: Print tokens to standard output

## Supported Integrity Providers

- `none`: No integrity verification
- `hmac`: HMAC-based integrity verification (requires an additional password)
- `ed25519`: Ed25519 signature-based integrity verification (not implemented yet)

## Seal Process

The `Seal` function orchestrates the entire sealing process:
1. Compresses the folder using the specified compression algorithm
2. Creates and encrypts the container with the compressed data
3. Applies integrity protection to the master key
4. Generates token(s) for later access
5. Saves the token(s) according to the specified method

## Shamir's Secret Sharing

When is set to `true`, the master key is split into multiple shares using Shamir's Secret Sharing algorithm. 
This allows the key to be distributed among multiple parties, where a subset (defined by the `Threshold` parameter) is required to reconstruct the original key. `Shamir.IsEnabled`

## Error Handling

The package provides detailed error handling with specific error codes and messages for different failure scenarios:
- Compression errors
- Container creation and encryption errors
- Integrity provider creation errors
- Token generation and saving errors
- I/O errors

## Security Considerations

- Uses PBKDF2 for secure key derivation from passphrases
- Implements strong encryption for data protection
- Supports integrity verification to prevent tampering
- Enables key splitting for distributed security
- Store tokens separately from encrypted containers
- Use strong passphrases for enhanced security

## Compatibility
The seal package creates containers that can be decrypted using the corresponding `unseal` package of the TVault Core system.

