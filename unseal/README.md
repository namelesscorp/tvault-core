# Unseal (tvault-core)

## Description

The `unseal` package is a core component of the TVault Core system that handles the decryption of encrypted containers. 
It uses cryptographic tokens to access encrypted data, verifies data integrity, and decompresses the content to restore the original files and folder structure.

## Features

- Decryption of TVault container files (.tvlt)
- Support for master key tokens and Shamir secret sharing tokens
- Integrity verification through various providers
- Automatic decompression of encrypted content
- Restoring original folder structure to a specified location

## Usage

The unseal package can be used programmatically or through the command-line interface:

### Command-Line Usage

```shell
tvault unseal \
container \
  -current-path="/path/to/container.tvlt" \
  -folder-path="/path/to/output" \
  -passphrase="your-passphrase" \
token-reader \
  -type="file" \
  -format="json" \
  -path="/path/to/token/file" \
  -flag="your-token" \
integrity-provider \
  -current-passphrase="your-integrity-password" \
log-writer \
  -type="stdout" \
  -format="json"
```

## Configuration Options

### Container Options

| Option | Description | Default | Required |
| --- | --- | --- | --- |
| CurrentPath | Path to the encrypted container file | - | Yes |
| FolderPath | Path to the folder where decrypted content will be saved | - | Yes |
| Passphrase | Passphrase for container without tokens | - | Yes (for containers without tokens) |

### Integrity Provider Options

| Option | Description | Default | Required |
| --- | --- | --- | --- |
| CurrentPassphrase | Password for integrity verification | - | Yes (for HMAC integrity provider) |

### Token Reader Options

| Option | Description | Default | Required |
| --- | --- | --- | --- |
| Type | Method to read tokens: or `file``flag` | - | Yes |
| Path | Path to read tokens from | - | Yes (for type) `file` |
| Format | Format of tokens: `plaintext` or `json` | - | Yes |
| Flag | Token value passed as flag | - | Yes (for type) `flag` |

### Log Writer Options

| Option | Description | Default | Required |
| --- | --- | --- | --- |
| Type | Method to write logs: or `stdout` `file` | - | Yes |
| Format | Format of logs: `plaintext` or `json` | - | Yes |
| Path | Path to write logs to | - | Yes (for type) `file` |

## Token Format

The unseal package supports two types of tokens:
1. **Master Token** - A single token containing the master key
2. **Shamir Shares** - Multiple tokens representing Shamir secret shares

### Plaintext Format

```<token1>|<token2>|<token3>```

### JSON Format

```json
{
  "tokenList": [
    "<token1>",
    "<token2>",
    "<token3>"
  ]
}
```

## Unseal Process
1. Open the encrypted container from the specified path
2. Determine the token type from the container header
3. Read and parse tokens from the specified source
4. Extract the master key (or reconstruct it from Shamir shares)
5. Apply the appropriate integrity verification
6. Decrypt the container using the master key
7. Decompress the decrypted data
8. Restore the original folder structure to the specified location

## Supported Integrity Providers
- `none`: No integrity verification
- : HMAC-based integrity verification (requires an additional password) `hmac`
- `ed25519`: Ed25519 signature-based integrity verification (not implemented yet)

## Error Handling

The package validates all configuration parameters before processing:
- Container paths must be valid and accessible
- Token reader configuration must be valid
- Log writer configuration must be valid

## Security Considerations

- Store tokens securely and separate from encrypted containers
- When using HMAC integrity verification, keep the additional password confidential
- Use secure channels for transferring tokens and passwords
- Consider using Shamir's Secret Sharing for distributed security
- Verify the integrity of decrypted content before use


## Compatibility
The unseal package is designed to work with containers created by the corresponding `seal` package of the TVault Core system.
