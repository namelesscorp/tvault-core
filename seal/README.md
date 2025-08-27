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

```json
{
  "token_list": [
    "master token"
  ]
}
```

```json
{
  "token_list": [
    "share token 1", 
    "share token 1"
  ]
}
```

## Configuration Options

### Container Options

Command: container 

| Option     | Description                               | Default                     | Required | Flag         |
|------------|-------------------------------------------|-----------------------------|----------|--------------|
| Name       | Container name                            | Container file name         | No       | -name        |
| NewPath    | Path to save the encrypted container file | Empty                       | Yes      | -new-path    |
| FolderPath | Path to the folder to be encrypted        | Empty                       | Yes      | -folder-path |
| Passphrase | Passphrase for encrypting the container   | Empty                       | Yes      | -passphrase  |
| Comment    | Container comment                         | Empty                       | No       | -comment     |
| Tags       | Container tags                            | created by trust vault core | No       | -tags        |

### Compression Options

Command: compression

| Option | Description                                 | Default | Required | Flag  |
|--------|---------------------------------------------|---------|----------|-------|
| Type   | Type of compression to use: `zip` or `none` | ZIP     | No       | -type |

### Token Options

Command: token

| Option | Description                                            | Default | Required | Flag  |
|--------|--------------------------------------------------------|---------|----------|-------|
| Type   | Type of token to generate: `none`, `share` or `master` | Share   | No       | -type |

### Token Writer Options

Command: token-writer

| Option | Description                                    | Default   | Required              | Flag    |
|--------|------------------------------------------------|-----------|-----------------------|---------|
| Type   | Method to save tokens: `file` or `stdout`      | stdout    | No                    | -type   |
| Path   | Path to save tokens                            | Empty     | Yes (for `file` type) | -path   |
| Format | Format for token output: `plaintext` or `json` | plaintext | No                    | -format |

### Integrity Provider Options

Command: integrity-provider

| Option        | Description                                  | Default | Required              | Flag            |
|---------------|----------------------------------------------|---------|-----------------------|-----------------|
| Type          | Type of integrity provider: `none` or `hmac` | hmac    | No                    | -type           |
| NewPassphrase | Password for the integrity provider          | Empty   | Yes (for `hmac` type) | -new-passphrase |

### Shamir Options

Command: shamir

| Option    | Description                                       | Default | Required                     | Flag        |
|-----------|---------------------------------------------------|---------|------------------------------|-------------|
| IsEnabled | Enable Shamir's Secret Sharing                    | True    | Yes (for token -type=shamir) | -is-enabled |
| Shares    | Number of shares to generate                      | 5       | No                           | -shares     |
| Threshold | Minimum shares required to reconstruct the secret | 3       | No                           | -threshold  |

### Log Writer Options

Command: log-writer

| Option | Description                              | Default   | Required              | Flag    |
|--------|------------------------------------------|-----------|-----------------------|---------|
| Type   | Method to write logs: `file` or `stdout` | stdout    | No                    | -type   |
| Format | Format of logs: `plaintext` or `json`    | plaintext | No                    | -format |
| Path   | Path to write logs                       | Empty     | Yes (for `file` type) | -path   |

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

