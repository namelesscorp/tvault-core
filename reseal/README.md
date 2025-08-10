# Reseal (tvault-core)

## Description

The `reseal` package is a core component of the TVault Core system that provides functionality for re-encrypting existing sealed containers with updated content.
It allows users to modify the content of an encrypted container without changing the encryption keys and token structure.

## Features

- Re-encrypting existing TVault containers
- Preserving original container metadata while updating content
- Maintaining the same token access method
- Supporting all token types and integrity providers
- Seamlessly working with Shamir's Secret Sharing

## Usage

The reseal package can be used programmatically or through the command-line interface:

### Command-Line Usage

```shell
tvault reseal \
container \
  -name="new-container-name" \
  -current-path="/path/to/original.tvlt" \
  -new-path="/path/to/updated.tvlt" \
  -folder-path="/path/to/new/content" \
  -passphrase="your-passphrase" \
  -comment="new-comment" \
  -tags="new-tag-1,new-tag-2,new-tag-3" \
token-reader \
  -type="file" \
  -format="json" \
  -path="/path/to/token/file" \
token-writer \
  -type="file" \
  -format="json" \
  -path="/path/to/updated/token/file" \
integrity-provider \
  -current-passphrase="your-current-integrity-password" \
  -new-passphrase="your-new-integrity-password" \
log-writer \
  -type="stdout" \
  -format="json"
```

## Configuration Options

### Container Options

| Option      | Description                                                  | Default     | Required                            |
|-------------|--------------------------------------------------------------|-------------|-------------------------------------|
| Name        | Reset container name                                         | -           | No                                  |
| CurrentPath | Path to the original encrypted container                     | -           | Yes                                 |
| NewPath     | Path to save the updated container (defaults to CurrentPath) | CurrentPath | No                                  |
| FolderPath  | Path to the folder with new content                          | -           | Yes                                 |
| Passphrase  | Passphrase for containers without tokens                     | -           | Yes (for containers without tokens) |
| Comment     | Reset comment for container                                  | -           | No                                  |
| Tags        | Reset tags for container                                     | -           | No                                  |

### Integrity Provider Options

| Option | Description | Default | Required |
| --- | --- | --- | --- |
| CurrentPassphrase | Current password for integrity verification | - | Yes (for HMAC integrity provider) |
| NewPassphrase | New password for integrity verification (defaults to CurrentPassphrase) | CurrentPassphrase | No |

### Token Reader Options

| Option | Description | Default | Required |
| --- | --- | --- | --- |
| Type | Method to read tokens: `file` or `flag` | - | Yes |
| Path | Path to read tokens from | - | Yes (for `file` type) |
| Format | Format of tokens: `plaintext` or `json` | - | Yes |
| Flag | Token value passed as flag | - | Yes (for `flag` type) |

### Token Writer Options

| Option | Description | Default | Required |
| --- | --- | --- | --- |
| Type | Method to write updated tokens: `file` or `stdout` | - | Yes |
| Path | Path to write tokens to | - | Yes (for `file` type) |
| Format | Format of tokens: `plaintext` or `json` | - | Yes |

### Log Writer Options

| Option | Description | Default | Required |
| --- | --- | --- | --- |
| Type | Method to write logs: `file` or `stdout` | - | Yes |
| Format | Format of logs: `plaintext` or `json` | - | Yes |
| Path | Path to write logs to | - | Yes (for `file` type) |

## Reseal Process

The `Reseal` function orchestrates the entire resealing process:
1. Open the original encrypted container
2. Extract the master key using the provided token(s)
3. Compress the new content folder
4. Re-encrypt the container with the updated content
5. Write the updated container to the specified path
6. Generate and save updated token(s) if needed

## Token Handling

The reseal package maintains the same token type and structure as the original container:
- For containers with a master token, a new master token is generated
- For containers with Shamir shares, new shares are generated with the same threshold parameters
- For containers without tokens (passphrase-only), no tokens are generated

## Metadata Handling

The reseal operation preserves the original creation metadata while updating the timestamp:
- `CreatedAt` - Preserved from the original container
- `UpdatedAt` - Set to the current time
- `Comment` - Сomment can be changed
- `Tags` - Tags cat be changed

## Error Handling

The package validates all configuration parameters before processing:
- Container paths must be valid and accessible
- Token reader and writer configurations must be valid
- Log writer configuration must be valid

During the resealing process, detailed error information is provided for:
- Container access errors
- Token parsing failures
- Compression errors
- Encryption failures
- Writing errors

## Security Considerations

- Store tokens securely and separate from encrypted containers
- When updating integrity passphrases, ensure both old and new values are kept secure
- Consider using different output paths for updated containers to maintain originals
- Verify the updated container can be unsealed before discarding originals

## Compatibility

The reseal package is designed to work with containers created by the `seal` package and can be unsealed using the `unseal` package of the TVault Core system.
