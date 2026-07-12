# Reseal (tvault-core)

## Description

The `reseal` package is a core component of the TVault Core system that provides functionality for re-encrypting existing sealed containers with updated content.
It allows users to modify the content of an encrypted container without changing the encryption keys and token structure.

## Features

- Re-encrypting existing TVault containers
- Preserving original container metadata while updating content
- Maintaining the same token access method
- Preserving token strings unless the integrity passphrase is rotated
- Atomically replacing container and token files
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

| Option      | Description                                                  | Default      | Required                                 | Flag          |
|-------------|--------------------------------------------------------------|--------------|------------------------------------------|---------------|
| Name        | Reset container name                                         | Current name | No                                       | -name         |
| CurrentPath | Path to the original encrypted container                     | Empty        | Yes                                      | -current-path |
| NewPath     | Path to save the updated container (defaults to CurrentPath) | Current path | No                                       | -new-path     |
| FolderPath  | Path to the folder with new content                          | Empty        | Yes                                      | -folder-path  |
| Passphrase  | Passphrase for containers without tokens                     | Empty        | Yes (for containers without tokens)      | -passphrase   |
| Comment     | Reset comment for container                                  | Empty        | Yes (enter current comment or set empty) | -comment      |
| Tags        | Reset tags for container                                     | Empty        | Yes (enter current tags or set empty)    | -tags         |

**Important: ** comment and tags should be current or empty

### Integrity Provider Options

Command: integrity-provider

| Option            | Description                                                             | Default            | Required                          | Flag                |
|-------------------|-------------------------------------------------------------------------|--------------------|-----------------------------------|---------------------|
| CurrentPassphrase | Current password for integrity verification                             | Empty              | Yes (for HMAC integrity provider) | -current-passphrase |
| NewPassphrase     | New password for integrity verification (defaults to CurrentPassphrase) | Current passphrase | No                                | -new-passphrase     |

### Token Reader Options

Command: token-reader

| Option | Description                                      | Default | Required              | Flag    |
|--------|--------------------------------------------------|---------|-----------------------|---------|
| Type   | Method to read tokens: `file`, `flag` or `stdin` | Flag    | Yes                   | -type   |
| Path   | Path to read tokens from                         | Empty   | Yes (for `file` type) | -path   |
| Format | Format of tokens: `plaintext` or `json`          | JSON    | Yes                   | -format |
| Flag   | Token value passed as flag                       | Empty   | Yes (for `flag` type) | -flag   |

### Token Writer Options

Command: token-writer

| Option | Description                                        | Default | Required              | Flag    |
|--------|----------------------------------------------------|---------|-----------------------|---------|
| Type   | Method to write updated tokens: `file` or `stdout` | stdout  | Yes                   | -type   |
| Path   | Path to write tokens to                            | Empty   | Yes (for `file` type) | -path   |
| Format | Format of tokens: `plaintext` or `json`            | JSON    | Yes                   | -format |

### Log Writer Options

Command: log-writer

| Option | Description                              | Default | Required              | Flag    |
|--------|------------------------------------------|---------|-----------------------|---------|
| Type   | Method to write logs: `file` or `stdout` | stdout  | Yes                   | -type   |
| Format | Format of logs: `plaintext` or `json`    | JSON    | Yes                   | -format |
| Path   | Path to write logs                       | Empty   | Yes (for `file` type) | -path   |

## Reseal Process

The `Reseal` function orchestrates the entire resealing process:
1. Open the original encrypted container
2. Extract the master key using the provided token(s)
3. Walk the new content folder for metadata (uncompressed size, file count, file names) and compute the security score
4. Generate token output in memory before modifying destination files
5. Compress and encrypt in a single streaming pass: the packer streams the archive through an in-memory pipe directly into the container writer (into a temporary file), so the compressed archive is never staged on disk and compression overlaps with encryption
6. Flush and atomically rename the new container over its destination
7. Flush and atomically replace the token file, if file output is configured

Compression uses the parallel ZIP packer, so resealing a folder of many files scales with the available CPU cores.

## Progress Output

While packing and encrypting, `reseal` emits progress on stdout as lines of the form `PROGRESS <percent>`, where `<percent>` is an integer from `0` to `100`. These lines are distinct from the JSON token/log output on the same stream and are intended for a wrapping GUI to render a progress bar; they can be ignored when the CLI is used directly.

## Token Handling

The reseal package maintains the same token type and structure as the original container:
- If `new-passphrase` is empty or equals `current-passphrase`, original token strings are preserved
- If `new-passphrase` differs, master/share tokens are re-issued with the same master key
- Re-issued Shamir shares use the original share and threshold parameters
- For containers without tokens (passphrase-only), no tokens are generated

## Metadata Handling

The reseal operation preserves the original creation metadata while updating the timestamp:
- `Name`      - Container name
- `CreatedAt` - Preserved from the original container
- `UpdatedAt` - Set to the current time
- `Comment` - Comment can be changed
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
- Container and token files are written through temporary files and atomically renamed; failures before rename preserve the previous destination
- The container and token renames are sequential rather than a single cross-file transaction; old tokens remain usable because reseal preserves the master key
- Verify the updated container can be unsealed before discarding originals

## Compatibility

The reseal package is designed to work with containers created by the `seal` package and can be unsealed using the `unseal` package of the TVault Core system.
