# Decrypt (tvault-core)

## Description

The `decrypt` package is a core component of the TVault Core system that handles the decryption of encrypted containers. 
It uses cryptographic tokens to access encrypted data, verifies data integrity, and decompresses the content to restore the original files and folder structure.

## Features

- Decryption of TVault container files (.tvlt)
- Support for master key tokens and Shamir secret sharing tokens
- Integrity verification through various providers
- Automatic decompression of encrypted content
- Restoring original folder structure to a specified location

## Usage

The decrypt package can be used programmatically or through the command-line interface:

### Command-Line Usage

```shell
# Using a single master token
tvault unseal \
  --container-path=/path/to/container.tvlt \
  --folder-path=/path/to/output \
  --token="AbCdEfGh..."

# Using multiple Shamir shares
tvault unseal \
  --container-path=/path/to/container.tvlt \
  --folder-path=/path/to/output \
  --token="AbCdEfGh...|IjKlMnOp...|QrStUvWx..."

# With additional password for HMAC integrity verification
tvault unseal \
  --container-path=/path/to/container.tvlt \
  --folder-path=/path/to/output \
  --token="AbCdEfGh..." \
  --additional-password="your-integrity-password"
```

## Configuration Options

| Option | Description | Default | Required |
| --- | --- | --- | --- |
| ContainerPath | Path to the encrypted container file | - | Yes |
| FolderPath | Path to the folder where decrypted content will be saved | - | Yes |
| Token | Token(s) for container decryption | - | Yes |
| AdditionalPassword | Additional password for integrity verification | - | No (Required only if HMAC was used during encryption) |

## Token Format

The decrypt package supports two types of tokens:

1. **Master Token** - A single token containing the master key:
```text
token=<base64-encoded-token>
```

1. **Shamir Shares** - Multiple tokens representing Shamir secret shares:
```text
token=<base64-encoded-token-1>|<base64-encoded-token-2> ...
```

## Decryption Process

1. Parse and validate the provided token(s)
2. Extract the master key (or reconstruct it from Shamir shares)
3. Verify the integrity of the key using the configured integrity provider
4. Open and decrypt the container
5. Decompress the decrypted data
6. Restore the original folder structure to the specified location

## Error Handling

The method checks all configuration parameters for correctness before proceeding with decryption: `Validate()`
- Required fields must be provided
- Container file must exist and be accessible
- Token format must be valid
- Output folder path must be valid

## Security Considerations

- Keep tokens secure and don't share
- When using HMAC integrity verification, keep the additional password confidential
- Verify the decrypted content before using it for critical operations
