# HMAC Integrity Provider (tvault-core)

## Description

The `hmac` package implements an integrity provider using HMAC (Hash-based Message Authentication Code) with SHA-256. 
This provider verifies data integrity by creating and validating signatures based on a shared secret key.

## Key Features

- **Robust Data Integrity**: Ensures data has not been modified by unauthorized parties
- **Efficient Verification**: High-performance signature generation and validation
- **Key-based Security**: Uses a cryptographic key for secure signature operations
- **SHA-256 Based**: Leverages the strength of SHA-256 for hash operations

## Implementation Details

The HMAC provider implements the `integrity_provider.IntegrityProvider` interface:

- **Sign**: Creates an HMAC-SHA256 signature for the provided data
- **Verify**: Checks if a signature is valid for the given data
- **ID**: Returns the provider type identifier (IntegrityHMAC)

## Security Properties

- **Authentication**: Confirms the data came from someone with access to the secret key
- **Integrity**: Detects any changes to the data after signing
- **Simplicity**: Uses well-established cryptographic primitives
- **No Confidentiality**: HMAC does not encrypt the data; it only verifies integrity

## Key Management

- The secret key should be kept confidential
- The same key must be used for both signing and verification
- Key length should be at least 32 bytes for optimal security
- For production use, consider deriving keys using a key derivation function (KDF)
