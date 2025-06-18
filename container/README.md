# Container (tvault-core)

## Description

The package provides an implementation of a cryptographic container for storing encrypted data in the TVault Core project. 
It ensures secure information storage using AES-GCM encryption and the PBKDF2 key derivation process. `container`

## Container Structure (format v1)

The container file format is a binary format with the following structure (all fields in little-endian order):

| Offset | Size | Field | Description |
| --- | --- | --- | --- |
| 0x00 | 4 | "TVLT" signature | Format identifier |
| 0x04 | 1 | Version | Container format version |
| 0x05 | 1 | Flags | Reserved |
| 0x06 | 16 | Salt | Salt for PBKDF2 |
| 0x16 | 4 | Iterations | Iterations for PBKDF2 |
| 0x1A | 1 | Compression type | Compression algorithm ID |
| 0x1B | 12 | Nonce | Nonce for AES-GCM |
| 0x27 | 4 | Metadata length | Size of metadata block |
| 0x2B | N | JSON metadata | Plaintext metadata |
| 0x2B+N | ... | Ciphertext + 16-byte tag | Encrypted data + GCM tag |

## Key Requirements

For the `Create` function, the key must meet AES requirements:
- 16 bytes for AES-128
- 24 bytes for AES-192
- 32 bytes for AES-256 (recommended)

The `PBKDF2Key` function is used to stretch the key and create a master key of the specified length.

## Security

The container provides the following security measures:
- AES-GCM encryption for data confidentiality and integrity
- PBKDF2 with configurable iteration count for protection against brute force attacks
- Random nonce for each container
- Metadata is stored in plaintext but does not contain sensitive information
