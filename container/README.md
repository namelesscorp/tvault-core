# Container (tvault-core)

## Description

The package provides an implementation of a cryptographic container for storing encrypted data in the TVault Core
project.
It ensures secure information storage using AES-GCM encryption and the PBKDF2 key derivation process. `container`

## Container Structure (format v1)

The container file format is a binary format with the following structure (all fields in little-endian order):

| Offset | Size | Field                    | Description                |
|--------|------|--------------------------|----------------------------|
| 0x00   | 4    | "TVLT" signature         | Format identifier          |
| 0x04   | 1    | Version                  | Container format version   |
| 0x05   | 1    | Flags                    | Reserved                   |
| 0x06   | 16   | Salt                     | Salt for PBKDF2            |
| 0x16   | 4    | Iterations               | Iterations for PBKDF2      |
| 0x1A   | 1    | Compression type         | Compression algorithm ID   |
| 0x1B   | 1    | Integrity provider type  | Integrity provider type ID |
| 0x1C   | 1    | Token type               | Token type ID              |
| 0x1D   | 12   | Nonce                    | Nonce for AES-GCM          |
| 0x29   | 4    | Metadata length          | Size of metadata block     |
| 0x2D   | 1    | Shares                   | Number of Shamir shares    |
| 0x2E   | 1    | Threshold                | Minimum shares threshold   |
| 0x2F   | 4    | Chunk size               | Plaintext chunk size (B)   |
| 0x33   | N    | JSON metadata            | Plaintext metadata         |
| 0x33+N | ...  | Chunked ciphertext       | Length-prefixed GCM chunks |

The payload is not a single ciphertext blob: it is a sequence of AES-GCM
chunks, each written as a little-endian `uint32` plaintext length followed by
the chunk ciphertext and its 16-byte GCM tag. A terminating `uint32(0)` length
marks the end of the stream. Each chunk reuses the base `Nonce` with a per-chunk
counter written into bytes `nonce[4:]`.

## Key Requirements

For the `Create` function, the key must meet AES requirements:

- 16 bytes for AES-128
- 24 bytes for AES-192
- 32 bytes for AES-256 (recommended)

The `PBKDF2Key` function is used to stretch the key and create a master key of the specified length.

### Command-Line Usage

```shell
tvault-core container \
info \
  -path="/path/to/container/file" \
info-writer \
  -type="file" \
  -format="json" \
  -path="/path/to/updated/token/file" \
log-writer \
  -type="stdout" \
  -format="json"
```

```json
{
  "name": "hello",
  "version": 1,
  "created_at": "2026-07-10 21:41:04",
  "updated_at": "2026-07-10 21:41:04",
  "comment": "created by trust vault core",
  "tags": [
    "docs"
  ],
  "token_type": "share",
  "integrity_provider_type": "hmac",
  "compression_type": "zip",
  "shares": 5,
  "threshold": 3,
  "file_count": 2,
  "compressed_size": 5321,
  "uncompressed_size": 6152,
  "security_score": 0.65
}
```

`compressed_size` is the size of the compressed archive in bytes. It is not
known until the whole payload has been streamed, so it is patched into the
plaintext metadata once writing completes (the field is reserved at maximum
width up front so the metadata length never changes).

## Security

The container provides the following security measures:

- AES-GCM encryption for data confidentiality and integrity
- PBKDF2 with configurable iteration count for protection against brute force attacks
- Random nonce for each container
- Shamir's Secret Sharing scheme for splitting sensitive data
- Metadata is stored in plaintext but does not contain sensitive information
- Hostile-input hardening on read: the metadata length is capped at 1 MiB and each declared chunk length at 64 MiB, so a malformed header cannot force a huge allocation before any bytes are read