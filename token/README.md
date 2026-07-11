# Token (tvault-core)

## Description

The `token` package provides functionality for creating, encrypting, decoding, and validating tokens within the tvault system.
Tokens are used to store and transmit metadata about secret shares and pass keys (master key) with optional encryption for secure transport.

## Features

- Creation of tokens with various types and metadata
- Authenticated token encryption using AES-GCM (AEAD)
- Token decoding and validation
- Support for signatures to verify integrity

## Token Types

The package defines the following token types:

- `TypeNone` (0x00) — token will not be created (use just passphrase)
- `TypeShare` (0x01) — token with a secret share
- `TypeMaster` (0x02) — token with a pass key (master key)

## Security

- Encrypted tokens use the envelope `0x01 || 12-byte nonce || ciphertext+tag`, encoded as Base64
- The format byte is authenticated as AES-GCM additional data
- Any modification of the format byte, nonce, ciphertext, or tag is rejected before JSON parsing
- A fresh random nonce is generated for every encrypted token
- The package validates token versions to ensure compatibility
- The signature field (`Signature`) can be used to ensure integrity

## Notes

Tokens in the current implementation use version 1. AES-CTR development tokens are intentionally not accepted.
When changing token formats, the `Version` constant should be updated to ensure backward compatibility.
