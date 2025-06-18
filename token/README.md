# Token (tvault-core)

## Description

The `token` package provides functionality for creating, encrypting, decoding, and validating tokens within the tvault system.
Tokens are used to store and transmit metadata about secret shares and pass keys (master key) with optional encryption for secure transport.

## Features

- Creation of tokens with various types and metadata
- Token encryption using AES-CTR
- Token decoding and validation
- Support for signatures to verify integrity

## Token Types

The package defines the following token types:

- `TypeShare` (0x01) — token with a secret share
- `TypeMaster` (0x02) — token with a pass key (master key)

## Security

- Tokens can be encrypted using AES-CTR to protect data
- The package validates token versions to ensure compatibility
- The signature field (`Signature`) can be used to ensure integrity

## Notes

Tokens in the current implementation use version 1. 
When changing token formats, the `Version` constant should be updated to ensure backward compatibility.
