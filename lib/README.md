# Lib (tvault-core)

## Description

The `lib` package contains core cryptographic utilities and shared functionality used across the tvault-core project. 
It provides essential cryptographic primitives that serve as building blocks for the secure storage and retrieval of sensitive data.

## Key Features

- **Key Derivation**: Implementation of PBKDF2-HMAC-SHA256 for secure password-based key derivation

## Components

### Key Derivation (key.go)

The package implements PBKDF2 (Password-Based Key Derivation Function 2) according to RFC 8018, providing:

- **PBKDF2Key**: Derives cryptographic keys from passwords using HMAC-SHA256
- High iteration count (100,000) to protect against brute-force attacks
- Configurable key length for different security requirements

### Constants

- **KeyLen**: Standard key length (32 bytes) for cryptographic operations
- **Iterations**: Default number of iterations (100,000) for PBKDF2

## Security Considerations

- The package implements PBKDF2 with a high iteration count to protect against brute-force attacks
- SHA-256 is used as the underlying hash function for HMAC operations
- Key derivation follows cryptographic best practices for secure password handling

## Performance Notes

The PBKDF2 implementation is designed to be computationally intensive (by using a high iteration count) to resist brute-force attacks. 
This intentional design choice means key derivation operations will take a noticeable amount of time, which is a security feature rather than a performance issue.
