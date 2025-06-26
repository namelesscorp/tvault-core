# Integrity Provider (tvault-core)

## Description

The `integrity` package defines interfaces and implementations for ensuring data integrity within the tvault-core system. 
It provides mechanisms to verify that data has not been tampered with during storage, transmission, or when shared between different components of the system.

## Key Features

- **Modular Design**: Pluggable integrity verification providers
- **Multiple Algorithms**: Support for various integrity verification methods (HMAC, ED25519, None)
- **Consistent Interface**: Unified API for all integrity providers
- **Secure Defaults**: Pre-configured secure options for common use cases

## Supported Providers

### HMAC Provider
Uses HMAC (Hash-based Message Authentication Code) with SHA-256 for integrity verification. 
Suitable for most use cases and provides a good balance between security and performance.

### ED25519 Provider
Implements cryptographic signatures using ED25519, offering stronger security guarantees through public key cryptography.

### None Provider
A no-op provider that performs no integrity checks. Only suitable for testing or when integrity verification is handled externally.

## Package Structure

- **integrity_provider.go** — Core interface definitions and constants
- **hmac/** — HMAC-based integrity provider
- **ed25519/** — ED25519-based integrity provider
- **mock/** — Mock implementations for testing

## Selecting a Provider

Choose an integrity provider based on your security requirements:

- **HMAC**: Good choice for most applications, requires a shared secret key
- **ED25519**: Higher security, suitable when public key verification is needed
- **None**: Use only when integrity verification is not required or handled elsewhere

## Integration with Other Packages
The integrity provider system is particularly important for the `shamir` package, where it ensures that secret shares have not been tampered with before reconstruction.
