# Lib (tvault-core)

## Description

The `lib` package contains core utilities and common components used throughout the tvault-core project.
This package serves as a foundation for building secure and reliable applications for storing and processing sensitive data.

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

### Error Handling (error.go, error_format.go)

- Unified mechanism for handling and formatting errors
- Structured error output with categories, codes, and detailed messages
- Support for various output formats (plaintext, JSON)

### I/O Systems (reader.go, writer.go)

- Various types of readers and writers (files, standard input/output)
- Support for different data formats (plaintext, JSON)
- Simple abstraction for working with files and streams

### Helper Functions (helpers.go)

- Set of common utilities and auxiliary functions
- Common methods for working with data and structures

### Options and Configuration (options.go)

- Customizable parameters for the package's core components
- Flexible options for adapting functionality to specific tasks
