# Shamir (tvault-core)

## Description

The `shamir` package implements Shamir's Secret Sharing scheme, which allows splitting a secret into multiple parts (shares) such that a specific number of these parts is required to reconstruct the original secret.

This implementation uses the Galois Field GF(2^8), making it efficient for working with byte data. The package provides share integrity protection through various cryptographic methods.

## Key Features

- **Secret Splitting**: Dividing a pass key into `n` shares, where any `t` shares are enough to recover the original secret
- **Secret Recovery**: Reconstructing the original secret from `t` or more shares
- **Integrity Verification**: Integration with various integrity providers (HMAC, ED25519)
- **Optimized Calculations**: Fast Galois field operations using pre-computed tables

## Package Structure

- **shamir.go** — Core functions for splitting and recovering secrets
- **shamir_math.go** — Mathematical operations in the Galois field GF(2^8)
- **shamir_test.go** — Tests for core functions
- **shamir_math_test.go** — Tests for mathematical operations
- **shamir_math_benchmark_test.go** — Benchmarks for performance optimization

## Mathematical Foundation

The implementation is based on polynomial interpolation in the Galois field GF(2^8). Lagrange interpolation is used to securely recover the original secret when a sufficient number of shares is available.

For efficient calculations in the GF(2^8) field, exponent and logarithm tables are used, which significantly speeds up multiplication and division operations.

## Security

- The implementation provides information-theoretic security according to Shamir's scheme
- The threshold scheme ensures that any number of shares less than the threshold `t` provides no information about the secret
- Integration with integrity providers prevents share modification attacks

## Limitations

- Maximum number of shares is limited to 255 (due to the use of GF(2^8))
- The threshold must be less than or equal to the total number of shares
- For maximum security, it's recommended to use integrity providers

## Performance Notes

Galois field operations are optimized using pre-computed tables, which significantly speeds up the processes of splitting and recovering secrets. This makes the library suitable for use in both high-performance and resource-constrained environments.
