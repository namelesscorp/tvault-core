# Compression (tvault-core)

## Description

The `compression` package provides interfaces and implementations for compressing and unpacking files in the tvault-core project. 
This package is a key component for managing data compression before encryption and storage.

## Compression Types

The following compression types are currently supported:

- **None**: No compression applied, used when compression is not needed or for testing purposes
- **Zip**: Standard ZIP compression format, offering efficient compression ratio and wide compatibility
