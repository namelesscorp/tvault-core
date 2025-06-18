# ZIP Compression (tvault-core)

## Description

The `zip` package provides an implementation of the `compression.Compression` interface using the ZIP format for compressing and unpacking files. 
This implementation is built on top of Go's standard `archive/zip` library.

## Functionality

### Compression (Pack)

The `Pack` method performs the following operations:
- Recursively traverses the specified directory
- Preserves relative file paths
- Creates a ZIP archive in memory (byte buffer)
- Returns the archive data as []byte

### Unpacking (Unpack)

The `Unpack` method performs the following operations:
- Creates a ZIP reader from a byte buffer
- Extracts all files while preserving directory structure
- Restores all file permissions
- Creates necessary directories

### Identifier

The `ID()` method returns the constant `compression.TypeZip` (0x01), which identifies this compression type in the system.
