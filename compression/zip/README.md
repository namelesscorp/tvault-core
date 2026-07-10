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

### Compression to writer (PackTo)

The `PackTo` method performs the following operations:
- Recursively traverses the specified directory
- Preserves relative file paths
- Writes ZIP archive data directly to the provided `io.Writer`
- Avoids keeping the whole archive in memory
- Updates compression statistics such as compressed size, uncompressed size, file count, and file name list

This method is intended for streaming scenarios, for example when compressed data should be written directly to a container, temporary file, network stream, or another writer.

### Unpacking (Unpack)

The `Unpack` method performs the following operations:
- Creates a ZIP reader from a byte buffer
- Extracts all files while preserving directory structure
- Restores all file permissions
- Creates necessary directories

### Unpacking from reader (UnpackFrom)

The `UnpackFrom` method performs the following operations:
- Creates a ZIP reader from the provided `io.ReaderAt` and archive size
- Extracts all files while preserving directory structure
- Restores all file permissions
- Creates necessary directories
- Avoids loading the whole archive into memory before unpacking

This method is intended for streaming or file-backed scenarios, for example when ZIP data is read directly from a container payload or temporary file.

### Identifier

The `ID()` method returns the constant `compression.TypeZip` (0x01), which identifies this compression type in the system.