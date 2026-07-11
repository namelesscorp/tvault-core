# ZIP Compression (tvault-core)

## Description

The `zip` package provides an implementation of the `compression.Compression` interface using the ZIP format for compressing and unpacking files.
This implementation is built on top of Go's standard `archive/zip` library.

## Constructors

- `New()` — deflate-compressing packer (compression type `zip`); `ID()` returns `compression.TypeZip` (0x01).
- `NewStore()` — packer that stores entries without compression (compression type `none`); `ID()` returns `compression.TypeNone` (0x00). The archive is still a valid ZIP, so unpacking is identical; only the deflate step is skipped, which is faster for large or already-compressed data.

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

### Single-walk packing (WalkFolder + PackEntriesTo)

To avoid traversing the directory tree twice (once to gather metadata such as size/file count, and again to compress), the package exposes:

- `WalkFolder(folder)` — walks the tree a single time and returns the entries to pack together with aggregate stats (uncompressed size, file count, file names).
- `PackEntriesTo(entries, w)` — writes pre-walked entries into a ZIP stream without re-walking the tree.

`PackTo` is implemented as `WalkFolder` followed by `PackEntriesTo`, so callers that already need the stats up front (e.g. `seal`, which writes metadata before the payload) can walk once and stream the same entries into the container.

### Identifier

The `ID()` method returns the compression type of the packer instance: `compression.TypeZip` (0x01) for `New`, or `compression.TypeNone` (0x00) for `NewStore`. This value is stored in the container header.