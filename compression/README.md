# Compression (tvault-core)

## Description

The `compression` package provides interfaces and implementations for compressing and unpacking files in the tvault-core project. 
This package is a key component for managing data compression before encryption and storage.

## Compression Types

The following compression types are currently supported:

- **None**: Files are bundled into a ZIP archive using the `Store` method (no deflate). The archive structure is preserved so it unpacks like any ZIP, but the CPU-heavy compression step is skipped — faster for large or already-compressed data.
- **Zip**: Standard ZIP compression (deflate), offering an efficient compression ratio and wide compatibility

Both types are produced by the `zip` package (`zip.New` for deflate, `zip.NewStore` for stored/"none").
