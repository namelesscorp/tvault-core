# Changelog (tvault-core)

All notable changes to this project will be documented in this file.

## Explanation:

1. Unreleased: This section is for changes that have not been officially released yet.
2. Tags: Each version release has a header with the version number, release date, and a list of changes categorized into “Added”, “Changed”, and “Fixed”.
3. Categories:
   - Added: New features or functionality.
   - Changed: Modifications to existing features, including improvements.
   - Fixed: Bug fixes and patches.

## Unreleased

### Added

### Changed

### Fixed

## Tags

### [v1.0.1](https://github.com/namelesscorp/tvault-core/releases/tag/v1.0.1) - 2026-07-12

#### Added

- `none` compression type that stores files in a ZIP archive without deflate, for faster handling of large or already-compressed data; added to the set of valid CLI compression types.

#### Changed

- Increased large-file container encryption throughput by coalescing the many small reads from the compression pipe into full chunks and reusing the AES-GCM ciphertext buffer, reducing per-chunk allocations and framing overhead.
- Container decryption now reuses the ciphertext and plaintext buffers across chunks instead of allocating on every chunk.
- Directory compression now walks the source tree a single time, shared between metadata collection and packing, instead of walking it twice.
- Removed the unused placeholder `noneCompression` implementation and `NewNoneCompression` constructor now that `none` is a real compression type.

#### Fixed

- Fixed container `compressed_size` metadata always being written as `-1`; the real compressed size is now recorded by patching it into the metadata after the payload is streamed.
- Fixed decryption trusting the per-chunk plaintext length from the container before allocating; each declared chunk length is now capped at 64 MiB to prevent hostile allocations.
- Fixed Shamir secret reconstruction (`Combine`) panicking on malformed shares from untrusted tokens — duplicate or zero share IDs (division by zero) and mismatched share value lengths (index out of range) — which now return errors.
- Fixed package documentation inaccuracies: `none` compression availability, container header layout (chunk-size field and offsets) and CLI examples, HMAC/Shamir/integrity provider details, and JSON field names.

### [v1.0.0](https://github.com/namelesscorp/tvault-core/releases/tag/v1.0.0) - 2026-07-12

#### Added

- Security score calculation based on token type, integrity provider, compression, Shamir configuration, passphrase strength, and sensitive file names.
- Streaming ZIP compression and chunked AES-256-GCM container encryption to support large inputs without loading the complete archive into memory.
- Container chunk size stored in the TVLT header for streaming decryption.
- Compressed and uncompressed size, file count, file names, and security score metadata.
- Atomic reseal writes for container and token files using temporary files, `fsync`, and rename.
- Durable directory synchronization after atomic rename on Unix, with a platform-specific Windows implementation.
- Authenticated AES-GCM token envelopes with a format marker, random nonce, ciphertext, and authentication tag.
- Token tampering detection for the format marker, nonce, ciphertext, and authentication tag.
- Token ID range validation before conversion to `byte`.
- Maximum accepted container metadata size of 1 MiB to prevent hostile allocations.
- Preservation of original token strings during reseal when the integrity-provider passphrase is not rotated.
- Token re-issuance with the existing master key when the integrity-provider passphrase is rotated.
- Non-zero CLI process exit codes for invalid usage, unknown commands, operation failures, and recovered panics.
- Runtime profiling and signal-based debug profile collection.
- Developer technical documentation, architecture diagrams, package documentation, and updated CLI examples.
- CI jobs for race-enabled tests, coverage, linting, security scanning, benchmarks, and release binaries.

#### Changed

- Updated the module and CI toolchain to Go 1.26.
- Refactored `seal`, `unseal`, and `reseal` to use streaming temporary artifacts and explicit resource cleanup.
- Changed encrypted token protection from unauthenticated AES-CTR to authenticated AES-GCM.
- Changed reseal behavior to preserve tokens unless an integrity-provider passphrase rotation is requested.
- Changed container writes to flush file contents before returning.
- Changed the CLI entry point to return explicit success and failure exit codes.
- Removed unused `GetCipherData` and `GetData` container methods that were incompatible with streaming operation.
- Expanded typed error codes and messages for token authentication, metadata limits, file synchronization, and atomic reseal failures.
- Updated project licensing, contribution documentation, package README files, examples, and security guidance.

#### Fixed

- Fixed token ciphertext malleability by authenticating the complete encrypted token envelope.
- Fixed nonce/keystream reuse in token encryption by generating a fresh random AES-GCM nonce for every token.
- Fixed reseal potentially truncating the original container before a replacement was fully written.
- Fixed reseal potentially truncating an existing token file during output.
- Fixed token regeneration on every reseal when no passphrase rotation was requested.
- Fixed loss of the original container or token file when a write fails before atomic commit.
- Fixed oversized `MetadataSize` values being trusted before memory allocation.
- Fixed out-of-range token IDs being silently truncated during byte conversion.
- Fixed CLI failures returning a successful process exit status.
- Fixed ZIP path and symlink handling and resolved static-analysis findings around file access and integer conversions.
- Fixed temporary-file cleanup and file-close handling across seal, unseal, and reseal error paths.
