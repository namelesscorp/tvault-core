# Developer Technical Guide

This document describes the current `tvault-core` implementation: repository structure, data formats, cryptographic flows, extension points, local development, testing, and known limitations.

## 1. Purpose and scope

`tvault-core` is a Go library and CLI that packages a directory into an encrypted `.tvlt` container, restores it, and replaces its encrypted contents through resealing.

```text
directory -> ZIP -> AES-256-GCM -> TVLT container
                                    + plaintext metadata
                                    + algorithm parameters
master key -> master token or Shamir shares -> external writer
```

The project is not a network service. It has no HTTP API, database, or background daemon. State is stored in container and token files. The module path is `github.com/namelesscorp/tvault-core`; the required Go version is declared in `go.mod` and is currently `1.26`. There are no external Go module dependencies.

## 2. Repository map

| Path | Responsibility |
|---|---|
| `cmd/` | CLI commands, grouped flag parsing, defaults, and process exit codes |
| `seal/` | Container, key, metadata, and token creation |
| `unseal/` | Key recovery, container decryption, and archive extraction |
| `reseal/` | Content replacement, token preservation/rotation, and atomic file updates |
| `container/` | TVLT v1 binary format, metadata, AES-GCM streaming, and `container info` |
| `token/` | Token JSON model, Base64 representation, and AES-GCM envelope |
| `shamir/` | Shamir Secret Sharing over GF(256) and share verification |
| `integrity/` | Share-signing abstraction: `none`, HMAC, and an Ed25519 placeholder |
| `compression/` | Compression abstraction and ZIP implementation |
| `lib/` | Shared options, readers/writers, PBKDF2, and typed errors |
| `security/` | Heuristic security score |
| `debug/` | CPU, trace, block, mutex, heap, and goroutine profiling |
| `example/` | Example container, tokens, files, and CLI scenarios |
| `docs/` | PlantUML architecture sources, generated SVG files, and this guide |

Dependencies flow from use-case packages (`seal`, `unseal`, and `reseal`) toward infrastructure packages. `cmd` should only build options and invoke use cases; cryptographic logic should not be added to the CLI layer.

## 3. Developer quick start

```shell
go version
go test ./...
go test -race ./...
make build
./tvault-core version
```

Additional commands:

```shell
go test -cover ./...
go test -bench=. -benchmem ./...
go vet ./...
make uml                    # requires PlantUML
TVAULT_DEBUG=true ./tvault-core version
```

`make clean` removes the binary, profiling output, and all root-level `*.log`, `*.json`, and `*.txt` files. Do not run it if those files must be preserved.

CI builds the project, runs tests with the race detector and coverage, runs golangci-lint and gosec, and executes benchmarks. The release job builds platform binaries for `v*` tags.

## 4. Core workflows

### 4.1 Seal

Entry point: `seal.Seal(Options)`.

1. `Options.Validate` checks paths, token/compression/integrity types, Shamir parameters, readers, and writers.
2. The source directory is written to a temporary ZIP while file count, names, and sizes are collected.
3. A random 32-byte master key and a `Header` with random salt and nonce are created.
4. Plaintext metadata and a heuristic security score are generated.
5. The ZIP is encrypted into the TVLT container using chunked AES-256-GCM.
6. `share` splits the master key with Shamir; `master` writes one master token; `none` creates no token.

Access modes:

| Token type | Unseal key source | Requirements |
|---|---|---|
| `none` (`0x00`) | PBKDF2 from the container passphrase | Integrity provider must be `none` |
| `share` (`0x01`) | Shamir share combination | Shamir enabled; `2 <= threshold <= shares <= 255` |
| `master` (`0x02`) | Master key stored in one token | Shamir recovery is not required |

### 4.2 Unseal

Entry point: `unseal.Unseal(Options)`.

1. The signature and format version are validated, then plaintext metadata is read.
2. For `none`, the key is derived from the container passphrase and header salt.
3. For `master/share`, tokens are read from a flag, file, or stdin. The integrity passphrase is derived with PBKDF2 and decrypts the tokens; HMAC additionally verifies Shamir shares.
4. The payload is decrypted into a temporary ZIP.
5. The ZIP is extracted into the destination directory. The implementation rejects archive paths that escape the destination.

An incorrect payload key is normally detected by AES-GCM while opening the first chunk. For share tokens, an incorrect integrity passphrase also causes token authentication, parsing, or share-verification failure.

### 4.3 Reseal

Entry point: `reseal.Reseal(Options)`.

`reseal` recovers the existing master key, packages a new directory, and writes the container to `new-path` or replaces `current-path`. It preserves `CreatedAt`, format version, salt, and token/compression/Shamir parameters. It updates `UpdatedAt`, file statistics, and the security score.

Token behavior depends on integrity-passphrase rotation:

| Condition | Behavior |
|---|---|
| `new-passphrase` is empty | Original Base64 token strings are preserved |
| `new-passphrase == current-passphrase` | Original token strings are preserved |
| A different `new-passphrase` is supplied | Tokens are re-issued with the same master key and a new derived key |
| Token type is `none` | Token reader and writer are not used |

Before parsing, `reseal` extracts the original token strings from a pipe-delimited plaintext value or JSON `token_list`. JSON formatting may change, but preserved array values remain byte-for-byte identical. Rotating share tokens performs a new Shamir split, so both shares and token nonces change.

Token output is generated in memory before destination files are modified. The new container is written to a temporary file in the destination directory, flushed with `fsync`, and atomically renamed over the target. File-based token output uses the same temp-file, `fsync`, and rename flow. On Unix the directory is synchronized after rename; on Windows `fsyncDir` is a no-op and durability relies on the NTFS journal. A failure before rename preserves the previous destination and removes the temporary file.

Container and token files are replaced sequentially, not as one cross-file transaction. If token writing fails after the container rename, the previous tokens remain available and can still open the new container because resealing preserves the master key.

## 5. TVLT container format v1

The header is serialized with `encoding/binary` in little-endian order, followed by JSON metadata and payload chunks.

| Field | Go type | Purpose |
|---|---:|---|
| `Signature` | `[4]byte` | ASCII `TVLT` |
| `Version` | `uint8` | Currently `1` |
| `Flags` | `uint8` | Reserved |
| `Salt` | `[16]byte` | PBKDF2 salt |
| `Iterations` | `uint32` | Normally `100000` |
| `CompressionType` | `uint8` | `none=0`, `zip=1` |
| `IntegrityProviderType` | `uint8` | `none=0`, `hmac=1`, `ed25519=2` |
| `TokenType` | `uint8` | `none=0`, `share=1`, `master=2` |
| `Nonce` | `[12]byte` | Base AES-GCM nonce |
| `MetadataSize` | `uint32` | JSON metadata length; at most 1 MiB when reading |
| `Shares`, `Threshold` | `uint8` | Shamir parameters |
| `ChunkSize` | `uint32` | Plaintext chunk size; 16 MiB by default |

Each payload chunk is encoded as `uint32 plaintextLength`, followed by ciphertext and a 16-byte GCM tag. A zero `uint32` terminates the stream. The per-chunk nonce consists of the first four random bytes of the base nonce and a little-endian `uint64` counter.

The layout comment at the beginning of `container/container.go` historically described the old contiguous payload and does not include `ChunkSize`. `Header`, `WriteEncrypted`, and `DecryptTo` are the sources of truth.

Metadata fields (`name`, timestamps, comment, tags, sizes, score, and file count) are plaintext JSON and are not passed to AES-GCM as associated data. `container info` can read them without decrypting the payload. Their confidentiality and cryptographic authenticity are therefore not guaranteed.

`Read` rejects `MetadataSize > MaxMetadataSize` (1 MiB) before allocation, preventing a hostile header from requesting a multi-gigabyte buffer. Any layout change requires a new container version and a compatible reading branch rather than a silent change to `Header`.

`container.Container` is streaming-oriented and exposes `WriteEncrypted`, `DecryptTo`, the header, metadata, and master key. The old `GetCipherData` and `GetData` methods were removed because the streaming implementation never populated those buffers.

## 6. Keys, tokens, and integrity

### Keys

- The master key is 32 random bytes used by AES-256-GCM.
- Password derivation uses the local PBKDF2-HMAC-SHA256 implementation with 100,000 iterations, a 16-byte salt, and a 32-byte result.
- In `none` mode, the container passphrase directly derives the master key.
- In `master/share` modes, the payload master key is random; the container passphrase does not encrypt the payload.

### Tokens

The internal JSON model is `{"v":1,"id":1,"vl":"hex...","s":"hex..."}`. A share token contains its ID, share value, and signature. A master token stores the master key in `vl`. Before converting a token ID to `byte`, unseal validates the `0..255` range and returns `ErrTokenIDOutOfRange` instead of truncating an invalid value.

The external token is always Base64. JSON writers wrap token strings as `{"token_list":["..."]}`. The plaintext reader expects pipe-delimited token strings.

When a key is supplied, the binary envelope before Base64 is:

```text
format byte (0x01) || nonce (12 bytes) || AES-GCM ciphertext || tag (16 bytes)
```

The token uses AES-GCM AEAD. The format byte is supplied as additional authenticated data, while the nonce, ciphertext, and tag are verified by GCM. Any modification is rejected with `ErrCodeTokenGCMOpenError` before JSON is processed. A new nonce is generated with `crypto/rand` for every token, so identical data encrypted with the same key produces different ciphertext. The parser requires at least `1 + 12 + 16` decoded bytes and reports `ErrTokenCiphertextTooShort` for a shorter envelope.

An AES-CTR envelope without a format byte is intentionally rejected. There is no unauthenticated fallback, which avoids a downgrade path.

The HMAC signature on a Shamir share remains separate: AEAD protects the token envelope, while HMAC validates the share during `shamir.Combine`.

### Token format stability

`0x01 || 12-byte nonce || ciphertext+tag` is the current token v1 format. The earlier AES-CTR variant existed only during internal development; there have been no public releases or user tokens requiring backward compatibility. A migration fallback or `token.Version` increment is therefore not currently required.

The fixtures in `example/keys.json` and `example/vault.tvlt` use the current format. After the first public release, incompatible token wire-format changes must use a new version or explicit format marker and include a migration strategy.

### Integrity providers

`integrity.Provider` defines `Sign`, `IsVerify`, and `ID`. HMAC-SHA256 signs `shareID || shareValue`. The `none` provider accepts all values. The Ed25519 ID is reserved, but its implementation returns `ErrEd25519Unimplemented` and it is not accepted as a CLI provider type.

## 7. Compression and file safety

`compression.Compression` provides buffer and streaming `PackTo`/`UnpackFrom` methods as well as archive statistics. Production workflows use ZIP. `noneCompression` is a placeholder and is not usable by seal/unseal workflows.

To add a compression format:

1. Assign stable numeric and textual identifiers.
2. Implement every interface method.
3. Add factories to `seal`, `unseal`, and `reseal`.
4. Update validation, ID/name converters, and the security score.
5. Add round-trip and malicious-archive tests.
6. Define behavior for existing containers.

## 8. CLI and programmatic API

The CLI supports `seal`, `unseal`, `reseal`, `container info`, `version`, and `info`. Arguments are grouped under named subcommands such as `container`, `token`, and `token-writer`. Groups may appear in any order, but each group name must be a separate argument.

Minimal seal using the default `share/zip/hmac/3-of-5` configuration (5 shares, threshold 3):

```shell
./tvault-core seal \
  container -new-path=out.tvlt -folder-path=./data -passphrase=unused \
  integrity-provider -new-passphrase='token secret' \
  token-writer -type=file -path=keys.json -format=json
```

Current validation requires `container -passphrase` even for `share/master`, although those modes use a random payload key. This is a CLI/API validation constraint rather than a cryptographic requirement.

Programmatic integration uses `seal.Options`, `unseal.Options`, `reseal.Options`, and shared types from `lib`. Call `Validate` before invoking a use case when options are not built by the CLI. Low-level `container.Container` access is suitable for header/metadata inspection and streaming encryption, but the caller is responsible for valid IDs, headers, and key management.

Readers: `flag`, `file`, and `stdin`. Writers: `stdout` and `file`. Formats: `json` and `plaintext`. A file writer creates or truncates its destination; token files should be placed in a protected directory with restrictive OS permissions.

Plaintext writer and reader formats are currently asymmetric. The reader expects `token1|token2`, while the writer emits `tokens:`/`token:` headings and `---` separators. JSON is the recommended machine-readable format and supports direct round trips.

## 9. Errors and diagnostics

`lib.Error` stores a type (`validation`, `internal`, `io`, `crypto`, or `format`), category, code, message, details, suggestion, cause, and stack trace. Use `ValidationErr`, `InternalErr`, `IOErr`, `CryptoErr`, and `FormatErr` instead of discarding context with plain `fmt.Errorf`. At the CLI boundary, `lib.ErrorFormatted` serializes the error through the configured log writer.

Inspect errors with `lib.AsError`, `errors.Is`/`errors.As`, or helpers such as `IsValidationError`. A new error should have a stable code, category, actionable message, suggestion where appropriate, and serialization/unwrap tests.

CLI execution is implemented by `run()`, which returns the process exit code. Successful commands return `0`; missing or unknown commands, use-case errors, and recovered panics return `1`. `main` calls `os.Exit(run())`, while deferred cleanup and `debug.Stop` run inside `run` before termination.

Set `TVAULT_DEBUG=true` to enable the `debug` package. Profiles are stored under `debug/profiles`; `SIGUSR1` saves available runtime profiles. Do not leave profiling enabled in production because profiles may expose sensitive behavioral information.

## 10. Testing changes

Minimum checks before merge:

```shell
gofmt -w <changed-go-files>
go test ./...
go test -race ./...
go vet ./...
go build ./...
```

Cryptographic or format changes additionally require tests for:

- seal → unseal and reseal → unseal round trips;
- incorrect passphrases, tokens, signatures, and insufficient shares;
- empty, large, and multi-chunk payloads;
- corrupted headers, metadata lengths, chunk lengths/tags, and truncated inputs;
- rejection of metadata larger than `MaxMetadataSize` before allocation;
- compatibility with fixtures from supported versions;
- nonce uniqueness and non-deterministic token ciphertext with successful round trips;
- rejection of modified format bytes, nonces, ciphertext, and authentication tags;
- token preservation without rotation and re-issuance with passphrase rotation;
- preservation of existing targets on pre-rename failure and cleanup of temp files;
- token ID boundaries (`-1`, `0`, `255`, and `256`) and short envelopes;
- archive path traversal and symlink cases;
- benchmarks when changing PBKDF2, GF(256), streaming, or allocation behavior.

Most existing tests are package-level unit tests. There is currently no complete automated CLI end-to-end suite. `example/` is useful for manual smoke tests but should not replace reproducible fixtures.

## 11. Extension rules

- Never reuse an existing numeric ID for a different algorithm.
- Do not change the binary `Header` without incrementing `container.Version`.
- Never log passphrases, master keys, shares, or complete tokens.
- Clean up temporary files on all error paths and use mode `0600` for containers and token files.
- Preserve streaming behavior; avoid loading full archives or ciphertext into memory without need.
- Treat container and archive data as untrusted and enforce limits before allocation.
- Update defaults, validation, README files, this guide, and tests for new CLI flags.
- Update both ID/name conversion directions and all factories for a new provider or compressor.

## 12. Known limitations and technical debt

- Ed25519 is declared but not implemented.
- `noneCompression` is only a placeholder.
- Plaintext token writer output cannot be passed directly to the plaintext reader without converting it to a pipe-delimited list.

These limitations must be considered during threat modeling and compatibility planning. Changes to cryptographic protocols or binary layouts require a migration strategy and a new format version after the first public release.

## 13. Contribution workflow

Follow `CONTRIBUTING.md`: use a dedicated branch, run tests, update `CHANGELOG.md`, obtain review, and squash merge. Changes to public behavior must also update the root README, relevant package README files, and this guide. PlantUML files under `docs/*.puml` are the editable diagram sources; regenerate SVG output with `make uml`.
