package reseal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/compression/zip"
	"github.com/namelesscorp/tvault-core/container"
	"github.com/namelesscorp/tvault-core/integrity"
	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/seal"
	"github.com/namelesscorp/tvault-core/security"
	"github.com/namelesscorp/tvault-core/shamir"
	"github.com/namelesscorp/tvault-core/token"
	"github.com/namelesscorp/tvault-core/unseal"
)

type compressedArtifact struct {
	Comp    compression.Compression
	ZipPath string
	ZipSize int64
}

// Reseal - processes a sealed container by decrypting, modifying, and re-encrypting it with updated metadata and tokens.
func Reseal(opts Options) error {
	currentContainer := container.NewContainer(
		*opts.Container.CurrentPath,
		nil,
		container.Metadata{Tags: make([]string, 0)},
		container.Header{},
	)
	if err := currentContainer.Read(); err != nil {
		return lib.IOErr(
			lib.CategoryReseal,
			lib.ErrCodeResealOpenContainerError,
			lib.ErrMessageResealOpenContainerError,
			"",
			err,
		)
	}

	var comment = currentContainer.GetMetadata().Comment
	if *opts.Container.Comment != comment {
		comment = *opts.Container.Comment
	}

	var tags = currentContainer.GetMetadata().Tags
	if *opts.Container.Tags != strings.Join(tags, ",") {
		tags = lib.ParseTags(*opts.Container.Tags)
	}

	var containerName = *opts.Container.Name
	if *opts.Container.Name == "" {
		containerName = currentContainer.GetMetadata().Name
	}

	var (
		masterKey         []byte
		originalRawTokens []string
	)
	switch currentContainer.GetHeader().TokenType {
	case token.TypeMaster, token.TypeShare:
		derivedPassphrase := unseal.DeriveIntegrityProviderPassphrase(
			*opts.IntegrityProvider.CurrentPassphrase,
			currentContainer.GetHeader().Salt,
		)

		var tokenString string
		tokenString, err := unseal.GetTokenString(opts.TokenReader)
		if err != nil {
			return lib.InternalErr(
				lib.CategoryReseal,
				lib.ErrCodeResealGetTokenStringError,
				lib.ErrMessageResealGetTokenStringError,
				"",
				err,
			)
		}

		if originalRawTokens, err = extractRawTokens(tokenString, *opts.TokenReader.Format); err != nil {
			return lib.InternalErr(
				lib.CategoryReseal,
				lib.ErrCodeResealParseTokensError,
				lib.ErrMessageResealParseTokensError,
				"",
				err,
			)
		}

		var shares []shamir.Share
		masterKey, shares, err = unseal.ParseTokens(
			currentContainer.GetHeader().TokenType,
			tokenString,
			*opts.TokenReader.Format,
			derivedPassphrase,
		)
		if err != nil {
			return lib.InternalErr(
				lib.CategoryReseal,
				lib.ErrCodeResealParseTokensError,
				lib.ErrMessageResealParseTokensError,
				"",
				err,
			)
		}

		if len(masterKey) == 0 {
			masterKey, err = unseal.RestoreMasterKey(shares, derivedPassphrase)
			if err != nil {
				return lib.InternalErr(
					lib.CategoryReseal,
					lib.ErrCodeResealRestoreMasterKeyError,
					lib.ErrMessageResealRestoreMasterKeyError,
					"",
					err,
				)
			}
		}
	case token.TypeNone:
		var salt = currentContainer.GetHeader().Salt
		masterKey = lib.PBKDF2Key(
			[]byte(*opts.Container.Passphrase),
			salt[:],
			currentContainer.GetHeader().Iterations,
			lib.KeyLen,
		)
	}

	artifact, err := compressFolderForReseal(
		compression.ConvertIDToName(currentContainer.GetHeader().CompressionType),
		*opts.Container.FolderPath,
	)
	if err != nil {
		return lib.InternalErr(
			lib.CategoryReseal,
			lib.ErrCodeResealCompressFolderError,
			lib.ErrMessageResealCompressFolderError,
			"",
			err,
		)
	}
	defer func() { _ = os.Remove(artifact.ZipPath) }()

	secScore := security.New(security.Params{
		TokenType:                   token.ConvertIDToName(currentContainer.GetHeader().TokenType),
		IntegrityProviderType:       integrity.ConvertIDToName(currentContainer.GetHeader().IntegrityProviderType),
		CompressionType:             compression.ConvertIDToName(currentContainer.GetHeader().CompressionType),
		NumberOfShares:              int(currentContainer.GetHeader().Shares),
		NumberOfThreshold:           int(currentContainer.GetHeader().Threshold),
		ContainerPassphrase:         *opts.Container.Passphrase,
		IntegrityProviderPassphrase: *getIntegrityProviderPassphrasePtr(opts.IntegrityProvider),
		FileNameList:                artifact.Comp.GetFileNameList(),
	})

	currentContainer.SetMetadata(container.Metadata{
		Name:             containerName,
		CreatedAt:        currentContainer.GetMetadata().CreatedAt,
		UpdatedAt:        time.Now(),
		Comment:          comment,
		Tags:             tags,
		CompressedSize:   artifact.ZipSize,
		UncompressedSize: artifact.Comp.GetUncompressedSize(),
		FileCount:        artifact.Comp.GetFileCount(),
		SecurityScore:    secScore.Calculate(),
	})

	currentContainer.SetMasterKey(masterKey)

	targetContainerPath := getContainerPath(opts.Container)
	tokenType := currentContainer.GetHeader().TokenType

	// Generate the token output up-front, into memory, before the container is
	// written. Any failure in token generation (integrity artifacts, Shamir split,
	// encryption) then aborts the whole reseal without having touched the existing
	// container or token files.
	var tokenBuf bytes.Buffer
	if tokenType != token.TypeNone {
		if err = generateResealTokens(opts, currentContainer, masterKey, originalRawTokens, &tokenBuf); err != nil {
			return err
		}
	}

	// Write the new container to a temporary file and atomically replace the
	// target. The original container is only ever destroyed once a complete new
	// one is in place, so a mid-write failure can never leave the vault without a
	// valid container.
	if err = writeContainerAtomic(currentContainer, artifact.ZipPath, targetContainerPath); err != nil {
		return err
	}

	if tokenType == token.TypeNone {
		return nil
	}

	// Only after the container is safely in place, write the tokens atomically.
	return writeTokensAtomic(opts.TokenWriter, tokenBuf.Bytes())
}

// generateResealTokens - produces the token output for reseal into w, without
// touching any files. Tokens are only re-issued (fresh Shamir split + fresh
// AES-CTR IV) when a new integrity-provider passphrase is set; otherwise the
// original token strings are written back verbatim so they remain unchanged.
func generateResealTokens(
	opts Options,
	cont container.Container,
	masterKey []byte,
	originalRawTokens []string,
	w io.Writer,
) error {
	if !isIntegrityProviderPassphraseChanged(opts.IntegrityProvider) {
		return writeRawTokens(
			cont.GetHeader().TokenType,
			originalRawTokens,
			*opts.TokenWriter.Format,
			w,
		)
	}

	salt := cont.GetHeader().Salt
	integrityProvider, additionalPassword, err := newIntegrityArtifacts(
		&lib.IntegrityProvider{
			Type:          lib.StringPtr(integrity.ConvertIDToName(cont.GetHeader().IntegrityProviderType)),
			NewPassphrase: getIntegrityProviderPassphrasePtr(opts.IntegrityProvider),
		},
		salt[:],
	)
	if err != nil {
		return err
	}

	switch cont.GetHeader().TokenType {
	case token.TypeShare:
		var (
			numShares = int(cont.GetHeader().Shares)
			threshold = int(cont.GetHeader().Threshold)
		)
		return seal.SaveShareTokens(
			&lib.Shamir{
				Shares:    &numShares,
				Threshold: &threshold,
			},
			additionalPassword,
			masterKey,
			integrityProvider,
			*opts.TokenWriter.Format,
			w,
		)
	case token.TypeMaster:
		return seal.SaveMasterToken(
			additionalPassword,
			masterKey,
			*opts.TokenWriter.Format,
			w,
		)
	}

	return nil
}

// writeContainerAtomic - encrypts the container into a temporary file in the
// target directory and atomically renames it over targetPath. This guarantees
// the previous container is never truncated in place: it is replaced only once a
// complete, valid new container exists on disk.
func writeContainerAtomic(cont container.Container, zipPath, targetPath string) error {
	tmp, err := os.CreateTemp(filepath.Dir(targetPath), ".tvault-container-*.tmp")
	if err != nil {
		return lib.IOErr(lib.CategoryReseal, lib.ErrCodeResealWriteContainerError, lib.ErrMessageResealWriteContainerError, "", err)
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()

	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	// zipPath is not user input: it is always the name of a temp file created by
	// compressFolderForReseal via os.CreateTemp, so there is no traversal risk.
	zf, err := os.Open(zipPath) // #nosec G304
	if err != nil {
		return lib.IOErr(lib.CategoryReseal, lib.ErrCodeResealEncryptContainerError, lib.ErrMessageResealEncryptContainerError, "", err)
	}
	defer func() { _ = zf.Close() }()

	// WriteEncrypted fsyncs the temp file's contents before returning, so the
	// data is durable before the rename below.
	cont.SetPath(tmpPath)
	if err = cont.WriteEncrypted(zf, nil); err != nil {
		return lib.InternalErr(lib.CategoryReseal, lib.ErrCodeResealEncryptContainerError, lib.ErrMessageResealEncryptContainerError, "", err)
	}

	if err = os.Rename(tmpPath, targetPath); err != nil {
		return lib.IOErr(lib.CategoryReseal, lib.ErrCodeResealWriteContainerError, lib.ErrMessageResealWriteContainerError, "", err)
	}
	committed = true

	// fsync the directory so the rename itself survives a power failure;
	// otherwise the target could still point at the old (now removed) inode.
	if err = fsyncDir(filepath.Dir(targetPath)); err != nil {
		return err
	}

	cont.SetPath(targetPath)

	return nil
}

// writeTokensAtomic - writes the pre-generated token bytes to their destination.
// For file output the bytes go to a temporary file that is atomically renamed
// over the target, so an existing token file is never truncated before the new
// tokens are fully written.
func writeTokensAtomic(writerOpts *lib.Writer, data []byte) error {
	switch *writerOpts.Type {
	case lib.WriterTypeFile:
		tmp, err := os.CreateTemp(filepath.Dir(*writerOpts.Path), ".tvault-tokens-*.tmp")
		if err != nil {
			return lib.IOErr(lib.CategoryReseal, lib.ErrCodeResealWriteTokensError, lib.ErrMessageResealWriteTokensError, "", err)
		}
		tmpPath := tmp.Name()

		committed := false
		defer func() {
			if !committed {
				_ = os.Remove(tmpPath)
			}
		}()

		if _, err = tmp.Write(data); err != nil {
			_ = tmp.Close()
			return lib.IOErr(lib.CategoryReseal, lib.ErrCodeResealWriteTokensError, lib.ErrMessageResealWriteTokensError, "", err)
		}
		// Flush the token bytes to stable storage before the rename.
		if err = tmp.Sync(); err != nil {
			_ = tmp.Close()
			return lib.IOErr(lib.CategoryReseal, lib.ErrCodeResealWriteTokensError, lib.ErrMessageResealWriteTokensError, "", err)
		}
		if err = tmp.Close(); err != nil {
			return lib.IOErr(lib.CategoryReseal, lib.ErrCodeResealWriteTokensError, lib.ErrMessageResealWriteTokensError, "", err)
		}

		if err = os.Rename(tmpPath, *writerOpts.Path); err != nil {
			return lib.IOErr(lib.CategoryReseal, lib.ErrCodeResealWriteTokensError, lib.ErrMessageResealWriteTokensError, "", err)
		}
		committed = true

		// fsync the directory so the rename is durable across a power failure.
		if err = fsyncDir(filepath.Dir(*writerOpts.Path)); err != nil {
			return err
		}

		return nil
	case lib.WriterTypeStdout:
		if _, err := fmt.Fprintln(os.Stdout, string(data)); err != nil {
			return lib.IOErr(lib.CategoryReseal, lib.ErrCodeResealWriteTokensError, lib.ErrMessageResealWriteTokensError, "", err)
		}

		return nil
	default:
		return lib.ErrUnknownWriterType
	}
}

func compressFolderForReseal(compressionType, folderPath string) (*compressedArtifact, error) {
	switch compressionType {
	case compression.TypeNameZip:
		comp := zip.New()

		tmp, err := os.CreateTemp("", "tvault-zip-*.zip")
		if err != nil {
			return nil, lib.IOErr(lib.CategorySeal, lib.ErrCodeSealCompressionPackError, lib.ErrMessageSealCompressionPackError, "", err)
		}
		tmpPath := tmp.Name()

		if err := comp.PackTo(folderPath, tmp); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
			return nil, lib.IOErr(lib.CategorySeal, lib.ErrCodeSealCompressionPackError, lib.ErrMessageSealCompressionPackError, "", err)
		}
		if err := tmp.Close(); err != nil {
			_ = os.Remove(tmpPath)
			return nil, lib.IOErr(lib.CategorySeal, lib.ErrCodeSealCompressionPackError, lib.ErrMessageSealCompressionPackError, "", err)
		}

		st, err := os.Stat(tmpPath)
		if err != nil {
			_ = os.Remove(tmpPath)
			return nil, lib.IOErr(lib.CategorySeal, lib.ErrCodeSealCompressionPackError, lib.ErrMessageSealCompressionPackError, "", err)
		}

		return &compressedArtifact{Comp: comp, ZipPath: tmpPath, ZipSize: st.Size()}, nil
	default:
		return nil, lib.ErrUnknownCompressionType
	}
}

func getContainerPath(containerOpts *lib.Container) string {
	var targetContainerPath = *containerOpts.CurrentPath
	if *containerOpts.NewPath != "" && *containerOpts.NewPath != targetContainerPath {
		targetContainerPath = *containerOpts.NewPath
	}

	return targetContainerPath
}

func getIntegrityProviderPassphrasePtr(
	integrityProviderOpts *lib.IntegrityProvider,
) *string {
	var passphrase = *integrityProviderOpts.CurrentPassphrase
	if *integrityProviderOpts.NewPassphrase != "" && *integrityProviderOpts.NewPassphrase != passphrase {
		passphrase = *integrityProviderOpts.NewPassphrase
	}

	return &passphrase
}

func newIntegrityArtifacts(
	integrityProviderOpts *lib.IntegrityProvider,
	salt []byte,
) (integrity.Provider, []byte, error) {
	ip, err := seal.CreateIntegrityProviderWithNewPassphrase(integrityProviderOpts)
	if err != nil {
		return nil, nil, lib.InternalErr(
			lib.CategoryReseal,
			lib.ErrCodeResealCreateIntegrityProviderError,
			lib.ErrMessageResealCreateIntegrityProviderError,
			"",
			err,
		)
	}

	derivedPassphrase, err := seal.DeriveIntegrityProviderNewPassphrase(integrityProviderOpts, salt)
	if err != nil {
		return nil, nil, lib.InternalErr(
			lib.CategoryReseal,
			lib.ErrCodeResealDeriveAdditionalPasswordError,
			lib.ErrMessageResealDeriveAdditionalPasswordError,
			"",
			err,
		)
	}

	return ip, derivedPassphrase, nil
}

// isIntegrityProviderPassphraseChanged - reports whether reseal was asked to
// rotate the integrity-provider passphrase. Tokens are only re-issued in that
// case; otherwise the original tokens are preserved unchanged.
func isIntegrityProviderPassphraseChanged(integrityProviderOpts *lib.IntegrityProvider) bool {
	return *integrityProviderOpts.NewPassphrase != "" &&
		*integrityProviderOpts.NewPassphrase != *integrityProviderOpts.CurrentPassphrase
}

// extractRawTokens - splits the raw token string read from the token reader into
// the individual (still-encrypted) token strings, without decrypting them, so
// they can be written back verbatim when tokens are not being re-issued.
func extractRawTokens(tokenString, readerFormat string) ([]string, error) {
	switch readerFormat {
	case lib.ReaderFormatPlaintext:
		return strings.Split(tokenString, "|"), nil
	case lib.ReaderFormatJSON:
		var list token.List
		if err := json.Unmarshal([]byte(tokenString), &list); err != nil {
			return nil, err
		}

		return list.TokenList, nil
	default:
		return nil, lib.ErrUnknownReaderType
	}
}

// writeRawTokens - writes the original token strings back to the token writer
// unchanged, matching the layout produced by seal.SaveShareTokens /
// seal.SaveMasterToken so the output stays consistent across seal and reseal.
func writeRawTokens(
	tokenType byte,
	rawTokens []string,
	writerFormat string,
	writer io.Writer,
) error {
	switch writerFormat {
	case lib.WriterFormatPlaintext:
		var b strings.Builder
		switch tokenType {
		case token.TypeShare:
			b.WriteString("tokens:\n")
			for _, raw := range rawTokens {
				b.WriteString(raw)
				b.WriteString("\n---\n")
			}
		case token.TypeMaster:
			b.WriteString("token:\n")
			for _, raw := range rawTokens {
				b.WriteString(raw)
				b.WriteString("\n")
			}
		default:
			return lib.ErrUnknownWriterType
		}

		if _, err := lib.WriteFormatted(writer, writerFormat, b.String()); err != nil {
			return lib.IOErr(
				lib.CategoryReseal,
				lib.ErrCodeResealWriteTokensError,
				lib.ErrMessageResealWriteTokensError,
				"",
				err,
			)
		}
	case lib.WriterFormatJSON:
		if _, err := lib.WriteFormatted(writer, writerFormat, token.List{TokenList: rawTokens}); err != nil {
			return lib.IOErr(
				lib.CategoryReseal,
				lib.ErrCodeResealWriteTokensError,
				lib.ErrMessageResealWriteTokensError,
				"",
				err,
			)
		}
	default:
		return lib.ErrUnknownWriterType
	}

	return nil
}
