package seal

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/compression/zip"
	"github.com/namelesscorp/tvault-core/container"
	"github.com/namelesscorp/tvault-core/integrity"
	"github.com/namelesscorp/tvault-core/integrity/hmac"
	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/security"
	"github.com/namelesscorp/tvault-core/shamir"
	"github.com/namelesscorp/tvault-core/token"
)

// Seal - seal container by options
// - select compressor
// - create container
// - select token type
// create master token or share tokens
// - select and create integrity provider
// - derive passphrase
func Seal(options Options) error {
	comp, err := newCompressor(*options.Compression.Type)
	if err != nil {
		return lib.InternalErr(
			lib.CategorySeal,
			lib.ErrCodeSealCompressFolderError,
			lib.ErrMessageSealCompressFolderError,
			"",
			err,
		)
	}

	masterKey, containerSalt, err := CreateContainer(
		comp,
		integrity.ConvertNameToID(*options.IntegrityProvider.Type),
		token.ConvertNameToID(*options.Token.Type),
		options.Container,
		options.Shamir,
		*options.IntegrityProvider.NewPassphrase,
		*options.Container.FolderPath,
	)
	if err != nil {
		return lib.InternalErr(
			lib.CategorySeal,
			lib.ErrCodeSealCreateContainerError,
			lib.ErrMessageSealCreateContainerError,
			"",
			err,
		)
	}

	if *options.Token.Type == token.TypeNameNone {
		return nil
	}

	integrityProvider, err := CreateIntegrityProviderWithNewPassphrase(options.IntegrityProvider)
	if err != nil {
		return lib.InternalErr(
			lib.CategorySeal,
			lib.ErrCodeSealCreateIntegrityProviderError,
			lib.ErrMessageSealCreateIntegrityProviderError,
			"",
			err,
		)
	}

	integrityProviderPassphrase, err := DeriveIntegrityProviderNewPassphrase(options.IntegrityProvider, containerSalt)
	if err != nil {
		return lib.InternalErr(
			lib.CategorySeal,
			lib.ErrCodeSealDeriveIntegrityProviderPassphraseError,
			lib.ErrMessageSealDeriveIntegrityProviderPassphraseError,
			"",
			err,
		)
	}

	if err = GenerateAndSaveTokens(options, integrityProviderPassphrase, masterKey, integrityProvider); err != nil {
		return lib.InternalErr(
			lib.CategorySeal,
			lib.ErrCodeSealGenerateAndSaveTokensError,
			lib.ErrMessageSealGenerateAndSaveTokensError,
			"",
			err,
		)
	}

	return nil
}

// entriesPacker is implemented by compressors that can pack a pre-walked entry
// list, letting the caller reuse a single filesystem walk for both stats and
// packing instead of walking twice.
type entriesPacker interface {
	PackEntriesTo(entries []zip.Entry, w io.Writer) error
}

// newCompressor - select compressor instance by type
func newCompressor(compressionType string) (compression.Compression, error) {
	switch compressionType {
	case compression.TypeNameZip:
		return zip.New(), nil
	case compression.TypeNameNone:
		// "none" still produces a zip archive (so unseal reads it unchanged) but
		// stores entries without deflate — faster for large/incompressible data.
		return zip.NewStore(), nil
	default:
		return nil, lib.ErrUnknownCompressionType
	}
}

// CreateContainer - create container file and return master key
// - init container header
// - select container name
// - get encrypted folder stats
// - create security score instance
// - calculate security score
// - create container instance with metadata
// - pack files to container
func CreateContainer(
	comp compression.Compression,
	integrityProviderID, tokenID byte,
	containerOpts *lib.Container,
	shamir *lib.Shamir,
	integrityProviderPassphrase string,
	folderPath string,
) ([]byte, []byte, error) {
	header, err := container.NewHeader(
		comp.ID(),
		integrityProviderID,
		tokenID,
		uint8(*shamir.Shares),    // #nosec G115
		uint8(*shamir.Threshold), // #nosec G115
	)
	if err != nil {
		return nil, nil, lib.CryptoErr(
			lib.CategorySeal,
			lib.ErrCodeSealCreateContainerHeaderError,
			lib.ErrMessageSealCreateContainerHeaderError,
			"",
			err,
		)
	}

	var containerName = *containerOpts.Name
	if containerName == "" {
		containerName = path.Base(*containerOpts.NewPath)

		var pathList = strings.Split(containerName, ".")
		if len(pathList) == 2 {
			containerName = pathList[0]
		}
	}

	// Walk the folder once: the returned stats populate the metadata/security
	// score (written before the payload), and the returned entries are handed to
	// the packer below so the tree is not walked a second time to compress it.
	entries, uncompressedSize, fileCount, fileNameList, err := zip.WalkFolder(folderPath)
	if err != nil {
		return nil, nil, lib.IOErr(
			lib.CategorySeal,
			lib.ErrCodeSealCompressionPackError,
			lib.ErrMessageSealCompressionPackError,
			"",
			err,
		)
	}

	// Report "PROGRESS <pct>" off the uncompressed input: WalkFolder already
	// gave the total, and the packer reports each source byte as it is read
	// (via SetProgress), so progress advances while the archive streams through
	// the pipe into WriteEncrypted below. Finish is emitted on success only.
	progress := lib.NewProgressReporter()
	packPhase := progress.Phase(0, 100, uncompressedSize)
	if p, ok := comp.(interface{ SetProgress(func(int64)) }); ok {
		p.SetProgress(packPhase.Add)
	}

	secScore := security.New(security.Params{
		TokenType:                   token.ConvertIDToName(tokenID),
		IntegrityProviderType:       integrity.ConvertIDToName(integrityProviderID),
		CompressionType:             compression.ConvertIDToName(comp.ID()),
		NumberOfShares:              *shamir.Shares,
		NumberOfThreshold:           *shamir.Threshold,
		ContainerPassphrase:         *containerOpts.Passphrase,
		IntegrityProviderPassphrase: integrityProviderPassphrase,
		FileNameList:                fileNameList,
	})

	cont := container.NewContainer(
		*containerOpts.NewPath,
		nil,
		container.Metadata{
			Name:      containerName,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Comment:   *containerOpts.Comment,
			Tags:      lib.ParseTags(*containerOpts.Tags),
			// CompressedSize is filled in by WriteEncrypted once the payload is
			// streamed (it equals the number of compressed bytes consumed).
			UncompressedSize: uncompressedSize,
			FileCount:        fileCount,
			SecurityScore:    secScore.Calculate(),
		},
		header,
	)

	pr, pw := io.Pipe()
	packErrCh := make(chan error, 1)

	go func() {
		defer func() { _ = pw.Close() }()

		// Reuse the entries already collected by WalkFolder above; fall back to a
		// fresh walk only if the compressor cannot pack pre-walked entries.
		var packErr error
		if packer, ok := comp.(entriesPacker); ok {
			packErr = packer.PackEntriesTo(entries, pw)
		} else {
			packErr = comp.PackTo(folderPath, pw)
		}

		if packErr != nil {
			_ = pw.CloseWithError(packErr)
			packErrCh <- packErr

			return
		}

		packErrCh <- nil
	}()

	if err = cont.WriteEncrypted(pr, []byte(*containerOpts.Passphrase)); err != nil {
		_ = pr.Close()
		<-packErrCh

		return nil, nil, lib.CryptoErr(
			lib.CategorySeal,
			lib.ErrCodeSealEncryptContainerError,
			lib.ErrMessageSealEncryptContainerError,
			"",
			err,
		)
	}

	if packErr := <-packErrCh; packErr != nil {
		return nil, nil, lib.IOErr(
			lib.CategorySeal,
			lib.ErrCodeSealCompressionPackError,
			lib.ErrMessageSealCompressionPackError,
			"",
			packErr,
		)
	}

	progress.Finish()

	var containerHeaderSalt = cont.GetHeader().Salt
	return cont.GetMasterKey(), containerHeaderSalt[:], nil
}

// CreateIntegrityProviderWithNewPassphrase - creates a new integrity provider based on the specified type and new passphrase.
func CreateIntegrityProviderWithNewPassphrase(integrityProvider *lib.IntegrityProvider) (integrity.Provider, error) {
	switch *integrityProvider.Type {
	case integrity.TypeNameNone:
		return integrity.NewNoneProvider(), nil
	case integrity.TypeNameHMAC:
		return hmac.New([]byte(*integrityProvider.NewPassphrase)), nil
	case integrity.TypeNameEd25519:
		return nil, lib.ErrEd25519Unimplemented
	default:
		return nil, lib.ErrUnknownIntegrityProvider
	}
}

// DeriveIntegrityProviderNewPassphrase - derives a new passphrase for the integrity provider using PBKDF2-HMAC-SHA256.
// It takes an IntegrityProvider object and a salt as input and returns the derived key or an error.
// If the IntegrityProvider's new passphrase is set and the type is HMAC, a PBKDF2-based key is generated.
// Returns nil if the conditions for key derivation are not met.
func DeriveIntegrityProviderNewPassphrase(integrityProvider *lib.IntegrityProvider, salt []byte) ([]byte, error) {
	if *integrityProvider.NewPassphrase != "" && *integrityProvider.Type == integrity.TypeNameHMAC {
		return lib.PBKDF2Key(
			[]byte(*integrityProvider.NewPassphrase),
			salt,
			lib.Iterations,
			lib.KeyLen,
		), nil
	}

	return nil, nil
}

func GenerateAndSaveTokens(
	options Options,
	integrityProviderPassphrase []byte,
	masterKey []byte,
	integrityProvider integrity.Provider,
) error {
	tokenWriter, closer, err := lib.NewWriter(options.TokenWriter)
	if err != nil {
		return err
	}
	if closer != nil {
		defer func(closer io.Closer) {
			_ = closer.Close()
		}(closer)
	}

	if *options.Shamir.IsEnabled {
		return SaveShareTokens(
			options.Shamir,
			integrityProviderPassphrase,
			masterKey,
			integrityProvider,
			*options.TokenWriter.Format,
			tokenWriter,
		)
	}

	return SaveMasterToken(
		integrityProviderPassphrase,
		masterKey,
		*options.TokenWriter.Format,
		tokenWriter,
	)
}

func SaveShareTokens(
	shamirOpts *lib.Shamir,
	additionalPassword []byte,
	masterKey []byte,
	integrityProvider integrity.Provider,
	tokenWriterFormat string,
	writer io.Writer,
) error {
	shares, err := shamir.Split(
		masterKey,
		*shamirOpts.Shares,
		*shamirOpts.Threshold,
		integrityProvider,
	)
	if err != nil {
		return lib.CryptoErr(
			lib.CategorySeal,
			lib.ErrCodeSealShamirSplitError,
			lib.ErrMessageSealShamirSplitError,
			"",
			err,
		)
	}

	switch tokenWriterFormat {
	case lib.WriterFormatPlaintext:
		var b strings.Builder
		b.WriteString("tokens:\n")

		for _, share := range shares {
			var shareToken []byte
			if shareToken, err = buildShareToken(&share, additionalPassword); err != nil {
				return err
			}

			b.WriteString(base64.StdEncoding.EncodeToString(shareToken))
			b.WriteString("\n---\n")
		}

		if _, err = lib.WriteFormatted(writer, tokenWriterFormat, b.String()); err != nil {
			return lib.IOErr(
				lib.CategorySeal,
				lib.ErrCodeSealWriteTokensShareError,
				lib.ErrMessageSealWriteTokensShareError,
				"",
				err,
			)
		}
	case lib.WriterFormatJSON:
		list := token.List{TokenList: make([]string, 0, len(shares))}
		for _, share := range shares {
			var shareToken []byte
			if shareToken, err = buildShareToken(&share, additionalPassword); err != nil {
				return err
			}

			list.TokenList = append(list.TokenList, base64.StdEncoding.EncodeToString(shareToken))
		}

		if _, err = lib.WriteFormatted(writer, tokenWriterFormat, list); err != nil {
			return lib.IOErr(
				lib.CategorySeal,
				lib.ErrCodeSealWriteTokensShareError,
				lib.ErrMessageSealWriteTokensShareError,
				"",
				err,
			)
		}
	default:
		return lib.ErrUnknownWriterType
	}

	return nil
}

func buildShareToken(share *shamir.Share, additionalPassword []byte) ([]byte, error) {
	shareToken, err := token.Build(
		token.Token{
			Version:   token.Version,
			ID:        int(share.ID),
			Value:     hex.EncodeToString(share.Value),
			Signature: hex.EncodeToString(share.Signature),
		},
		additionalPassword,
	)
	if err != nil {
		return nil, lib.CryptoErr(
			lib.CategorySeal,
			lib.ErrCodeSealBuildShareTokenError,
			lib.ErrMessageSealBuildShareTokenError,
			"",
			err,
		)
	}

	return shareToken, nil
}

func SaveMasterToken(
	additionalPassword, masterKey []byte,
	writerFormat string,
	w io.Writer,
) error {
	encodedToken, err := buildMasterToken(additionalPassword, masterKey)
	if err != nil {
		return err
	}

	var msg any
	switch writerFormat {
	case lib.WriterFormatPlaintext:
		msg = fmt.Sprintf("token:\n%s\n", encodedToken)
	case lib.WriterFormatJSON:
		msg = token.List{TokenList: []string{encodedToken}}
	default:
		return lib.ErrUnknownWriterFormat
	}

	if _, err = lib.WriteFormatted(w, writerFormat, msg); err != nil {
		return lib.IOErr(
			lib.CategorySeal,
			lib.ErrCodeSealWriteTokenMasterError,
			lib.ErrMessageSealWriteTokenMasterError,
			"",
			err,
		)
	}

	return nil
}

func buildMasterToken(pwd, masterKey []byte) (string, error) {
	raw, err := token.Build(
		token.Token{
			Version: token.Version,
			Value:   hex.EncodeToString(masterKey),
		},
		pwd,
	)
	if err != nil {
		return "", lib.CryptoErr(
			lib.CategorySeal,
			lib.ErrCodeSealBuildMasterTokenError,
			lib.ErrMessageSealBuildMasterTokenError,
			"",
			err,
		)
	}

	return base64.StdEncoding.EncodeToString(raw), nil
}
