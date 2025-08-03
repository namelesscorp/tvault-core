package seal

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/compression/zip"
	"github.com/namelesscorp/tvault-core/container"
	"github.com/namelesscorp/tvault-core/integrity"
	"github.com/namelesscorp/tvault-core/integrity/hmac"
	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/shamir"
	"github.com/namelesscorp/tvault-core/token"
)

// Seal - creates a secure container by compressing a folder, encrypting the data, and saving cryptographic tokens.
func Seal(options Options) error {
	// compressing folder and getting data, compression
	data, compID, err := CompressFolder(*options.Compression.Type, *options.Container.FolderPath)
	if err != nil {
		return lib.InternalErr(
			lib.CategorySeal,
			lib.ErrCodeSealCompressFolderError,
			lib.ErrMessageSealCompressFolderError,
			"",
			err,
		)
	}

	// create container and get master key and container salt
	masterKey, containerSalt, err := CreateContainer(
		data,
		[]byte(*options.Container.Passphrase),
		compID,
		*options.Container.NewPath,
		options.Shamir,
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

func CompressFolder(compressionType, folderPath string) ([]byte, byte, error) {
	switch compressionType {
	case compression.TypeNameZip:
		var comp = zip.New()
		data, err := comp.Pack(folderPath)
		if err != nil {
			return nil, 0, lib.IOErr(
				lib.CategorySeal,
				lib.ErrCodeSealCompressionPackError,
				lib.ErrMessageSealCompressionPackError,
				"",
				err,
			)
		}

		return data, comp.ID(), nil
	case compression.TypeNameNone:
		return nil, 0, lib.ErrNoneCompressionUnimplemented
	default:
		return nil, 0, lib.ErrUnknownCompressionType
	}
}

func CreateContainer(
	data, passphrase []byte,
	compressionID byte,
	containerPath string,
	shamir *lib.Shamir,
) ([]byte, []byte, error) {
	header, err := container.NewHeader(compressionID, uint8(*shamir.Shares), uint8(*shamir.Threshold))
	if err != nil {
		return nil, nil, lib.CryptoErr(
			lib.CategorySeal,
			lib.ErrCodeSealCreateContainerHeaderError,
			lib.ErrMessageSealCreateContainerHeaderError,
			"",
			err,
		)
	}

	cont := container.NewContainer(
		containerPath,
		nil,
		container.Metadata{
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Comment:   "created by tvault-core",
		},
		header,
	)

	if err = cont.Encrypt(data, passphrase); err != nil {
		return nil, nil, lib.CryptoErr(
			lib.CategorySeal,
			lib.ErrCodeSealEncryptContainerError,
			lib.ErrMessageSealEncryptContainerError,
			"",
			err,
		)
	}

	if err = cont.Write(); err != nil {
		return nil, nil, lib.IOErr(
			lib.CategorySeal,
			lib.ErrCodeSealWriteContainerError,
			lib.ErrMessageSealWriteContainerError,
			"",
			err,
		)
	}

	var containerHeaderSalt = cont.GetHeader().Salt

	return cont.GetMasterKey(), containerHeaderSalt[:], nil
}

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
		integrityProvider.ID(),
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
			Version:    token.Version,
			ID:         int(share.ID),
			Type:       int(token.TypeShare),
			Value:      hex.EncodeToString(share.Value),
			Signature:  hex.EncodeToString(share.Signature),
			ProviderID: int(share.ProviderID),
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
	integrityProviderID byte,
	w io.Writer,
) error {
	encodedToken, err := buildMasterToken(additionalPassword, masterKey, integrityProviderID)
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

func buildMasterToken(pwd, masterKey []byte, integrityProviderID byte) (string, error) {
	raw, err := token.Build(
		token.Token{
			Version:    token.Version,
			Type:       int(token.TypeMaster),
			Value:      hex.EncodeToString(masterKey),
			ProviderID: int(integrityProviderID),
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
