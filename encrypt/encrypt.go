package encrypt

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

func Encrypt(options Options) error {
	// compressing folder and getting data, compression
	data, compID, err := compressFolder(options)
	if err != nil {
		return lib.InternalErr(0x111, fmt.Errorf("compress folder error; %w", err))
	}

	// create container and get master key and container salt
	masterKey, containerSalt, err := createContainer(
		data,
		[]byte(*options.Passphrase),
		compID,
		*options.ContainerPath,
	)
	if err != nil {
		return lib.InternalErr(0x112, fmt.Errorf("create container error; %w", err))
	}

	integrityProvider, err := createIntegrityProvider(*options.IntegrityProvider, *options.AdditionalPassword)
	if err != nil {
		return lib.InternalErr(0x113, fmt.Errorf("create integrity provider error; %w", err))
	}

	additionalPassword, err := deriveAdditionalPassword(
		*options.AdditionalPassword,
		*options.IntegrityProvider,
		containerSalt,
	)
	if err != nil {
		return lib.InternalErr(0x114, fmt.Errorf("derive additional password error; %w", err))
	}

	if err = generateAndSaveTokens(options, additionalPassword, masterKey, integrityProvider); err != nil {
		return lib.InternalErr(0x115, fmt.Errorf("generate and save tokens error; %w", err))
	}

	return nil
}

func compressFolder(options Options) ([]byte, byte, error) {
	switch *options.CompressionType {
	case compression.TypeNameZip:
		var comp = zip.New()
		data, err := comp.Pack(*options.FolderPath)
		if err != nil {
			return nil, 0, fmt.Errorf("compression pack error; %w", err)
		}

		return data, comp.ID(), nil
	case compression.TypeNameNone:
		return nil, 0, lib.ErrNoneCompressionUnimplemented
	default:
		return nil, 0, lib.ErrUnknownCompressionType
	}
}

func createContainer(data, passphrase []byte, compressionID byte, containerPath string) ([]byte, []byte, error) {
	cont := container.NewContainer(containerPath, container.Metadata{
		CreatedAt: time.Now(),
		Comment:   "created by tvault-core",
	})

	masterKey, err := cont.Create(data, passphrase, compressionID)
	if err != nil {
		return nil, nil, fmt.Errorf("create container error; %w", err)
	}

	var containerHeaderSalt = cont.GetHeader().Salt

	return masterKey, containerHeaderSalt[:], nil
}

func createIntegrityProvider(integrityProviderName, additionalPassword string) (integrity.Provider, error) {
	switch integrityProviderName {
	case integrity.TypeNameNone:
		return integrity.NewNoneProvider(), nil
	case integrity.TypeNameHMAC:
		return hmac.New([]byte(additionalPassword)), nil
	case integrity.TypeNameEd25519:
		return nil, lib.ErrEd25519Unimplemented
	default:
		return nil, lib.ErrUnknownIntegrityProvider
	}
}

func deriveAdditionalPassword(additionalPassword, integrityProviderName string, salt []byte) ([]byte, error) {
	if additionalPassword != "" && integrityProviderName == integrity.TypeNameHMAC {
		return lib.PBKDF2Key(
			[]byte(additionalPassword),
			salt,
			lib.Iterations,
			lib.KeyLen,
		), nil
	}

	return nil, nil
}

func generateAndSaveTokens(
	options Options,
	additionalPassword []byte,
	masterKey []byte,
	integrityProvider integrity.Provider,
) error {
	tokenWriter, closer, err := lib.NewWriter(
		*options.TokenWriterType,
		*options.TokenWriterFormat,
		*options.TokenWriterPath,
	)
	if err != nil {
		return err
	}
	if closer != nil {
		defer func(closer io.Closer) {
			_ = closer.Close()
		}(closer)
	}

	if *options.IsShamirEnabled {
		return saveShareTokens(
			*options.Shares,
			*options.Threshold,
			additionalPassword,
			masterKey,
			integrityProvider,
			*options.TokenWriterFormat,
			tokenWriter,
		)
	}
	return saveMasterToken(additionalPassword, masterKey, *options.TokenWriterFormat, tokenWriter)
}

func saveShareTokens(
	numShares, threshold int,
	additionalPassword []byte,
	masterKey []byte,
	integrityProvider integrity.Provider,
	tokenWriterFormat string,
	writer io.Writer,
) error {
	shares, err := shamir.Split(
		masterKey,
		numShares,
		threshold,
		integrityProvider,
	)
	if err != nil {
		return fmt.Errorf("shamir split error; %w", err)
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
			return fmt.Errorf("failed to write tokens (share); %w", err)
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
			return fmt.Errorf("failed to write tokens (share); %w", err)
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
		return nil, fmt.Errorf("build token (share) error; %w", err)
	}

	return shareToken, nil
}

func saveMasterToken(
	additionalPassword, masterKey []byte,
	format string,
	w io.Writer,
) error {
	encodedToken, err := buildMasterToken(additionalPassword, masterKey)
	if err != nil {
		return err
	}

	var msg any
	switch format {
	case lib.WriterFormatPlaintext:
		msg = fmt.Sprintf("token:\n%s\n", encodedToken)
	case lib.WriterFormatJSON:
		msg = token.List{TokenList: []string{encodedToken}}
	default:
		return lib.ErrUnknownWriterFormat
	}

	if _, err = lib.WriteFormatted(w, format, msg); err != nil {
		return fmt.Errorf("failed to write token (master); %w", err)
	}

	return nil
}

func buildMasterToken(pwd, masterKey []byte) (string, error) {
	raw, err := token.Build(
		token.Token{
			Version:    token.Version,
			Type:       int(token.TypeMaster),
			Value:      hex.EncodeToString(masterKey),
			ProviderID: int(integrity.TypeNone),
		},
		pwd,
	)
	if err != nil {
		return "", fmt.Errorf("build token (master) error; %w", err)
	}

	return base64.StdEncoding.EncodeToString(raw), nil
}
