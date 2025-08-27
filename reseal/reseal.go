package reseal

import (
	"io"
	"strings"
	"time"

	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/container"
	"github.com/namelesscorp/tvault-core/integrity"
	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/seal"
	"github.com/namelesscorp/tvault-core/shamir"
	"github.com/namelesscorp/tvault-core/token"
	"github.com/namelesscorp/tvault-core/unseal"
)

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

	currentContainer.SetMetadata(container.Metadata{
		Name:      containerName,
		CreatedAt: currentContainer.GetMetadata().CreatedAt,
		UpdatedAt: time.Now(),
		Comment:   comment,
		Tags:      tags,
	})

	var masterKey []byte
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
			int(currentContainer.GetHeader().Iterations),
			lib.KeyLen,
		)
	}

	data, _, err := seal.CompressFolder(
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

	currentContainer.SetMasterKey(masterKey)
	if err = currentContainer.Encrypt(data, nil); err != nil {
		return lib.InternalErr(
			lib.CategoryReseal,
			lib.ErrCodeResealEncryptContainerError,
			lib.ErrMessageResealEncryptContainerError,
			"",
			err,
		)
	}

	currentContainer.SetPath(getContainerPath(opts.Container))
	if err = currentContainer.Write(); err != nil {
		return lib.InternalErr(
			lib.CategoryReseal,
			lib.ErrCodeResealWriteContainerError,
			lib.ErrMessageResealWriteContainerError,
			"",
			err,
		)
	}

	if currentContainer.GetHeader().TokenType == token.TypeNone {
		return nil
	}

	salt := currentContainer.GetHeader().Salt
	integrityProvider, additionalPassword, err := newIntegrityArtifacts(
		&lib.IntegrityProvider{
			Type:          lib.StringPtr(integrity.ConvertIDToName(currentContainer.GetHeader().IntegrityProviderType)),
			NewPassphrase: getIntegrityProviderPassphrasePtr(opts.IntegrityProvider),
		},
		salt[:],
	)
	if err != nil {
		return err
	}

	tokenWriter, closer, err := lib.NewWriter(opts.TokenWriter)
	if err != nil {
		return err
	}
	if closer != nil {
		defer func(closer io.Closer) {
			_ = closer.Close()
		}(closer)
	}

	switch currentContainer.GetHeader().TokenType {
	case token.TypeShare:
		var (
			numShares = int(currentContainer.GetHeader().Shares)
			threshold = int(currentContainer.GetHeader().Threshold)
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
			tokenWriter,
		)
	case token.TypeMaster:
		return seal.SaveMasterToken(
			additionalPassword,
			masterKey,
			*opts.TokenWriter.Format,
			tokenWriter,
		)
	}

	return nil
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
