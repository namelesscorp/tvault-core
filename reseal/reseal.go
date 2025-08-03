package reseal

import (
	"io"
	"time"

	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/container"
	"github.com/namelesscorp/tvault-core/integrity"
	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/seal"
	"github.com/namelesscorp/tvault-core/shamir"
	"github.com/namelesscorp/tvault-core/unseal"
)

// Reseal - processes a sealed container by decrypting, modifying, and re-encrypting it with updated metadata and tokens.
func Reseal(opts Options) error {
	currentContainer, err := unseal.OpenContainer(*opts.Container.CurrentPath)
	if err != nil {
		return lib.InternalErr(
			lib.CategoryReseal,
			lib.ErrCodeResealOpenContainerError,
			lib.ErrMessageResealOpenContainerError,
			"",
			err,
		)
	}

	currentContainer.SetMetadata(container.Metadata{
		CreatedAt: currentContainer.GetMetadata().CreatedAt,
		UpdatedAt: time.Now(),
		Comment:   currentContainer.GetMetadata().Comment,
	})

	derivedPassphrase := unseal.DeriveIntegrityProviderPassphrase(
		*opts.IntegrityProvider.CurrentPassphrase,
		currentContainer.GetHeader().Salt,
	)

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

	masterKey, shares, err := unseal.ParseTokens(tokenString, *opts.TokenReader.Format, derivedPassphrase)
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

	salt := currentContainer.GetHeader().Salt
	integrityProvider, additionalPassword, err := newIntegrityArtifacts(
		&lib.IntegrityProvider{
			Type:          getProviderNamePtr(shares),
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

	switch {
	case len(shares) > 1:
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
	case len(shares) == 1:
		return seal.SaveMasterToken(
			additionalPassword,
			masterKey,
			*opts.TokenWriter.Format,
			integrityProvider.ID(),
			tokenWriter,
		)
	}

	return nil
}

func getProviderNamePtr(shares []shamir.Share) *string {
	if len(shares) == 0 {
		return nil
	}

	return lib.StringPtr(integrity.ConvertIDToName(shares[0].ProviderID))
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
