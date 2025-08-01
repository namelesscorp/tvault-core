package reseal

import (
	"fmt"
	"io"

	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/integrity"
	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/seal"
	"github.com/namelesscorp/tvault-core/unseal"
)

func Reseal(opts Options) error {
	container, err := unseal.OpenContainer(*opts.Container.CurrentPath)
	if err != nil {
		return lib.InternalErr(0x011, fmt.Errorf("open container error; %w", err))
	}

	derivedPassphrase := unseal.DeriveIntegrityProviderPassphrase(
		*opts.IntegrityProvider.CurrentPassphrase,
		container.GetHeader().Salt,
	)

	tokenString, err := unseal.GetTokenString(opts.TokenReader)
	if err != nil {
		return lib.InternalErr(0x012, fmt.Errorf("get token string error; %w", err))
	}

	masterKey, shares, err := unseal.ParseTokens(tokenString, *opts.TokenReader.Format, derivedPassphrase)
	if err != nil {
		return lib.InternalErr(0x013, fmt.Errorf("parse tokens error; %w", err))
	}
	if len(masterKey) == 0 {
		masterKey, err = unseal.RestoreMasterKey(shares, derivedPassphrase)
		if err != nil {
			return lib.InternalErr(0x014, fmt.Errorf("restore master key error; %w", err))
		}
	}

	data, _, err := seal.CompressFolder(
		compression.ConvertIDToName(container.GetHeader().CompressionType),
		*opts.Container.FolderPath,
	)
	if err != nil {
		return lib.InternalErr(0x111, fmt.Errorf("compress folder error; %w", err))
	}

	container.SetMasterKey(masterKey)
	if err = container.Encrypt(data, nil); err != nil {
		return lib.InternalErr(0x112, fmt.Errorf("encrypt container error; %w", err))
	}

	targetContainerPath := *opts.Container.CurrentPath
	if *opts.Container.NewPath != "" && *opts.Container.NewPath != targetContainerPath {
		targetContainerPath = *opts.Container.NewPath
	}
	container.SetPath(targetContainerPath)

	if err = container.Write(); err != nil {
		return lib.InternalErr(0x113, fmt.Errorf("write container error; %w", err))
	}

	providerName := integrity.ConvertIDToName(shares[0].ProviderID)
	salt := container.GetHeader().Salt

	passphrase := *opts.IntegrityProvider.CurrentPassphrase
	if *opts.IntegrityProvider.NewPassphrase != "" && *opts.IntegrityProvider.NewPassphrase != passphrase {
		passphrase = *opts.IntegrityProvider.NewPassphrase
	}

	integrityProvider, additionalPassword, err := newIntegrityArtifacts(
		&lib.IntegrityProvider{
			Type:          &providerName,
			NewPassphrase: &passphrase,
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
			numShares = int(container.GetHeader().Shares)
			threshold = int(container.GetHeader().Threshold)
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

func newIntegrityArtifacts(integrityProviderOpts *lib.IntegrityProvider, salt []byte) (integrity.Provider, []byte, error) {
	ip, err := seal.CreateIntegrityProviderWithNewPassphrase(integrityProviderOpts)
	if err != nil {
		return nil, nil, lib.InternalErr(0x113, fmt.Errorf("create integrity provider error; %w", err))
	}

	derivedPassphrase, err := seal.DeriveIntegrityProviderNewPassphrase(integrityProviderOpts, salt)
	if err != nil {
		return nil, nil, lib.InternalErr(0x114, fmt.Errorf("derive additional password error; %w", err))
	}

	return ip, derivedPassphrase, nil
}
