package decrypt

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/compression/zip"
	"github.com/namelesscorp/tvault-core/container"
	"github.com/namelesscorp/tvault-core/integrity"
	"github.com/namelesscorp/tvault-core/integrity/hmac"
	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/shamir"
	"github.com/namelesscorp/tvault-core/token"
)

type Options struct {
	ContainerPath      *string
	FolderPath         *string
	Token              *string
	AdditionalPassword *string
}

func (o *Options) Validate() error {
	if *o.ContainerPath == "" {
		return &lib.Error{
			Message: lib.ErrContainerPathRequired,
			Code:    0x001,
			Type:    lib.ValidationErrorType,
		}
	}
	if *o.FolderPath == "" {
		return &lib.Error{
			Message: lib.ErrFolderPathRequired,
			Code:    0x002,
			Type:    lib.ValidationErrorType,
		}
	}
	if *o.Token == "" {
		return &lib.Error{
			Message: lib.ErrTokenRequired,
			Code:    0x002,
			Type:    lib.ValidationErrorType,
		}
	}

	return nil
}

func Decrypt(options Options) error {
	cont, err := openContainer(*options.ContainerPath)
	if err != nil {
		return &lib.Error{
			Message: fmt.Errorf("open container error; %w", err),
			Code:    0x011,
			Type:    lib.InternalErrorType,
		}
	}

	additionalPassword := deriveAdditionalPassword(*options.AdditionalPassword, cont.GetHeader().Salt)

	masterKey, shares, err := parseTokens(*options.Token, additionalPassword)
	if err != nil {
		return &lib.Error{
			Message: fmt.Errorf("parse tokens error; %w", err),
			Code:    0x012,
			Type:    lib.InternalErrorType,
		}
	}

	if len(masterKey) == 0 {
		masterKey, err = restoreMasterKey(shares, additionalPassword)
		if err != nil {
			return &lib.Error{
				Message: fmt.Errorf("restore master key error; %w", err),
				Code:    0x013,
				Type:    lib.InternalErrorType,
			}
		}
	}

	content, err := cont.Decrypt(masterKey)
	if err != nil {
		return &lib.Error{
			Message: fmt.Errorf("decrypt container error; %w", err),
			Code:    0x014,
			Type:    lib.InternalErrorType,
		}
	}

	if err = unpackContent(content, *options.FolderPath, cont.GetHeader().CompressionType); err != nil {
		return &lib.Error{
			Message: fmt.Errorf("unpack content error; %w", err),
			Code:    0x015,
			Type:    lib.InternalErrorType,
		}
	}

	return nil
}

func openContainer(containerPath string) (container.Container, error) {
	cont := container.NewContainer(containerPath, container.Metadata{})
	if err := cont.Open(); err != nil {
		return nil, fmt.Errorf("open container error; %w", err)
	}

	return cont, nil
}

func deriveAdditionalPassword(password string, salt [16]byte) []byte {
	if password == "" {
		return nil
	}

	return lib.PBKDF2Key(
		[]byte(password),
		salt[:],
		lib.Iterations,
		lib.KeyLen,
	)
}

func parseTokens(tokenString string, additionalPassword []byte) (masterKey []byte, shares []shamir.Share, err error) {
	for _, key := range strings.Split(tokenString, "|") {
		var tokenItem token.Token
		if tokenItem, err = token.Parse([]byte(key), additionalPassword); err != nil {
			return nil, nil, fmt.Errorf("parse token error; %w", err)
		}

		switch byte(tokenItem.Type) {
		case token.TypeMaster:
			if masterKey, err = hex.DecodeString(tokenItem.Value); err != nil {
				return nil, nil, fmt.Errorf("decode master key error; %w", err)
			}
		case token.TypeShare:
			var share shamir.Share
			if share, err = createShareFromToken(tokenItem); err != nil {
				return nil, nil, err
			}

			shares = append(shares, share)
		default:
			return nil, nil, lib.ErrUnknownTokenType
		}
	}

	return masterKey, shares, nil
}

func createShareFromToken(item token.Token) (shamir.Share, error) {
	decodedValue, err := hex.DecodeString(item.Value)
	if err != nil {
		return shamir.Share{}, fmt.Errorf("decode share value error; %w", err)
	}

	decodedSignature, err := hex.DecodeString(item.Signature)
	if err != nil {
		return shamir.Share{}, fmt.Errorf("decode share signature error; %w", err)
	}

	return shamir.Share{
		ID:         byte(item.ID),
		Value:      decodedValue,
		ProviderID: byte(item.ProviderID),
		Signature:  decodedSignature,
	}, nil
}

func restoreMasterKey(shares []shamir.Share, additionalPassword []byte) ([]byte, error) {
	if len(shares) == 0 {
		return nil, lib.ErrEmptyShares
	}

	integrityProvider, err := createIntegrityProvider(shares[0].ProviderID, additionalPassword)
	if err != nil {
		return nil, err
	}

	masterKey, err := shamir.Combine(shares, integrityProvider)
	if err != nil {
		return nil, fmt.Errorf("combine shamir shares error; %w", err)
	}

	return masterKey, nil
}

func createIntegrityProvider(providerID byte, additionalPassword []byte) (integrity.Provider, error) {
	switch providerID {
	case integrity.TypeNone:
		return integrity.NewNoneProvider(), nil
	case integrity.TypeHMAC:
		return hmac.New(additionalPassword), nil
	case integrity.TypeEd25519:
		return nil, lib.ErrEd25519Unimplemented
	default:
		return nil, lib.ErrUnknownIntegrityProvider
	}
}

func unpackContent(content []byte, folderPath string, compressionType byte) error {
	switch compressionType {
	case compression.TypeZip:
		if err := zip.New().Unpack(content, folderPath); err != nil {
			return fmt.Errorf("compression unpack error; %w", err)
		}

		return nil
	case compression.TypeNone:
		return lib.ErrNoneCompressionUnimplemented
	default:
		return lib.ErrUnknownCompressionType
	}
}
