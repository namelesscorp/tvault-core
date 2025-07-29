package decrypt

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

func Decrypt(opts Options) error {
	cont, err := openContainer(*opts.ContainerPath)
	if err != nil {
		return lib.InternalErr(0x011, fmt.Errorf("open container error; %w", err))
	}

	addPwd := deriveAdditionalPassword(*opts.AdditionalPassword, cont.GetHeader().Salt)

	tokenString, err := getTokenString(opts)
	if err != nil {
		return lib.InternalErr(0x012, fmt.Errorf("get token string error; %w", err))
	}

	masterKey, shares, err := parseTokens(tokenString, *opts.TokenReaderFormat, addPwd)
	if err != nil {
		return lib.InternalErr(0x013, fmt.Errorf("parse tokens error; %w", err))
	}

	if len(masterKey) == 0 {
		masterKey, err = restoreMasterKey(shares, addPwd)
		if err != nil {
			return lib.InternalErr(0x014, fmt.Errorf("restore master key error; %w", err))
		}
	}

	content, err := cont.Decrypt(masterKey)
	if err != nil {
		return lib.InternalErr(0x015, fmt.Errorf("decrypt container error; %w", err))
	}

	if err = unpackContent(content, *opts.FolderPath, cont.GetHeader().CompressionType); err != nil {
		return lib.InternalErr(0x016, fmt.Errorf("unpack content error; %w", err))
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

	return lib.PBKDF2Key([]byte(password), salt[:], lib.Iterations, lib.KeyLen)
}

func getTokenString(opts Options) (string, error) {
	if *opts.TokenReaderType == lib.ReaderTypeFlag {
		return *opts.TokenReaderFlag, nil
	}

	return readTokens(*opts.TokenReaderType, *opts.TokenReaderFormat, *opts.TokenReaderPath)
}

func readTokens(readerType, format, path string) (string, error) {
	reader, closer, err := lib.NewReader(readerType, format, path)
	if err != nil {
		return "", fmt.Errorf("get reader error; %w", err)
	}

	if closer != nil {
		defer func(closer io.ReadCloser) {
			_ = closer.Close()
		}(closer)
	}

	content, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("read all error; %w", err)
	}

	return string(content), nil
}

func parseTokens(tokenString, tokenFormat string, addPwd []byte) (masterKey []byte, shares []shamir.Share, err error) {
	switch tokenFormat {
	case lib.ReaderFormatPlaintext:
		tokenList := strings.Split(tokenString, "|")
		if len(tokenList) == 0 {
			return nil, nil, fmt.Errorf("invalid token format")
		}

		return parseTokenList(tokenList, addPwd)
	case lib.ReaderFormatJSON:
		var list token.List
		if err = json.Unmarshal([]byte(tokenString), &list); err != nil {
			return nil, nil, fmt.Errorf("unmarshal token list error; %w", err)
		}

		return parseTokenList(list.TokenList, addPwd)
	default:
		return nil, nil, lib.ErrUnknownReaderType
	}
}

func parseTokenList(tokenList []string, addPwd []byte) (masterKey []byte, shares []shamir.Share, err error) {
	for _, raw := range tokenList {
		var tok token.Token
		if tok, err = token.Parse([]byte(raw), addPwd); err != nil {
			return nil, nil, fmt.Errorf("parse token error; %w", err)
		}

		switch byte(tok.Type) {
		case token.TypeMaster:
			if masterKey, err = hex.DecodeString(tok.Value); err != nil {
				return nil, nil, fmt.Errorf("decode master key error; %w", err)
			}
		case token.TypeShare:
			var share shamir.Share
			if share, err = createShareFromToken(tok); err != nil {
				return nil, nil, err
			}

			shares = append(shares, share)
		default:
			return nil, nil, lib.ErrUnknownWriterType
		}
	}

	return masterKey, shares, nil
}

func createShareFromToken(item token.Token) (shamir.Share, error) {
	val, err := hex.DecodeString(item.Value)
	if err != nil {
		return shamir.Share{}, fmt.Errorf("decode share value error; %w", err)
	}

	sig, err := hex.DecodeString(item.Signature)
	if err != nil {
		return shamir.Share{}, fmt.Errorf("decode share signature error; %w", err)
	}

	return shamir.Share{
		ID:         byte(item.ID),
		Value:      val,
		ProviderID: byte(item.ProviderID),
		Signature:  sig,
	}, nil
}

func restoreMasterKey(shares []shamir.Share, addPwd []byte) ([]byte, error) {
	if len(shares) == 0 {
		return nil, lib.ErrEmptyShares
	}

	integrityProvider, err := createIntegrityProvider(shares[0].ProviderID, addPwd)
	if err != nil {
		return nil, err
	}

	return shamir.Combine(shares, integrityProvider)
}

func createIntegrityProvider(providerID byte, addPwd []byte) (integrity.Provider, error) {
	switch providerID {
	case integrity.TypeNone:
		return integrity.NewNoneProvider(), nil
	case integrity.TypeHMAC:
		return hmac.New(addPwd), nil
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
