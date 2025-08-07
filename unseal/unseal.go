package unseal

import (
	"encoding/hex"
	"encoding/json"
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

// Unseal - decrypts a container, restores its data, and unpacks its content to the specified folder using given options.
func Unseal(opts Options) error {
	cont := container.NewContainer(
		*opts.Container.CurrentPath,
		nil,
		container.Metadata{Tags: make([]string, 0)},
		container.Header{},
	)
	if err := cont.Read(); err != nil {
		return lib.IOErr(
			lib.CategoryUnseal,
			lib.ErrCodeUnsealOpenContainerError,
			lib.ErrMessageUnsealOpenContainerError,
			"",
			err,
		)
	}

	var masterKey []byte
	switch cont.GetHeader().TokenType {
	case token.TypeMaster, token.TypeShare:
		derivedPassphrase := DeriveIntegrityProviderPassphrase(
			*opts.IntegrityProvider.CurrentPassphrase,
			cont.GetHeader().Salt,
		)

		var tokenString string
		tokenString, err := GetTokenString(opts.TokenReader)
		if err != nil {
			return lib.InternalErr(
				lib.CategoryUnseal,
				lib.ErrCodeUnsealGetTokenStringError,
				lib.ErrMessageUnsealGetTokenStringError,
				"",
				err,
			)
		}

		var shares []shamir.Share
		masterKey, shares, err = ParseTokens(
			cont.GetHeader().TokenType,
			tokenString,
			*opts.TokenReader.Format,
			derivedPassphrase,
		)
		if err != nil {
			return lib.InternalErr(
				lib.CategoryUnseal,
				lib.ErrCodeUnsealParseTokensError,
				lib.ErrMessageUnsealParseTokensError,
				"",
				err,
			)
		}

		if len(masterKey) == 0 {
			masterKey, err = RestoreMasterKey(shares, derivedPassphrase)
			if err != nil {
				return lib.InternalErr(
					lib.CategoryUnseal,
					lib.ErrCodeUnsealRestoreMasterKeyError,
					lib.ErrMessageUnsealRestoreMasterKeyError,
					"",
					err,
				)
			}
		}
	case token.TypeNone:
		var salt = cont.GetHeader().Salt
		masterKey = lib.PBKDF2Key(
			[]byte(*opts.Container.Passphrase),
			salt[:],
			int(cont.GetHeader().Iterations),
			lib.KeyLen,
		)
	}

	if err := cont.Decrypt(masterKey); err != nil {
		return lib.InternalErr(
			lib.CategoryUnseal,
			lib.ErrCodeUnsealContainerError,
			lib.ErrMessageUnsealContainerError,
			"",
			err,
		)
	}

	if err := unpackContent(cont.GetData(), *opts.Container.FolderPath, cont.GetHeader().CompressionType); err != nil {
		return lib.InternalErr(
			lib.CategoryUnseal,
			lib.ErrCodeUnsealUnpackContentError,
			lib.ErrMessageUnsealUnpackContentError,
			"",
			err,
		)
	}

	return nil
}

func DeriveIntegrityProviderPassphrase(passphrase string, salt [16]byte) []byte {
	if passphrase == "" {
		return nil
	}

	return lib.PBKDF2Key([]byte(passphrase), salt[:], lib.Iterations, lib.KeyLen)
}

func GetTokenString(tokenReader *lib.Reader) (string, error) {
	reader, closer, err := lib.NewReader(tokenReader)
	if err != nil {
		return "", lib.IOErr(
			lib.CategoryUnseal,
			lib.ErrCodeUnsealGetReaderError,
			lib.ErrMessageUnsealGetReaderError,
			"",
			err,
		)
	}

	if closer != nil {
		defer func(closer io.ReadCloser) {
			_ = closer.Close()
		}(closer)
	}

	content, err := io.ReadAll(reader)
	if err != nil {
		return "", lib.IOErr(
			lib.CategoryUnseal,
			lib.ErrCodeUnsealReadAllError,
			lib.ErrMessageUnsealReadAllError,
			"",
			err,
		)
	}

	return string(content), nil
}

func ParseTokens(
	tokenType byte,
	tokenString, tokenFormat string,
	addPwd []byte,
) (masterKey []byte, shares []shamir.Share, err error) {
	switch tokenFormat {
	case lib.ReaderFormatPlaintext:
		tokenList := strings.Split(tokenString, "|")
		if len(tokenList) == 0 {
			return nil, nil, lib.FormatErr(
				lib.CategoryUnseal,
				lib.ErrCodeUnsealInvalidTokenFormatError,
				lib.ErrMessageUnsealInvalidTokenFormatError,
				"",
				nil,
			)
		}

		return parseTokenList(tokenType, tokenList, addPwd)
	case lib.ReaderFormatJSON:
		var list token.List
		if err = json.Unmarshal([]byte(tokenString), &list); err != nil {
			return nil, nil, lib.FormatErr(
				lib.CategoryUnseal,
				lib.ErrCodeUnsealUnmarshalTokenListError,
				lib.ErrMessageUnsealUnmarshalTokenListError,
				"",
				err,
			)
		}

		return parseTokenList(tokenType, list.TokenList, addPwd)
	default:
		return nil, nil, lib.ErrUnknownReaderType
	}
}

func parseTokenList(
	tokenType byte,
	tokenList []string,
	addPwd []byte,
) (masterKey []byte, shares []shamir.Share, err error) {
	for _, raw := range tokenList {
		var tok token.Token
		if tok, err = token.Parse([]byte(raw), addPwd); err != nil {
			return nil, nil, lib.FormatErr(
				lib.CategoryUnseal,
				lib.ErrCodeUnsealParseTokenError,
				lib.ErrMessageUnsealParseTokenError,
				"",
				err,
			)
		}

		switch tokenType {
		case token.TypeMaster:
			if masterKey, err = hex.DecodeString(tok.Value); err != nil {
				return nil, nil, lib.FormatErr(
					lib.CategoryUnseal,
					lib.ErrCodeUnsealDecodeMasterKeyError,
					lib.ErrMessageUnsealDecodeMasterKeyError,
					"",
					err,
				)
			}

			shares = append(shares, shamir.Share{
				ID:        byte(tok.ID),
				Value:     masterKey,
				Signature: []byte{},
			})
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
		return shamir.Share{}, lib.FormatErr(
			lib.CategoryUnseal,
			lib.ErrCodeUnsealDecodeShareValueError,
			lib.ErrMessageUnsealDecodeShareValueError,
			"",
			err,
		)
	}

	sig, err := hex.DecodeString(item.Signature)
	if err != nil {
		return shamir.Share{}, lib.FormatErr(
			lib.CategoryUnseal,
			lib.ErrCodeUnsealDecodeShareSignatureError,
			lib.ErrMessageUnsealDecodeShareSignatureError,
			"",
			err,
		)
	}

	return shamir.Share{
		ID:        byte(item.ID),
		Value:     val,
		Signature: sig,
	}, nil
}

func RestoreMasterKey(shares []shamir.Share, addPwd []byte) ([]byte, error) {
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
			return lib.IOErr(
				lib.CategoryUnseal,
				lib.ErrCodeUnsealCompressionUnpackError,
				lib.ErrMessageUnsealCompressionUnpackError,
				"",
				err,
			)
		}

		return nil
	case compression.TypeNone:
		return lib.ErrNoneCompressionUnimplemented
	default:
		return lib.ErrUnknownCompressionType
	}
}
