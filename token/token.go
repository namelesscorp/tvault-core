package token

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"

	"github.com/namelesscorp/tvault-core/lib"
)

const (
	// Version - defines the current version number as an integer.
	Version = 1

	TypeNone   byte = 0x00
	TypeShare  byte = 0x01
	TypeMaster byte = 0x02

	TypeNameNone   string = "none"
	TypeNameShare  string = "share"
	TypeNameMaster string = "master"

	// encFormatGCM - first byte of an encrypted token envelope, identifying the
	// AES-GCM (AEAD) format: encFormatGCM || nonce || ciphertext+tag.
	// It is authenticated as additional data so any tampering with the format
	// byte is detected. Legacy AES-CTR tokens (no format byte) are not accepted.
	encFormatGCM byte = 0x01
)

var Types = map[string]struct{}{
	TypeNameNone:   {},
	TypeNameShare:  {},
	TypeNameMaster: {},
}

// Token - represents a data structure for handling token information with properties like version, ID, type.
type (
	Token struct {
		Version   int    `json:"v"`
		ID        int    `json:"id,omitempty"`
		Value     string `json:"vl"`
		Signature string `json:"s,omitempty"`
	}
	List struct {
		TokenList []string `json:"token_list"`
	}
)

// Build - serializes a Token into a JSON byte slice and encrypts it if a key is provided.
func Build(token Token, key []byte) ([]byte, error) {
	tokenBytes, err := json.Marshal(&token)
	if err != nil {
		return nil, lib.FormatErr(
			lib.CategoryToken,
			lib.ErrCodeTokenMarshalJSONError,
			lib.ErrMessageTokenMarshalJSONError,
			"",
			err,
		)
	}

	if key == nil {
		return tokenBytes, nil
	}

	encrypted, err := encrypt(tokenBytes, key)
	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

// Parse - parses a base64-encoded token, optionally decrypts it using the provided key, and unmarshals it into a Token structure.
// Returns the parsed Token object or an error if decoding, decryption, or unmarshaling fails.
// Validates the token version against the expected Version constant and returns an error for mismatched versions.
func Parse(tokenBytes, key []byte) (Token, error) {
	decoded, err := decodeBase64(tokenBytes)
	if err != nil {
		return Token{}, err
	}

	var decrypted []byte
	if len(key) > 0 {
		decrypted, err = decrypt(decoded, key)
		if err != nil {
			return Token{}, err
		}
	} else {
		decrypted = decoded
	}

	var result Token
	if err = json.Unmarshal(decrypted, &result); err != nil {
		return Token{}, lib.FormatErr(
			lib.CategoryToken,
			lib.ErrCodeTokenUnmarshalJSONError,
			lib.ErrMessageTokenUnmarshalJSONError,
			"",
			err,
		)
	}

	if result.Version != Version {
		return Token{}, lib.ErrInvalidTokenVersion
	}

	return result, nil
}

// encrypt - encrypts the provided data with AES-GCM (AEAD) and returns the
// envelope: encFormatGCM || nonce || ciphertext+tag. The format byte is bound
// into the tag as additional authenticated data, so any modification of the
// envelope (format byte, nonce, ciphertext or tag) is detected on decrypt.
func encrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, lib.CryptoErr(
			lib.CategoryToken,
			lib.ErrCodeTokenCreateCipherError,
			lib.ErrMessageTokenCreateCipherError,
			"",
			err,
		)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, lib.CryptoErr(
			lib.CategoryToken,
			lib.ErrCodeTokenGCMSealError,
			lib.ErrMessageTokenGCMSealError,
			"",
			err,
		)
	}

	// A fresh random nonce per token keeps the AES-GCM keystream unique even when
	// the same key encrypts multiple tokens.
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, lib.CryptoErr(
			lib.CategoryToken,
			lib.ErrCodeRandReadNonceError,
			lib.ErrMessageRandReadNonceError,
			"",
			err,
		)
	}

	// Envelope layout: [format byte][nonce][ciphertext+tag]. The format byte is
	// passed as additional authenticated data so it is covered by the tag.
	envelope := make([]byte, 1+len(nonce), 1+len(nonce)+len(data)+aesGCM.Overhead())
	envelope[0] = encFormatGCM
	copy(envelope[1:], nonce)

	return aesGCM.Seal(envelope, nonce, data, envelope[:1]), nil
}

// decrypt - decrypts and authenticates an AES-GCM token envelope produced by
// encrypt. It rejects any envelope that is too short, does not start with the
// expected format byte, or fails authentication.
func decrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, lib.CryptoErr(
			lib.CategoryToken,
			lib.ErrCodeTokenCreateCipherError,
			lib.ErrMessageTokenCreateCipherError,
			"",
			err,
		)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, lib.CryptoErr(
			lib.CategoryToken,
			lib.ErrCodeTokenGCMOpenError,
			lib.ErrMessageTokenGCMOpenError,
			"",
			err,
		)
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < 1+nonceSize+aesGCM.Overhead() {
		return nil, lib.CryptoErr(
			lib.CategoryToken,
			lib.ErrCodeTokenGCMOpenError,
			lib.ErrMessageTokenGCMOpenError,
			"",
			lib.ErrTokenCiphertextTooShort,
		)
	}

	// Legacy AES-CTR tokens have no format byte and are intentionally not
	// accepted: the clean switch to AES-GCM leaves no unauthenticated read path.
	if data[0] != encFormatGCM {
		return nil, lib.CryptoErr(
			lib.CategoryToken,
			lib.ErrCodeTokenGCMOpenError,
			lib.ErrMessageTokenGCMOpenError,
			"",
			lib.ErrTokenUnsupportedEncoding,
		)
	}

	nonce := data[1 : 1+nonceSize]
	ciphertext := data[1+nonceSize:]

	decrypted, err := aesGCM.Open(nil, nonce, ciphertext, data[:1])
	if err != nil {
		return nil, lib.CryptoErr(
			lib.CategoryToken,
			lib.ErrCodeTokenGCMOpenError,
			lib.ErrMessageTokenGCMOpenError,
			"",
			err,
		)
	}

	return decrypted, nil
}

// decodeBase64 - decodes a Base64-encoded byte slice and returns the decoded data or an error if the decoding fails.
func decodeBase64(data []byte) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, lib.FormatErr(
			lib.CategoryToken,
			lib.ErrCodeTokenDecodeBase64Error,
			lib.ErrMessageTokenDecodeBase64Error,
			"",
			err,
		)
	}

	return decoded, nil
}

func ConvertNameToID(name string) byte {
	switch name {
	case TypeNameNone:
		return TypeNone
	case TypeNameShare:
		return TypeShare
	case TypeNameMaster:
		return TypeMaster
	default:
		return TypeNone
	}
}

func ConvertIDToName(id byte) string {
	switch id {
	case TypeNone:
		return TypeNameNone
	case TypeShare:
		return TypeNameShare
	case TypeMaster:
		return TypeNameMaster
	default:
		return TypeNameNone
	}
}
