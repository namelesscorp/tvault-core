package token

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	// Version - defines the current version number as an integer.
	Version = 1

	// TypeShare - represents a byte constant for the share type.
	TypeShare byte = 0x01

	// TypeMaster - represents a byte constant for the master type.
	TypeMaster byte = 0x02
)

// ErrInvalidTokenVersion - indicates the token's version does not match the expected version.
var ErrInvalidTokenVersion = errors.New("invalid token version")

// Token - represents a data structure for handling token information with properties like version, ID, type, and provider ID.
type Token struct {
	Version    int    `json:"v"`
	ID         int    `json:"id,omitempty"`
	Type       int    `json:"t"`
	Value      string `json:"vl"`
	Signature  string `json:"s,omitempty"`
	ProviderID int    `json:"pid"`
}

// Build - serializes a Token into a JSON byte slice and encrypts it if a key is provided.
func Build(token Token, key []byte) ([]byte, error) {
	tokenBytes, err := json.Marshal(&token)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal token to JSON: %w", err)
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
		return Token{}, fmt.Errorf("failed to unmarshal token JSON: %w", err)
	}

	if result.Version != Version {
		return Token{}, ErrInvalidTokenVersion
	}

	return result, nil
}

// encrypt - encrypts the provided data using the given key with AES in CTR mode and returns the encrypted data or an error.
func encrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	encrypted := make([]byte, len(data))
	stream := cipher.NewCTR(block, make([]byte, block.BlockSize()))
	stream.XORKeyStream(encrypted, data)

	return encrypted, nil
}

// decrypt - decrypts the given encrypted data using the provided key with AES-CTR mode and returns the decrypted data.
func decrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	decrypted := make([]byte, len(data))
	stream := cipher.NewCTR(block, make([]byte, block.BlockSize()))
	stream.XORKeyStream(decrypted, data)

	return decrypted, nil
}

// decodeBase64 - decodes a Base64-encoded byte slice and returns the decoded data or an error if the decoding fails.
func decodeBase64(data []byte) ([]byte, error) {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("failed to decode Base64 token: %w", err)
	}
	return decoded, nil
}
