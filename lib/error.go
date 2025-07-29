package lib

import (
	"errors"
)

const (
	ValidationErrorType byte = 0x01
	InternalErrorType   byte = 0x02

	ErrDecryptCodeContainerPathRequired  = 0x001
	ErrDecryptCodeFolderPathRequired     = 0x002
	ErrDecryptCodeInvalidTokenReaderType = 0x003
	ErrDecryptCodeMissingTokenReaderFlag = 0x004
	ErrDecryptCodeMissingTokenReaderPath = 0x005
	ErrDecryptCodeInvalidTokenReaderFmt  = 0x006
	ErrDecryptCodeInvalidLogWriterType   = 0x007
	ErrDecryptCodeMissingLogWriterPath   = 0x008
	ErrDecryptCodeInvalidLogWriterFormat = 0x009

	ErrEncryptCodeContainerPathRequired     = 0x101
	ErrEncryptCodeFolderPathRequired        = 0x102
	ErrEncryptCodePassphraseRequired        = 0x103
	ErrEncryptCodeInvalidCompression        = 0x104
	ErrEncryptCodeInvalidIntegrityProvider  = 0x105
	ErrEncryptCodeMissingAdditionalPassword = 0x106
	ErrEncryptCodeInvalidTokenWriterType    = 0x107
	ErrEncryptCodeMissingTokenWriterPath    = 0x108
	ErrEncryptCodeInvalidTokenWriterFormat  = 0x109
	ErrEncryptCodeInvalidLogWriterType      = 0x1010
	ErrEncryptCodeMissingLogWriterPath      = 0x1011
	ErrEncryptCodeInvalidLogWriterFormat    = 0x1012
)

var (
	ErrEmptyShares                  = errors.New("shares list is empty")
	ErrUnknownCompressionType       = errors.New("unknown compression type")
	ErrNoneCompressionUnimplemented = errors.New("compression type none unimplemented")
	ErrUnknownIntegrityProvider     = errors.New("unknown integrity provider")
	ErrEd25519Unimplemented         = errors.New("integrity provider ed25519 unimplemented")
	ErrTypeAssertionFailed          = errors.New("type assertion failed")

	ErrUnknownWriterFormat = errors.New("unknown writer format")
	ErrUnknownWriterType   = errors.New("unknown writer type")

	ErrUnknownReaderFormat = errors.New("unknown reader format")
	ErrUnknownReaderType   = errors.New("unknown reader type")

	ErrContainerPathRequired = errors.New("container-path is required")
	ErrFolderPathRequired    = errors.New("folder-path is required")
	ErrPassphraseRequired    = errors.New("passphrase is required")
	ErrMissingPassword       = errors.New("additional-password is required for -integrity-provider=hmac")

	ErrInvalidCompression = errors.New("compression-type must be [zip]")

	ErrInvalidIntegrity = errors.New("integrity-provider must be [none | hmac ]")

	ErrInvalidTokenWriterType   = errors.New("token-writer-type must be [file | stdout]")
	ErrInvalidTokenWriterFormat = errors.New("token-writer-format must be [plaintext | json]")
	ErrMissingTokenWriterPath   = errors.New("token-writer-path is required for -token-writer-type=[file]")

	ErrInvalidLogWriterType   = errors.New("log-writer-type must be [file | stdout]")
	ErrInvalidLogWriterFormat = errors.New("log-writer-format must be [plaintext | json]")
	ErrMissingLogWriterPath   = errors.New("log-writer-path is required for -log-writer-type=[file]")

	ErrInvalidTokenReaderType   = errors.New("token-reader-type must be [file | stdin | flag]")
	ErrInvalidTokenReaderFormat = errors.New("token-reader-format must be [plaintext | json]")
	ErrMissingTokenReaderPath   = errors.New("token-reader-path is required for -token-reader-type=[file]")
	ErrMissingTokenReaderFlag   = errors.New("token-reader-flag is required for -token-reader-type=[flag]")

	ErrInvalidTokenVersion       = errors.New("invalid token version")
	ErrInvalidContainerVersion   = errors.New("invalid container version")
	ErrInvalidContainerSignature = errors.New("invalid container signature")
)

type Error struct {
	error

	Message string `json:"message"`
	Code    int    `json:"code"`
	Type    byte   `json:"type"`
}

func InternalErr(code int, err error) *Error {
	return &Error{
		Message: err.Error(),
		Code:    code,
		Type:    InternalErrorType,
	}
}

func ValidationErr(code int, err error) *Error {
	return &Error{
		Message: err.Error(),
		Code:    code,
		Type:    ValidationErrorType,
	}
}
