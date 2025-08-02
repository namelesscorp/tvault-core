package lib

import (
	"errors"
)

const (
	ValidationErrorType byte = 0x01
	InternalErrorType   byte = 0x02
)

// Unseal error codes
const (
	ErrCodeUnsealContainerCurrentPathRequired = 0x001
	ErrCodeUnsealContainerFolderPathRequired  = 0x002
	ErrCodeUnsealTokenReaderTypeInvalid       = 0x003
	ErrCodeUnsealTokenReaderFlagRequired      = 0x004
	ErrCodeUnsealTokenReaderPathRequired      = 0x005
	ErrCodeUnsealTokenReaderFormatInvalid     = 0x006
	ErrCodeUnsealLogWriterTypeInvalid         = 0x007
	ErrCodeUnsealLogWriterPathRequired        = 0x008
	ErrCodeUnsealLogWriterFormatInvalid       = 0x009
)

// Seal error codes
const (
	ErrCodeSealContainerNewPathRequired               = 0x101
	ErrCodeSealContainerFolderPathRequired            = 0x102
	ErrCodeSealContainerPassphraseRequired            = 0x103
	ErrCodeSealCompressionTypeInvalid                 = 0x104
	ErrCodeSealIntegrityProviderTypeInvalid           = 0x105
	ErrCodeSealIntegrityProviderNewPassphraseRequired = 0x106
	ErrCodeSealShamirSharesEqualZero                  = 0x107
	ErrCodeSealShamirThresholdEqualZero               = 0x108
	ErrCodeSealShamirSharesLessThanThreshold          = 0x109
	ErrCodeSealShamirSharesLessThanTwo                = 0x1010
	ErrCodeSealShamirThresholdLessThanTwo             = 0x1011
	ErrCodeSealShamirSharesGreaterThan255             = 0x1012
	ErrCodeSealShamirThresholdGreaterThan255          = 0x1013
	ErrCodeSealTokenWriterTypeInvalid                 = 0x1014
	ErrCodeSealTokenWriterPathRequired                = 0x1015
	ErrCodeSealTokenWriterFormatInvalid               = 0x1016
	ErrCodeSealLogWriterTypeInvalid                   = 0x1017
	ErrCodeSealLogWriterPathRequired                  = 0x1018
	ErrCodeSealLogWriterFormatInvalid                 = 0x1019
)

// Reseal error codes
const (
	ErrCodeResealContainerCurrentPathRequired = 0x201
	ErrCodeResealContainerFolderPathRequired  = 0x202
	ErrCodeResealTokenReaderTypeInvalid       = 0x203
	ErrCodeResealTokenReaderFlagRequired      = 0x204
	ErrCodeResealTokenReaderPathRequired      = 0x205
	ErrCodeResealTokenReaderFormatInvalid     = 0x206
	ErrCodeResealTokenWriterTypeInvalid       = 0x207
	ErrCodeResealTokenWriterPathRequired      = 0x208
	ErrCodeResealTokenWriterFormatInvalid     = 0x209
	ErrCodeResealLogWriterTypeInvalid         = 0x2010
	ErrCodeResealLogWriterPathRequired        = 0x2011
	ErrCodeResealLogWriterFormatInvalid       = 0x2012
)

// Validation errors
var (
	ErrContainerNewPathRequired     = errors.New("container -new-path is required")
	ErrContainerCurrentPathRequired = errors.New("container -current-path is required")
	ErrContainerFolderPathRequired  = errors.New("container -folder-path is required")
	ErrContainerPassphraseRequired  = errors.New("container -passphrase is required")

	ErrIntegrityProviderTypeInvalid           = errors.New("integrity-provider -type must be [none | hmac ]")
	ErrIntegrityProviderNewPassphraseRequired = errors.New("integrity-provider -new-passphrase is required for integrity-provider -type=[hmac]")

	ErrCompressionTypeInvalid = errors.New("compression -type must be [zip]")

	ErrTokenWriterTypeInvalid   = errors.New("token-writer -type must be [file | stdout]")
	ErrTokenWriterFormatInvalid = errors.New("token-writer -format must be [plaintext | json]")
	ErrTokenWriterPathRequired  = errors.New("token-writer -path is required for token-writer -type=[file]")

	ErrLogWriterTypeInvalid   = errors.New("log-writer -type must be [file | stdout]")
	ErrLogWriterFormatInvalid = errors.New("log-writer -format must be [plaintext | json]")
	ErrLogWriterPathRequired  = errors.New("log-writer -path is required for log-writer -type=[file]")

	ErrTokenReaderTypeInvalid   = errors.New("token-reader -type must be [file | stdin | flag]")
	ErrTokenReaderFormatInvalid = errors.New("token-reader -format must be [plaintext | json]")
	ErrTokenReaderPathRequired  = errors.New("token-reader -path is required for token-reader -type=[file]")
	ErrTokenReaderFlagRequired  = errors.New("token-reader -flag is required for token-reader -type=[flag]")

	ErrShamirSharesEqual0            = errors.New("shamir -shares must be greater than 0")
	ErrShamirThresholdEqual0         = errors.New("shamir -threshold must be greater than 0")
	ErrShamirSharesLessThanThreshold = errors.New("shamir -shares must be less than shamir-threshold")
	ErrShamirSharesLessThan2         = errors.New("shamir -shares must be less than 2")
	ErrShamirThresholdLessThan2      = errors.New("shamir -threshold must be less than 2")
	ErrShamirSharesGreaterThan255    = errors.New("shamir -shares must be less than 255")
	ErrShamirThresholdGreaterThan255 = errors.New("shamir -threshold must be less than 255")
)

// Internal errors
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
