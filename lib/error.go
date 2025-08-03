package lib

import (
	"errors"
	"fmt"
)

type ErrorType byte

const (
	ErrorTypeValidation ErrorType = 0x000
	ErrorTypeInternal   ErrorType = 0x010
	ErrorTypeAuth       ErrorType = 0x020
	ErrorTypeIO         ErrorType = 0x030
	ErrorTypeCrypto     ErrorType = 0x040
	ErrorTypeFormat     ErrorType = 0x050
)

type ErrorCategory uint16

const (
	CategoryGeneral     ErrorCategory = 0x000
	CategoryUnseal      ErrorCategory = 0x100
	CategorySeal        ErrorCategory = 0x200
	CategoryReseal      ErrorCategory = 0x300
	CategoryCompression ErrorCategory = 0x400
	CategoryIntegrity   ErrorCategory = 0x500
	CategoryToken       ErrorCategory = 0x600
	CategoryShamir      ErrorCategory = 0x700
)

type ErrorCode uint16

const (
	ErrCodeContainerCurrentPathRequired           ErrorCode = 0x000
	ErrCodeContainerNewPathRequired               ErrorCode = 0x001
	ErrCodeContainerFolderPathRequired            ErrorCode = 0x002
	ErrCodeContainerPassphraseRequired            ErrorCode = 0x003
	ErrCodeCompressionTypeInvalid                 ErrorCode = 0x004
	ErrCodeIntegrityProviderTypeInvalid           ErrorCode = 0x005
	ErrCodeIntegrityProviderNewPassphraseRequired ErrorCode = 0x006
	ErrCodeShamirSharesEqualZero                  ErrorCode = 0x007
	ErrCodeShamirThresholdEqualZero               ErrorCode = 0x008
	ErrCodeShamirSharesLessThanThreshold          ErrorCode = 0x009
	ErrCodeShamirSharesLessThanTwo                ErrorCode = 0x0010
	ErrCodeShamirThresholdLessThanTwo             ErrorCode = 0x0011
	ErrCodeShamirSharesGreaterThan255             ErrorCode = 0x0012
	ErrCodeShamirThresholdGreaterThan255          ErrorCode = 0x0013
	ErrCodeTokenWriterTypeInvalid                 ErrorCode = 0x0014
	ErrCodeTokenWriterPathRequired                ErrorCode = 0x0015
	ErrCodeTokenWriterFormatInvalid               ErrorCode = 0x0016
	ErrCodeTokenReaderTypeInvalid                 ErrorCode = 0x0017
	ErrCodeTokenReaderFlagRequired                ErrorCode = 0x0018
	ErrCodeTokenReaderPathRequired                ErrorCode = 0x0019
	ErrCodeTokenReaderFormatInvalid               ErrorCode = 0x0020
	ErrCodeLogWriterTypeInvalid                   ErrorCode = 0x0021
	ErrCodeLogWriterPathRequired                  ErrorCode = 0x0022
	ErrCodeLogWriterFormatInvalid                 ErrorCode = 0x0023

	ErrCodeGetFilePathRelative ErrorCode = 0x0024
)

const (
	ErrSubcommandRequired = "'%s' subcommand is required for %s"
	ErrFailedParseFlags   = "failed to parse '%s' flags; %v"
	ErrUnknownSubcommand  = "unknown subcommand for reseal: '%s'"
)

const (
	SuggestionContainerNewPath     = "specify the path to the new container using the -new-path flag"
	SuggestionContainerCurrentPath = "specify the path to the current container using the -current-path flag"
	SuggestionContainerFolderPath  = "specify the container folder path using the -folder-path flag"
	SuggestionContainerPassphrase  = "specify the container passphrase using the -passphrase flag"

	SuggestionIntegrityProviderType          = "specify a valid integrity provider type, available options: [none | hmac]"
	SuggestionIntegrityProviderNewPassphrase = "for integrity provider type hmac, you must specify a new passphrase using the -new-passphrase flag"

	SuggestionCompressionType = "specify a valid compression type, the only available option is: [zip]"

	SuggestionTokenWriterType   = "specify a valid token writer type, available options: [file | stdout]"
	SuggestionTokenWriterFormat = "specify a valid token writer format, available options: [plaintext | json]"
	SuggestionTokenWriterPath   = "for token writer type file, you must specify a path using the -path flag"

	SuggestionLogWriterType   = "specify a valid log writer type, available options: [file | stdout]"
	SuggestionLogWriterFormat = "specify a valid log writer format, available options: [plaintext | json]"
	SuggestionLogWriterPath   = "for log writer type file, you must specify a path using the -path flag"

	SuggestionTokenReaderType   = "specify a valid token reader type, available options: [file | stdin | flag]"
	SuggestionTokenReaderFormat = "specify a valid token reader format, available options: [plaintext | json]"
	SuggestionTokenReaderPath   = "for token reader type file, you must specify a path using the -path flag"
	SuggestionTokenReaderFlag   = "for token reader type flag, you must specify a flag using the -flag parameter"

	SuggestionShamirSharesEqual0            = "specify a number of shares greater than 0 using the -shares flag"
	SuggestionShamirThresholdEqual0         = "specify a threshold greater than 0 using the -threshold flag"
	SuggestionShamirSharesLessThanThreshold = "number of shares must be greater than or equal to the threshold"
	SuggestionShamirSharesLessThan2         = "number of shares must be at least 2, specify a value >= 2"
	SuggestionShamirThresholdLessThan2      = "threshold must be at least 2, specify a value >= 2"
	SuggestionShamirSharesGreaterThan255    = "number of shares must not exceed 255, specify a value <= 255"
	SuggestionShamirThresholdGreaterThan255 = "threshold must not exceed 255, specify a value <= 255"
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

var errorToSuggestion = map[error]string{
	ErrContainerNewPathRequired:     SuggestionContainerNewPath,
	ErrContainerCurrentPathRequired: SuggestionContainerCurrentPath,
	ErrContainerFolderPathRequired:  SuggestionContainerFolderPath,
	ErrContainerPassphraseRequired:  SuggestionContainerPassphrase,

	ErrIntegrityProviderTypeInvalid:           SuggestionIntegrityProviderType,
	ErrIntegrityProviderNewPassphraseRequired: SuggestionIntegrityProviderNewPassphrase,

	ErrCompressionTypeInvalid: SuggestionCompressionType,

	ErrTokenWriterTypeInvalid:   SuggestionTokenWriterType,
	ErrTokenWriterFormatInvalid: SuggestionTokenWriterFormat,
	ErrTokenWriterPathRequired:  SuggestionTokenWriterPath,

	ErrLogWriterTypeInvalid:   SuggestionLogWriterType,
	ErrLogWriterFormatInvalid: SuggestionLogWriterFormat,
	ErrLogWriterPathRequired:  SuggestionLogWriterPath,

	ErrTokenReaderTypeInvalid:   SuggestionTokenReaderType,
	ErrTokenReaderFormatInvalid: SuggestionTokenReaderFormat,
	ErrTokenReaderPathRequired:  SuggestionTokenReaderPath,
	ErrTokenReaderFlagRequired:  SuggestionTokenReaderFlag,

	ErrShamirSharesEqual0:            SuggestionShamirSharesEqual0,
	ErrShamirThresholdEqual0:         SuggestionShamirThresholdEqual0,
	ErrShamirSharesLessThanThreshold: SuggestionShamirSharesLessThanThreshold,
	ErrShamirSharesLessThan2:         SuggestionShamirSharesLessThan2,
	ErrShamirThresholdLessThan2:      SuggestionShamirThresholdLessThan2,
	ErrShamirSharesGreaterThan255:    SuggestionShamirSharesGreaterThan255,
	ErrShamirThresholdGreaterThan255: SuggestionShamirThresholdGreaterThan255,
}

var errorToCode = map[error]ErrorCode{
	ErrContainerNewPathRequired:     ErrCodeContainerNewPathRequired,
	ErrContainerCurrentPathRequired: ErrCodeContainerCurrentPathRequired,
	ErrContainerFolderPathRequired:  ErrCodeContainerFolderPathRequired,
	ErrContainerPassphraseRequired:  ErrCodeContainerPassphraseRequired,

	ErrIntegrityProviderTypeInvalid:           ErrCodeIntegrityProviderTypeInvalid,
	ErrIntegrityProviderNewPassphraseRequired: ErrCodeIntegrityProviderNewPassphraseRequired,

	ErrCompressionTypeInvalid: ErrCodeCompressionTypeInvalid,

	ErrTokenWriterTypeInvalid:   ErrCodeTokenWriterTypeInvalid,
	ErrTokenWriterFormatInvalid: ErrCodeTokenWriterFormatInvalid,
	ErrTokenWriterPathRequired:  ErrCodeTokenWriterPathRequired,

	ErrLogWriterTypeInvalid:   ErrCodeLogWriterTypeInvalid,
	ErrLogWriterFormatInvalid: ErrCodeLogWriterFormatInvalid,
	ErrLogWriterPathRequired:  ErrCodeLogWriterPathRequired,

	ErrTokenReaderTypeInvalid:   ErrCodeTokenReaderTypeInvalid,
	ErrTokenReaderFormatInvalid: ErrCodeTokenReaderFormatInvalid,
	ErrTokenReaderPathRequired:  ErrCodeTokenReaderPathRequired,
	ErrTokenReaderFlagRequired:  ErrCodeTokenReaderFlagRequired,

	ErrShamirSharesEqual0:            ErrCodeShamirSharesEqualZero,
	ErrShamirThresholdEqual0:         ErrCodeShamirThresholdEqualZero,
	ErrShamirSharesLessThanThreshold: ErrCodeShamirSharesLessThanThreshold,
	ErrShamirSharesLessThan2:         ErrCodeShamirSharesLessThanTwo,
	ErrShamirThresholdLessThan2:      ErrCodeShamirThresholdLessThanTwo,
	ErrShamirSharesGreaterThan255:    ErrCodeShamirSharesGreaterThan255,
	ErrShamirThresholdGreaterThan255: ErrCodeShamirThresholdGreaterThan255,
}

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
	Message    string        `json:"message"`
	Code       ErrorCode     `json:"code"`
	Type       ErrorType     `json:"type"`
	Category   ErrorCategory `json:"category"`
	Details    string        `json:"details"`
	Suggestion string        `json:"suggestion"`
	Wrapped    error         `json:"-"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("[E-%04X] %s", e.Code, e.Message)
}

func (e *Error) FullError() string {
	result := fmt.Sprintf("[E-%04X] %s", e.Code, e.Message)

	if e.Suggestion != "" {
		result += fmt.Sprintf("\nSuggestion: %s", e.Suggestion)
	}

	if e.Details != "" {
		result += fmt.Sprintf("\nDetails: %s", e.Details)
	}

	return result
}

func (e *Error) IsType(t ErrorType) bool {
	return e.Type == t
}

func (e *Error) IsCategory(c ErrorCategory) bool {
	return e.Category == c
}

func (e *Error) Unwrap() error {
	return e.Wrapped
}

func NewError(
	errorType ErrorType,
	category ErrorCategory,
	code ErrorCode,
	message, details, suggestion string,
	wrapped error,
) *Error {
	return &Error{
		Type:       errorType,
		Category:   category,
		Code:       code,
		Message:    message,
		Details:    details,
		Suggestion: suggestion,
		Wrapped:    wrapped,
	}
}

func ValidationErr(category ErrorCategory, err error) *Error {
	return NewError(
		ErrorTypeValidation, category, errorToCode[err], err.Error(), "", errorToSuggestion[err], err,
	)
}

func InternalErr(category ErrorCategory, code ErrorCode, message string, details string, err error) *Error {
	return NewError(ErrorTypeInternal, category, code, message, details, "", err)
}

func AuthErr(category ErrorCategory, code ErrorCode, message string, suggestion string, err error) *Error {
	return NewError(ErrorTypeAuth, category, code, message, "", suggestion, err)
}

func IOErr(category ErrorCategory, code ErrorCode, message string, suggestion string, err error) *Error {
	return NewError(ErrorTypeIO, category, code, message, "", suggestion, err)
}

func CryptoErr(category ErrorCategory, code ErrorCode, message string, details string, err error) *Error {
	return NewError(ErrorTypeCrypto, category, code, message, details, "", err)
}

func FormatErr(category ErrorCategory, code ErrorCode, message string, suggestion string, err error) *Error {
	return NewError(ErrorTypeFormat, category, code, message, "", suggestion, err)
}

func AsError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}

	return nil, false
}

func IsValidationError(err error) bool {
	e, ok := AsError(err)
	return ok && e.IsType(ErrorTypeValidation)
}

func IsInternalError(err error) bool {
	e, ok := AsError(err)
	return ok && e.IsType(ErrorTypeInternal)
}

func IsAuthError(err error) bool {
	e, ok := AsError(err)
	return ok && e.IsType(ErrorTypeAuth)
}

func IsIOError(err error) bool {
	e, ok := AsError(err)
	return ok && e.IsType(ErrorTypeIO)
}

func IsCryptoError(err error) bool {
	e, ok := AsError(err)
	return ok && e.IsType(ErrorTypeCrypto)
}

func IsFormatError(err error) bool {
	e, ok := AsError(err)
	return ok && e.IsType(ErrorTypeFormat)
}
