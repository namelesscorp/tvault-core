package lib

import (
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/namelesscorp/tvault-core/debug"
)

var unwrappedErrorList = make(map[error]struct{})

type ErrorType byte

const (
	ErrorTypeValidation ErrorType = 0x000
	ErrorTypeInternal   ErrorType = 0x020
	ErrorTypeIO         ErrorType = 0x030
	ErrorTypeCrypto     ErrorType = 0x040
	ErrorTypeFormat     ErrorType = 0x050
)

type ErrorCategory uint16

const (
	CategoryUnseal      ErrorCategory = 0x000
	CategorySeal        ErrorCategory = 0x100
	CategoryReseal      ErrorCategory = 0x200
	CategoryCompression ErrorCategory = 0x300
	CategoryIntegrity   ErrorCategory = 0x400
	CategoryToken       ErrorCategory = 0x500
	CategoryShamir      ErrorCategory = 0x600
	CategoryContainer   ErrorCategory = 0x700
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

	ErrCodeGetFilePathRelative  ErrorCode = 0x0024
	ErrCodeOpenFileError        ErrorCode = 0x0025
	ErrCodeCreateZipError       ErrorCode = 0x0026
	ErrCodeIOCopyError          ErrorCode = 0x0027
	ErrCodeWalkDirError         ErrorCode = 0x0028
	ErrCodeCloseZipError        ErrorCode = 0x0029
	ErrCodeCreateZipReaderError ErrorCode = 0x0030
	ErrCodeCreateDirectoryError ErrorCode = 0x0031
	ErrCodeOSOpenFileError      ErrorCode = 0x0032
	ErrCodeCloseFileError       ErrorCode = 0x0033
	ErrCodeReaderCloserError    ErrorCode = 0x0034

	ErrCodeHMACWriteIDError   ErrorCode = 0x0035
	ErrCodeHMACWriteDataError ErrorCode = 0x0036
	ErrCodeHMACSignError      ErrorCode = 0x0037

	ErrCodeRandReadSaltError          ErrorCode = 0x0038
	ErrCodeRandReadNonceError         ErrorCode = 0x0039
	ErrCodeCreateNewCipherError       ErrorCode = 0x0040
	ErrCodeCreateNewGCMError          ErrorCode = 0x0041
	ErrCodeGenerateNonceError         ErrorCode = 0x0042
	ErrCodeContainerOpenFileError     ErrorCode = 0x0043
	ErrCodeJSONMarshalMetadataError   ErrorCode = 0x0044
	ErrCodeMetadataSizeExceedsError   ErrorCode = 0x0045
	ErrCodeWriteHeaderBinaryError     ErrorCode = 0x0046
	ErrCodeWriteMetadataError         ErrorCode = 0x0047
	ErrCodeWriteCipherTextError       ErrorCode = 0x0048
	ErrCodeInitHeaderError            ErrorCode = 0x0049
	ErrCodeReadBinaryError            ErrorCode = 0x0050
	ErrCodeReadMetadataError          ErrorCode = 0x0051
	ErrCodeJSONUnmarshalMetadataError ErrorCode = 0x0052
	ErrCodeReadCipherTextError        ErrorCode = 0x0053
	ErrCodeOpenCipherTextError        ErrorCode = 0x0054

	ErrCodeTokenMarshalJSONError   ErrorCode = 0x0055
	ErrCodeTokenUnmarshalJSONError ErrorCode = 0x0056
	ErrCodeTokenCreateCipherError  ErrorCode = 0x0057
	ErrCodeTokenDecodeBase64Error  ErrorCode = 0x0058

	ErrCodeShamirInvalidThresholdOrShares ErrorCode = 0x0059
	ErrCodeShamirIOReadFullError          ErrorCode = 0x0060
	ErrCodeShamirSignShareError           ErrorCode = 0x0061
	ErrCodeShamirVerifySignatureError     ErrorCode = 0x0062
	ErrCodeShamirVerifySignatureFailed    ErrorCode = 0x0063

	ErrCodeUnsealOpenContainerError        ErrorCode = 0x0064
	ErrCodeUnsealGetTokenStringError       ErrorCode = 0x0065
	ErrCodeUnsealParseTokensError          ErrorCode = 0x0066
	ErrCodeUnsealRestoreMasterKeyError     ErrorCode = 0x0067
	ErrCodeUnsealContainerError            ErrorCode = 0x0068
	ErrCodeUnsealUnpackContentError        ErrorCode = 0x0069
	ErrCodeUnsealGetReaderError            ErrorCode = 0x0070
	ErrCodeUnsealReadAllError              ErrorCode = 0x0071
	ErrCodeUnsealInvalidTokenFormatError   ErrorCode = 0x0072
	ErrCodeUnsealUnmarshalTokenListError   ErrorCode = 0x0073
	ErrCodeUnsealParseTokenError           ErrorCode = 0x0074
	ErrCodeUnsealDecodeMasterKeyError      ErrorCode = 0x0075
	ErrCodeUnsealDecodeShareValueError     ErrorCode = 0x0076
	ErrCodeUnsealDecodeShareSignatureError ErrorCode = 0x0077
	ErrCodeUnsealCompressionUnpackError    ErrorCode = 0x0078

	ErrCodeSealCompressFolderError                    ErrorCode = 0x0079
	ErrCodeSealCreateContainerError                   ErrorCode = 0x0080
	ErrCodeSealCreateIntegrityProviderError           ErrorCode = 0x0081
	ErrCodeSealDeriveIntegrityProviderPassphraseError ErrorCode = 0x0082
	ErrCodeSealGenerateAndSaveTokensError             ErrorCode = 0x0083
	ErrCodeSealCompressionPackError                   ErrorCode = 0x0084
	ErrCodeSealCreateContainerHeaderError             ErrorCode = 0x0085
	ErrCodeSealEncryptContainerError                  ErrorCode = 0x0086
	ErrCodeSealWriteContainerError                    ErrorCode = 0x0087
	ErrCodeSealShamirSplitError                       ErrorCode = 0x0088
	ErrCodeSealWriteTokensShareError                  ErrorCode = 0x0089
	ErrCodeSealBuildShareTokenError                   ErrorCode = 0x0090
	ErrCodeSealWriteTokenMasterError                  ErrorCode = 0x0091
	ErrCodeSealBuildMasterTokenError                  ErrorCode = 0x0092

	ErrCodeResealOpenContainerError            ErrorCode = 0x0093
	ErrCodeResealGetTokenStringError           ErrorCode = 0x0094
	ErrCodeResealParseTokensError              ErrorCode = 0x0095
	ErrCodeResealRestoreMasterKeyError         ErrorCode = 0x0096
	ErrCodeResealCompressFolderError           ErrorCode = 0x0097
	ErrCodeResealEncryptContainerError         ErrorCode = 0x0098
	ErrCodeResealWriteContainerError           ErrorCode = 0x0099
	ErrCodeResealCreateIntegrityProviderError  ErrorCode = 0x00100
	ErrCodeResealDeriveAdditionalPasswordError ErrorCode = 0x00101
)

const (
	ErrSubcommandRequired = "'%s' subcommand is required for %s"
	ErrFailedParseFlags   = "failed to parse '%s' flags; %v"
	ErrUnknownSubcommand  = "unknown subcommand for reseal: '%s'"

	ErrMessageGetFilePathRelative  = "failed to get relative path"
	ErrMessageOpenFileError        = "open file error"
	ErrMessageCreateZipError       = "create zip error"
	ErrMessageIOCopyError          = "io copy error"
	ErrMessageWalkDirError         = "walk dir error"
	ErrMessageCloseZipError        = "close zip error"
	ErrMessageCreateZipReaderError = "create new zip reader error"
	ErrMessageCreateDirectoryError = "create directory error"
	ErrMessageOSOpenFileError      = "os open file error"
	ErrMessageCloseFileError       = "close file error"
	ErrMessageReaderCloserError    = "reader closer error"

	ErrMessageHMACWriteIDError   = "error writing ID to HMAC"
	ErrMessageHMACWriteDataError = "error writing data to HMAC"
	ErrMessageHMACSignError      = "error signing data with HMAC"

	ErrMessageRandReadSaltError          = "rand read salt error"
	ErrMessageRandReadNonceError         = "rand read nonce error"
	ErrMessageCreateNewCipherError       = "create new cipher error"
	ErrMessageCreateNewGCMError          = "create new gcm error"
	ErrMessageGenerateNonceError         = "failed to generate nonce"
	ErrMessageContainerOpenFileError     = "open file error"
	ErrMessageJSONMarshalMetadataError   = "json marshal metadata error"
	ErrMessageMetadataSizeExceedsError   = "metadata size exceeds maximum allowed"
	ErrMessageWriteHeaderBinaryError     = "write header binary error"
	ErrMessageWriteMetadataError         = "write metadata error"
	ErrMessageWriteCipherTextError       = "write cipher text error"
	ErrMessageInitHeaderError            = "init header error"
	ErrMessageReadBinaryError            = "read binary error"
	ErrMessageReadMetadataError          = "read metadata error"
	ErrMessageJSONUnmarshalMetadataError = "json unmarshal metadata error"
	ErrMessageReadCipherTextError        = "read cipher text error"
	ErrMessageOpenCipherTextError        = "open cipher text error"

	ErrMessageTokenMarshalJSONError   = "failed to marshal token to JSON"
	ErrMessageTokenUnmarshalJSONError = "failed to unmarshal token JSON"
	ErrMessageTokenCreateCipherError  = "failed to create cipher"
	ErrMessageTokenDecodeBase64Error  = "failed to decode Base64 token"

	ErrMessageShamirInvalidThresholdOrShares = "invalid threshold or number of shares"
	ErrMessageShamirIOReadFullError          = "io read full error"
	ErrMessageShamirSignShareError           = "sign share error"
	ErrMessageShamirVerifySignatureError     = "verify share signature error"
	ErrMessageShamirVerifySignatureFailed    = "verify share signature failed"

	ErrMessageUnsealOpenContainerError        = "open container error"
	ErrMessageUnsealGetTokenStringError       = "get token string error"
	ErrMessageUnsealParseTokensError          = "parse tokens error"
	ErrMessageUnsealRestoreMasterKeyError     = "restore master key error"
	ErrMessageUnsealContainerError            = "unseal container error"
	ErrMessageUnsealUnpackContentError        = "unpack content error"
	ErrMessageUnsealGetReaderError            = "get reader error"
	ErrMessageUnsealReadAllError              = "read all error"
	ErrMessageUnsealInvalidTokenFormatError   = "invalid token format"
	ErrMessageUnsealUnmarshalTokenListError   = "unmarshal token list error"
	ErrMessageUnsealParseTokenError           = "parse token error"
	ErrMessageUnsealDecodeMasterKeyError      = "decode master key error"
	ErrMessageUnsealDecodeShareValueError     = "decode share value error"
	ErrMessageUnsealDecodeShareSignatureError = "decode share signature error"
	ErrMessageUnsealCompressionUnpackError    = "compression unpack error"

	ErrMessageSealCompressFolderError                    = "compress folder error"
	ErrMessageSealCreateContainerError                   = "create container error"
	ErrMessageSealCreateIntegrityProviderError           = "create integrity provider error"
	ErrMessageSealDeriveIntegrityProviderPassphraseError = "derive integrity provider passphrase error"
	ErrMessageSealGenerateAndSaveTokensError             = "generate and save tokens error"
	ErrMessageSealCompressionPackError                   = "compression pack error"
	ErrMessageSealCreateContainerHeaderError             = "create container header error"
	ErrMessageSealEncryptContainerError                  = "encrypt container error"
	ErrMessageSealWriteContainerError                    = "write container error"
	ErrMessageSealShamirSplitError                       = "shamir split error"
	ErrMessageSealWriteTokensShareError                  = "write tokens (share) error"
	ErrMessageSealBuildShareTokenError                   = "build token (share) error"
	ErrMessageSealWriteTokenMasterError                  = "write token (master) error"
	ErrMessageSealBuildMasterTokenError                  = "build token (master) error"

	ErrMessageResealOpenContainerError            = "open container error"
	ErrMessageResealGetTokenStringError           = "get token string error"
	ErrMessageResealParseTokensError              = "parse tokens error"
	ErrMessageResealRestoreMasterKeyError         = "restore master key error"
	ErrMessageResealCompressFolderError           = "compress folder error"
	ErrMessageResealEncryptContainerError         = "encrypt container error"
	ErrMessageResealWriteContainerError           = "write container error"
	ErrMessageResealCreateIntegrityProviderError  = "create integrity provider error"
	ErrMessageResealDeriveAdditionalPasswordError = "derive additional password error"
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

type (
	Error struct {
		Message    string        `json:"message"`
		Code       ErrorCode     `json:"code"`
		Type       ErrorType     `json:"type"`
		Category   ErrorCategory `json:"category"`
		Details    string        `json:"details"`
		Suggestion string        `json:"suggestion"`
		Unwrapped  []string      `json:"unwrapped"`
		Stacktrace []StackFrame  `json:"stacktrace"`
		Wrapped    error         `json:"-"`
	}

	StackFrame struct {
		Function string `json:"function"`
		File     string `json:"file"`
		Line     int    `json:"line"`
	}
)

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
	err := &Error{
		Type:       errorType,
		Category:   category,
		Code:       code,
		Message:    message,
		Details:    details,
		Suggestion: suggestion,
		Wrapped:    wrapped,
		Unwrapped:  unwrap(wrapped),
		Stacktrace: make([]StackFrame, 0),
	}
	if debug.IsEnabled() {
		err.Stacktrace = captureStackTrace(3)
	}

	return err
}

func captureStackTrace(skip int) []StackFrame {
	const depth = 32

	var (
		stackFrames     []StackFrame
		programCounters = make([]uintptr, depth)
		n               = runtime.Callers(skip, programCounters)
	)

	if n == 0 {
		return stackFrames
	}

	var frames = runtime.CallersFrames(programCounters[:n])
	for {
		var frame, more = frames.Next()
		stackFrames = append(stackFrames, StackFrame{
			Function: frame.Function,
			File:     frame.File,
			Line:     frame.Line,
		})

		if !more {
			break
		}
	}

	return stackFrames
}

func ValidationErr(category ErrorCategory, err error) *Error {
	return NewError(
		ErrorTypeValidation,
		category,
		errorToCode[err],
		err.Error(),
		"",
		errorToSuggestion[err],
		err,
	)
}

func InternalErr(category ErrorCategory, code ErrorCode, message string, details string, err error) *Error {
	return NewError(
		ErrorTypeInternal,
		category,
		code,
		message,
		details,
		"",
		err,
	)
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

func unwrap(err error) []string {
	if err == nil {
		return nil
	}

	if err.Error() == "" {
		return []string{}
	}

	unwrappedErrorList[err] = struct{}{}

	seen := make(map[string]struct{})
	var result []string

	msgs := strings.Split(err.Error(), ":")
	for _, msg := range msgs {
		msg = strings.TrimSpace(msg)
		if msg != "" {
			if _, ok := seen[msg]; !ok {
				seen[msg] = struct{}{}
				result = append(result, msg)
			}
		}
	}

	for e := range unwrappedErrorList {
		msg := strings.TrimSpace(e.Error())
		if msg != "" {
			if _, ok := seen[msg]; !ok {
				seen[msg] = struct{}{}
				result = append(result, msg)
			}
		}
	}

	return result
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
