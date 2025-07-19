package lib

import "errors"

const (
	ValidationErrorType byte = 0x01
	InternalErrorType   byte = 0x02
)

var (
	ErrEmptyShares                  = errors.New("shares list is empty")
	ErrUnknownTokenType             = errors.New("unknown token type")
	ErrUnknownCompressionType       = errors.New("unknown compression type")
	ErrNoneCompressionUnimplemented = errors.New("compression type none unimplemented")
	ErrUnknownIntegrityProvider     = errors.New("unknown integrity provider")
	ErrEd25519Unimplemented         = errors.New("integrity provider ed25519 unimplemented")

	ErrTokenRequired         = errors.New("token(s) is required")
	ErrContainerPathRequired = errors.New("container-path is required")
	ErrFolderPathRequired    = errors.New("folder-path is required")
	ErrPassphraseRequired    = errors.New("passphrase is required")
	ErrInvalidCompression    = errors.New("compression-type must be [zip]")
	ErrInvalidTokenSave      = errors.New("token-save-type must be [file | stdout]")
	ErrInvalidIntegrity      = errors.New("integrity-provider must be [none | hmac ]")
	ErrMissingPassword       = errors.New("additional-password is required for -integrity-provider=hmac")
	ErrMissingKeyPath        = errors.New("key-save-path is required for -key-save-type=[file]")
)

type Error struct {
	error

	Message error
	Code    int
	Type    byte
}
