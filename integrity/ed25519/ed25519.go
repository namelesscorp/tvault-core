package ed25519

import (
	"github.com/namelesscorp/tvault-core/integrity"
)

type (
	ed25519 struct {
		publicKey  []byte
		privateKey []byte
	}
)

func New(publicKey, privateKey []byte) integrity.Provider {
	return &ed25519{
		publicKey:  publicKey,
		privateKey: privateKey,
	}
}

// Sign - unimplemented
func (e *ed25519) Sign(_ byte, _ []byte) ([]byte, error) {
	panic("not implemented")
}

// IsVerify - unimplemented
func (e *ed25519) IsVerify(_ byte, _, _ []byte) (bool, error) {
	panic("not implemented")
}

func (e *ed25519) ID() byte {
	return integrity.TypeEd25519
}
