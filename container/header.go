package container

import (
	"crypto/rand"
	"fmt"

	"github.com/namelesscorp/tvault-core/lib"
)

const (
	// signature for validation container
	signature = "TVLT"

	// Version container version for backward compatibility
	Version = 1
)

type Header struct {
	Signature       [4]byte  // signature for validate container - "TVLT"
	Version         uint8    // container version - "0x01"
	Flags           uint8    // binary flags - "0x01". NOT SUPPORTED
	Salt            [16]byte // salt for passphrase
	Iterations      uint32   // PBKDF2 rounds
	CompressionType uint8    // compression type for data - "0x01"
	Nonce           [12]byte // AES‑GCM nonce (number used once)
	MetadataSize    uint32   // metadata size
}

func NewHeader(compressionType byte) (Header, error) {
	var h = Header{
		Version:         Version,
		Iterations:      lib.Iterations,
		CompressionType: compressionType,
	}

	if _, err := rand.Read(h.Salt[:]); err != nil {
		return h, fmt.Errorf("rand read salt error; %w", err)
	}

	if _, err := rand.Read(h.Nonce[:]); err != nil {
		return h, fmt.Errorf("rand read nonce error; %w", err)
	}

	copy(h.Signature[:], signature)

	return h, nil
}
