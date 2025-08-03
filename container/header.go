package container

import (
	"crypto/rand"

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
	Shares          uint8    // shamir number of shares
	Threshold       uint8    // shamir threshold count
}

func NewHeader(compressionType byte, shares, threshold uint8) (Header, error) {
	var h = Header{
		Version:         Version,
		Iterations:      lib.Iterations,
		CompressionType: compressionType,
		Shares:          shares,
		Threshold:       threshold,
	}

	if _, err := rand.Read(h.Salt[:]); err != nil {
		return h, lib.CryptoErr(
			lib.CategoryContainer,
			lib.ErrCodeRandReadSaltError,
			lib.ErrMessageRandReadSaltError,
			"",
			err,
		)
	}

	if _, err := rand.Read(h.Nonce[:]); err != nil {
		return h, lib.CryptoErr(
			lib.CategoryContainer,
			lib.ErrCodeRandReadNonceError,
			lib.ErrMessageRandReadNonceError,
			"",
			err,
		)
	}

	copy(h.Signature[:], signature)

	return h, nil
}
