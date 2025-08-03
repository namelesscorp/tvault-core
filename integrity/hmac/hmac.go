package hmac

import (
	cryptoHMAC "crypto/hmac"
	"crypto/sha256"

	"github.com/namelesscorp/tvault-core/integrity"
	"github.com/namelesscorp/tvault-core/lib"
)

type (
	hmac struct {
		key []byte
	}
)

func New(key []byte) integrity.Provider {
	return &hmac{
		key: key,
	}
}

// Sign - generates an HMAC signature for the given id and data using the hmac's secret key.
func (h *hmac) Sign(id byte, data []byte) ([]byte, error) {
	newHmac := cryptoHMAC.New(sha256.New, h.key)

	if _, err := newHmac.Write([]byte{id}); err != nil {
		return nil, lib.CryptoErr(
			lib.CategoryIntegrity,
			lib.ErrCodeHMACWriteIDError,
			lib.ErrMessageHMACWriteIDError,
			"",
			err,
		)
	}

	if _, err := newHmac.Write(data); err != nil {
		return nil, lib.CryptoErr(
			lib.CategoryIntegrity,
			lib.ErrCodeHMACWriteDataError,
			lib.ErrMessageHMACWriteDataError,
			"",
			err,
		)
	}

	var mac [32]byte
	copy(mac[:], newHmac.Sum(nil))

	return mac[:], nil
}

// IsVerify - verifies if the provided signature matches the expected HMAC for the given id and data, returning a boolean result.
func (h *hmac) IsVerify(id byte, data, signature []byte) (bool, error) {
	expectedMac, err := h.Sign(id, data)
	if err != nil {
		return false, lib.CryptoErr(
			lib.CategoryIntegrity,
			lib.ErrCodeHMACSignError,
			lib.ErrMessageHMACSignError,
			"",
			err,
		)
	}

	return cryptoHMAC.Equal(expectedMac, signature), nil
}

func (h *hmac) ID() byte {
	return integrity.TypeHMAC
}
