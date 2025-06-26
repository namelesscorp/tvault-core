package hmac

import (
	cryptoHMAC "crypto/hmac"
	"crypto/sha256"

	"github.com/namelesscorp/tvault-core/integrity"
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

func (h *hmac) Sign(id byte, data []byte) ([]byte, error) {
	newHmac := cryptoHMAC.New(sha256.New, h.key)
	newHmac.Write([]byte{id})
	newHmac.Write(data)

	var mac [32]byte
	copy(mac[:], newHmac.Sum(nil))

	return mac[:], nil
}

func (h *hmac) IsVerify(id byte, data, signature []byte) (bool, error) {
	expectedMac, err := h.Sign(id, data)
	if err != nil {
		return false, err
	}

	return cryptoHMAC.Equal(expectedMac, signature), nil
}

func (h *hmac) ID() byte {
	return integrity.TypeHMAC
}
