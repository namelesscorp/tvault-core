package hmac

import (
	"bytes"
	cyrptoHMAC "crypto/hmac"
	"crypto/sha256"
	"testing"
)

func TestSign(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		id        byte
		data      []byte
		expectErr bool
	}{
		{
			name:      "Valid key and data",
			key:       []byte("validkey"),
			id:        1,
			data:      []byte("testdata"),
			expectErr: false,
		},
		{
			name:      "Empty key",
			key:       []byte{},
			id:        2,
			data:      []byte("testdata"),
			expectErr: false,
		},
		{
			name:      "Empty data",
			key:       []byte("validkey"),
			id:        3,
			data:      []byte{},
			expectErr: false,
		},
		{
			name:      "Both key and data empty",
			key:       []byte{},
			id:        0,
			data:      []byte{},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &hmac{key: tt.key}
			signature, err := h.Sign(tt.id, tt.data)

			if (err != nil) != tt.expectErr {
				t.Errorf("Sign() error = %v, expectErr %v", err, tt.expectErr)
				return
			}

			if !tt.expectErr {
				newHmac := cyrptoHMAC.New(sha256.New, tt.key)
				newHmac.Write([]byte{tt.id})
				newHmac.Write(tt.data)
				expected := newHmac.Sum(nil)

				if !bytes.Equal(signature, expected) {
					t.Errorf("Sign() signature mismatch; got %x, expected %x", signature, expected)
				}
			}
		})
	}
}
