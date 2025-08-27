package lib

import (
	"encoding/hex"
	"testing"
)

func TestPBKDF2Key(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		salt       []byte
		iterations uint32
		keyLen     uint32
		expected   func() []byte
	}{
		{
			name:       "valid_key_generation",
			data:       []byte("password"),
			salt:       []byte("salt"),
			iterations: Iterations,
			keyLen:     KeyLen,
			expected: func() []byte {
				key, _ := hex.DecodeString("0394a2ede332c9a13eb82e9b24631604c31df978b4e2f0fbd2c549944f9d79a5")
				return key
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PBKDF2Key(tt.data, tt.salt, tt.iterations, tt.keyLen)
			expected := tt.expected()

			if len(result) != len(expected) {
				t.Errorf("PBKDF2Key() len = %v, want %v", len(result), len(expected))
				return
			}

			for i := range result {
				if result[i] != expected[i] {
					t.Errorf("PBKDF2Key() = %v, want %v", result, expected)
					return
				}
			}
		})
	}
}
