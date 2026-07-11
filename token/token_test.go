package token

import (
	"crypto/aes"
	"encoding/base64"
	"testing"
)

func TestBuild(t *testing.T) {
	validKey := make([]byte, aes.BlockSize)
	validToken := Token{Version: 1, ID: 123, Value: "example"}

	tests := []struct {
		name          string
		token         Token
		key           []byte
		expectedToken string
		expectedErr   bool
	}{
		{
			name:          "valid_token_no_key",
			token:         validToken,
			key:           nil,
			expectedToken: base64.StdEncoding.EncodeToString([]byte(`{"v":1,"id":123,"vl":"example"}`)),
			expectedErr:   false,
		},
		{
			// With a random IV the ciphertext is non-deterministic, so this case
			// is verified via round-trip below instead of a fixed expected value.
			name:          "valid_token_valid_key",
			token:         validToken,
			key:           validKey,
			expectedToken: "",
			expectedErr:   false,
		},
		{
			name:          "invalid_key",
			token:         validToken,
			key:           []byte("short"),
			expectedToken: "",
			expectedErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Build(tt.token, tt.key)
			if err == nil && tt.expectedErr {
				t.Errorf("Build() error = %v", err)
			}
			if tt.expectedErr {
				return
			}

			// Encrypted output uses a random IV, so verify it round-trips back to
			// the original token instead of matching a fixed ciphertext.
			if tt.key != nil {
				parsed, parseErr := Parse([]byte(base64.StdEncoding.EncodeToString(got)), tt.key)
				if parseErr != nil {
					t.Errorf("Parse() error = %v", parseErr)
				}
				if parsed != tt.token {
					t.Errorf("round-trip = %v, want %v", parsed, tt.token)
				}
				return
			}

			base64Got := base64.StdEncoding.EncodeToString(got)
			if base64Got != tt.expectedToken {
				t.Errorf("Build() = %v, want %v", base64Got, tt.expectedToken)
			}
		})
	}
}

func TestParse(t *testing.T) {
	validKey := make([]byte, aes.BlockSize)
	validToken := Token{Version: 1, ID: 123, Value: "example"}
	encrypted, _ := Build(validToken, validKey)
	base64Encrypted := base64.StdEncoding.EncodeToString(encrypted)

	tests := []struct {
		name        string
		payload     string
		key         []byte
		want        Token
		expectedErr bool
	}{
		{
			name:        "valid_token_with_key",
			payload:     base64Encrypted,
			key:         validKey,
			want:        validToken,
			expectedErr: false,
		},
		{
			name:        "valid_token_no_key",
			payload:     base64.StdEncoding.EncodeToString([]byte(`{"v":1,"id":123,"t":2,"vl":"example","pid":45}`)),
			key:         nil,
			want:        validToken,
			expectedErr: false,
		},
		{
			name:        "invalid_base64_data",
			payload:     "invalid_base64",
			key:         validKey,
			want:        Token{},
			expectedErr: true,
		},
		{
			name:        "decryption_error",
			payload:     base64Encrypted,
			key:         []byte("wrongkey12345678"),
			want:        Token{},
			expectedErr: true,
		},
		{
			name:        "invalid_json",
			payload:     base64.StdEncoding.EncodeToString([]byte("not valid json")),
			key:         validKey,
			want:        Token{},
			expectedErr: true,
		},
		{
			name:        "invalid_version",
			payload:     base64.StdEncoding.EncodeToString([]byte(`{"v":99,"id":123,"t":2,"vl":"example","pid":45}`)),
			key:         nil,
			want:        Token{},
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse([]byte(tt.payload), tt.key)
			if err == nil && tt.expectedErr {
				t.Errorf("Parse() error = %v", err)
			}

			if err == nil && got != tt.want {
				t.Errorf("Parse() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestParseDetectsTampering is the core AEAD guarantee that AES-CTR lacked:
// any modification of the encrypted token envelope (format byte, nonce,
// ciphertext or tag) must be detected and rejected before the JSON is trusted.
func TestParseDetectsTampering(t *testing.T) {
	key := make([]byte, aes.BlockSize)
	tok := Token{Version: 1, ID: 7, Value: "secret"}

	built, err := Build(tok, key)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// Baseline: the unmodified token round-trips cleanly.
	if _, err := Parse([]byte(base64.StdEncoding.EncodeToString(built)), key); err != nil {
		t.Fatalf("baseline parse: %v", err)
	}

	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{
			name:   "flipped ciphertext/tag byte",
			mutate: func(b []byte) { b[len(b)-1] ^= 0xFF },
		},
		{
			name:   "flipped format byte",
			mutate: func(b []byte) { b[0] ^= 0xFF },
		},
		{
			name:   "flipped nonce byte",
			mutate: func(b []byte) { b[1] ^= 0xFF },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tampered := make([]byte, len(built))
			copy(tampered, built)
			tt.mutate(tampered)

			if _, err := Parse([]byte(base64.StdEncoding.EncodeToString(tampered)), key); err == nil {
				t.Fatal("expected tampering to be rejected, got nil error")
			}
		})
	}

	t.Run("truncated envelope", func(t *testing.T) {
		short := built[:len(built)-1]
		if _, err := Parse([]byte(base64.StdEncoding.EncodeToString(short)), key); err == nil {
			t.Fatal("expected truncated envelope to be rejected, got nil error")
		}
	})
}

func TestBuildAndParseIntegration(t *testing.T) {
	validKey := make([]byte, aes.BlockSize)
	validToken := Token{Version: 1, ID: 123, Value: "example"}

	encrypted, err := Build(validToken, validKey)
	if err != nil {
		t.Fatalf("Failed to build token: %v", err)
	}

	base64Encoded := base64.StdEncoding.EncodeToString(encrypted)

	decodedToken, err := Parse([]byte(base64Encoded), validKey)
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	if decodedToken != validToken {
		t.Errorf("Integration test failed: got %v, want %v", decodedToken, validToken)
	}
}
