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
			name:          "valid_token_valid_key",
			token:         validToken,
			key:           validKey,
			expectedToken: "Hcs99tW7ABnhKNhj+wYYAnqUkOzAXFUZVxJtO8HFOA==",
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
