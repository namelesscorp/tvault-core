package container

import (
	"bytes"
	"testing"
)

func TestHeader(t *testing.T) {
	t.Run("create header", func(t *testing.T) {
		var (
			compressionType = byte(1)
			providerType    = byte(2)
			tokenType       = byte(3)
			shares          = uint8(5)
			threshold       = uint8(3)
		)

		header, err := NewHeader(compressionType, providerType, tokenType, shares, threshold)
		if err != nil {
			t.Fatalf("Failed to create header: %v", err)
		}

		expectedSignature := [4]byte{'T', 'V', 'L', 'T'}
		if header.Signature != expectedSignature {
			t.Errorf("Expected Signature to be %v, got %v", expectedSignature, header.Signature)
		}

		if header.Version != Version {
			t.Errorf("Expected Version to be %d, got %d", Version, header.Version)
		}

		if header.CompressionType != compressionType {
			t.Errorf("Expected CompressionType to be %d, got %d", compressionType, header.CompressionType)
		}

		if header.IntegrityProviderType != providerType {
			t.Errorf("Expected ProviderType to be %d, got %d", providerType, header.IntegrityProviderType)
		}

		if header.TokenType != tokenType {
			t.Errorf("Expected TokenType to be %d, got %d", tokenType, header.TokenType)
		}

		if header.Shares != shares {
			t.Errorf("Expected Shares to be %d, got %d", shares, header.Shares)
		}

		if header.Threshold != threshold {
			t.Errorf("Expected Threshold to be %d, got %d", threshold, header.Threshold)
		}

		if bytes.Equal(header.Salt[:], make([]byte, 16)) {
			t.Errorf("Expected Salt to be non-zero, got all zeros")
		}

		if bytes.Equal(header.Nonce[:], make([]byte, 12)) {
			t.Errorf("Expected Nonce to be non-zero, got all zeros")
		}
	})

	t.Run("default values", func(t *testing.T) {
		header, err := NewHeader(0, 0, 0, 0, 0)
		if err != nil {
			t.Fatalf("Failed to create header: %v", err)
		}

		expectedSignature := [4]byte{'T', 'V', 'L', 'T'}
		if header.Signature != expectedSignature {
			t.Errorf("Expected Signature to be %v, got %v", expectedSignature, header.Signature)
		}

		if header.Version != Version {
			t.Errorf("Expected Version to be %d, got %d", Version, header.Version)
		}

		if bytes.Equal(header.Salt[:], make([]byte, 16)) {
			t.Errorf("Expected Salt to be non-zero, got all zeros")
		}

		if bytes.Equal(header.Nonce[:], make([]byte, 12)) {
			t.Errorf("Expected Nonce to be non-zero, got all zeros")
		}
	})
}
