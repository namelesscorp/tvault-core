package container

import (
	"bytes"
	"testing"

	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/lib"
)

func TestNewHeader(t *testing.T) {
	t.Run("init new header", func(t *testing.T) {
		header, err := NewHeader(compression.TypeZip)
		if err != nil {
			t.Fatalf("NewHeader() error: %v", err)
		}

		if !bytes.Equal(header.Signature[:], []byte(signature)) {
			t.Errorf("Expected Signature: %s, got: %s", signature, header.Signature)
		}

		if header.Version != Version {
			t.Errorf("Expected Version: %d, got: %d", Version, header.Version)
		}

		if header.Iterations != lib.Iterations {
			t.Errorf("Expected Iterations: %d, got: %d", lib.Iterations, header.Iterations)
		}

		if header.CompressionType != compression.TypeZip {
			t.Errorf("Expected compression type: %d, got: %d", compression.TypeZip, header.CompressionType)
		}

		if isAllZeros(header.Salt[:]) {
			t.Error("Salt was not properly initialized")
		}

		if isAllZeros(header.Nonce[:]) {
			t.Error("Nonce was not properly initialized")
		}
	})
}

func isAllZeros(data []byte) bool {
	for _, v := range data {
		if v != 0 {
			return false
		}
	}

	return true
}
