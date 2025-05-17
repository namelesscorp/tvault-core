package shamir

import (
	"bytes"
	"testing"

	"github.com/namelesscorp/tvault-core/secret"
)

func TestSplitCombine(t *testing.T) {
	secretData := []byte("supersecretdata123")
	sec := secret.New(secretData)

	macKey := []byte("thisis32byteslongmackeyforhmac!!")

	shares, err := Split(sec, 5, 3, macKey)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	if len(shares) != 5 {
		t.Fatalf("Expected 5 shares, got %d", len(shares))
	}

	subset := shares[:3]

	combined, err := Combine(subset, macKey)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	if !bytes.Equal(combined.Bytes(), secretData) {
		t.Errorf("Combined secret does not match original.\nGot:  %x\nWant: %x", combined.Bytes(), secretData)
	}
}

func TestMACMismatch(t *testing.T) {
	secretData := []byte("data")
	sec := secret.New(secretData)
	macKey := []byte("thisis32byteslongmackeyforhmac!!")

	shares, err := Split(sec, 3, 2, macKey)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	shares[0].MAC[0] ^= 0xFF

	_, err = Combine(shares[:2], macKey)
	if err == nil {
		t.Fatal("Expected MAC mismatch error, got nil")
	}
}

func TestInvalidParameters(t *testing.T) {
	sec := secret.New([]byte("data"))
	macKey := []byte("thisis32byteslongmackeyforhmac!!")

	if _, err := Split(sec, 5, 1, macKey); err == nil {
		t.Error("Expected error for threshold < 2, got nil")
	}

	if _, err := Split(sec, 5, 300, macKey); err == nil {
		t.Error("Expected error for threshold > 255, got nil")
	}

	if _, err := Split(sec, 2, 3, macKey); err == nil {
		t.Error("Expected error for n < t, got nil")
	}

	if _, err := Split(sec, 300, 3, macKey); err == nil {
		t.Error("Expected error for n > 255, got nil")
	}
}

func TestCombineWithLessThanTwoShares(t *testing.T) {
	sec := secret.New([]byte("data"))
	macKey := []byte("thisis32byteslongmackeyforhmac!!")

	shares, err := Split(sec, 3, 2, macKey)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	_, err = Combine(shares[:1], macKey)
	if err == nil {
		t.Error("Expected error for less than 2 shares, got nil")
	}
}
