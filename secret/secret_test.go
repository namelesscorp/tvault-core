package secret

import (
	"bytes"
	"testing"
)

func TestNew(t *testing.T) {
	data := []byte("super-secret")
	sec := New(data)

	if sec.Len() != len(data) {
		t.Errorf("expected length %d, got %d", len(data), sec.Len())
	}

	b := sec.Bytes()
	if !bytes.Equal(b, data) {
		t.Error("bytes mismatch")
	}
	if &b[0] == &data[0] {
		t.Error("should not return reference to original data")
	}
}

func TestEqual(t *testing.T) {
	sec := New([]byte("secret"))
	if !sec.Equal([]byte("secret")) {
		t.Error("expected secrets to be equal")
	}

	if sec.Equal([]byte("SECRET")) {
		t.Error("expected secrets to differ")
	}

	if sec.Equal(nil) {
		t.Error("expected comparison with nil to be false")
	}
}

func TestDestroy(t *testing.T) {
	data := []byte("test_destroy_secret")
	sec := New(data)

	sec.Destroy()
	if !sec.IsDestroyed() {
		t.Error("expected secret to be destroyed")
	}

	if sec.Len() != 0 {
		t.Error("expected zero length after destroy")
	}

	if out := sec.Bytes(); len(out) != 0 {
		t.Error("expected empty bytes after destroy")
	}

	if sec.Equal([]byte("test_destroy_secret")) {
		t.Error("expected comparison to fail after destroy")
	}

	sec.Destroy()
}
