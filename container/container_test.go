package container

import (
	"bytes"
	"os"
	"testing"
	"time"
)

func TestContainer(t *testing.T) {
	t.Run("create container", func(t *testing.T) {
		tempFile, err := os.CreateTemp("", "container_test_*.tvlt")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer func(name string) {
			_ = os.Remove(name)
		}(tempFile.Name())

		_ = tempFile.Close()

		testData := []byte("test data for encryption")
		passphrase := []byte("test passphrase")

		now := time.Now()
		metadata := Metadata{
			CreatedAt: now,
			UpdatedAt: now,
			Comment:   "Test comment",
		}

		header, err := NewHeader(1, 1, 1, 3, 2)
		if err != nil {
			t.Fatalf("Failed to create header: %v", err)
		}

		cont := NewContainer(tempFile.Name(), nil, metadata, header)

		if cont.GetHeader().Version != Version {
			t.Errorf("Expected Version to be %d, got %d", Version, cont.GetHeader().Version)
		}

		if !cont.GetMetadata().CreatedAt.Equal(now) {
			t.Errorf("Expected CreatedAt to be %v, got %v", now, cont.GetMetadata().CreatedAt)
		}

		if cont.GetMetadata().Comment != "Test comment" {
			t.Errorf("Expected Comment to be %s, got %s", "Test comment", cont.GetMetadata().Comment)
		}

		err = cont.Encrypt(testData, passphrase)
		if err != nil {
			t.Fatalf("Failed to encrypt data: %v", err)
		}

		if len(cont.GetCipherData()) == 0 {
			t.Errorf("Expected cipherData to be non-empty")
		}

		err = cont.Write()
		if err != nil {
			t.Fatalf("Failed to write container: %v", err)
		}

		readContainer := NewContainer(tempFile.Name(), nil, Metadata{}, Header{})

		err = readContainer.Read()
		if err != nil {
			t.Fatalf("Failed to read container: %v", err)
		}

		if readContainer.GetHeader().Version != Version {
			t.Errorf("Expected Version to be %d, got %d", Version, readContainer.GetHeader().Version)
		}

		if !readContainer.GetMetadata().CreatedAt.Equal(now) {
			t.Errorf("Expected CreatedAt to be %v, got %v", now, readContainer.GetMetadata().CreatedAt)
		}

		if readContainer.GetMetadata().Comment != "Test comment" {
			t.Errorf("Expected Comment to be %s, got %s", "Test comment", readContainer.GetMetadata().Comment)
		}

		err = readContainer.Decrypt(cont.GetMasterKey())
		if err != nil {
			t.Fatalf("Failed to decrypt data: %v", err)
		}

		if !bytes.Equal(readContainer.GetData(), testData) {
			t.Errorf("Expected decrypted data to be %v, got %v", testData, readContainer.GetData())
		}
	})

	t.Run("setter methods", func(t *testing.T) {
		cont := NewContainer("", nil, Metadata{}, Header{})

		path := "/tmp/test.tvlt"
		cont.SetPath(path)

		key := []byte("test key")
		cont.SetMasterKey(key)
		if !bytes.Equal(cont.GetMasterKey(), key) {
			t.Errorf("Expected master key to be %v, got %v", key, cont.GetMasterKey())
		}

		now := time.Now()
		metadata := Metadata{
			CreatedAt: now,
			UpdatedAt: now,
			Comment:   "New comment",
		}

		cont.SetMetadata(metadata)
		if !cont.GetMetadata().CreatedAt.Equal(now) {
			t.Errorf("Expected CreatedAt to be %v, got %v", now, cont.GetMetadata().CreatedAt)
		}

		if cont.GetMetadata().Comment != "New comment" {
			t.Errorf("Expected Comment to be %s, got %s", "New comment", cont.GetMetadata().Comment)
		}
	})
}
