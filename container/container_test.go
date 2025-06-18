package container

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"time"
)

func TestContainerCreate(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		key          []byte
		compression  byte
		path         string
		expectedErr  error
		expectOutput bool
	}{
		{
			name:         "valid_data_and_key",
			data:         []byte("test data"),
			key:          make([]byte, 32),
			compression:  0,
			path:         "./test/vault.tvlt",
			expectedErr:  nil,
			expectOutput: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _ = rand.Read(tt.key)
			c := NewContainer(tt.path, Metadata{})

			masterKey, err := c.Create(tt.data, tt.key, tt.compression)
			if (err != nil) != (tt.expectedErr != nil) {
				t.Errorf("Create() = expected error: %v, got: %v", tt.expectedErr, err)
			}

			if (masterKey != nil) != tt.expectOutput {
				t.Errorf("unexpected masterKey value")
			}
		})
	}
}

func TestContainerOpen(t *testing.T) {
	validPath := "/test/vault.tvlt"
	defer func(name string) {
		_ = os.Remove(name)
	}(validPath)

	content := []byte("test content")
	metadata := Metadata{
		CreatedAt: time.Now(),
		Comment:   "test metadata",
	}
	header := Header{
		Signature:    [4]byte{'t', 'v', 'c', 't'},
		Version:      1,
		MetadataSize: uint32(len(content)),
	}
	file, _ := os.Create(validPath)
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	err := binary.Write(file, binary.LittleEndian, header)
	if err != nil {
		return
	}

	_, err = file.Write(content)
	if err != nil {
		return
	}

	tests := []struct {
		name        string
		path        string
		expectedErr error
	}{
		{
			name:        "valid_container_file",
			path:        validPath,
			expectedErr: nil,
		},
		{
			name:        "invalid_path",
			path:        "nonexistent_container",
			expectedErr: errors.New("open"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewContainer(tt.path, metadata).(*container)
			err := c.Open()
			if (err != nil) != (tt.expectedErr != nil) {
				t.Errorf("expected error: %v, got: %v", tt.expectedErr, err)
			}
		})
	}
}

func TestContainer_Decrypt(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	block, _ := aes.NewCipher(key)
	aesGcm, _ := cipher.NewGCM(block)

	nonce := make([]byte, aesGcm.NonceSize())
	_, _ = rand.Read(nonce)

	plaintext := []byte("test data")
	ciphertext := aesGcm.Seal(nil, nonce, plaintext, nil)

	c := &container{
		header: Header{
			Nonce: [12]byte{},
		},
		cipherData: ciphertext,
	}

	copy(c.header.Nonce[:], nonce)

	tests := []struct {
		name        string
		key         []byte
		expectedErr error
		expectedOut []byte
	}{
		{
			name:        "valid key",
			key:         key,
			expectedErr: nil,
			expectedOut: plaintext,
		},
		{
			name:        "invalid key",
			key:         make([]byte, 32),
			expectedErr: errors.New("open cipher text error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := c.Decrypt(tt.key)
			if (err != nil) != (tt.expectedErr != nil) {
				t.Errorf("expected error: %v, got: %v", tt.expectedErr, err)
			}
			if !bytes.Equal(data, tt.expectedOut) {
				t.Errorf("expected output: %v, got: %v", tt.expectedOut, data)
			}
		})
	}
}

func TestContainerGetters(t *testing.T) {
	cipherData := []byte{1, 2, 3, 4}
	header := Header{
		Signature: [4]byte{'t', 'v', 'c', 't'},
		Version:   1,
	}
	metadata := Metadata{
		CreatedAt: time.Now(),
		Comment:   "test metadata",
	}
	c := &container{
		cipherData: cipherData,
		header:     header,
		metadata:   metadata,
	}

	t.Run("get_cipher_data", func(t *testing.T) {
		if !bytes.Equal(c.GetCipherData(), cipherData) {
			t.Error("GetCipherData did not return expected data")
		}
	})

	t.Run("get_header", func(t *testing.T) {
		if c.GetHeader() != header {
			t.Error("GetHeader did not return expected header")
		}
	})

	t.Run("get_metadata", func(t *testing.T) {
		if c.GetMetadata() != metadata {
			t.Error("GetMetadata did not return expected metadata")
		}
	})
}
