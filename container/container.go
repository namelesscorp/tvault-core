package container

// Container implementation for Trust Vault Core (format v1).
// ----------------------------------------------------------------------
//
// +--------+-------+-------------------------------------------+
// | Offset | Size  | Field                                     |
// +--------+-------+-------------------------------------------+
// | 0x00   | 4     | "TVLT" signature                          |
// | 0x04   | 1     | version                                   |
// | 0x05   | 1     | flags (reserved)                          |
// | 0x06   | 16    | salt (PBKDF2)                             |
// | 0x16   | 4     | iterations (PBKDF2)                       |
// | 0x1A   | 1     | compression type                          |
// | 0x1B   | 12    | nonce (AES‑GCM)                           |
// | 0x27   | 4     | metadata length                           |
// | 0x2B   | N     | metadata JSON (plaintext)                 |
// | 0x2B+N | ...   | ciphertext + 16‑byte GCM tag              |
// +--------+-------+-------------------------------------------+
//

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"

	"github.com/namelesscorp/tvault-core/lib"
)

type (
	// Container - defines an interface for creating, opening, decrypting, and retrieving data from a container.
	Container interface {
		Create(data, key []byte, compressionType byte) (masterKey []byte, err error)

		Open() error
		Decrypt(key []byte) ([]byte, error)

		GetCipherData() []byte
		GetHeader() Header
		GetMetadata() Metadata
	}

	container struct {
		path       string
		cipherData []byte
		header     Header
		metadata   Metadata
	}
)

// NewContainer - creates a new instance of a container with the specified file path and metadata.
func NewContainer(path string, metadata Metadata) Container {
	return &container{
		path:     path,
		metadata: metadata,
	}
}

// Create - encrypts input data, storing it along with metadata and header to a specified file.
func (c *container) Create(data, key []byte, compressionType byte) ([]byte, error) {
	var (
		err error
	)
	if c.header, err = NewHeader(compressionType); err != nil {
		return nil, fmt.Errorf("init header error; %w", err)
	}

	// key derivation
	masterKey := lib.PBKDF2Key(key, c.header.Salt[:], int(c.header.Iterations), lib.KeyLen)

	// encrypt plaintext
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("create new cipher error; %w", err)
	}

	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create new gcm error; %w", err)
	}

	if _, err = io.ReadFull(rand.Reader, c.header.Nonce[:]); err != nil {
		return nil, fmt.Errorf("failed to generate noncel; %w", err)
	}

	ciphertext := aesGcm.Seal(nil, c.header.Nonce[:], data, nil) // #nosec G407

	var metaBytes []byte
	if metaBytes, err = json.Marshal(c.metadata); err != nil {
		return nil, fmt.Errorf("json marshal metadata error; %w", err)
	}

	if len(metaBytes) > math.MaxUint32 {
		return nil, fmt.Errorf("metadata size exceeds maximum allowed")
	}

	c.header.MetadataSize = uint32(len(metaBytes)) // #nosec G115

	var f *os.File
	if f, err = os.OpenFile(c.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err != nil {
		return nil, fmt.Errorf("open file error; %w", err)
	}
	defer func(f *os.File) {
		if err = f.Close(); err != nil {
			fmt.Printf("error closing file; %v", err)
		}
	}(f)

	if err = binary.Write(f, binary.LittleEndian, &c.header); err != nil {
		return nil, fmt.Errorf("write header binary error; %w", err)
	}

	if _, err = f.Write(metaBytes); err != nil {
		return nil, fmt.Errorf("write metadata error; %w", err)
	}

	if _, err = f.Write(ciphertext); err != nil {
		return nil, fmt.Errorf("write cipher text error; %w", err)
	}

	return masterKey, nil
}

// Open - reads, validates, and initializes container data from the specified file.
func (c *container) Open() error {
	f, err := os.Open(c.path)
	if err != nil {
		return err
	}
	defer func(f *os.File) {
		if err = f.Close(); err != nil {
			fmt.Printf("error closing file; %v", err)
		}
	}(f)

	// read header
	if c.header, err = NewHeader(0); err != nil {
		return fmt.Errorf("init header error; %w", err)
	}

	if err = binary.Read(f, binary.LittleEndian, &c.header); err != nil {
		return fmt.Errorf("read binary error; %w", err)
	}

	if string(c.header.Signature[:]) != signature {
		return lib.ErrInvalidContainerSignature
	}

	if c.header.Version != Version {
		return lib.ErrInvalidContainerVersion
	}

	// metadata
	metaBytes := make([]byte, c.header.MetadataSize)
	if _, err = io.ReadFull(f, metaBytes); err != nil {
		return fmt.Errorf("read metadata error; %w", err)
	}

	if err = json.Unmarshal(metaBytes, &c.metadata); err != nil {
		return fmt.Errorf("json unmarshal metadata; %w", err)
	}

	// ciphertext
	var ciphertext []byte
	if ciphertext, err = io.ReadAll(f); err != nil {
		return fmt.Errorf("read cipher text error; %w", err)
	}

	c.cipherData = ciphertext

	return nil
}

// Decrypt - decrypts the container's encrypted data using the provided key and returns the plaintext or an error.
func (c *container) Decrypt(key []byte) ([]byte, error) {
	// decrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create new cipher error; %w", err)
	}

	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create new gcm error; %w", err)
	}

	var data []byte
	if data, err = aesGcm.Open(nil, c.header.Nonce[:], c.cipherData, nil); err != nil {
		return nil, fmt.Errorf("open cipher text error; %w", err)
	}

	return data, err
}

// GetHeader - returns the Header associated with the container.
func (c *container) GetHeader() Header {
	return c.header
}

// GetMetadata - returns the Metadata associated with the container. The Metadata contains unencrypted arbitrary information.
func (c *container) GetMetadata() Metadata {
	return c.metadata
}

// GetCipherData - returns the encrypted cipher data stored in the container.
func (c *container) GetCipherData() []byte {
	return c.cipherData
}
