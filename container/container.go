package container

// Container implementation for Trust Vault Core (format v1).
// --------------------------------------------------------------
//
// +--------+-------+-------------------------------------------+
// | Offset | Size  | Field									    |
// +--------+-------+-------------------------------------------+
// | 0x00   | 4	  | "TVLT" signature					        |
// | 0x04   | 1	  | version								        |
// | 0x05   | 1	  | flags (reserved)			     	        |
// | 0x06   | 16  | salt (PBKDF2)						        |
// | 0x16   | 4	  | iterations (PBKDF2)					        |
// | 0x1A   | 1	  | compression type				            |
// | 0x1B   | 12  | nonce (AES‑GCM)					            |
// | 0x27   | 4   | metadata length						        |
// | 0x2B   | 1	  | shares								        |
// | 0x2C   | 1	  | threshold								    |
// | 0x2D   | N	  | metadata JSON (plaintext)				    |
// | 0x2D+N | ... | ciphertext + 16‑byte GCM tag			    |
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
		Encrypt(data, key []byte) error
		Write() error

		Read() error
		Decrypt(masterKey []byte) error

		GetCipherData() []byte
		GetHeader() Header
		GetMetadata() Metadata
		GetData() []byte
		GetMasterKey() []byte

		SetPath(path string)
		SetMasterKey(key []byte)
		SetMetadata(metadata Metadata)
	}

	container struct {
		path       string
		cipherData []byte
		data       []byte
		header     Header
		metadata   Metadata
		masterKey  []byte
	}
)

func NewContainer(
	path string,
	masterKey []byte,
	metadata Metadata,
	header Header,
) Container {
	return &container{
		path:      path,
		metadata:  metadata,
		masterKey: masterKey,
		header:    header,
	}
}

// Encrypt encrypts the provided plaintext `data` using a derived AES-GCM key generated from the given `key`.
// This method initializes the `main key`, generates nonce, seals the data, and stores the ciphertext in `cipherData`.
func (c *container) Encrypt(data, key []byte) error {
	if len(c.masterKey) == 0 || c.masterKey == nil {
		// key derivation
		c.masterKey = lib.PBKDF2Key(key, c.header.Salt[:], int(c.header.Iterations), lib.KeyLen)
	}

	// seal plaintext
	block, err := aes.NewCipher(c.masterKey)
	if err != nil {
		return fmt.Errorf("create new cipher error; %w", err)
	}

	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create new gcm error; %w", err)
	}

	if _, err = io.ReadFull(rand.Reader, c.header.Nonce[:]); err != nil {
		return fmt.Errorf("failed to generate noncel; %w", err)
	}

	c.cipherData = aesGcm.Seal(nil, c.header.Nonce[:], data, nil) // #nosec G407

	return nil
}

// Write - writes the encrypted data, metadata, header of the container to the specified file path.
func (c *container) Write() error {
	var (
		f   *os.File
		err error
	)
	if f, err = os.OpenFile(c.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err != nil {
		return fmt.Errorf("open file error; %w", err)
	}
	defer func(f *os.File) {
		if err = f.Close(); err != nil {
			fmt.Printf("error closing file; %v", err)
		}
	}(f)

	var metaBytes []byte
	if metaBytes, err = json.Marshal(c.metadata); err != nil {
		return fmt.Errorf("json marshal metadata error; %w", err)
	}

	if len(metaBytes) > math.MaxUint32 {
		return fmt.Errorf("metadata size exceeds maximum allowed")
	}

	c.header.MetadataSize = uint32(len(metaBytes)) // #nosec G115

	if err = binary.Write(f, binary.LittleEndian, &c.header); err != nil {
		return fmt.Errorf("write header binary error; %w", err)
	}

	if _, err = f.Write(metaBytes); err != nil {
		return fmt.Errorf("write metadata error; %w", err)
	}

	if _, err = f.Write(c.cipherData); err != nil {
		return fmt.Errorf("write cipher text error; %w", err)
	}

	return nil
}

// Read - reads, validates, and initializes container data from the specified file.
func (c *container) Read() error {
	f, err := os.Open(c.path)
	if err != nil {
		return err
	}
	defer func(f *os.File) {
		if err = f.Close(); err != nil {
			fmt.Printf("error closing file; %v", err)
		}
	}(f)

	if c.header, err = NewHeader(0, 0, 0); err != nil {
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

	metaBytes := make([]byte, c.header.MetadataSize)
	if _, err = io.ReadFull(f, metaBytes); err != nil {
		return fmt.Errorf("read metadata error; %w", err)
	}

	if err = json.Unmarshal(metaBytes, &c.metadata); err != nil {
		return fmt.Errorf("json unmarshal metadata; %w", err)
	}

	var ciphertext []byte
	if ciphertext, err = io.ReadAll(f); err != nil {
		return fmt.Errorf("read cipher text error; %w", err)
	}

	c.cipherData = ciphertext

	return nil
}

// Decrypt - decrypts the container's cipherData using the provided masterKey and initializes the decrypted data in memory.
func (c *container) Decrypt(masterKey []byte) error {
	if len(c.masterKey) == 0 || c.masterKey == nil {
		c.masterKey = masterKey
	}

	// unseal
	block, err := aes.NewCipher(c.masterKey)
	if err != nil {
		return fmt.Errorf("create new cipher error; %w", err)
	}

	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create new gcm error; %w", err)
	}

	if c.data, err = aesGcm.Open(nil, c.header.Nonce[:], c.cipherData, nil); err != nil {
		return fmt.Errorf("open cipher text error; %w", err)
	}

	return nil
}

// GetHeader - returns the Header associated with the container.
func (c *container) GetHeader() Header {
	return c.header
}

// GetMetadata - returns the Metadata associated with the container.
// The Metadata contains unencrypted arbitrary information.
func (c *container) GetMetadata() Metadata {
	return c.metadata
}

// GetCipherData - returns the encrypted cipher data stored in the container.
func (c *container) GetCipherData() []byte {
	return c.cipherData
}

// GetData - returns the decrypted data.
func (c *container) GetData() []byte {
	return c.data
}

// GetMasterKey - return master key used for decrypting container.
func (c *container) GetMasterKey() []byte {
	return c.masterKey
}

// SetPath - sets the file path for the container where it can read or write data.
func (c *container) SetPath(path string) {
	c.path = path
}

// SetMasterKey - sets the master key used for decrypting the container.
func (c *container) SetMasterKey(key []byte) {
	c.masterKey = key
}

// SetMetadata - sets the Metadata associated with the container.
func (c *container) SetMetadata(metadata Metadata) {
	c.metadata = metadata
}
