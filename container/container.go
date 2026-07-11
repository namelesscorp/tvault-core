package container

// Container implementation for Trust Vault Core (format v1).
// --------------------------------------------------------------
//
// +--------+-------+-------------------------------------------+
// | Offset | Size  | Field									    |
// +--------+-------+-------------------------------------------+
// | 0x00   | 4	  | "TVLT" signature						    |
// | 0x04   | 1	  | version								        |
// | 0x05   | 1	  | flags (reserved)						    |
// | 0x06   | 16  | salt (PBKDF2)						        |
// | 0x16   | 4	  | iterations (PBKDF2)					        |
// | 0x1A   | 1	  | compression type					     	|
// | 0x1B   | 1	  | integrity provider type				     	|
// | 0x1C   | 1	  | token type							        |
// | 0x1D   | 12  | nonce (AES-GCM)						        |
// | 0x29   | 4	  | metadata length						        |
// | 0x2D   | 1	  | shares								        |
// | 0x2E   | 1	  | threshold							        |
// | 0x2F   | N	  | metadata JSON (plaintext)			        |
// | 0x2F+N | ... | ciphertext + 16-byte GCM tag		        |
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
	"os"

	"github.com/namelesscorp/tvault-core/lib"
)

type (
	// Container - defines an interface for creating, opening, decrypting, and retrieving data from a container.
	Container interface {
		WriteEncrypted(r io.Reader, key []byte) error

		Read() error
		DecryptTo(w io.Writer, masterKey []byte) error

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
	if metadata.Comment == "" {
		metadata.Comment = defaultComment
	}

	return &container{
		path:      path,
		metadata:  metadata,
		masterKey: masterKey,
		header:    header,
	}
}

// WriteEncrypted - writes encrypted data to the container
func (c *container) WriteEncrypted(r io.Reader, key []byte) error {
	if len(c.masterKey) == 0 || c.masterKey == nil {
		c.masterKey = lib.PBKDF2Key(key, c.header.Salt[:], c.header.Iterations, lib.KeyLen)
	}

	block, err := aes.NewCipher(c.masterKey)
	if err != nil {
		return lib.CryptoErr(lib.CategoryContainer, lib.ErrCodeCreateNewCipherError, lib.ErrMessageCreateNewCipherError, "", err)
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return lib.CryptoErr(lib.CategoryContainer, lib.ErrCodeCreateNewGCMError, lib.ErrMessageCreateNewGCMError, "", err)
	}

	if _, err = io.ReadFull(rand.Reader, c.header.Nonce[:]); err != nil {
		return lib.CryptoErr(lib.CategoryContainer, lib.ErrCodeGenerateNonceError, lib.ErrMessageGenerateNonceError, "", err)
	}

	metaBytes, err := json.Marshal(c.metadata)
	if err != nil {
		return lib.IOErr(lib.CategoryContainer, lib.ErrCodeJSONMarshalMetadataError, lib.ErrMessageJSONMarshalMetadataError, "", err)
	}
	c.header.MetadataSize = uint32(len(metaBytes)) // #nosec G115

	f, err := os.OpenFile(c.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return lib.IOErr(lib.CategoryContainer, lib.ErrCodeContainerOpenFileError, lib.ErrMessageContainerOpenFileError, "", err)
	}
	defer func() {
		if errClose := f.Close(); errClose != nil {
			fmt.Printf("error closing file; %v", errClose)
		}
	}()

	if err = binary.Write(f, binary.LittleEndian, &c.header); err != nil {
		return lib.IOErr(lib.CategoryContainer, lib.ErrCodeWriteHeaderBinaryError, lib.ErrMessageWriteHeaderBinaryError, "", err)
	}
	if _, err = f.Write(metaBytes); err != nil {
		return lib.IOErr(lib.CategoryContainer, lib.ErrCodeWriteMetadataError, lib.ErrMessageWriteMetadataError, "", err)
	}

	var chunkSize = int(c.header.ChunkSize)
	if chunkSize <= 0 {
		chunkSize = 4 * 1024 * 1024
	}

	var (
		plainBuf        = make([]byte, chunkSize)
		counter  uint64 = 0
	)
	for {
		n, readErr := r.Read(plainBuf)
		if n > 0 {
			nonce := c.header.Nonce
			binary.LittleEndian.PutUint64(nonce[4:], counter)

			// nonce is a random prefix (crypto/rand, see header.Nonce) combined
			// with a per-chunk counter, so it is unique per chunk and not hardcoded.
			cipherChunk := aesGcm.Seal(nil, nonce[:], plainBuf[:n], nil) // #nosec G407

			// n is the number of bytes read into plainBuf, so 0 <= n <= chunkSize <= math.MaxUint32.
			chunkLen := uint32(n) // #nosec G115
			if err := binary.Write(f, binary.LittleEndian, chunkLen); err != nil {
				return lib.IOErr(lib.CategoryContainer, lib.ErrCodeWriteCipherTextError, lib.ErrMessageWriteCipherTextError, "", err)
			}
			if _, err := f.Write(cipherChunk); err != nil {
				return lib.IOErr(lib.CategoryContainer, lib.ErrCodeWriteCipherTextError, lib.ErrMessageWriteCipherTextError, "", err)
			}

			counter++
		}

		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return lib.IOErr(lib.CategoryContainer, lib.ErrCodeReadCipherTextError, lib.ErrMessageReadCipherTextError, "", readErr)
		}
	}

	if err := binary.Write(f, binary.LittleEndian, uint32(0)); err != nil {
		return lib.IOErr(lib.CategoryContainer, lib.ErrCodeWriteCipherTextError, lib.ErrMessageWriteCipherTextError, "", err)
	}

	return nil
}

// Read - reads encrypted data from the container
func (c *container) Read() error {
	f, err := os.Open(c.path)
	if err != nil {
		return lib.IOErr(lib.CategoryContainer, lib.ErrCodeContainerOpenFileError, lib.ErrMessageContainerOpenFileError, "", err)
	}
	defer func() {
		if errClose := f.Close(); errClose != nil {
			fmt.Printf("error closing file; %v", errClose)
		}
	}()

	if c.header, err = NewHeader(0, 0, 0, 0, 0); err != nil {
		return lib.IOErr(lib.CategoryContainer, lib.ErrCodeInitHeaderError, lib.ErrMessageInitHeaderError, "", err)
	}
	if err = binary.Read(f, binary.LittleEndian, &c.header); err != nil {
		return lib.IOErr(lib.CategoryContainer, lib.ErrCodeReadBinaryError, lib.ErrMessageReadBinaryError, "", err)
	}

	if string(c.header.Signature[:]) != signature {
		return lib.ErrInvalidContainerSignature
	}
	if c.header.Version != Version {
		return lib.ErrInvalidContainerVersion
	}

	metaBytes := make([]byte, c.header.MetadataSize)
	if _, err = io.ReadFull(f, metaBytes); err != nil {
		return lib.IOErr(lib.CategoryContainer, lib.ErrCodeReadMetadataError, lib.ErrMessageReadMetadataError, "", err)
	}

	if err = json.Unmarshal(metaBytes, &c.metadata); err != nil {
		return lib.IOErr(lib.CategoryContainer, lib.ErrCodeJSONUnmarshalMetadataError, lib.ErrMessageJSONUnmarshalMetadataError, "", err)
	}

	return nil
}

// DecryptTo - decrypts the container data and writes it to the provided writer
func (c *container) DecryptTo(w io.Writer, masterKey []byte) error {
	if len(c.masterKey) == 0 || c.masterKey == nil {
		c.masterKey = masterKey
	}

	block, err := aes.NewCipher(c.masterKey)
	if err != nil {
		return lib.CryptoErr(lib.CategoryContainer, lib.ErrCodeCreateNewCipherError, lib.ErrMessageCreateNewCipherError, "", err)
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return lib.CryptoErr(lib.CategoryContainer, lib.ErrCodeCreateNewGCMError, lib.ErrMessageCreateNewGCMError, "", err)
	}

	f, err := os.Open(c.path)
	if err != nil {
		return lib.IOErr(lib.CategoryContainer, lib.ErrCodeContainerOpenFileError, lib.ErrMessageContainerOpenFileError, "", err)
	}
	defer func() { _ = f.Close() }()

	headerSize := int64(binary.Size(Header{}))
	payloadOffset := headerSize + int64(c.header.MetadataSize)
	if _, err := f.Seek(payloadOffset, io.SeekStart); err != nil {
		return lib.IOErr(lib.CategoryContainer, lib.ErrCodeReadCipherTextError, lib.ErrMessageReadCipherTextError, "", err)
	}

	var counter uint64 = 0
	for {
		var plainLen uint32
		if err := binary.Read(f, binary.LittleEndian, &plainLen); err != nil {
			return lib.IOErr(lib.CategoryContainer, lib.ErrCodeReadCipherTextError, lib.ErrMessageReadCipherTextError, "", err)
		}
		if plainLen == 0 {
			break
		}

		cipherLen := int(plainLen) + aesGcm.Overhead()
		cipherBuf := make([]byte, cipherLen)
		if _, err := io.ReadFull(f, cipherBuf); err != nil {
			return lib.IOErr(lib.CategoryContainer, lib.ErrCodeReadCipherTextError, lib.ErrMessageReadCipherTextError, "", err)
		}

		nonce := c.header.Nonce
		binary.LittleEndian.PutUint64(nonce[4:], counter)

		plain, err := aesGcm.Open(nil, nonce[:], cipherBuf, nil)
		if err != nil {
			return lib.CryptoErr(lib.CategoryContainer, lib.ErrCodeOpenCipherTextError, lib.ErrMessageOpenCipherTextError, "", err)
		}

		if _, err := w.Write(plain); err != nil {
			return lib.IOErr(lib.CategoryContainer, lib.ErrCodeWriteCipherTextError, lib.ErrMessageWriteCipherTextError, "", err)
		}

		counter++
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
