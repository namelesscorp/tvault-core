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
// | 0x2F   | 4	  | chunk size (plaintext bytes)			        |
// | 0x33   | N	  | metadata JSON (plaintext)			        |
// | 0x33+N | ... | length-prefixed AES-GCM chunks		        |
// +--------+-------+-------------------------------------------+
//
// The payload is a sequence of chunks, each a little-endian uint32 plaintext
// length followed by that chunk's ciphertext + 16-byte GCM tag, terminated by
// a uint32(0) length. Each chunk reuses the base nonce with a per-chunk
// counter in bytes nonce[4:].
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
		WriteEncrypted(r io.Reader, key []byte) error

		Read() error
		DecryptTo(w io.Writer, masterKey []byte) error

		GetHeader() Header
		GetMetadata() Metadata
		GetMasterKey() []byte

		SetPath(path string)
		SetMasterKey(key []byte)
		SetMetadata(metadata Metadata)
	}

	container struct {
		path      string
		header    Header
		metadata  Metadata
		masterKey []byte
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

	// The compressed size is only known once the whole stream has been consumed,
	// but the metadata is written before the payload. Marshal it with the widest
	// possible CompressedSize so the field can be patched in place afterwards
	// without changing the metadata length (see patch below the streaming loop).
	c.metadata.CompressedSize = math.MaxInt64
	metaBytes, err := json.Marshal(c.metadata)
	if err != nil {
		return lib.IOErr(lib.CategoryContainer, lib.ErrCodeJSONMarshalMetadataError, lib.ErrMessageJSONMarshalMetadataError, "", err)
	}
	metadataSize := len(metaBytes)
	c.header.MetadataSize = uint32(metadataSize) // #nosec G115

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
		plainBuf = make([]byte, chunkSize)
		// Reused across chunks so Seal does not allocate a fresh ciphertext
		// slice every iteration. Capacity holds a full chunk plus the GCM tag.
		cipherBuf        = make([]byte, 0, chunkSize+aesGcm.Overhead())
		lenBuf           = make([]byte, 4)
		counter   uint64 = 0
		// Total plaintext (i.e. compressed archive) bytes consumed from the
		// stream; patched into the metadata's CompressedSize once known.
		compressedSize int64 = 0
	)
	for {
		// io.ReadFull coalesces the many small reads returned by the unbuffered
		// source pipe (archive/zip+flate flushes in small blocks) into a full
		// chunkSize block. Without it, each tiny read became its own AES-GCM
		// chunk with a 16-byte tag + 4-byte length, producing hundreds of
		// thousands of chunks and allocations for large inputs.
		n, readErr := io.ReadFull(r, plainBuf)
		if n > 0 {
			nonce := c.header.Nonce
			binary.LittleEndian.PutUint64(nonce[4:], counter)

			// nonce is a random prefix (crypto/rand, see header.Nonce) combined
			// with a per-chunk counter, so it is unique per chunk and not hardcoded.
			cipherChunk := aesGcm.Seal(cipherBuf[:0], nonce[:], plainBuf[:n], nil) // #nosec G407

			// n is the number of bytes read into plainBuf, so 0 <= n <= chunkSize <= math.MaxUint32.
			binary.LittleEndian.PutUint32(lenBuf, uint32(n)) // #nosec G115
			if _, err := f.Write(lenBuf); err != nil {
				return lib.IOErr(lib.CategoryContainer, lib.ErrCodeWriteCipherTextError, lib.ErrMessageWriteCipherTextError, "", err)
			}
			if _, err := f.Write(cipherChunk); err != nil {
				return lib.IOErr(lib.CategoryContainer, lib.ErrCodeWriteCipherTextError, lib.ErrMessageWriteCipherTextError, "", err)
			}

			compressedSize += int64(n)
			counter++
		}

		if readErr != nil {
			// EOF (clean end) and ErrUnexpectedEOF (final short chunk) both mean
			// the stream is fully consumed; anything else is a real read error.
			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				break
			}
			return lib.IOErr(lib.CategoryContainer, lib.ErrCodeReadCipherTextError, lib.ErrMessageReadCipherTextError, "", readErr)
		}
	}

	if err := binary.Write(f, binary.LittleEndian, uint32(0)); err != nil {
		return lib.IOErr(lib.CategoryContainer, lib.ErrCodeWriteCipherTextError, lib.ErrMessageWriteCipherTextError, "", err)
	}

	// Patch the now-known CompressedSize back into the metadata. The reserved
	// marshal above used math.MaxInt64, the widest decimal value, so the real
	// value is never longer; pad the remainder with spaces (which json.Unmarshal
	// ignores) to keep MetadataSize and the payload offset unchanged.
	c.metadata.CompressedSize = compressedSize
	patched, err := json.Marshal(c.metadata)
	if err != nil {
		return lib.IOErr(lib.CategoryContainer, lib.ErrCodeJSONMarshalMetadataError, lib.ErrMessageJSONMarshalMetadataError, "", err)
	}
	if len(patched) > metadataSize {
		return lib.IOErr(lib.CategoryContainer, lib.ErrCodeWriteMetadataError, lib.ErrMessageWriteMetadataError, "", nil)
	}
	for len(patched) < metadataSize {
		patched = append(patched, ' ')
	}
	if _, err = f.WriteAt(patched, int64(binary.Size(c.header))); err != nil {
		return lib.IOErr(lib.CategoryContainer, lib.ErrCodeWriteMetadataError, lib.ErrMessageWriteMetadataError, "", err)
	}

	// Flush the file contents to stable storage before returning so a subsequent
	// atomic rename cannot expose a container whose data was lost to a power
	// failure still sitting in the OS page cache.
	if err := f.Sync(); err != nil {
		return lib.IOErr(lib.CategoryContainer, lib.ErrCodeContainerSyncFileError, lib.ErrMessageContainerSyncFileError, "", err)
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

	if c.header.MetadataSize > MaxMetadataSize {
		return lib.FormatErr(lib.CategoryContainer, lib.ErrCodeMetadataSizeExceedsError, lib.ErrMessageMetadataSizeExceedsError, "", nil)
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

	var (
		// Buffers reused across chunks so each iteration does not allocate a
		// fresh ciphertext/plaintext slice; they grow on demand and are then
		// retained for subsequent same-size chunks (the common case).
		lenBuf    = make([]byte, 4)
		cipherBuf []byte
		plainBuf  []byte
		counter   uint64 = 0
	)
	for {
		if _, err := io.ReadFull(f, lenBuf); err != nil {
			return lib.IOErr(lib.CategoryContainer, lib.ErrCodeReadCipherTextError, lib.ErrMessageReadCipherTextError, "", err)
		}
		plainLen := binary.LittleEndian.Uint32(lenBuf)
		if plainLen == 0 {
			break
		}
		// plainLen is read from an untrusted file; reject an over-large chunk
		// before allocating so a hostile header cannot force a huge allocation.
		if plainLen > MaxChunkSize {
			return lib.FormatErr(lib.CategoryContainer, lib.ErrCodeChunkSizeExceedsError, lib.ErrMessageChunkSizeExceedsError, "", nil)
		}

		cipherLen := int(plainLen) + aesGcm.Overhead()
		if cap(cipherBuf) < cipherLen {
			cipherBuf = make([]byte, cipherLen)
		}
		cipherBuf = cipherBuf[:cipherLen]
		if _, err := io.ReadFull(f, cipherBuf); err != nil {
			return lib.IOErr(lib.CategoryContainer, lib.ErrCodeReadCipherTextError, lib.ErrMessageReadCipherTextError, "", err)
		}

		nonce := c.header.Nonce
		binary.LittleEndian.PutUint64(nonce[4:], counter)

		// Decrypt into plainBuf (distinct from cipherBuf, so no overlap); retain
		// the possibly-grown backing array for the next chunk.
		plain, err := aesGcm.Open(plainBuf[:0], nonce[:], cipherBuf, nil)
		if err != nil {
			return lib.CryptoErr(lib.CategoryContainer, lib.ErrCodeOpenCipherTextError, lib.ErrMessageOpenCipherTextError, "", err)
		}
		plainBuf = plain

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
