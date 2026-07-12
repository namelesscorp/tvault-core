package container

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"testing"
	"time"
)

func TestContainerCreate(t *testing.T) {
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

	err = cont.WriteEncrypted(bytes.NewReader(testData), passphrase)
	if err != nil {
		t.Fatalf("Failed to write encrypted data: %v", err)
	}

	if len(cont.GetMasterKey()) == 0 {
		t.Errorf("Expected master key to be non-empty")
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

	var decrypted bytes.Buffer
	err = readContainer.DecryptTo(&decrypted, cont.GetMasterKey())
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	if !bytes.Equal(decrypted.Bytes(), testData) {
		t.Errorf("Expected decrypted data to be %v, got %v", testData, decrypted.Bytes())
	}
}

func TestContainerReadRejectsOversizedMetadataSize(t *testing.T) {
	tempFile, err := os.CreateTemp("", "container_hostile_*.tvlt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func(name string) {
		_ = os.Remove(name)
	}(tempFile.Name())

	// Craft a valid-looking header whose MetadataSize claims more than the
	// cap. A hostile container would use this to force a huge allocation in
	// Read before any bytes are actually read from disk.
	header, err := NewHeader(1, 1, 1, 3, 2)
	if err != nil {
		t.Fatalf("Failed to create header: %v", err)
	}
	header.MetadataSize = MaxMetadataSize + 1

	if err = binary.Write(tempFile, binary.LittleEndian, &header); err != nil {
		t.Fatalf("Failed to write header: %v", err)
	}
	if err = tempFile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	cont := NewContainer(tempFile.Name(), nil, Metadata{}, Header{})
	if err = cont.Read(); err == nil {
		t.Fatal("Expected Read to reject oversized metadata size, got nil error")
	}
}

func TestContainerCompressedSizeIsRecorded(t *testing.T) {
	tempFile, err := os.CreateTemp("", "container_size_*.tvlt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func(name string) { _ = os.Remove(name) }(tempFile.Name())
	_ = tempFile.Close()

	header, err := NewHeader(1, 1, 1, 3, 2)
	if err != nil {
		t.Fatalf("Failed to create header: %v", err)
	}

	payload := bytes.Repeat([]byte("x"), 40000)
	cont := NewContainer(tempFile.Name(), nil, Metadata{Comment: "size"}, header)
	if err = cont.WriteEncrypted(bytes.NewReader(payload), []byte("pw")); err != nil {
		t.Fatalf("Failed to write container: %v", err)
	}

	// In-memory metadata is patched to the real compressed size.
	if got := cont.GetMetadata().CompressedSize; got != int64(len(payload)) {
		t.Errorf("Expected in-memory CompressedSize %d, got %d", len(payload), got)
	}

	// And it must persist / round-trip through Read (metadata stays valid JSON
	// despite the space padding used to keep MetadataSize constant).
	rc := NewContainer(tempFile.Name(), nil, Metadata{}, Header{})
	if err = rc.Read(); err != nil {
		t.Fatalf("Failed to read container: %v", err)
	}
	if got := rc.GetMetadata().CompressedSize; got != int64(len(payload)) {
		t.Errorf("Expected persisted CompressedSize %d, got %d", len(payload), got)
	}
	if rc.GetMetadata().Comment != "size" {
		t.Errorf("Metadata did not round-trip: comment = %q", rc.GetMetadata().Comment)
	}
}

func TestContainerDecryptRejectsOversizedChunkSize(t *testing.T) {
	tempFile, err := os.CreateTemp("", "container_chunk_*.tvlt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func(name string) { _ = os.Remove(name) }(tempFile.Name())
	_ = tempFile.Close()

	header, err := NewHeader(1, 1, 1, 3, 2)
	if err != nil {
		t.Fatalf("Failed to create header: %v", err)
	}

	cont := NewContainer(tempFile.Name(), nil, Metadata{Comment: "chunk"}, header)
	if err = cont.WriteEncrypted(bytes.NewReader([]byte("some payload data")), []byte("pass")); err != nil {
		t.Fatalf("Failed to write container: %v", err)
	}
	masterKey := cont.GetMasterKey()

	// Reopen to load the on-disk header, then overwrite the first chunk's
	// length prefix with a value beyond MaxChunkSize to simulate a hostile
	// container. Decrypt must reject it before allocating.
	rc := NewContainer(tempFile.Name(), nil, Metadata{}, Header{})
	if err = rc.Read(); err != nil {
		t.Fatalf("Failed to read container: %v", err)
	}

	f, err := os.OpenFile(tempFile.Name(), os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("Failed to open for corruption: %v", err)
	}
	payloadOffset := int64(binary.Size(Header{})) + int64(rc.GetHeader().MetadataSize)
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], MaxChunkSize+1)
	if _, err = f.WriteAt(lenBuf[:], payloadOffset); err != nil {
		t.Fatalf("Failed to write oversized chunk length: %v", err)
	}
	_ = f.Close()

	if err = rc.DecryptTo(io.Discard, masterKey); err == nil {
		t.Fatal("Expected DecryptTo to reject oversized chunk size, got nil error")
	}
}

func TestContainerSetterMethods(t *testing.T) {
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
}
