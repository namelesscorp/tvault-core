package zip

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/namelesscorp/tvault-core/compression"
)

func TestNew(t *testing.T) {
	var z = New()
	if z.ID() != compression.TypeZip {
		t.Errorf("Expected compression ID to be %d, got %d", compression.TypeZip, z.ID())
	}
}

func TestZipID(t *testing.T) {
	var z = &zip{}
	if z.ID() != compression.TypeZip {
		t.Errorf("Expected compression ID to be %d, got %d", compression.TypeZip, z.ID())
	}
}

func TestZipPackUnpack(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "zip_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func(path string) {
		_ = os.RemoveAll(path)
	}(tempDir)

	testContent := []byte("test content")
	testFilePath := filepath.Join(tempDir, "test.txt")
	if err = os.WriteFile(testFilePath, testContent, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	subDir := filepath.Join(tempDir, "subdir")
	if err = os.MkdirAll(subDir, 0750); err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	subFileContent := []byte("subdir content")
	subFilePath := filepath.Join(subDir, "subfile.txt")
	if err = os.WriteFile(subFilePath, subFileContent, 0644); err != nil {
		t.Fatalf("Failed to write subdir file: %v", err)
	}

	z := New()
	packedData, err := z.Pack(tempDir)
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	if len(packedData) == 0 {
		t.Error("Expected non-empty packed data")
	}

	unpackDir, err := os.MkdirTemp("", "zip_unpack_test")
	if err != nil {
		t.Fatalf("Failed to create unpack dir: %v", err)
	}
	defer func(path string) {
		_ = os.RemoveAll(path)
	}(unpackDir)

	err = z.Unpack(packedData, unpackDir)
	if err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}

	unpackedTestFile := filepath.Join(unpackDir, "test.txt")
	unpackedContent, err := os.ReadFile(unpackedTestFile)
	if err != nil {
		t.Fatalf("Failed to read unpacked test file: %v", err)
	}

	if !bytes.Equal(unpackedContent, testContent) {
		t.Errorf("Unpacked content doesn't match original. Expected %q, got %q", testContent, unpackedContent)
	}

	unpackedSubFile := filepath.Join(unpackDir, "subdir", "subfile.txt")
	unpackedSubContent, err := os.ReadFile(unpackedSubFile)
	if err != nil {
		t.Fatalf("Failed to read unpacked subdir file: %v", err)
	}

	if !bytes.Equal(unpackedSubContent, subFileContent) {
		t.Errorf(
			"Unpacked subdir content doesn't match original. Expected %q, got %q",
			subFileContent,
			unpackedSubContent,
		)
	}
}

func TestZipUnpackError(t *testing.T) {
	var z = New()
	if err := z.Unpack([]byte("not a zip file"), ""); err == nil {
		t.Error("Expected error when unpacking invalid data, got nil")
	}
}

func TestZipPackError(t *testing.T) {
	var z = New()
	if _, err := z.Pack("/non/existent/directory"); err == nil {
		t.Error("Expected error when packing non-existent directory, got nil")
	}
}
