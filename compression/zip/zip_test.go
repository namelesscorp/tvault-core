package zip

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/namelesscorp/tvault-core/compression"
)

func TestNew(t *testing.T) {
	z := New()

	if z == nil {
		t.Error("Expected non-nil zip compression, got nil")
	}

	if z.ID() != compression.TypeZip {
		t.Errorf("Expected compression ID to be %d, got %d", compression.TypeZip, z.ID())
	}
}

func TestZipID(t *testing.T) {
	z := &zip{}

	if z.ID() != compression.TypeZip {
		t.Errorf("Expected compression ID to be %d, got %d", compression.TypeZip, z.ID())
	}
}

func TestZipPackUnpack(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := ioutil.TempDir("", "zip_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test file in the temp directory
	testContent := []byte("test content")
	testFilePath := filepath.Join(tempDir, "test.txt")
	if err := ioutil.WriteFile(testFilePath, testContent, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Create a subdirectory with a file
	subDir := filepath.Join(tempDir, "subdir")
	if err := os.MkdirAll(subDir, 0750); err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	subFileContent := []byte("subdir content")
	subFilePath := filepath.Join(subDir, "subfile.txt")
	if err := ioutil.WriteFile(subFilePath, subFileContent, 0644); err != nil {
		t.Fatalf("Failed to write subdir file: %v", err)
	}

	// Test Pack
	z := New()
	packedData, err := z.Pack(tempDir)
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	if len(packedData) == 0 {
		t.Error("Expected non-empty packed data")
	}

	// Create a directory for unpacking
	unpackDir, err := ioutil.TempDir("", "zip_unpack_test")
	if err != nil {
		t.Fatalf("Failed to create unpack dir: %v", err)
	}
	defer os.RemoveAll(unpackDir)

	// Test Unpack
	err = z.Unpack(packedData, unpackDir)
	if err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}

	// Verify the unpacked files
	unpackedTestFile := filepath.Join(unpackDir, "test.txt")
	unpackedContent, err := ioutil.ReadFile(unpackedTestFile)
	if err != nil {
		t.Fatalf("Failed to read unpacked test file: %v", err)
	}

	if !bytes.Equal(unpackedContent, testContent) {
		t.Errorf("Unpacked content doesn't match original. Expected %q, got %q", testContent, unpackedContent)
	}

	// Verify the unpacked subdir file
	unpackedSubFile := filepath.Join(unpackDir, "subdir", "subfile.txt")
	unpackedSubContent, err := ioutil.ReadFile(unpackedSubFile)
	if err != nil {
		t.Fatalf("Failed to read unpacked subdir file: %v", err)
	}

	if !bytes.Equal(unpackedSubContent, subFileContent) {
		t.Errorf("Unpacked subdir content doesn't match original. Expected %q, got %q", subFileContent, unpackedSubContent)
	}
}

func TestZipUnpackError(t *testing.T) {
	z := New()

	// Test with invalid zip data
	invalidData := []byte("not a zip file")
	err := z.Unpack(invalidData, "")
	if err == nil {
		t.Error("Expected error when unpacking invalid data, got nil")
	}
}

func TestZipPackError(t *testing.T) {
	z := New()

	// Test with non-existent directory
	_, err := z.Pack("/non/existent/directory")
	if err == nil {
		t.Error("Expected error when packing non-existent directory, got nil")
	}
}
