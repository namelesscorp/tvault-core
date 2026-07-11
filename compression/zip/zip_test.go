package zip

import (
	archiveZip "archive/zip"
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
	if z := New(); z.ID() != compression.TypeZip {
		t.Errorf("Expected New ID to be %d, got %d", compression.TypeZip, z.ID())
	}
	if z := NewStore(); z.ID() != compression.TypeNone {
		t.Errorf("Expected NewStore ID to be %d, got %d", compression.TypeNone, z.ID())
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

func TestZipStoreRoundTrip(t *testing.T) {
	tempDir := t.TempDir()

	// Incompressible-ish content; with Store it must survive a round trip and be
	// written using the Store method (no deflate).
	content := []byte("store mode payload that should not be deflated")
	if err := os.WriteFile(filepath.Join(tempDir, "data.bin"), content, 0o644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	z := NewStore()
	if z.ID() != compression.TypeNone {
		t.Fatalf("Expected store ID %d, got %d", compression.TypeNone, z.ID())
	}

	packed, err := z.Pack(tempDir)
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	zr, err := archiveZip.NewReader(bytes.NewReader(packed), int64(len(packed)))
	if err != nil {
		t.Fatalf("Failed to open packed zip: %v", err)
	}
	if len(zr.File) != 1 {
		t.Fatalf("Expected 1 entry, got %d", len(zr.File))
	}
	if zr.File[0].Method != archiveZip.Store {
		t.Errorf("Expected Store method (%d), got %d", archiveZip.Store, zr.File[0].Method)
	}

	unpackDir := t.TempDir()
	if err = z.Unpack(packed, unpackDir); err != nil {
		t.Fatalf("Unpack failed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(unpackDir, "data.bin"))
	if err != nil {
		t.Fatalf("Failed to read unpacked file: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("Round trip mismatch: expected %q, got %q", content, got)
	}
}

func TestWalkFolderPackEntriesMatchesPackTo(t *testing.T) {
	tempDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tempDir, "a.txt"), []byte("alpha"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(tempDir, "sub")
	if err := os.MkdirAll(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "b.txt"), []byte("bravo"), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, uncompressed, count, names, err := WalkFolder(tempDir)
	if err != nil {
		t.Fatalf("WalkFolder failed: %v", err)
	}
	if count != 2 || len(entries) != 2 || len(names) != 2 {
		t.Fatalf("Expected 2 files, got count=%d entries=%d names=%d", count, len(entries), len(names))
	}
	if uncompressed != int64(len("alpha")+len("bravo")) {
		t.Errorf("Unexpected uncompressed size: %d", uncompressed)
	}

	// PackEntriesTo (single-walk path) and PackTo (walks internally) must produce
	// archives with the same set of entries.
	var viaEntries, viaPackTo bytes.Buffer
	if err = New().(*zip).PackEntriesTo(entries, &viaEntries); err != nil {
		t.Fatalf("PackEntriesTo failed: %v", err)
	}
	if err = New().PackTo(tempDir, &viaPackTo); err != nil {
		t.Fatalf("PackTo failed: %v", err)
	}

	namesOf := func(b []byte) map[string]bool {
		zr, zerr := archiveZip.NewReader(bytes.NewReader(b), int64(len(b)))
		if zerr != nil {
			t.Fatalf("read zip: %v", zerr)
		}
		m := map[string]bool{}
		for _, f := range zr.File {
			m[f.Name] = true
		}
		return m
	}
	e, p := namesOf(viaEntries.Bytes()), namesOf(viaPackTo.Bytes())
	if len(e) != len(p) {
		t.Fatalf("Entry count mismatch: PackEntriesTo=%d PackTo=%d", len(e), len(p))
	}
	for name := range p {
		if !e[name] {
			t.Errorf("PackEntriesTo missing entry %q present in PackTo", name)
		}
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
