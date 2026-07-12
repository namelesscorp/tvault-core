package reseal

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/namelesscorp/tvault-core/container"
	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/token"
)

// failingReader always fails on Read with a non-EOF error, so WriteEncrypted
// treats it as a real read failure (not a clean end of stream).
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("simulated read failure") }

func TestIsIntegrityProviderPassphraseChanged(t *testing.T) {
	tests := []struct {
		name    string
		current string
		next    string
		want    bool
	}{
		{name: "new empty keeps tokens", current: "old", next: "", want: false},
		{name: "new equals current keeps tokens", current: "old", next: "old", want: false},
		{name: "new differs re-issues tokens", current: "old", next: "new", want: true},
		{name: "new set from empty current", current: "", next: "new", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &lib.IntegrityProvider{
				CurrentPassphrase: lib.StringPtr(tt.current),
				NewPassphrase:     lib.StringPtr(tt.next),
			}
			if got := isIntegrityProviderPassphraseChanged(opts); got != tt.want {
				t.Fatalf("isIntegrityProviderPassphraseChanged() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractRawTokens(t *testing.T) {
	t.Run("plaintext splits on pipe", func(t *testing.T) {
		got, err := extractRawTokens("aaa|bbb|ccc", lib.ReaderFormatPlaintext)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := []string{"aaa", "bbb", "ccc"}; !equalStrings(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("json reads token_list", func(t *testing.T) {
		got, err := extractRawTokens(`{"token_list":["aaa","bbb"]}`, lib.ReaderFormatJSON)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if want := []string{"aaa", "bbb"}; !equalStrings(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("invalid json errors", func(t *testing.T) {
		if _, err := extractRawTokens("{not json", lib.ReaderFormatJSON); err == nil {
			t.Fatal("expected error for invalid json, got nil")
		}
	})

	t.Run("unknown format errors", func(t *testing.T) {
		if _, err := extractRawTokens("aaa", "xml"); err == nil {
			t.Fatal("expected error for unknown reader format, got nil")
		}
	})
}

// TestWriteRawTokensPreservesTokens is the core guarantee: when the integrity
// passphrase is not changed, reseal must emit the exact same token strings it
// read. Writing then re-reading must yield the original tokens byte-for-byte.
func TestWriteRawTokensPreservesTokens(t *testing.T) {
	raw := []string{"dG9rZW4tb25l", "dG9rZW4tdHdv"}

	for _, tt := range []struct {
		name       string
		tokenType  byte
		format     string
		readerFmt  string
		wantSubstr []string
	}{
		{
			name:       "share json",
			tokenType:  token.TypeShare,
			format:     lib.WriterFormatJSON,
			readerFmt:  lib.ReaderFormatJSON,
			wantSubstr: raw,
		},
		{
			name:       "master json",
			tokenType:  token.TypeMaster,
			format:     lib.WriterFormatJSON,
			readerFmt:  lib.ReaderFormatJSON,
			wantSubstr: raw,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := writeRawTokens(tt.tokenType, raw, tt.format, &buf); err != nil {
				t.Fatalf("writeRawTokens() error: %v", err)
			}

			// The original token strings must survive verbatim.
			for _, want := range tt.wantSubstr {
				if !strings.Contains(buf.String(), want) {
					t.Fatalf("output missing token %q:\n%s", want, buf.String())
				}
			}

			// Round-trip: re-reading the output yields the original tokens.
			got, err := extractRawTokens(buf.String(), tt.readerFmt)
			if err != nil {
				t.Fatalf("re-read error: %v", err)
			}
			if !equalStrings(got, raw) {
				t.Fatalf("round-trip mismatch: got %v, want %v", got, raw)
			}
		})
	}
}

func TestWriteRawTokensPlaintextLayout(t *testing.T) {
	raw := []string{"aaa", "bbb"}

	t.Run("share plaintext", func(t *testing.T) {
		var buf bytes.Buffer
		if err := writeRawTokens(token.TypeShare, raw, lib.WriterFormatPlaintext, &buf); err != nil {
			t.Fatalf("writeRawTokens() error: %v", err)
		}
		want := "tokens:\naaa\n---\nbbb\n---\n"
		if buf.String() != want {
			t.Fatalf("got %q, want %q", buf.String(), want)
		}
	})

	t.Run("master plaintext", func(t *testing.T) {
		var buf bytes.Buffer
		if err := writeRawTokens(token.TypeMaster, raw[:1], lib.WriterFormatPlaintext, &buf); err != nil {
			t.Fatalf("writeRawTokens() error: %v", err)
		}
		want := "token:\naaa\n"
		if buf.String() != want {
			t.Fatalf("got %q, want %q", buf.String(), want)
		}
	})

	t.Run("unknown writer format errors", func(t *testing.T) {
		var buf bytes.Buffer
		if err := writeRawTokens(token.TypeShare, raw, "xml", &buf); err == nil {
			t.Fatal("expected error for unknown writer format, got nil")
		}
	})
}

func TestWriteContainerAtomicSuccess(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "vault.tvlt")

	key := bytes.Repeat([]byte{0x01}, lib.KeyLen)
	cont := container.NewContainer(targetPath, key, container.Metadata{Tags: []string{}}, container.Header{})

	if err := writeContainerAtomic(cont, bytes.NewReader([]byte("plaintext-payload")), targetPath); err != nil {
		t.Fatalf("writeContainerAtomic() error: %v", err)
	}

	st, err := os.Stat(targetPath)
	if err != nil {
		t.Fatalf("target not created: %v", err)
	}
	if st.Size() == 0 {
		t.Fatal("target container is empty")
	}
	if n := countTempFiles(t, dir); n != 0 {
		t.Fatalf("leftover temp files: %d", n)
	}
}

// TestWriteContainerAtomicFailurePreservesTarget is the core durability guarantee:
// if the container write fails, the pre-existing container must remain intact and
// no partial/temp file must be left behind.
func TestWriteContainerAtomicFailurePreservesTarget(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "vault.tvlt")

	const original = "ORIGINAL-CONTAINER-BYTES"
	if err := os.WriteFile(targetPath, []byte(original), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}

	key := bytes.Repeat([]byte{0x01}, lib.KeyLen)
	cont := container.NewContainer(targetPath, key, container.Metadata{Tags: []string{}}, container.Header{})

	// A source that errors mid-read makes the encrypt fail after the temp file is
	// created but before the target would be replaced.
	err := writeContainerAtomic(cont, &failingReader{}, targetPath)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	got, readErr := os.ReadFile(targetPath)
	if readErr != nil {
		t.Fatalf("original container gone: %v", readErr)
	}
	if string(got) != original {
		t.Fatalf("original container mutated: got %q, want %q", got, original)
	}
	if n := countTempFiles(t, dir); n != 0 {
		t.Fatalf("leftover temp files after failure: %d", n)
	}
}

func TestWriteTokensAtomicFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")

	if err := os.WriteFile(path, []byte("OLD-TOKENS"), 0o600); err != nil {
		t.Fatalf("seed tokens: %v", err)
	}

	opts := &lib.Writer{
		Type:   lib.StringPtr(lib.WriterTypeFile),
		Path:   lib.StringPtr(path),
		Format: lib.StringPtr(lib.WriterFormatJSON),
	}

	const data = "NEW-TOKENS-PAYLOAD"
	if err := writeTokensAtomic(opts, []byte(data)); err != nil {
		t.Fatalf("writeTokensAtomic() error: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read tokens: %v", err)
	}
	if string(got) != data {
		t.Fatalf("got %q, want %q", got, data)
	}
	if n := countTempFiles(t, dir); n != 0 {
		t.Fatalf("leftover temp files: %d", n)
	}
}

func TestWriteTokensAtomicUnknownType(t *testing.T) {
	opts := &lib.Writer{
		Type:   lib.StringPtr("bogus"),
		Path:   lib.StringPtr("ignored"),
		Format: lib.StringPtr(lib.WriterFormatJSON),
	}
	if err := writeTokensAtomic(opts, []byte("x")); err == nil {
		t.Fatal("expected error for unknown writer type, got nil")
	}
}

func countTempFiles(t *testing.T, dir string) int {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}

	var n int
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tvault-") && strings.HasSuffix(e.Name(), ".tmp") {
			n++
		}
	}
	return n
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
