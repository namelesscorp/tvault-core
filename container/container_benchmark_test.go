package container

import (
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// benchWriteEncryptedPiped mimics the real seal pipeline: a producer writes to
// an io.Pipe in small blocks (like archive/zip+flate flushing), and
// WriteEncrypted consumes the pipe. This is the large-file hot path.
func benchWriteEncryptedPiped(b *testing.B, totalBytes int, producerWrite int) {
	b.Helper()

	header, err := NewHeader(1, 1, 1, 3, 2)
	if err != nil {
		b.Fatal(err)
	}
	passphrase := []byte("bench passphrase")

	// Pre-generate one block of random data reused by the producer.
	block := make([]byte, producerWrite)
	if _, err := rand.Read(block); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(totalBytes))
	b.ReportAllocs()
	b.ResetTimer()

	var lastOutSize int64
	for i := 0; i < b.N; i++ {
		path := filepath.Join(b.TempDir(), "bench.tvlt")
		cont := NewContainer(path, nil, Metadata{Comment: "bench"}, header)

		pr, pw := io.Pipe()
		go func() {
			remaining := totalBytes
			for remaining > 0 {
				n := producerWrite
				if n > remaining {
					n = remaining
				}
				if _, werr := pw.Write(block[:n]); werr != nil {
					_ = pw.CloseWithError(werr)
					return
				}
				remaining -= n
			}
			_ = pw.Close()
		}()

		if err := cont.WriteEncrypted(pr, passphrase); err != nil {
			b.Fatal(err)
		}

		if st, serr := os.Stat(path); serr == nil {
			lastOutSize = st.Size()
		}
	}
	b.StopTimer()
	// Overhead over plaintext reflects per-chunk framing (16-byte tag + 4-byte
	// length). Smaller is better: it means fewer, larger chunks.
	b.ReportMetric(float64(lastOutSize-int64(totalBytes)), "framing_bytes")
}

// Producer flushes ~4 KiB blocks, typical of flate output.
func BenchmarkWriteEncrypted_SmallPipeWrites(b *testing.B) {
	benchWriteEncryptedPiped(b, 128*1024*1024, 4*1024)
}

// BenchmarkDecryptTo measures the decrypt hot path (buffer reuse across chunks).
func BenchmarkDecryptTo(b *testing.B) {
	const totalBytes = 128 * 1024 * 1024

	header, err := NewHeader(1, 1, 1, 3, 2)
	if err != nil {
		b.Fatal(err)
	}
	passphrase := []byte("bench passphrase")

	// Write one container up front, then decrypt it repeatedly.
	path := filepath.Join(b.TempDir(), "bench.tvlt")
	cont := NewContainer(path, nil, Metadata{Comment: "bench"}, header)

	src := make([]byte, totalBytes)
	if _, err := rand.Read(src); err != nil {
		b.Fatal(err)
	}
	if err := cont.WriteEncrypted(bytesReader(src), passphrase); err != nil {
		b.Fatal(err)
	}
	masterKey := cont.GetMasterKey()

	b.SetBytes(int64(totalBytes))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rc := NewContainer(path, nil, Metadata{}, Header{})
		if err := rc.Read(); err != nil {
			b.Fatal(err)
		}
		if err := rc.DecryptTo(io.Discard, masterKey); err != nil {
			b.Fatal(err)
		}
	}
}

func bytesReader(b []byte) io.Reader { return &sliceReader{b: b} }

type sliceReader struct {
	b   []byte
	off int
}

func (s *sliceReader) Read(p []byte) (int, error) {
	if s.off >= len(s.b) {
		return 0, io.EOF
	}
	n := copy(p, s.b[s.off:])
	s.off += n
	return n, nil
}
