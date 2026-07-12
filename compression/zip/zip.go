package zip

import (
	archiveZip "archive/zip"
	"bytes"
	"compress/flate"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/lib"
)

type zip struct {
	uncompressedSize int64
	compressedSize   int64
	compressedData   []byte
	fileCount        int64
	fileNameList     []string
	method           uint16
	id               byte
	// progress, when set, is called with the number of uncompressed bytes read
	// from source files while packing, or written to disk while unpacking. It
	// lets a caller drive a byte-level progress bar without the packer needing to
	// know how progress is displayed. Set via SetProgress.
	progress func(n int64)
}

// SetProgress registers a callback invoked with uncompressed byte counts as
// entries are packed (PackTo/PackEntriesTo) or unpacked (UnpackFrom). Passing
// nil disables reporting. Not part of the compression.Compression interface;
// callers reach it via a type assertion so the hook stays optional.
func (z *zip) SetProgress(fn func(n int64)) {
	z.progress = fn
}

// progressCountWriter forwards writes to w and reports the byte count to fn.
type progressCountWriter struct {
	w  io.Writer
	fn func(n int64)
}

func (p *progressCountWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	if n > 0 {
		p.fn(int64(n))
	}

	return n, err
}

// Entry is a pre-walked filesystem entry to be packed. Collecting entries once
// lets the packer avoid re-walking the tree (see WalkFolder / PackEntriesTo).
type Entry struct {
	AbsPath    string
	RelPath    string
	Info       fs.FileInfo
	LinkTarget string // non-empty only for symlinks
	IsSymlink  bool
}

var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 256*1024)
		return &b
	},
}

// New returns a packer that deflate-compresses entries (compression type "zip").
func New() compression.Compression {
	return &zip{method: archiveZip.Deflate, id: compression.TypeZip}
}

// NewStore returns a packer that stores entries without compression
// (compression type "none"). The archive is still a valid zip, so unseal reads
// it unchanged, but the CPU-heavy deflate step is skipped — much faster for
// large or already-compressed data that does not benefit from compression.
func NewStore() compression.Compression {
	return &zip{method: archiveZip.Store, id: compression.TypeNone}
}

// Pack - packs to []byte
func (z *zip) Pack(folder string) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := z.PackTo(folder, buf); err != nil {
		return nil, err
	}
	z.compressedSize = int64(buf.Len())
	z.compressedData = buf.Bytes()
	return z.compressedData, nil
}

// WalkFolder walks folder a single time, returning the entries to pack together
// with aggregate stats (uncompressed size, file count, file names). Callers that
// need the stats up front (e.g. to build container metadata before streaming the
// payload) can walk once here and then hand the entries to PackEntriesTo, so the
// filesystem tree is traversed only once instead of once for stats and again for
// packing.
func WalkFolder(folder string) (entries []Entry, uncompressedSize, fileCount int64, fileNames []string, err error) {
	walkErr := filepath.WalkDir(folder, func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return nil
		}

		fi, err := d.Info()
		if err != nil {
			return lib.InternalErr(lib.CategoryCompression, 0, "", "", err)
		}

		relPath, err := filepath.Rel(folder, path)
		if err != nil {
			return lib.InternalErr(
				lib.CategoryCompression,
				lib.ErrCodeGetFilePathRelative,
				lib.ErrMessageGetFilePathRelative,
				"",
				err,
			)
		}
		relPath = filepath.ToSlash(relPath)

		mode := fi.Mode()

		switch {
		case mode&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return lib.IOErr(lib.CategoryCompression, lib.ErrCodeOpenFileError, lib.ErrMessageOpenFileError, "", err)
			}

			entries = append(entries, Entry{AbsPath: path, RelPath: relPath, Info: fi, LinkTarget: target, IsSymlink: true})
			uncompressedSize += int64(len(target))
			fileCount++
			fileNames = append(fileNames, fi.Name())
		case mode.IsRegular():
			entries = append(entries, Entry{AbsPath: path, RelPath: relPath, Info: fi})
			uncompressedSize += fi.Size()
			fileCount++
			fileNames = append(fileNames, fi.Name())
		}

		return nil
	})
	if walkErr != nil {
		return nil, 0, 0, nil, lib.IOErr(lib.CategoryCompression, lib.ErrCodeWalkDirError, lib.ErrMessageWalkDirError, "", walkErr)
	}

	return entries, uncompressedSize, fileCount, fileNames, nil
}

// PackTo - streaming zip to writer.
func (z *zip) PackTo(folder string, out io.Writer) error {
	entries, _, _, _, err := WalkFolder(folder)
	if err != nil {
		return err
	}

	return z.PackEntriesTo(entries, out)
}

// PackEntriesTo writes pre-walked entries into a zip stream. The tree is not
// re-walked here, so when the caller already walked it (WalkFolder) the
// filesystem is traversed only once. Regular files use the packer's method
// (Deflate for "zip", Store for "none").
//
// For the Deflate method the per-file compression (the CPU bottleneck of a
// seal/reseal) is fanned out across workers: files are deflated concurrently
// into buffers and the finished buffers are written into the single zip stream
// in the original order via CreateRaw. The Store method has no CPU cost worth
// parallelizing, so it stays on the simple sequential path.
func (z *zip) PackEntriesTo(entries []Entry, out io.Writer) error {
	if z.method == archiveZip.Deflate && len(entries) > 1 {
		return z.packEntriesParallel(entries, out)
	}

	zw := archiveZip.NewWriter(out)

	if z.method == archiveZip.Deflate {
		zw.RegisterCompressor(archiveZip.Deflate, func(w io.Writer) (io.WriteCloser, error) {
			return flate.NewWriter(w, flate.BestSpeed)
		})
	}

	for i := range entries {
		if err := z.packEntry(zw, &entries[i]); err != nil {
			_ = zw.Close()
			return err
		}
	}

	if err := zw.Close(); err != nil {
		return lib.IOErr(lib.CategoryCompression, lib.ErrCodeCloseZipError, lib.ErrMessageCloseZipError, "", err)
	}

	return nil
}

// maxPackWorkers caps compression concurrency; beyond a handful of cores the
// packer is bounded by disk and memory bandwidth, not CPU.
const maxPackWorkers = 8

// packBudgetBytes bounds the total uncompressed bytes held in flight across all
// worker buffers, so packing a vault of huge files cannot balloon memory. A
// single file larger than the budget is still processed (alone), it just does
// not run alongside others.
const packBudgetBytes = 128 * 1024 * 1024

// flateWriterPool reuses flate.Writers (each carries a few hundred KiB of state)
// across files so a folder with many entries does not allocate one per file.
var flateWriterPool = sync.Pool{
	New: func() any {
		w, _ := flate.NewWriter(io.Discard, flate.BestSpeed)
		return w
	},
}

// packResult is the compressed form of one entry, handed from a worker to the
// ordered writer. For symlinks comp is nil and the writer stores the target.
type packResult struct {
	entry *Entry
	comp  []byte // raw deflate bytes (nil for symlinks)
	crc   uint32
	usize int64
	err   error
}

// packEntriesParallel deflates entries concurrently and writes them to the zip
// stream in their original order. Ordering is preserved by handing the writer a
// channel of per-entry result channels: the writer consumes them in dispatch
// order, so entry N is always written before N+1 even if it finished later.
func (z *zip) packEntriesParallel(entries []Entry, out io.Writer) error {
	zw := archiveZip.NewWriter(out)

	workers := runtime.GOMAXPROCS(0)
	if workers > maxPackWorkers {
		workers = maxPackWorkers
	}

	var (
		slots   = make(chan struct{}, workers)        // caps live goroutines
		budget  = newByteSem(packBudgetBytes)         // caps bytes in flight
		results = make(chan chan packResult, workers) // ordered result handoff
	)

	go func() {
		defer close(results)

		for i := range entries {
			e := &entries[i]
			ch := make(chan packResult, 1)
			results <- ch

			if e.IsSymlink {
				// Symlinks carry no file body to deflate; let the writer store them.
				ch <- packResult{entry: e}
				continue
			}

			budget.acquire(e.Info.Size())
			slots <- struct{}{}

			go func(e *Entry, ch chan packResult) {
				defer func() { <-slots }()

				comp, crc, usize, err := z.deflateEntry(e)
				ch <- packResult{entry: e, comp: comp, crc: crc, usize: usize, err: err}
			}(e, ch)
		}
	}()

	// Writer: consume results in order and assemble the zip. On the first error
	// drain the remaining results (releasing their budget) so no worker blocks.
	var writeErr error
	for ch := range results {
		res := <-ch
		if writeErr != nil {
			if res.comp != nil {
				budget.release(res.entry.Info.Size())
			}
			continue
		}

		if res.err != nil {
			writeErr = res.err
		} else if err := z.writePackResult(zw, &res); err != nil {
			writeErr = err
		}

		if res.comp != nil {
			budget.release(res.entry.Info.Size())
		}
	}

	if writeErr != nil {
		_ = zw.Close()
		return writeErr
	}

	if err := zw.Close(); err != nil {
		return lib.IOErr(lib.CategoryCompression, lib.ErrCodeCloseZipError, lib.ErrMessageCloseZipError, "", err)
	}

	return nil
}

// deflateEntry reads and raw-deflates a single regular file into a buffer,
// returning the compressed bytes, CRC-32 (IEEE) and uncompressed size that
// CreateRaw needs to emit the entry without re-compressing.
func (z *zip) deflateEntry(e *Entry) ([]byte, uint32, int64, error) {
	// Symlinks are handled by the writer and never followed here; only regular
	// files from the user's own trusted folder are opened (no TOCTOU boundary).
	f, err := os.Open(filepath.Clean(e.AbsPath)) // #nosec G304 G122
	if err != nil {
		return nil, 0, 0, lib.IOErr(lib.CategoryCompression, lib.ErrCodeOpenFileError, lib.ErrMessageOpenFileError, "", err)
	}
	defer func() { _ = f.Close() }()

	buf := bytes.NewBuffer(make([]byte, 0, e.Info.Size()/2+64))

	fw := flateWriterPool.Get().(*flate.Writer)
	fw.Reset(buf)

	var (
		crc    uint32
		usize  int64
		bufPtr = copyBufPool.Get().(*[]byte)
	)
	for {
		n, readErr := f.Read(*bufPtr)
		if n > 0 {
			chunk := (*bufPtr)[:n]
			crc = crc32.Update(crc, crc32.IEEETable, chunk)
			if _, werr := fw.Write(chunk); werr != nil {
				copyBufPool.Put(bufPtr)
				flateWriterPool.Put(fw)
				return nil, 0, 0, lib.IOErr(lib.CategoryCompression, lib.ErrCodeIOCopyError, lib.ErrMessageIOCopyError, "", werr)
			}
			usize += int64(n)

			if z.progress != nil {
				z.progress(int64(n))
			}
		}

		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			copyBufPool.Put(bufPtr)
			flateWriterPool.Put(fw)
			return nil, 0, 0, lib.IOErr(lib.CategoryCompression, lib.ErrCodeIOCopyError, lib.ErrMessageIOCopyError, "", readErr)
		}
	}
	copyBufPool.Put(bufPtr)

	if err = fw.Close(); err != nil {
		flateWriterPool.Put(fw)
		return nil, 0, 0, lib.IOErr(lib.CategoryCompression, lib.ErrCodeIOCopyError, lib.ErrMessageIOCopyError, "", err)
	}
	flateWriterPool.Put(fw)

	return buf.Bytes(), crc, usize, nil
}

// writePackResult writes one already-compressed entry (or a symlink) into the
// zip stream. Runs only in the single writer goroutine, so the packer's stat
// fields are updated without locking.
func (z *zip) writePackResult(zw *archiveZip.Writer, res *packResult) error {
	e := res.entry

	if e.IsSymlink {
		h := &archiveZip.FileHeader{Name: e.RelPath, Method: archiveZip.Store}
		h.SetMode(os.ModeSymlink | 0o777)

		w, err := zw.CreateHeader(h)
		if err != nil {
			return lib.IOErr(lib.CategoryCompression, lib.ErrCodeCreateZipError, lib.ErrMessageCreateZipError, "", err)
		}
		if _, err = w.Write([]byte(e.LinkTarget)); err != nil {
			return lib.IOErr(lib.CategoryCompression, lib.ErrCodeIOCopyError, lib.ErrMessageIOCopyError, "", err)
		}

		if z.progress != nil {
			z.progress(int64(len(e.LinkTarget)))
		}

		z.uncompressedSize += int64(len(e.LinkTarget))
		z.fileCount++
		z.fileNameList = append(z.fileNameList, e.Info.Name())
		return nil
	}

	// Preserve mode and modtime from the walked FileInfo, then supply the
	// pre-computed CRC/sizes so CreateRaw emits the entry without recompressing.
	h, err := archiveZip.FileInfoHeader(e.Info)
	if err != nil {
		return lib.InternalErr(lib.CategoryCompression, 0, "", "", err)
	}
	h.Name = e.RelPath
	h.Method = archiveZip.Deflate
	h.SetMode(e.Info.Mode())
	h.CRC32 = res.crc
	h.CompressedSize64 = uint64(len(res.comp)) // #nosec G115
	h.UncompressedSize64 = uint64(res.usize)   // #nosec G115

	w, err := zw.CreateRaw(h)
	if err != nil {
		return lib.IOErr(lib.CategoryCompression, lib.ErrCodeCreateZipError, lib.ErrMessageCreateZipError, "", err)
	}
	if _, err = w.Write(res.comp); err != nil {
		return lib.IOErr(lib.CategoryCompression, lib.ErrCodeIOCopyError, lib.ErrMessageIOCopyError, "", err)
	}

	z.uncompressedSize += res.usize
	z.fileCount++
	z.fileNameList = append(z.fileNameList, e.Info.Name())

	return nil
}

// byteSem is a weighted counting semaphore bounding total bytes in flight. A
// request larger than the maximum is clamped so it can still proceed once the
// pool is otherwise empty, rather than deadlocking.
type byteSem struct {
	mu   sync.Mutex
	cond *sync.Cond
	cur  int64
	max  int64
}

func newByteSem(max int64) *byteSem {
	s := &byteSem{max: max}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *byteSem) acquire(n int64) {
	if n > s.max {
		n = s.max
	}

	s.mu.Lock()
	for s.cur > 0 && s.cur+n > s.max {
		s.cond.Wait()
	}
	s.cur += n
	s.mu.Unlock()
}

func (s *byteSem) release(n int64) {
	if n > s.max {
		n = s.max
	}

	s.mu.Lock()
	s.cur -= n
	s.cond.Broadcast()
	s.mu.Unlock()
}

func (z *zip) packEntry(zw *archiveZip.Writer, e *Entry) error {
	if e.IsSymlink {
		h := &archiveZip.FileHeader{Name: e.RelPath, Method: archiveZip.Store}
		h.SetMode(os.ModeSymlink | 0o777)

		w, err := zw.CreateHeader(h)
		if err != nil {
			return lib.IOErr(lib.CategoryCompression, lib.ErrCodeCreateZipError, lib.ErrMessageCreateZipError, "", err)
		}

		if _, err := w.Write([]byte(e.LinkTarget)); err != nil {
			return lib.IOErr(lib.CategoryCompression, lib.ErrCodeIOCopyError, lib.ErrMessageIOCopyError, "", err)
		}

		if z.progress != nil {
			z.progress(int64(len(e.LinkTarget)))
		}

		z.uncompressedSize += int64(len(e.LinkTarget))
		z.fileCount++
		z.fileNameList = append(z.fileNameList, e.Info.Name())
		return nil
	}

	// Symlinks are handled above and never followed here; only regular files
	// from the user's own trusted folder are opened, so there is no TOCTOU boundary.
	f, err := os.Open(filepath.Clean(e.AbsPath)) // #nosec G304 G122
	if err != nil {
		return lib.IOErr(lib.CategoryCompression, lib.ErrCodeOpenFileError, lib.ErrMessageOpenFileError, "", err)
	}

	h, err := archiveZip.FileInfoHeader(e.Info)
	if err != nil {
		_ = f.Close()
		return lib.InternalErr(lib.CategoryCompression, 0, "", "", err)
	}
	h.Name = e.RelPath
	h.Method = z.method
	h.SetMode(e.Info.Mode())

	w, err := zw.CreateHeader(h)
	if err != nil {
		_ = f.Close()
		return lib.IOErr(lib.CategoryCompression, lib.ErrCodeCreateZipError, lib.ErrMessageCreateZipError, "", err)
	}

	dst := w
	if z.progress != nil {
		dst = &progressCountWriter{w: w, fn: z.progress}
	}

	bufPtr := copyBufPool.Get().(*[]byte)
	_, copyErr := io.CopyBuffer(dst, f, *bufPtr)
	copyBufPool.Put(bufPtr)

	if errClose := f.Close(); errClose != nil {
		fmt.Printf("error closing file; %v", errClose)
	}
	if copyErr != nil {
		return lib.IOErr(lib.CategoryCompression, lib.ErrCodeIOCopyError, lib.ErrMessageIOCopyError, "", copyErr)
	}

	z.uncompressedSize += e.Info.Size()
	z.fileCount++
	z.fileNameList = append(z.fileNameList, e.Info.Name())

	return nil
}

func (z *zip) Unpack(data []byte, targetDir string) error {
	return z.UnpackFrom(bytes.NewReader(data), int64(len(data)), targetDir)
}

// unpackJob is a regular file or symlink entry queued for parallel extraction,
// with its already-validated destination path.
type unpackJob struct {
	file *archiveZip.File
	dst  string
}

// UnpackFrom - unzip from file-like ReaderAt (e.g., *os.File).
//
// Extraction runs in two passes: a sequential pass validates every entry path
// (fail-fast on traversal) and creates directories, then regular files and
// symlinks — which write to distinct paths and can be inflated independently —
// are extracted across a worker pool. archive/zip's per-file Open reads through
// the shared ReaderAt (an *os.File or bytes.Reader), whose ReadAt is safe for
// concurrent use, so the workers do not contend on a single stream position.
func (z *zip) UnpackFrom(r io.ReaderAt, size int64, targetDir string) error {
	zr, err := archiveZip.NewReader(r, size)
	if err != nil {
		return lib.IOErr(
			lib.CategoryCompression,
			lib.ErrCodeCreateZipReaderError,
			lib.ErrMessageCreateZipReaderError,
			"",
			err,
		)
	}

	base := filepath.Clean(targetDir) + string(os.PathSeparator)

	jobs := make([]unpackJob, 0, len(zr.File))
	for _, f := range zr.File {
		rel := filepath.FromSlash(f.Name)
		dst := filepath.Clean(filepath.Join(targetDir, rel)) // #nosec G305

		if !strings.HasPrefix(dst+string(os.PathSeparator), base) && dst != filepath.Clean(targetDir) {
			return lib.IOErr(
				lib.CategoryCompression,
				lib.ErrCodeCreateDirectoryError,
				lib.ErrMessageCreateDirectoryError,
				"zip path traversal detected",
				fmt.Errorf("invalid zip entry path: %q", f.Name),
			)
		}

		if f.FileInfo().IsDir() {
			if err = os.MkdirAll(dst, 0o750); err != nil {
				return lib.IOErr(lib.CategoryCompression, lib.ErrCodeCreateDirectoryError, lib.ErrMessageCreateDirectoryError, "", err)
			}
			continue
		}

		jobs = append(jobs, unpackJob{file: f, dst: dst})
	}

	if len(jobs) == 0 {
		return nil
	}

	workers := runtime.GOMAXPROCS(0)
	if workers > maxPackWorkers {
		workers = maxPackWorkers
	}
	if workers > len(jobs) {
		workers = len(jobs)
	}
	if workers < 1 {
		workers = 1
	}

	var (
		wg       sync.WaitGroup
		sem      = make(chan struct{}, workers)
		errOnce  sync.Once
		firstErr error
		stop     atomic.Bool
	)
	for i := range jobs {
		if stop.Load() {
			break
		}

		j := jobs[i]
		sem <- struct{}{}
		wg.Add(1)

		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			if stop.Load() {
				return
			}
			if e := z.extractEntry(j.file, j.dst); e != nil {
				errOnce.Do(func() {
					firstErr = e
					stop.Store(true)
				})
			}
		}()
	}
	wg.Wait()

	return firstErr
}

// extractEntry writes one regular file or symlink to dst, creating its parent
// directory. Safe to call concurrently for distinct dst paths.
func (z *zip) extractEntry(f *archiveZip.File, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return lib.IOErr(lib.CategoryCompression, lib.ErrCodeCreateDirectoryError, lib.ErrMessageCreateDirectoryError, "", err)
	}

	if f.Mode()&os.ModeSymlink != 0 {
		rc, errOpen := f.Open()
		if errOpen != nil {
			return lib.IOErr(lib.CategoryCompression, lib.ErrCodeOpenFileError, lib.ErrMessageOpenFileError, "", errOpen)
		}

		b, errRead := io.ReadAll(rc)
		if errClose := rc.Close(); errClose != nil {
			return lib.IOErr(lib.CategoryCompression, lib.ErrCodeReaderCloserError, lib.ErrMessageReaderCloserError, "", errClose)
		}
		if errRead != nil {
			return lib.IOErr(lib.CategoryCompression, lib.ErrCodeIOCopyError, lib.ErrMessageIOCopyError, "", errRead)
		}

		if err := os.Symlink(string(b), dst); err != nil {
			return lib.IOErr(lib.CategoryCompression, lib.ErrCodeOSOpenFileError, lib.ErrMessageOSOpenFileError, "", err)
		}

		if z.progress != nil {
			z.progress(int64(len(b)))
		}

		return nil
	}

	out, err := os.OpenFile(filepath.Clean(dst), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return lib.IOErr(lib.CategoryCompression, lib.ErrCodeOSOpenFileError, lib.ErrMessageOSOpenFileError, "", err)
	}

	rc, err := f.Open()
	if err != nil {
		_ = out.Close()
		return lib.IOErr(lib.CategoryCompression, lib.ErrCodeOpenFileError, lib.ErrMessageOpenFileError, "", err)
	}

	var unpackDst io.Writer = out
	if z.progress != nil {
		unpackDst = &progressCountWriter{w: out, fn: z.progress}
	}

	bufPtr := copyBufPool.Get().(*[]byte)
	_, copyErr := io.CopyBuffer(unpackDst, rc, *bufPtr) // #nosec G110
	copyBufPool.Put(bufPtr)

	if errClose := out.Close(); errClose != nil {
		return lib.IOErr(lib.CategoryCompression, lib.ErrCodeCloseFileError, lib.ErrMessageCloseFileError, "", errClose)
	}
	if errClose := rc.Close(); errClose != nil {
		return lib.IOErr(lib.CategoryCompression, lib.ErrCodeReaderCloserError, lib.ErrMessageReaderCloserError, "", errClose)
	}
	if copyErr != nil {
		return lib.IOErr(lib.CategoryCompression, lib.ErrCodeIOCopyError, lib.ErrMessageIOCopyError, "", copyErr)
	}

	return nil
}

func (z *zip) GetUncompressedSize() int64 {
	return z.uncompressedSize
}

func (z *zip) GetCompressedSize() int64 {
	return z.compressedSize
}

func (z *zip) GetCompressedData() []byte {
	return z.compressedData
}

func (z *zip) GetFileCount() int64 {
	return z.fileCount
}

func (z *zip) GetFileNameList() []string {
	return z.fileNameList
}

func (z *zip) ID() byte {
	return z.id
}
