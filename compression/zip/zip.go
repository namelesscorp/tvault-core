package zip

import (
	archiveZip "archive/zip"
	"bytes"
	"compress/flate"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/lib"
)

type zip struct {
	uncompressedSize int64
	compressedSize   int64
	compressedData   []byte
	fileCount        int64
	fileNameList     []string
}

var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 256*1024)
		return &b
	},
}

func New() compression.Compression {
	return &zip{
		uncompressedSize: 0,
		compressedSize:   0,
	}
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

// PackTo - streaming zip to writer.
func (z *zip) PackTo(folder string, out io.Writer) error {
	zw := archiveZip.NewWriter(out)

	zw.RegisterCompressor(archiveZip.Deflate, func(w io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(w, flate.BestSpeed)
	})

	if err := filepath.WalkDir(folder, func(path string, d fs.DirEntry, err error) error {
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

		if mode&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return lib.IOErr(lib.CategoryCompression, lib.ErrCodeOpenFileError, lib.ErrMessageOpenFileError, "", err)
			}

			h := &archiveZip.FileHeader{Name: relPath, Method: archiveZip.Store}
			h.SetMode(os.ModeSymlink | 0o777)

			w, err := zw.CreateHeader(h)
			if err != nil {
				return lib.IOErr(lib.CategoryCompression, lib.ErrCodeCreateZipError, lib.ErrMessageCreateZipError, "", err)
			}

			if _, err := w.Write([]byte(target)); err != nil {
				return lib.IOErr(lib.CategoryCompression, lib.ErrCodeIOCopyError, lib.ErrMessageIOCopyError, "", err)
			}

			z.uncompressedSize += int64(len(target))
			z.fileCount += 1
			z.fileNameList = append(z.fileNameList, fi.Name())
			return nil
		}

		if !mode.IsRegular() {
			return nil
		}

		f, err := os.Open(filepath.Clean(path))
		if err != nil {
			return lib.IOErr(lib.CategoryCompression, lib.ErrCodeOpenFileError, lib.ErrMessageOpenFileError, "", err)
		}

		h, err := archiveZip.FileInfoHeader(fi)
		if err != nil {
			_ = f.Close()
			return lib.InternalErr(lib.CategoryCompression, 0, "", "", err)
		}
		h.Name = relPath
		h.Method = archiveZip.Deflate
		h.SetMode(mode)

		w, err := zw.CreateHeader(h)
		if err != nil {
			_ = f.Close()
			return lib.IOErr(lib.CategoryCompression, lib.ErrCodeCreateZipError, lib.ErrMessageCreateZipError, "", err)
		}

		bufPtr := copyBufPool.Get().(*[]byte)
		_, copyErr := io.CopyBuffer(w, f, *bufPtr)
		copyBufPool.Put(bufPtr)

		if errClose := f.Close(); errClose != nil {
			fmt.Printf("error closing file; %v", errClose)
		}
		if copyErr != nil {
			return lib.IOErr(lib.CategoryCompression, lib.ErrCodeIOCopyError, lib.ErrMessageIOCopyError, "", copyErr)
		}

		z.uncompressedSize += fi.Size()
		z.fileCount += 1
		z.fileNameList = append(z.fileNameList, fi.Name())

		return nil
	}); err != nil {
		_ = zw.Close()
		return lib.IOErr(lib.CategoryCompression, lib.ErrCodeWalkDirError, lib.ErrMessageWalkDirError, "", err)
	}

	if err := zw.Close(); err != nil {
		return lib.IOErr(lib.CategoryCompression, lib.ErrCodeCloseZipError, lib.ErrMessageCloseZipError, "", err)
	}

	return nil
}

func (z *zip) Unpack(data []byte, targetDir string) error {
	return z.UnpackFrom(bytes.NewReader(data), int64(len(data)), targetDir)
}

// UnpackFrom - unzip from file-like ReaderAt (e.g., *os.File).
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

	for _, f := range zr.File {
		rel := filepath.FromSlash(f.Name)
		dst := filepath.Join(targetDir, rel) // #nosec G305
		dst = filepath.Clean(dst)

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

		if err = os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
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

			if err = os.Symlink(string(b), dst); err != nil {
				return lib.IOErr(lib.CategoryCompression, lib.ErrCodeOSOpenFileError, lib.ErrMessageOSOpenFileError, "", err)
			}
			continue
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

		_, copyErr := io.Copy(out, rc) // #nosec G110

		if errClose := out.Close(); errClose != nil {
			return lib.IOErr(lib.CategoryCompression, lib.ErrCodeCloseFileError, lib.ErrMessageCloseFileError, "", errClose)
		}
		if errClose := rc.Close(); errClose != nil {
			return lib.IOErr(lib.CategoryCompression, lib.ErrCodeReaderCloserError, lib.ErrMessageReaderCloserError, "", errClose)
		}
		if copyErr != nil {
			return lib.IOErr(lib.CategoryCompression, lib.ErrCodeIOCopyError, lib.ErrMessageIOCopyError, "", copyErr)
		}
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
	return compression.TypeZip
}
