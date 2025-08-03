package zip

import (
	archiveZip "archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/lib"
)

type zip struct{}

func New() compression.Compression {
	return &zip{}
}

// Pack - zips a folder into a []byte buffer.
func (z *zip) Pack(folder string) ([]byte, error) {
	var (
		buf = new(bytes.Buffer)
		zw  = archiveZip.NewWriter(buf)
	)
	if err := filepath.WalkDir(folder, func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return nil
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

		cleanPath := filepath.Clean(path)

		f, err := os.Open(cleanPath)
		if err != nil {
			return lib.IOErr(
				lib.CategoryCompression,
				lib.ErrCodeOpenFileError,
				lib.ErrMessageOpenFileError,
				"",
				err,
			)
		}
		defer func(f *os.File) {
			if errClose := f.Close(); err != nil {
				fmt.Printf("error closing file; %v", errClose)
			}
		}(f)

		w, err := zw.Create(relPath)
		if err != nil {
			return lib.IOErr(
				lib.CategoryCompression,
				lib.ErrCodeCreateZipError,
				lib.ErrMessageCreateZipError,
				"",
				err,
			)
		}

		if _, err = io.Copy(w, f); err != nil {
			return lib.IOErr(
				lib.CategoryCompression,
				lib.ErrCodeIOCopyError,
				lib.ErrMessageIOCopyError,
				"",
				err,
			)
		}

		return nil
	}); err != nil {
		return nil, lib.IOErr(
			lib.CategoryCompression,
			lib.ErrCodeWalkDirError,
			lib.ErrMessageWalkDirError,
			"",
			err,
		)
	}

	if err := zw.Close(); err != nil {
		return nil, lib.IOErr(
			lib.CategoryCompression,
			lib.ErrCodeCloseZipError,
			lib.ErrMessageCloseZipError,
			"",
			err,
		)
	}

	return buf.Bytes(), nil
}

// Unpack - extracts container content to the target directory.
func (z *zip) Unpack(data []byte, targetDir string) error {
	r, err := archiveZip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return lib.IOErr(
			lib.CategoryCompression,
			lib.ErrCodeCreateZipReaderError,
			lib.ErrMessageCreateZipReaderError,
			"",
			err,
		)
	}

	for _, f := range r.File {
		path := filepath.Join(targetDir, f.Name) // #nosec G305
		if f.FileInfo().IsDir() {
			if err = os.MkdirAll(path, 0750); err != nil {
				return lib.IOErr(
					lib.CategoryCompression,
					lib.ErrCodeCreateDirectoryError,
					lib.ErrMessageCreateDirectoryError,
					"",
					err,
				)
			}

			continue
		}

		if err = os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			return lib.IOErr(
				lib.CategoryCompression,
				lib.ErrCodeCreateDirectoryError,
				lib.ErrMessageCreateDirectoryError,
				"",
				err,
			)
		}

		cleanPath := filepath.Clean(path)

		var out *os.File
		if out, err = os.OpenFile(cleanPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode()); err != nil {
			return lib.IOErr(
				lib.CategoryCompression,
				lib.ErrCodeOSOpenFileError,
				lib.ErrMessageOSOpenFileError,
				"",
				err,
			)
		}

		var rc io.ReadCloser
		if rc, err = f.Open(); err != nil {
			if errClose := out.Close(); errClose != nil {
				return lib.IOErr(
					lib.CategoryCompression,
					lib.ErrCodeCloseFileError,
					lib.ErrMessageCloseFileError,
					"",
					errClose,
				)
			}

			return lib.IOErr(
				lib.CategoryCompression,
				lib.ErrCodeOpenFileError,
				lib.ErrMessageOpenFileError,
				"",
				err,
			)
		}

		_, err = io.Copy(out, rc) // #nosec G110

		if errClose := out.Close(); errClose != nil {
			return lib.IOErr(
				lib.CategoryCompression,
				lib.ErrCodeCloseFileError,
				lib.ErrMessageCloseFileError,
				"",
				errClose,
			)
		}

		if errClose := rc.Close(); errClose != nil {
			return lib.IOErr(
				lib.CategoryCompression,
				lib.ErrCodeReaderCloserError,
				lib.ErrMessageReaderCloserError,
				"",
				errClose,
			)
		}

		if err != nil {
			return lib.IOErr(
				lib.CategoryCompression,
				lib.ErrCodeIOCopyError,
				lib.ErrMessageIOCopyError,
				"",
				err,
			)
		}
	}

	return nil
}

func (z *zip) ID() byte {
	return compression.TypeZip
}
