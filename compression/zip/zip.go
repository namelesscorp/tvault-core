package zip

import (
	archiveZip "archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/namelesscorp/tvault-core/compression"
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
			return fmt.Errorf("get relative path error; %w", err)
		}

		cleanPath := filepath.Clean(path)
		if strings.Contains(cleanPath, "..") {
			return fmt.Errorf("path contains prohibited sequences")
		}

		f, err := os.Open(cleanPath)
		if err != nil {
			return fmt.Errorf("open file error; %w", err)
		}
		defer func(f *os.File) {
			if errClose := f.Close(); err != nil {
				log.Printf("error closing file; %v", errClose)
			}
		}(f)

		w, err := zw.Create(relPath)
		if err != nil {
			return fmt.Errorf("create zip error; %w", err)
		}

		if _, err = io.Copy(w, f); err != nil {
			return fmt.Errorf("io copy error; %w", err)
		}

		return nil
	}); err != nil {
		return nil, fmt.Errorf("walk dir error; %w", err)
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("close zip error; %w", err)
	}

	return buf.Bytes(), nil
}

// Unpack - extracts container content to the target directory.
func (z *zip) Unpack(data []byte, targetDir string) error {
	r, err := archiveZip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("create new zip reader error; %w", err)
	}

	for _, f := range r.File {
		path := filepath.Join(targetDir, f.Name)

		var relPath string
		if relPath, err = filepath.Rel(targetDir, path); err != nil || strings.HasPrefix(relPath, "..") ||
			filepath.IsAbs(relPath) {
			return fmt.Errorf("illegal file path: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err = os.MkdirAll(path, 0750); err != nil {
				return fmt.Errorf("create directory error; %w", err)
			}

			continue
		}

		if err = os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			return fmt.Errorf("create directory error; %w", err)
		}

		cleanPath := filepath.Clean(path)
		if strings.Contains(cleanPath, "..") {
			return fmt.Errorf("path contains prohibited sequences")
		}

		var out *os.File
		if out, err = os.OpenFile(cleanPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode()); err != nil {
			return fmt.Errorf("os open file error; %w", err)
		}

		var rc io.ReadCloser
		if rc, err = f.Open(); err != nil {
			if errClose := out.Close(); errClose != nil {
				return fmt.Errorf("close file error; %w", errClose)
			}

			return fmt.Errorf("open file error; %w", err)
		}

		_, err = io.Copy(out, rc)

		if errClose := out.Close(); errClose != nil {
			return fmt.Errorf("close file error; %w", errClose)
		}

		if errClose := rc.Close(); errClose != nil {
			return fmt.Errorf("reader closer error; %w", errClose)
		}

		if err != nil {
			return fmt.Errorf("io copy error; %w", err)
		}
	}

	return nil
}

func (z *zip) ID() byte {
	return compression.TypeZip
}
