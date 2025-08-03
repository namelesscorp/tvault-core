package lib

import (
	"fmt"
	"io"
	"os"
)

const (
	WriterTypeFile   = "file"
	WriterTypeStdout = "stdout"
)

var (
	WriterTypes = map[string]struct{}{
		WriterTypeFile:   {},
		WriterTypeStdout: {},
	}
)

type (
	StdoutWriter struct {
		format string
	}

	FileWriter struct {
		format string
		file   *os.File
	}
)

// NewWriter - creates an io.Writer and optionally an io.Closer based on the provided Writer configuration.
// Supported types: "file", "stdout".
// Supported formats: "plaintext", "json".
//
// Stdout writer:
// - writes a formatted message to stdout based on the specified format.
// - supports two formats: "plaintext" and "json".
//
// File writer:
// - writes a formatted message to the provided file path based on the specified format.
func NewWriter(opts *Writer) (io.Writer, io.Closer, error) {
	switch *opts.Type {
	case WriterTypeFile:
		w, err := newFileWriter(*opts.Path, *opts.Format)
		if err != nil {
			return nil, nil, err
		}

		return w, w, nil
	case WriterTypeStdout:
		return newStdoutWriter(*opts.Format), nil, nil
	default:
		return nil, nil, ErrUnknownWriterType
	}
}

func newStdoutWriter(format string) StdoutWriter {
	return StdoutWriter{format: format}
}

func (s StdoutWriter) Write(p []byte) (int, error) {
	return fmt.Println(string(p))
}

func newFileWriter(path, format string) (*FileWriter, error) {
	f, err := os.Create(path) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("failed to create token file: %w", err)
	}

	return &FileWriter{
		format: format,
		file:   f,
	}, nil
}

func (f *FileWriter) Write(p []byte) (int, error) {
	return f.file.Write(p)
}

func (f *FileWriter) Close() error {
	return f.file.Close()
}
