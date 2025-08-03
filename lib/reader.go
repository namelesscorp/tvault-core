package lib

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	ReaderTypeFlag  = "flag"
	ReaderTypeFile  = "file"
	ReaderTypeStdin = "stdin"

	stdoutPlainTextMessage = "Format plaintext: <token_1>|<token_2>...\nEnter your token(s):"
	stdoutJSONMessage      = "Format json: {'token_list': ['token_1', 'token_2']}\nEnter your token(s):"
)

var ReaderTypes = map[string]struct{}{
	ReaderTypeFlag:  {},
	ReaderTypeFile:  {},
	ReaderTypeStdin: {},
}

type (
	byteSliceReader struct {
		data   []byte
		offset int
	}
	CloserWrapper struct {
		io.Closer
	}
)

// NewReader - creates an io.Reader and optionally an io.Closer based on the provided Reader configuration.
// Supported types: "flag", "file", "stdin".
// Supported formats: "plaintext", "json".
//
// Stdin reader:
// - reads a single line from stdin and returns it as a byte slice.
// - prompts the user to enter a token.
// - supports two formats: "plaintext" and "json".
//
// Flag reader:
// - reads a single line from stdin and returns it as a byte slice.
//
// File reader:
// - reads a file and returns it as a byte slice.
func NewReader(opts *Reader) (io.Reader, io.ReadCloser, error) {
	switch *opts.Type {
	case ReaderTypeFile:
		return newFileReader(*opts.Path)
	case ReaderTypeStdin:
		return newStdinReader(*opts.Format)
	case ReaderTypeFlag:
		return newFlagReader(*opts.Flag)
	default:
		return nil, nil, ErrUnknownReaderType
	}
}

func newFileReader(path string) (io.Reader, io.ReadCloser, error) {
	content, err := os.ReadFile(path) // #nosec G304
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read file; %w", err)
	}

	return &byteSliceReader{data: content}, CloserWrapper{}, nil
}

func newStdinReader(format string) (io.Reader, io.ReadCloser, error) {
	delim, prompt, err := endDelimiter(format)
	if err != nil {
		return nil, nil, err
	}

	fmt.Println(prompt)

	line, readErr := bufio.NewReader(os.Stdin).ReadBytes(delim)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, nil, fmt.Errorf("read stdin; %w", readErr)
	}

	return &byteSliceReader{data: line}, CloserWrapper{Closer: os.Stdin}, nil
}

func newFlagReader(flag string) (io.Reader, io.ReadCloser, error) {
	return &byteSliceReader{data: []byte(flag)}, CloserWrapper{}, nil
}

func endDelimiter(format string) (byte, string, error) {
	switch format {
	case ReaderFormatPlaintext:
		return '\n', stdoutPlainTextMessage, nil
	case ReaderFormatJSON:
		return '}', stdoutJSONMessage, nil
	default:
		return 0, "", ErrUnknownReaderFormat
	}
}

func (r *byteSliceReader) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}

	n := copy(p, r.data[r.offset:])
	r.offset += n

	return n, nil
}

func (CloserWrapper) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c CloserWrapper) Close() error {
	if c.Closer != nil {
		return c.Closer.Close()
	}

	return nil
}
