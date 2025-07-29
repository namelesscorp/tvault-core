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

	promptPlainText = "Format plaintext: <token_1>|<token_2>...\nEnter your token(s):"
	promptJSON      = "Format json: {'token_list': ['token_1', 'token_2']}\nEnter your token(s):"
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

func NewReader(readerType, format, path string) (io.Reader, io.ReadCloser, error) {
	switch readerType {
	case ReaderTypeFile:
		return newFileReader(path)
	case ReaderTypeStdin:
		return newStdinReader(format)
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

func endDelimiter(format string) (byte, string, error) {
	switch format {
	case ReaderFormatPlaintext:
		return '\n', promptPlainText, nil
	case ReaderFormatJSON:
		return '}', promptJSON, nil
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
