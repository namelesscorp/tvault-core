package lib

import (
	"encoding/json"
	"fmt"
	"io"
)

const (
	WriterFormatJSON      = "json"
	WriterFormatPlaintext = "plaintext"

	jsonIndent = " "
)

var (
	WriterFormats = map[string]struct{}{
		WriterFormatJSON:      {},
		WriterFormatPlaintext: {},
	}
)

// WriteFormatted - writes a formatted message to the provided io.Writer based on the specified format.
// Supported formats: "plaintext", "json".
func WriteFormatted(w io.Writer, format string, msg any) (int, error) {
	switch format {
	case WriterFormatPlaintext:
		str, ok := msg.(string)
		if !ok {
			return 0, ErrTypeAssertionFailed
		}

		return write(w, []byte(str))
	case WriterFormatJSON:
		switch v := msg.(type) {
		case string:
			return write(w, []byte(v))
		default:
			b, err := jsonBytes(v)
			if err != nil {
				return 0, err
			}

			return write(w, b)
		}
	default:
		return 0, ErrUnknownWriterFormat
	}
}

func write(w io.Writer, data []byte) (int, error) {
	if w == nil {
		return fmt.Println(string(data))
	}

	return w.Write(data)
}

func jsonBytes(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", jsonIndent)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message: %w", err)
	}

	return b, nil
}
