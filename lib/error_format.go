package lib

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func ErrorFormatted(logWriter *Writer, operation string, err error) {
	writer, closer, _ := NewWriter(logWriter)
	if closer != nil {
		defer func(closer io.Closer) {
			_ = closer.Close()
		}(closer)
	}

	var errLib *Error
	if ok := errors.As(err, &errLib); !ok {
		fmt.Printf("[error]\noperation: %s;\nmessage: %v", operation, err)
		os.Exit(1)
		return
	}

	var message any
	switch *logWriter.Format {
	case WriterFormatPlaintext:
		message = fmt.Sprintf(
			"[error]\noperation: %s;\nmessage: %s;\ncode: %d;\ntype: %d;\ncategory: %d;"+
				"\ndetails: %s;\nsuggestion: %s;\nstacktrace: %s\n",
			operation,
			errLib.Message,
			errLib.Code,
			errLib.Type,
			errLib.Category,
			errLib.Details,
			errLib.Suggestion,
			strings.Join(errLib.Stacktrace, ": "),
		)
	case WriterFormatJSON:
		message = errLib
	}

	if _, err = WriteFormatted(writer, *logWriter.Format, message); err != nil {
		fmt.Printf("failed to write error message; %v", err)
	}

	os.Exit(1)
}
