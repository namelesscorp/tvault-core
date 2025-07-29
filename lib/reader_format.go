package lib

const (
	ReaderFormatJSON      = "json"
	ReaderFormatPlaintext = "plaintext"
)

var (
	ReaderFormats = map[string]struct{}{
		ReaderFormatJSON:      {},
		ReaderFormatPlaintext: {},
	}
)
