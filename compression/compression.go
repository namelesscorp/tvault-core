package compression

import "io"

const (
	TypeNone byte = 0x00
	TypeZip  byte = 0x01

	TypeNameNone string = "none"
	TypeNameZip  string = "zip"
)

var Types = map[string]struct{}{
	TypeNameNone: {},
	TypeNameZip:  {},
}

// Compression bundles a folder into a single stream and back. Both supported
// types ("zip" and "none") are produced by the zip package: "zip" deflates
// entries, "none" stores them uncompressed (see zip.New / zip.NewStore).
type Compression interface {
	Pack(folder string) ([]byte, error)
	Unpack(data []byte, targetDir string) error

	PackTo(folder string, w io.Writer) error
	UnpackFrom(r io.ReaderAt, size int64, targetDir string) error

	ID() byte
	GetUncompressedSize() int64
	GetCompressedSize() int64
	GetCompressedData() []byte
	GetFileCount() int64
	GetFileNameList() []string
}

func ConvertIDToName(id byte) string {
	switch id {
	case TypeNone:
		return TypeNameNone
	case TypeZip:
		return TypeNameZip
	default:
		return ""
	}
}
