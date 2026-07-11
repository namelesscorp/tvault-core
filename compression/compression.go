package compression

import "io"

const (
	TypeNone byte = 0x00
	TypeZip  byte = 0x01

	TypeNameNone string = "none"
	TypeNameZip  string = "zip"
)

var Types = map[string]struct{}{
	TypeNameZip: {},
}

type (
	Compression interface {
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

	noneCompression struct{}
)

func NewNoneCompression() Compression {
	return &noneCompression{}
}

// Pack - unimplemented
func (n noneCompression) Pack(_ string) ([]byte, error) {
	panic("not implemented")
}

// Unpack - unimplemented
func (n noneCompression) Unpack(_ []byte, _ string) error {
	panic("not implemented")
}

func (n noneCompression) PackTo(_ string, _ io.Writer) error {
	panic("not implemented")
}

func (n noneCompression) UnpackFrom(_ io.ReaderAt, _ int64, _ string) error {
	panic("not implemented")
}

func (n noneCompression) ID() byte {
	return TypeNone
}

func (n noneCompression) GetUncompressedSize() int64 {
	panic("not implemented")
}

func (n noneCompression) GetCompressedSize() int64 {
	panic("not implemented")
}

func (n noneCompression) GetCompressedData() []byte {
	panic("not implemented")
}

func (n noneCompression) GetFileCount() int64 {
	panic("not implemented")
}

func (n noneCompression) GetFileNameList() []string {
	panic("not implemented")
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
