package compression

const (
	TypeNone byte = 0x00
	TypeZip  byte = 0x01

	TypeNameNone string = "none"
	TypeNameZip  string = "zip"
)

type (
	Compression interface {
		Pack(folder string) ([]byte, error)
		Unpack(data []byte, targetDir string) error
		ID() byte
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

func (n noneCompression) ID() byte {
	return TypeNone
}
