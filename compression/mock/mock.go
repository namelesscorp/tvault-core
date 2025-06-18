package mock

type Compression struct {
	CompressionID int
	PackContent   []byte
	PackError     error
	UnpackError   error
}

func (c *Compression) Pack(_ string) ([]byte, error) {
	if c.PackError != nil {
		return nil, c.PackError
	}

	return c.PackContent, nil
}

func (c *Compression) Unpack(_ []byte, _ string) error {
	return c.UnpackError
}

func (c *Compression) ID() byte {
	return byte(c.CompressionID)
}
