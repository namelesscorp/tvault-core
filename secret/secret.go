package secret

import "crypto/subtle"

type (
	Secret interface {
		Bytes() []byte
		Equal(other []byte) bool
		Destroy()
		IsDestroyed() bool
		Len() int
	}

	secret struct {
		data []byte
	}
)

func New(data []byte) Secret {
	s := &secret{
		data: make([]byte, len(data)),
	}
	copy(s.data, data)

	return s
}

func (s *secret) Bytes() []byte {
	out := make([]byte, len(s.data))
	copy(out, s.data)

	return out
}

func (s *secret) Equal(other []byte) bool {
	if other == nil || len(other) != len(s.data) {
		return false
	}

	return subtle.ConstantTimeCompare(s.data, other) == 1
}

func (s *secret) Destroy() {
	if s.IsDestroyed() {
		return
	}
	for i := range s.data {
		s.data[i] = 0
	}
	s.data = nil
}

func (s *secret) IsDestroyed() bool {
	return s.data == nil
}

func (s *secret) Len() int {
	return len(s.data)
}
