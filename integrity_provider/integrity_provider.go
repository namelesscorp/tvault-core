package integrity_provider

const (
	TypeNone    byte = 0x00
	TypeHMAC    byte = 0x01
	TypeEd25519 byte = 0x02

	TypeNameNone    string = "none"
	TypeNameHMAC    string = "hmac"
	TypeNameEd25519 string = "ed25519"
)

type (
	IntegrityProvider interface {
		Sign(id byte, data []byte) (signature []byte, _ error)
		IsVerify(id byte, data, signature []byte) (isVerify bool, _ error)
		ID() byte
	}

	noneProvider struct{}
)

func NewNoneProvider() IntegrityProvider {
	return &noneProvider{}
}

func (n *noneProvider) Sign(_ byte, _ []byte) ([]byte, error) {
	return nil, nil
}

func (n *noneProvider) IsVerify(_ byte, _, _ []byte) (bool, error) {
	return true, nil
}

func (n *noneProvider) ID() byte {
	return TypeNone
}
