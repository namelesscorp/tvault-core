package mock

type Provider struct {
	VerifyError  error
	IsVerifySign bool
	SignError    error
	Signature    []byte
	ProviderID   byte
}

func (p *Provider) Sign(_ byte, _ []byte) ([]byte, error) {
	if p.SignError != nil {
		return nil, p.SignError
	}

	return p.Signature, nil
}

func (p *Provider) IsVerify(_ byte, _, _ []byte) (bool, error) {
	if p.VerifyError != nil {
		return false, p.VerifyError
	}

	return p.IsVerifySign, nil
}

func (p *Provider) ID() byte {
	return p.ProviderID
}
