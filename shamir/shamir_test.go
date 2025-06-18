package shamir

import (
	"bytes"
	"errors"
	"testing"

	"github.com/namelesscorp/tvault-core/integrity_provider"
	"github.com/namelesscorp/tvault-core/integrity_provider/mock"
)

func TestSplit(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		n, t      int
		provider  integrity_provider.IntegrityProvider
		expectErr bool
	}{
		{
			name:  "valid input",
			input: []byte("secret"),
			n:     5, t: 3,
			provider: &mock.Provider{
				VerifyError:  nil,
				IsVerifySign: true,
				SignError:    nil,
				Signature:    []byte("abcd"),
				ProviderID:   1,
			},
			expectErr: false,
		},
		{
			name:  "t less than 2",
			input: []byte("secret"),
			n:     5, t: 1,
			provider: &mock.Provider{
				VerifyError:  nil,
				IsVerifySign: true,
				SignError:    nil,
				Signature:    []byte("abcd"),
				ProviderID:   1,
			},
			expectErr: true,
		},
		{
			name:  "n less than t",
			input: []byte("secret"),
			n:     2, t: 3,
			provider: &mock.Provider{
				VerifyError:  nil,
				IsVerifySign: true,
				SignError:    nil,
				Signature:    []byte("abcd"),
				ProviderID:   1,
			},
			expectErr: true,
		},
		{
			name:  "n greater than 255",
			input: []byte("secret"),
			n:     300, t: 3,
			provider: &mock.Provider{
				VerifyError:  nil,
				IsVerifySign: true,
				SignError:    nil,
				Signature:    []byte("abcd"),
				ProviderID:   1,
			},
			expectErr: true,
		},
		{
			name:  "t greater than 255",
			input: []byte("secret"),
			n:     5, t: 300,
			provider: &mock.Provider{
				VerifyError:  nil,
				IsVerifySign: true,
				SignError:    nil,
				Signature:    []byte("abcd"),
				ProviderID:   1,
			},
			expectErr: true,
		},
		{
			name:  "sign error",
			input: []byte("secret"),
			n:     5, t: 3,
			provider: &mock.Provider{
				VerifyError:  nil,
				IsVerifySign: true,
				SignError:    errors.New("sign error"),
				Signature:    []byte("abcd"),
				ProviderID:   1,
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Split(tt.input, tt.n, tt.t, tt.provider); (err != nil) != tt.expectErr {
				t.Errorf("Split() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}

func TestCombine(t *testing.T) {
	tests := []struct {
		name         string
		shares       []Share
		provider     integrity_provider.IntegrityProvider
		expectResult []byte
		expectErr    bool
	}{
		{
			name: "valid shares",
			shares: []Share{
				{ID: 1, Value: []byte("abcd"), Signature: []byte("abcd1")},
				{ID: 2, Value: []byte("abcd"), Signature: []byte("abcd2")},
			},
			provider: &mock.Provider{
				VerifyError:  nil,
				IsVerifySign: true,
				SignError:    nil,
				Signature:    []byte("abcd"),
				ProviderID:   1,
			},
			expectResult: []byte("abcd"),
			expectErr:    false,
		},
		{
			name: "not enough shares",
			shares: []Share{
				{ID: 1, Value: []byte("abcd"), Signature: []byte("abcd1")},
			},
			provider: &mock.Provider{
				VerifyError:  nil,
				IsVerifySign: true,
				SignError:    nil,
				Signature:    []byte("abcd"),
				ProviderID:   1,
			},
			expectResult: nil,
			expectErr:    true,
		},
		{
			name: "invalid signature",
			shares: []Share{
				{ID: 1, Value: []byte("abcd"), Signature: []byte("abcd1")},
				{ID: 2, Value: []byte("invalid"), Signature: []byte("abcd2")},
			},
			provider: &mock.Provider{
				VerifyError:  errors.New("verify error"),
				IsVerifySign: true,
				SignError:    nil,
				Signature:    []byte("abcd"),
				ProviderID:   1,
			},
			expectResult: nil,
			expectErr:    true,
		},
		{
			name: "verify error",
			shares: []Share{
				{ID: 1, Value: []byte("abcd"), Signature: []byte("abcd1")},
				{ID: 2, Value: []byte("abcd"), Signature: []byte("abcd2")},
			},
			provider: &mock.Provider{
				VerifyError:  errors.New("verify error"),
				IsVerifySign: true,
				SignError:    nil,
				Signature:    []byte("abcd"),
				ProviderID:   1,
			},
			expectResult: nil,
			expectErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Combine(tt.shares, tt.provider)
			if (err != nil) != tt.expectErr {
				t.Errorf("Combine() error = %v, expectErr %v", err, tt.expectErr)
			}

			if !bytes.Equal(result, tt.expectResult) {
				t.Errorf("Combine() result = %v, expected %v", result, tt.expectResult)
			}
		})
	}
}
