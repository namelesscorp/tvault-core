package shamir

import (
	"bytes"
	"errors"
	"testing"

	"github.com/namelesscorp/tvault-core/integrity"
	"github.com/namelesscorp/tvault-core/integrity/mock"
)

func TestSplit(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		n, t      int
		provider  integrity.Provider
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
		provider     integrity.Provider
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

// TestCombineRejectsMalformedShares checks that malformed share sets from
// untrusted tokens produce errors rather than panics (division-by-zero on
// duplicate ids, index-out-of-range on mismatched value lengths).
func TestCombineRejectsMalformedShares(t *testing.T) {
	p := integrity.NewNoneProvider()

	build := func(t *testing.T) []Share {
		t.Helper()
		shares, err := Split([]byte("this-is-a-32-byte-master-key!!!!"), 5, 3, p)
		if err != nil {
			t.Fatalf("Split failed: %v", err)
		}
		return shares
	}

	t.Run("threshold subset round-trips", func(t *testing.T) {
		shares := build(t)
		got, err := Combine([]Share{shares[0], shares[2], shares[4]}, p)
		if err != nil {
			t.Fatalf("Combine failed: %v", err)
		}
		if !bytes.Equal(got, []byte("this-is-a-32-byte-master-key!!!!")) {
			t.Fatalf("round-trip mismatch: %q", got)
		}
	})

	t.Run("duplicate id returns error not panic", func(t *testing.T) {
		shares := build(t)
		if _, err := Combine([]Share{shares[0], shares[0], shares[1]}, p); err == nil {
			t.Fatal("expected error for duplicate share id, got nil")
		}
	})

	t.Run("zero id returns error not panic", func(t *testing.T) {
		shares := build(t)
		zero := shares[0]
		zero.ID = 0
		if _, err := Combine([]Share{zero, shares[1], shares[2]}, p); err == nil {
			t.Fatal("expected error for zero share id, got nil")
		}
	})

	t.Run("mismatched value length returns error not panic", func(t *testing.T) {
		shares := build(t)
		short := shares[1]
		short.Value = short.Value[:len(short.Value)-1]
		if _, err := Combine([]Share{shares[0], short, shares[2]}, p); err == nil {
			t.Fatal("expected error for mismatched share length, got nil")
		}
	})
}
