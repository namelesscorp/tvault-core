package integrity

import (
	"testing"
)

func TestNewNoneProvider(t *testing.T) {
	provider := NewNoneProvider()

	if provider == nil {
		t.Error("Expected non-nil provider, got nil")
	}

	if provider.ID() != TypeNone {
		t.Errorf("Expected provider ID to be %d, got %d", TypeNone, provider.ID())
	}
}

func TestNoneProviderSign(t *testing.T) {
	provider := NewNoneProvider()

	signature, err := provider.Sign(0, []byte("test data"))
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if signature != nil {
		t.Errorf("Expected nil signature, got %v", signature)
	}
}

func TestNoneProviderIsVerify(t *testing.T) {
	provider := NewNoneProvider()

	isVerify, err := provider.IsVerify(0, []byte("test data"), nil)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if !isVerify {
		t.Error("Expected isVerify to be true, got false")
	}
}

func TestConvertIDToName(t *testing.T) {
	tests := []struct {
		name     string
		id       byte
		expected string
	}{
		{
			name:     "TypeNone",
			id:       TypeNone,
			expected: TypeNameNone,
		},
		{
			name:     "TypeHMAC",
			id:       TypeHMAC,
			expected: TypeNameHMAC,
		},
		{
			name:     "TypeEd25519",
			id:       TypeEd25519,
			expected: TypeNameEd25519,
		},
		{
			name:     "Unknown type",
			id:       0xFF,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConvertIDToName(tt.id)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestConvertNameToID(t *testing.T) {
	tests := []struct {
		name     string
		typeName string
		expected byte
	}{
		{
			name:     "TypeNameNone",
			typeName: TypeNameNone,
			expected: TypeNone,
		},
		{
			name:     "TypeNameHMAC",
			typeName: TypeNameHMAC,
			expected: TypeHMAC,
		},
		{
			name:     "TypeNameEd25519",
			typeName: TypeNameEd25519,
			expected: TypeEd25519,
		},
		{
			name:     "Unknown type",
			typeName: "unknown",
			expected: TypeNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConvertNameToID(tt.typeName)
			if result != tt.expected {
				t.Errorf("Expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestTypes(t *testing.T) {
	// Verify that TypeNameNone is in the Types map
	if _, ok := Types[TypeNameNone]; !ok {
		t.Errorf("Expected %q to be in Types map", TypeNameNone)
	}

	// Verify that TypeNameHMAC is in the Types map
	if _, ok := Types[TypeNameHMAC]; !ok {
		t.Errorf("Expected %q to be in Types map", TypeNameHMAC)
	}

	// Verify that TypeNameEd25519 is not in the Types map
	if _, ok := Types[TypeNameEd25519]; ok {
		t.Errorf("Expected %q not to be in Types map", TypeNameEd25519)
	}
}
