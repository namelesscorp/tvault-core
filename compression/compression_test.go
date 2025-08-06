package compression

import (
	"testing"
)

func TestNewNoneCompression(t *testing.T) {
	var compression = NewNoneCompression()
	if compression == nil {
		t.Error("Expected non-nil compression, got nil")
	}

	if compression.ID() != TypeNone {
		t.Errorf("Expected compression ID to be %d, got %d", TypeNone, compression.ID())
	}
}

func TestNoneCompressionPanic(t *testing.T) {
	compression := NewNoneCompression()

	t.Run("pack panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected Pack to panic, but it didn't")
			}
		}()

		_, _ = compression.Pack("")
	})

	t.Run("unpack panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected Unpack to panic, but it didn't")
			}
		}()

		_ = compression.Unpack(nil, "")
	})
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
			name:     "TypeZip",
			id:       TypeZip,
			expected: TypeNameZip,
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

func TestTypes(t *testing.T) {
	if _, ok := Types[TypeNameZip]; !ok {
		t.Errorf("Expected %q to be in Types map", TypeNameZip)
	}

	if _, ok := Types[TypeNameNone]; ok {
		t.Errorf("Expected %q not to be in Types map", TypeNameNone)
	}
}
