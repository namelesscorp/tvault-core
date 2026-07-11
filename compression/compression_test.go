package compression

import (
	"testing"
)

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

	if _, ok := Types[TypeNameNone]; !ok {
		t.Errorf("Expected %q to be in Types map", TypeNameNone)
	}
}
