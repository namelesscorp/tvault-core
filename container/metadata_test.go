package container

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMetadata(t *testing.T) {
	// Test creating a new Metadata struct
	t.Run("create metadata", func(t *testing.T) {
		now := time.Now()
		comment := "Test comment"

		metadata := Metadata{
			CreatedAt: now,
			UpdatedAt: now,
			Comment:   comment,
		}

		if !metadata.CreatedAt.Equal(now) {
			t.Errorf("Expected CreatedAt to be %v, got %v", now, metadata.CreatedAt)
		}

		if !metadata.UpdatedAt.Equal(now) {
			t.Errorf("Expected UpdatedAt to be %v, got %v", now, metadata.UpdatedAt)
		}

		if metadata.Comment != comment {
			t.Errorf("Expected Comment to be %s, got %s", comment, metadata.Comment)
		}
	})

	// Test JSON marshaling and unmarshaling
	t.Run("json marshaling", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Microsecond) // Truncate to avoid precision issues
		comment := "Test comment"

		metadata := Metadata{
			CreatedAt: now,
			UpdatedAt: now,
			Comment:   comment,
		}

		// Marshal to JSON
		jsonData, err := json.Marshal(metadata)
		if err != nil {
			t.Fatalf("Failed to marshal metadata: %v", err)
		}

		// Unmarshal back to struct
		var unmarshaledMetadata Metadata
		err = json.Unmarshal(jsonData, &unmarshaledMetadata)
		if err != nil {
			t.Fatalf("Failed to unmarshal metadata: %v", err)
		}

		// Verify fields match
		if !unmarshaledMetadata.CreatedAt.Equal(metadata.CreatedAt) {
			t.Errorf("Expected CreatedAt to be %v, got %v", metadata.CreatedAt, unmarshaledMetadata.CreatedAt)
		}

		if !unmarshaledMetadata.UpdatedAt.Equal(metadata.UpdatedAt) {
			t.Errorf("Expected UpdatedAt to be %v, got %v", metadata.UpdatedAt, unmarshaledMetadata.UpdatedAt)
		}

		if unmarshaledMetadata.Comment != metadata.Comment {
			t.Errorf("Expected Comment to be %s, got %s", metadata.Comment, unmarshaledMetadata.Comment)
		}
	})

	// Test zero values
	t.Run("zero values", func(t *testing.T) {
		metadata := Metadata{}

		if !metadata.CreatedAt.IsZero() {
			t.Errorf("Expected CreatedAt to be zero, got %v", metadata.CreatedAt)
		}

		if !metadata.UpdatedAt.IsZero() {
			t.Errorf("Expected UpdatedAt to be zero, got %v", metadata.UpdatedAt)
		}

		if metadata.Comment != "" {
			t.Errorf("Expected Comment to be empty, got %s", metadata.Comment)
		}
	})
}
