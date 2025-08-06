package container

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMetadata(t *testing.T) {
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

	t.Run("json marshaling", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Microsecond)
		comment := "Test comment"

		metadata := Metadata{
			CreatedAt: now,
			UpdatedAt: now,
			Comment:   comment,
		}

		jsonData, err := json.Marshal(metadata)
		if err != nil {
			t.Fatalf("Failed to marshal metadata: %v", err)
		}

		var unmarshalMetadata Metadata
		err = json.Unmarshal(jsonData, &unmarshalMetadata)
		if err != nil {
			t.Fatalf("Failed to unmarshal metadata: %v", err)
		}

		if !unmarshalMetadata.CreatedAt.Equal(metadata.CreatedAt) {
			t.Errorf("Expected CreatedAt to be %v, got %v", metadata.CreatedAt, unmarshalMetadata.CreatedAt)
		}

		if !unmarshalMetadata.UpdatedAt.Equal(metadata.UpdatedAt) {
			t.Errorf("Expected UpdatedAt to be %v, got %v", metadata.UpdatedAt, unmarshalMetadata.UpdatedAt)
		}

		if unmarshalMetadata.Comment != metadata.Comment {
			t.Errorf("Expected Comment to be %s, got %s", metadata.Comment, unmarshalMetadata.Comment)
		}
	})

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
