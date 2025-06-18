package container

import "time"

// Metadata — arbitrary container metadata (stored unencrypted).
type Metadata struct {
	CreatedAt time.Time `json:"created_at"`
	Comment   string    `json:"comment"`
}
