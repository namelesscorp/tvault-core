package container

import "time"

const defaultComment = "created by trust vault core"

// Metadata — arbitrary container metadata (stored unencrypted).
type Metadata struct {
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Comment   string    `json:"comment"`
	Tags      []string  `json:"tags"`
}
