package container

import "time"

const defaultComment = "created by trust vault core"

// Metadata — arbitrary container metadata (stored unencrypted).
type Metadata struct {
	Name             string    `json:"name"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	Comment          string    `json:"comment"`
	Tags             []string  `json:"tags"`
	CompressedSize   int64     `json:"compressed_size"`
	UncompressedSize int64     `json:"uncompressed_size"`
	SecurityScore    float64   `json:"security_score"`
	FileCount        int64     `json:"file_count"`
}
