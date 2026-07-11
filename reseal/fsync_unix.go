//go:build !windows

package reseal

import (
	"os"

	"github.com/namelesscorp/tvault-core/lib"
)

// fsyncDir - flushes a directory's metadata to stable storage so that a rename
// into that directory becomes durable across a power failure.
func fsyncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304
	if err != nil {
		return lib.IOErr(lib.CategoryReseal, lib.ErrCodeResealSyncDirError, lib.ErrMessageResealSyncDirError, "", err)
	}
	defer func() { _ = d.Close() }()

	if err = d.Sync(); err != nil {
		return lib.IOErr(lib.CategoryReseal, lib.ErrCodeResealSyncDirError, lib.ErrMessageResealSyncDirError, "", err)
	}

	return nil
}
