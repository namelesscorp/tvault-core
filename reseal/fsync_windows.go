//go:build windows

package reseal

// fsyncDir - on Windows there is no supported way to flush a directory handle
// (FlushFileBuffers fails on directories), so this is a no-op. Durability of the
// rename relies on the NTFS metadata journal instead.
func fsyncDir(_ string) error {
	return nil
}
