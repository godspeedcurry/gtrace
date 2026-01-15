//go:build !windows

package plugin

import "os"

// openFileShared delegates to os.Open on non-Windows systems
func openFileShared(path string) (*os.File, error) {
	return os.Open(path)
}
