//go:build !windows

package engine

import "fmt"

func performRegSave(hiveKey, outFile string) error {
	// On non-windows systems, we cannot dump registry hives using 'reg save'.
	return fmt.Errorf("registry dumping not supported on this OS")
}

func copyLockedFile(src, dst string) error {
	return fmt.Errorf("copy locked file not supported on this OS")
}
