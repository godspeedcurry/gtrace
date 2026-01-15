//go:build !windows

package engine

import "fmt"

func performRegSave(hiveKey, outFile string) error {
	// On non-windows systems, we cannot dump registry hives using 'reg save'.
	return fmt.Errorf("registry dumping not supported on this OS")
}
