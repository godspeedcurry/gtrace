//go:build windows

package plugin

import (
	"os/exec"
	"syscall"
)

// copyLockedFile attempts to copy a file that might be locked by another process (like a browser or system log).
func copyLockedFile(src, dst string) error {
	// Use cmd /c copy /b which is more robust against certain Windows locks
	cmd := exec.Command("cmd", "/c", "copy", "/y", "/b", src, dst)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}
