//go:build windows

package engine

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"syscall"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

func performRegSave(hiveKey, outFile string) error {
	// Try direct execution first using short key (HKLM\SYSTEM)
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

	// Fallback: PowerShell
	// powershell -NoProfile -WindowStyle Hidden -Command "Reg Save HKLM\SYSTEM 'path' /y"
	psCmd := fmt.Sprintf("reg save %s '%s' /y", hiveKey, outFile)
	cmdPS := exec.Command("powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", psCmd)
	cmdPS.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	outPS, errPS := cmdPS.CombinedOutput()
	if errPS == nil {
		return nil
	}

	utf8OutPS, _ := gbkToUtf8(outPS)
	return fmt.Errorf("Both methods failed. Reg: %v. PS: %v, out: %s", firstErr, errPS, utf8OutPS)
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
	// Attempt to copy a locked file using cmd.exe /c copy /b
	// The /b flag is for binary.
	// We use cmd.exe because it's more direct than PowerShell for simple copies
	// and often behaves differently with locks.
	cmd := exec.Command("cmd", "/c", "copy", "/y", "/b", src, dst)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	err := cmd.Run()
	return err
}
