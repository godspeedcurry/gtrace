package ntfs

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"www.velocidex.com/golang/go-ntfs/parser"
)

// CopyLockedFile attempts to copy a file using Raw NTFS parsing to bypass OS locks.
// This requires Administrator privileges.
func CopyLockedFile(sourcePath, destPath string) error {
	// Identify drive letter
	drive := filepath.VolumeName(sourcePath)
	if drive == "" {
		// Fallback for paths without drive letter? Usually we deal with absolute paths on Windows.
		// If empty, assume C:? Or maybe it's a relative path.
		// Let's assume absolute paths for now.
		return fmt.Errorf("source path must include drive letter")
	}

	// Convert drive to device path: C: -> \\.\C:
	devicePath := fmt.Sprintf(`\\.\%s`, drive)

	// Open the volume
	f, err := os.Open(devicePath)
	if err != nil {
		return fmt.Errorf("failed to open raw volume %s: %w", devicePath, err)
	}
	defer f.Close()

	// Initialize NTFS parser
	// Using a smaller cache for oneshot operations to save memory
	pagedReader, err := parser.NewPagedReader(f, 1024*1024, 10)
	if err != nil {
		return fmt.Errorf("failed to create paged reader: %w", err)
	}

	ntfsContext, err := parser.GetNTFSContext(pagedReader, 0)
	if err != nil {
		return fmt.Errorf("failed to get NTFS context: %w", err)
	}

	// Clean path for NTFS parser: remove drive letter and ensure backslashes
	// C:\Windows\System32... -> \Windows\System32...
	relPath := sourcePath[len(drive):]
	relPath = strings.ReplaceAll(relPath, "/", "\\")

	// Get data stream
	dataStream, err := parser.GetDataForPath(ntfsContext, relPath)
	if err != nil {
		return fmt.Errorf("failed to resolve path in MFT %s: %w", relPath, err)
	}

	// Create destination file
	dst, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file %s: %w", destPath, err)
	}
	defer dst.Close()

	// Copy data
	// dataStream is ReaderAt, we need an io.Reader adapter or just read in chunks
	// NewReader adapter is available in io/ioutil or similar, but let's just make a simple one or use io.SectionReader
	// RangeReaderAt has logic.

	// Create a SectionReader-like wrapper because GetDataForPath returns parser.RangeReaderAt
	// We can simply loop and read.

	chunkSize := 1024 * 1024 // 1MB chunks
	buf := make([]byte, chunkSize)
	var offset int64 = 0

	for {
		n, err := dataStream.ReadAt(buf, offset)
		if n > 0 {
			if _, wErr := dst.Write(buf[:n]); wErr != nil {
				return wErr
			}
			offset += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error reading raw stream at offset %d: %w", offset, err)
		}
	}

	return nil
}
