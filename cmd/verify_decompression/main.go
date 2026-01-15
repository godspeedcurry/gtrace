package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"

	"gtrace/internal/plugin"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: verify_decompression <pf_file>")
	}
	path := os.Args[1]

	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}

	if len(data) < 8 || string(data[:3]) != "MAM" {
		log.Fatal("Not a MAM compressed file")
	}

	decompSize := binary.LittleEndian.Uint32(data[4:8])
	fmt.Printf("MAM Header detected. Target Size: %d\n", decompSize)

	// Call the CGO implementation
	out, err := plugin.DecompressW10Prefetch(data[8:], decompSize)
	if err != nil {
		log.Fatalf("Decompression FAILED: %v", err)
	}

	fmt.Printf("Decompression SUCCESS! Output size: %d\n", len(out))
	if len(out) > 4 {
		fmt.Printf("Head: %x\n", out[:4])
	}

	// Check for SCCA signature in decompressed data
	if len(out) > 4 && string(out[:4]) == "SCCA" {
		fmt.Printf("Verified SCCA Signature!\n")
	} else {
		fmt.Printf("WARNING: SCCA signature missing (Head: %x)\n", out[:8])
	}
}
