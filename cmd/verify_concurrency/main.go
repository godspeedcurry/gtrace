package main

import (
	"encoding/binary"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sync"

	"gtrace/internal/plugin"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: verify_concurrency <dir>")
	}
	dir := os.Args[1]

	files, err := filepath.Glob(filepath.Join(dir, "*.pf"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Found %d files. Starting concurrent test...", len(files))

	var wg sync.WaitGroup
	// Limit concurrency to 8
	sem := make(chan struct{}, 8)

	for _, f := range files {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			data, err := ioutil.ReadFile(path)
			if err != nil {
				log.Printf("Error reading %s: %v", path, err)
				return
			}

			if len(data) > 8 && string(data[:3]) == "MAM" {
				// Decompress
				decompSize := binary.LittleEndian.Uint32(data[4:8])
				out, err := plugin.DecompressW10Prefetch(data[8:], decompSize)
				if err != nil {
					log.Printf("FAIL %s: %v", filepath.Base(path), err)
				} else {
					// Minimal check
					if len(out) != int(decompSize) {
						log.Printf("SIZE MISMATCH %s", filepath.Base(path))
					} else {
						// log.Printf("OK %s", filepath.Base(path))
					}
				}
			}
		}(f)
	}

	wg.Wait()
	log.Println("Done. If you see this, no crash occurred.")
}
