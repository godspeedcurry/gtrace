package ioc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gtrace/pkg/model"
)

// LoadFromFile loads IOC entries from a JSONL file containing model.IOCMaterial.
func LoadFromFile(path string) ([]model.IOCMaterial, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var out []model.IOCMaterial
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry model.IOCMaterial
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, fmt.Errorf("parse ioc: %w", err)
		}
		out = append(out, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
