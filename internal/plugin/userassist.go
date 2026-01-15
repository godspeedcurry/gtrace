package plugin

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gtrace/pkg/model"
	"gtrace/pkg/pluginsdk"

	"www.velocidex.com/golang/regparser"
)

// UserAssistParser extracts execution history from NTUSER.DAT UserAssist keys.
type UserAssistParser struct{}

func (p *UserAssistParser) Manifest() pluginsdk.Manifest {
	return pluginsdk.Manifest{
		Name:      "win-userassist-parser",
		Version:   "1.0.0",
		Type:      "parser",
		Platforms: []string{"windows"},
		Input: pluginsdk.IODecl{
			Kind: "file",
			MIME: "application/octet-stream",
		},
		Output: pluginsdk.IODecl{
			Artifact: "userassist",
		},
	}
}

func (p *UserAssistParser) CanParse(path string, header []byte) bool {
	base := strings.ToUpper(filepath.Base(path))
	if base == "NTUSER.DAT" || strings.HasPrefix(base, "NTUSER.DAT") {
		if len(header) >= 4 && string(header[:4]) == "regf" {
			return true
		}
	}
	return false
}

func (p *UserAssistParser) Parse(ctx context.Context, in pluginsdk.ParseRequest) (*pluginsdk.ParseResponse, error) {
	f, err := os.Open(in.EvidencePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open registry file: %w", err)
	}
	defer f.Close()

	reader, err := regparser.NewRegistry(f)
	if err != nil {
		return nil, fmt.Errorf("failed to parse registry hive: %w", err)
	}

	keyPath := `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`
	uaKey := reader.OpenKey(keyPath)
	if uaKey == nil {
		// Key not found, might not be a valid NTUSER.DAT or different version
		return &pluginsdk.ParseResponse{}, nil
	}

	var events []model.TimelineEvent

	// UserAssist has subkeys capable of tracking different things (CEBFF5CD... is Executables)
	for _, subKey := range uaKey.Subkeys() {
		// Find "Count" subkey under the GUID key
		// Using strict type inference from range
		var countKey *regparser.CM_KEY_NODE
		for _, k := range subKey.Subkeys() {
			if strings.EqualFold(k.Name(), "Count") {
				countKey = k
				break
			}
		}

		if countKey == nil {
			continue
		}

		for _, value := range countKey.Values() {
			// Name is ROT13 encoded path
			path := rot13(value.Name())

			// Value Data structure (Win7+):
			// Offset 0-4: ?
			// Offset 4-8: Run Counter (uint32)
			// ...
			// Offset 60-68: Last Execution Time (FILETIME)

			valDataFunc := value.ValueData()
			if valDataFunc == nil {
				continue
			}
			data := valDataFunc.Data

			if len(data) < 68 {
				continue
			}

			runCount := binary.LittleEndian.Uint32(data[4:8])
			// focusbit := binary.LittleEndian.Uint32(data[8:12]) // Focus count?
			// timeFocus := binary.LittleEndian.Uint32(data[12:16]) // Focus time?

			// Last Execution Timestamp
			lastExec := windowsFiletimeToGo(uint64(binary.LittleEndian.Uint64(data[60:68])))

			if runCount > 0 && !lastExec.IsZero() {
				events = append(events, model.TimelineEvent{
					ID:        fmt.Sprintf("ua-%d-%s", lastExec.UnixNano(), path),
					EventTime: lastExec,
					Source:    "UserAssist",
					Artifact:  "UserAssist",
					Action:    "Execution",
					Subject:   path,
					Details: map[string]string{
						"run_count": fmt.Sprintf("%d", runCount),
						"rot13_raw": value.Name(),
						"guid":      subKey.Name(),
					},
					EvidenceRef: model.EvidenceRef{
						SourcePath: in.EvidencePath,
					},
				})
			}
		}
	}

	return &pluginsdk.ParseResponse{
		Events: events,
	}, nil
}

// rot13 decodes UserAssist ROT13 paths
func rot13(input string) string {
	var result strings.Builder
	for _, r := range input {
		switch {
		case r >= 'a' && r <= 'z':
			result.WriteRune('a' + (r-'a'+13)%26)
		case r >= 'A' && r <= 'Z':
			result.WriteRune('A' + (r-'A'+13)%26)
		default:
			result.WriteRune(r)
		}
	}
	return result.String()
}
