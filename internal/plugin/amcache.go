package plugin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gtrace/pkg/model"
	"gtrace/pkg/pluginsdk"

	"www.velocidex.com/golang/regparser"
)

// AmcacheParser extracts SHA1, paths, and timestamps from Amcache.hve
type AmcacheParser struct{}

func (p *AmcacheParser) Manifest() pluginsdk.Manifest {
	return pluginsdk.Manifest{
		Name:      "win-amcache-parser",
		Version:   "1.0.0",
		Type:      "parser",
		Platforms: []string{"windows"},
		Input: pluginsdk.IODecl{
			Kind: "file",
			MIME: "application/octet-stream",
		},
		Output: pluginsdk.IODecl{
			Artifact: "amcache",
		},
	}
}

func (p *AmcacheParser) CanParse(filename string, header []byte) bool {
	fname := strings.ToUpper(filepath.Base(filename))
	if fname == "AMCACHE.HVE" {
		if len(header) >= 4 && string(header[:4]) == "regf" {
			return true
		}
	}
	return false
}

func (p *AmcacheParser) Parse(ctx context.Context, in pluginsdk.ParseRequest) (*pluginsdk.ParseResponse, error) {
	f, err := os.Open(in.EvidencePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	registry, err := regparser.NewRegistry(f)
	if err != nil {
		return nil, fmt.Errorf("open hive: %w", err)
	}

	// Navigate to Root\File
	// Try classic Root\File
	fileKey := registry.OpenKey("Root\\File")
	if fileKey == nil {
		// Try Inventory
		fileKey = registry.OpenKey("Root\\InventoryApplicationFile")
		if fileKey == nil {
			return nil, fmt.Errorf("Amcache File key not found")
		}
	}

	var events []model.TimelineEvent

	// Iterate Volumes
	for _, vol := range fileKey.Subkeys() {
		// Iterate Files under volume
		for _, file := range vol.Subkeys() {
			var fullPath string
			var sha1 string

			// Iterate values to find 15 and 101
			for _, val := range file.Values() {
				vName := val.ValueName()
				if vName == "15" {
					vd := val.ValueData()
					if vd.Error == nil {
						fullPath = vd.String
						// Fallback if String is empty but Data is not?
						// regparser usually handles it.
					}
				} else if vName == "101" {
					vd := val.ValueData()
					if vd.Error == nil {
						sha1 = vd.String
						sha1 = strings.TrimPrefix(sha1, "0000")
					}
				}
			}

			if fullPath != "" {
				// Timestamp from Key LastWriteTime
				// file (CM_KEY_NODE) has LastWriteTime method
				ts := file.LastWriteTime().Time

				evt := model.TimelineEvent{
					ID:        fmt.Sprintf("amcache-%s-%d", sha1, ts.UnixNano()),
					EventTime: ts,
					Source:    "amcache",
					Artifact:  "amcache",
					Action:    "EXECUTION_EVIDENCE",
					Subject:   fullPath,
					Details: map[string]string{
						"path": fullPath,
						"sha1": sha1,
					},
					EvidenceRef: model.EvidenceRef{
						SourcePath: in.EvidencePath,
					},
				}
				events = append(events, evt)
			}
		}
	}

	return &pluginsdk.ParseResponse{
		Events: events,
	}, nil
}
