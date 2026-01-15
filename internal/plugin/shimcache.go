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
	"www.velocidex.com/golang/regparser/appcompatcache"
)

// ShimCacheParser (AppCompatCache)
type ShimCacheParser struct{}

func (p *ShimCacheParser) Manifest() pluginsdk.Manifest {
	return pluginsdk.Manifest{
		Name:      "win-shimcache-parser",
		Version:   "1.0.0",
		Type:      "parser",
		Platforms: []string{"windows"},
		Input: pluginsdk.IODecl{
			Kind: "file",
			MIME: "application/octet-stream",
		},
		Output: pluginsdk.IODecl{
			Artifact: "shimcache",
		},
	}
}

func (p *ShimCacheParser) CanParse(filename string, header []byte) bool {
	// Must be named SYSTEM or SYSTEM.* (case-insensitive)
	fname := strings.ToUpper(filepath.Base(filename))
	if strings.HasPrefix(fname, "SYSTEM") {
		if len(header) >= 4 && string(header[:4]) == "regf" {
			return true
		}
	}
	return false
}

func (p *ShimCacheParser) Parse(ctx context.Context, in pluginsdk.ParseRequest) (*pluginsdk.ParseResponse, error) {
	// Open the file using os.Open (regparser takes ReaderAt)
	f, err := os.Open(in.EvidencePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	registry, err := regparser.NewRegistry(f)
	if err != nil {
		return nil, fmt.Errorf("open hive: %w", err)
	}

	// Try ControlSet001 first
	key := registry.OpenKey("ControlSet001\\Control\\Session Manager\\AppCompatCache")
	if key == nil {
		// Try ControlSet002
		key = registry.OpenKey("ControlSet002\\Control\\Session Manager\\AppCompatCache")
	}
	if key == nil {
		return nil, fmt.Errorf("AppCompatCache key not found")
	}

	var data []byte
	for _, v := range key.Values() {
		if v.Name() == "AppCompatCache" {
			data = v.ValueData().Data // Retrieve the raw bytes via ValueData helper
			break
		}
	}

	if data == nil {
		// Some systems use "AppCompatCache" (default) but checking name is safer
		return nil, fmt.Errorf("AppCompatCache value missing")
	}

	// Use Velocidex/regparser/appcompatcache helper
	entries := appcompatcache.ParseValueData(data)

	var events []model.TimelineEvent
	for _, entry := range entries {
		if entry.Name == "" {
			continue
		}

		evt := model.TimelineEvent{
			ID:        fmt.Sprintf("shim-%s-%d", filepath.Base(entry.Name), entry.Time.UnixNano()),
			EventTime: entry.Time,
			Source:    "shimcache",
			Artifact:  "shimcache",
			Action:    "FILE_MODIFIED",
			Subject:   entry.Name,
			Details: map[string]string{
				"path": entry.Name,
				"key":  "AppCompatCache",
			},
			EvidenceRef: model.EvidenceRef{
				SourcePath: in.EvidencePath,
			},
		}
		events = append(events, evt)
	}

	return &pluginsdk.ParseResponse{
		Events: events,
	}, nil
}
