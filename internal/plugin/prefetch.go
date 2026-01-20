package plugin

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"gtrace/pkg/model"
	"gtrace/pkg/pluginsdk"

	prefetch "www.velocidex.com/golang/go-prefetch"
)

// Windows Prefetch Header (simplified for Version 30 / Windows 10)
// Ref: https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc
type PrefetchParser struct{}

func (p *PrefetchParser) Manifest() pluginsdk.Manifest {
	return pluginsdk.Manifest{
		Name:      "win-prefetch-parser",
		Version:   "1.0.0",
		Type:      "parser",
		Platforms: []string{"windows"},
		Input: pluginsdk.IODecl{
			Kind: "file",
			MIME: "application/x-prefetch",
		},
		Output: pluginsdk.IODecl{
			Artifact: "prefetch",
		},
	}
}

func (p *PrefetchParser) CanParse(filename string, header []byte) bool {
	// Magic: SCCA (0x41434353) or MAM (0x4D414D04) for compressed
	if len(header) < 8 {
		return false
	}
	// Check SCCA signature
	if string(header[:4]) == "SCCA" {
		return true
	}
	// Check MAM signature (Compressed) - Windows 10+ often compresses them
	if string(header[:3]) == "MAM" {
		return true
	}

	return strings.HasSuffix(strings.ToLower(filename), ".pf")
}

func (p *PrefetchParser) Parse(ctx context.Context, in pluginsdk.ParseRequest) (*pluginsdk.ParseResponse, error) {
	// Added debug logging
	// fmt.Printf("DEBUG: Prefetch Parser attempting %s\n", in.EvidencePath)
	f, err := os.Open(in.EvidencePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Use Velocidex Go-Prefetch library
	pfInfo, err := prefetch.LoadPrefetch(f)
	if err != nil {
		return nil, fmt.Errorf("failed to parse prefetch %s: %w", in.EvidencePath, err)
	}

	// Create Event
	// Use the most recent execution time as the primary event time
	var eventTime time.Time
	if len(pfInfo.LastRunTimes) > 0 {
		eventTime = pfInfo.LastRunTimes[0]
	} else {
		eventTime = time.Now() // Fallback
	}

	evt := model.TimelineEvent{
		ID:        fmt.Sprintf("pf-%s-%d", pfInfo.Executable, eventTime.UnixNano()),
		EventTime: eventTime,
		Source:    "Prefetch",
		Artifact:  "Prefetch",
		Action:    "EXECUTION",
		Subject:   pfInfo.Executable,
		Details: map[string]string{
			"run_count":      fmt.Sprintf("%d", pfInfo.RunCount),
			"version":        pfInfo.Version,
			"path":           in.EvidencePath,
			"hash":           pfInfo.Hash,
			"files_accessed": fmt.Sprintf("%d", len(pfInfo.FilesAccessed)),
		},
		EvidenceRef: model.EvidenceRef{
			SourcePath: in.EvidencePath,
		},
	}

	if in.StreamCallback != nil {
		in.StreamCallback(evt)
		return &pluginsdk.ParseResponse{}, nil
	}

	return &pluginsdk.ParseResponse{
		Events: []model.TimelineEvent{evt},
	}, nil
}
