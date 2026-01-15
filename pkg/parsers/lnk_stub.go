package parsers

import (
	"context"
	"time"

	"gtrace/pkg/model"
	"gtrace/pkg/pluginsdk"
)

// LNKStubParser demonstrates parser plugin contract without full parsing logic.
type LNKStubParser struct{}

func (p *LNKStubParser) Manifest() pluginsdk.Manifest {
	return pluginsdk.Manifest{
		Name:      "win-lnk-parser",
		Version:   "0.1.0",
		Type:      "parser",
		Platforms: []string{"windows", "darwin", "linux"},
		Input: pluginsdk.IODecl{
			Kind: "file",
			MIME: "application/x-ms-shortcut",
		},
		Output: pluginsdk.IODecl{
			Artifact: "lnk",
		},
		Permissions: []string{"read_file"},
	}
}

func (p *LNKStubParser) CanParse(filename string, header []byte) bool {
	// 4C 00 00 00 is the LNK header signature
	if len(header) >= 4 && header[0] == 0x4c && header[1] == 0x00 && header[2] == 0x00 && header[3] == 0x00 {
		return true
	}
	// Fallback to extension check
	if len(filename) > 4 && filename[len(filename)-4:] == ".lnk" {
		return true
	}
	return false
}

func (p *LNKStubParser) Parse(ctx context.Context, in pluginsdk.ParseRequest) (*pluginsdk.ParseResponse, error) {
	// This stub does not parse real binary data; it illustrates the expected shape.
	now := time.Now().UTC()
	artifact := model.Artifact{
		ID:       "lnk-stub-1",
		Type:     "lnk",
		Path:     in.EvidencePath,
		Created:  &now,
		Modified: &now,
		EvidenceRef: model.EvidenceRef{
			SourcePath: in.EvidencePath,
			SHA256:     "stub",
		},
	}

	event := model.TimelineEvent{
		ID:        "lnk-stub-event-1",
		EventTime: now,
		Source:    "lnk",
		Artifact:  artifact.ID,
		Action:    "execute",
		Details:   map[string]string{"note": "stub event", "path": in.EvidencePath},
		EvidenceRef: model.EvidenceRef{
			SourcePath: in.EvidencePath,
			SHA256:     "stub",
		},
	}

	return &pluginsdk.ParseResponse{
		Artifacts: []model.Artifact{artifact},
		Events:    []model.TimelineEvent{event},
	}, nil
}
