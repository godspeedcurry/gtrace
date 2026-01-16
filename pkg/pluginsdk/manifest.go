package pluginsdk

import (
	"context"

	"gtrace/pkg/model"
)

// Manifest describes plugin capabilities and compatibility.
type Manifest struct {
	Name        string   `json:"name" yaml:"name"`
	Version     string   `json:"version" yaml:"version"`
	Type        string   `json:"type" yaml:"type"` // parser | analyzer
	Platforms   []string `json:"platforms" yaml:"platforms"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Input       IODecl   `json:"input" yaml:"input"`
	Output      IODecl   `json:"output" yaml:"output"`
	Permissions []string `json:"permissions,omitempty" yaml:"permissions,omitempty"`
	Entry       string   `json:"entry" yaml:"entry"`
}

type IODecl struct {
	Kind     string `json:"kind" yaml:"kind"`
	MIME     string `json:"mime,omitempty" yaml:"mime,omitempty"`
	Schema   string `json:"schema_ref,omitempty" yaml:"schema_ref,omitempty"`
	Artifact string `json:"artifact_type,omitempty" yaml:"artifact_type,omitempty"`
}

type ParseRequest struct {
	EvidencePath string            `json:"evidence_path"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	// Callback for long running operations
	ProgressCallback func(percent int) `json:"-"`

	// StreamCallback for memory-efficient event processing
	StreamCallback func(event model.TimelineEvent) `json:"-"`
}

type ParseResponse struct {
	Artifacts []model.Artifact      `json:"artifacts"`
	Events    []model.TimelineEvent `json:"events,omitempty"`
}

type AnalyzeRequest struct {
	Timeline []model.TimelineEvent `json:"timeline"`
	IOCs     []model.IOCMaterial   `json:"iocs,omitempty"`
}

type AnalyzeResponse struct {
	Findings []model.Finding `json:"findings"`
}

type ParserPlugin interface {
	Manifest() Manifest
	// CanParse checks if the plugin can handle the file based on name and initial bytes
	CanParse(filename string, header []byte) bool
	Parse(ctx context.Context, in ParseRequest) (*ParseResponse, error)
}

type AnalyzerPlugin interface {
	Manifest() Manifest
	Analyze(ctx context.Context, in AnalyzeRequest) (*AnalyzeResponse, error)
}
