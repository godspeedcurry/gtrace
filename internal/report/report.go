package report

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gtrace/pkg/model"
)

// Summary is a minimal snapshot of timeline and findings for export.
type Summary struct {
	GeneratedAt time.Time             `json:"generated_at"`
	Timeline    []model.TimelineEvent `json:"timeline"`
	Findings    []model.Finding       `json:"findings"`
	Counts      Counts                `json:"counts"`
}

// Counts provides a quick-glance view for the UI or CLI.
type Counts struct {
	Timeline int `json:"timeline"`
	Findings int `json:"findings"`
}

// SaveJSON writes a JSON report under the case data directory.
func SaveJSON(ctx context.Context, casePath string, timeline []model.TimelineEvent, findings []model.Finding) (string, error) {
	out := Summary{
		GeneratedAt: time.Now().UTC(),
		Timeline:    timeline,
		Findings:    findings,
		Counts: Counts{
			Timeline: len(timeline),
			Findings: len(findings),
		},
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal report: %w", err)
	}
	outPath := filepath.Join(casePath, "data", "report.json")
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		return "", fmt.Errorf("write report: %w", err)
	}
	return outPath, nil
}
