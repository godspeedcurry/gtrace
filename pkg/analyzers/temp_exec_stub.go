package analyzers

import (
	"context"
	"fmt"
	"strings"

	"gtrace/pkg/model"
	"gtrace/pkg/pluginsdk"
)

// TempExecutionAnalyzer is a stub analyzer that flags executions from temp-like paths.
type TempExecutionAnalyzer struct{}

func (a *TempExecutionAnalyzer) Manifest() pluginsdk.Manifest {
	return pluginsdk.Manifest{
		Name:      "temp-exec-detector",
		Version:   "0.1.0",
		Type:      "analyzer",
		Platforms: []string{"windows", "darwin", "linux"},
		Input: pluginsdk.IODecl{
			Kind: "timeline",
		},
		Output: pluginsdk.IODecl{
			Artifact: "finding",
		},
	}
}

func (a *TempExecutionAnalyzer) Analyze(ctx context.Context, in pluginsdk.AnalyzeRequest) (*pluginsdk.AnalyzeResponse, error) {
	var findings []model.Finding
	for _, ev := range in.Timeline {
		path := strings.ToLower(ev.Details["path"])
		if path == "" {
			continue
		}
		if strings.Contains(path, "temp") {
			findings = append(findings, model.Finding{
				ID:          fmt.Sprintf("temp-exec-%s", ev.ID),
				Severity:    "medium",
				Title:       "Execution from temp-like path",
				Description: fmt.Sprintf("Timeline %s executed from %s", ev.ID, path),
				RuleID:      "temp-exec",
				EvidenceRefs: []model.EvidenceRef{
					ev.EvidenceRef,
				},
			})
		}
	}
	return &pluginsdk.AnalyzeResponse{Findings: findings}, nil
}
