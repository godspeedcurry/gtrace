package analyzers

import (
	"context"
	"fmt"
	"strings"

	"gtrace/pkg/model"
	"gtrace/pkg/pluginsdk"
)

// ExecutionAnomalyAnalyzer detects processes running without corresponding prefetch evidence
type ExecutionAnomalyAnalyzer struct{}

func (a *ExecutionAnomalyAnalyzer) Manifest() pluginsdk.Manifest {
	return pluginsdk.Manifest{
		Name:      "execution-anomaly",
		Version:   "1.0.0",
		Type:      "analyzer",
		Platforms: []string{"windows"},
		Input: pluginsdk.IODecl{
			Kind: "timeline",
		},
		Output: pluginsdk.IODecl{
			Artifact: "finding",
		},
	}
}

func (a *ExecutionAnomalyAnalyzer) Analyze(ctx context.Context, in pluginsdk.AnalyzeRequest) (*pluginsdk.AnalyzeResponse, error) {
	prefetchSet := make(map[string]bool)
	var processEvents []model.TimelineEvent

	// Pass 1: Build Prefetch Set
	for _, ev := range in.Timeline {
		if ev.Source == "prefetch" {
			// Subject is typically "CMD.EXE"
			name := strings.ToUpper(ev.Subject)
			prefetchSet[name] = true
		} else if ev.Source == "wintri-process" {
			processEvents = append(processEvents, ev)
		}
	}

	var findings []model.Finding

	// Pass 2: Check Processes
	for _, proc := range processEvents {
		name := strings.ToUpper(proc.Subject)

		// Skip System/Idle processes which don't produce prefetch
		if name == "SYSTEM" || name == "SYSTEM IDLE PROCESS" || name == "REGISTRY" || name == "MEMORY COMPRESSION" {
			continue
		}

		if !prefetchSet[name] {
			findings = append(findings, model.Finding{
				ID:       fmt.Sprintf("anomaly-no-pf-%s", proc.ID),
				Severity: "high",
				Title:    "Process Execution without Prefetch Evidence",
				Description: fmt.Sprintf("Process %s (PID: %s) is running but no corresponding Prefetch file was found. This could indicate time-stomping, prefetch disabling, or execution from a location that does not generate prefetch (e.g. some removable media configurations).",
					proc.Subject, proc.Details["pid"]),
				RuleID: "exec-anomaly-no-prefetch",
				EvidenceRefs: []model.EvidenceRef{
					proc.EvidenceRef,
				},
			})
		}
	}

	return &pluginsdk.AnalyzeResponse{Findings: findings}, nil
}
