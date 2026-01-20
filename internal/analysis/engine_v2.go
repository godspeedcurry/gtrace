package analysis

import (
	"context"
	"fmt"
	"gtrace/pkg/model"
	"io/fs"
	"strings"

	"github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator"
)

// ActiveRule wraps a compiled Sigma rule
type ActiveRule struct {
	ID          string
	Title       string
	Description string
	Level       string
	Tags        []string
	Category    string // logsource.category
	Evaluator   *evaluator.RuleEvaluator
}

// EngineV2 is the new Sigma engine using the industry standard library
type EngineV2 struct {
	Rules       []ActiveRule
	RulesByCat  map[string][]int // Maps category to indices in Rules slice
	GlobalRules []int            // Rules with no specific category
}

// NewEngineV2 initializes the engine with bundled YAML rules and optional external rules via FS
func NewEngineV2(ruleFS fs.FS, rootDir string) (*EngineV2, error) {
	var activeRules []ActiveRule
	rulesByCat := make(map[string][]int)
	var globalRules []int

	// Helper to load rule
	load := func(content []byte, name string) {
		rule, err := sigma.ParseRule(content)
		if err != nil {
			return
		}

		idx := len(activeRules)
		ar := ActiveRule{
			ID:          rule.ID,
			Title:       rule.Title,
			Description: rule.Description,
			Level:       rule.Level,
			Tags:        rule.Tags,
			Category:    rule.Logsource.Category,
			Evaluator:   evaluator.ForRule(rule),
		}
		activeRules = append(activeRules, ar)

		if ar.Category != "" {
			rulesByCat[ar.Category] = append(rulesByCat[ar.Category], idx)
		} else {
			globalRules = append(globalRules, idx)
		}
	}

	// 1. Load Bundled Rules (Hardcoded)
	for _, ruleYaml := range BundledSigmaRules {
		load([]byte(ruleYaml), "bundled")
	}

	// 2. Load External/Embedded Rules
	if ruleFS != nil && rootDir != "" {
		err := fs.WalkDir(ruleFS, rootDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
				data, err := fs.ReadFile(ruleFS, path)
				if err == nil {
					load(data, path)
				}
			}
			return nil
		})
		if err != nil {
			fmt.Printf("Warning: failed to walk rules FS %s: %v\n", rootDir, err)
		}
	}

	return &EngineV2{
		Rules:       activeRules,
		RulesByCat:  rulesByCat,
		GlobalRules: globalRules,
	}, nil
}

// Evaluate checks an event against all loaded rules
func (e *EngineV2) Evaluate(ev model.TimelineEvent) *ActiveRule {
	// 1. Adapter: Convert TimelineEvent to map for Sigma
	// We map our heterogeneous fields to standard Sysmon-style schema used by most Sigma rules.
	obj := make(map[string]interface{})

	// Flat copy of all details
	for k, v := range ev.Details {
		obj[k] = v
	}

	// Heuristic/Standard Mappings
	ensure := func(target string, sources ...string) {
		for _, s := range sources {
			if v, ok := ev.Details[s]; ok && v != "" && v != "-" {
				obj[target] = v
				return
			}
		}
	}

	// Core Fields
	ensure("EventID", "EventID")
	ensure("Channel", "Channel")
	ensure("Provider_Name", "Provider")

	// Process Creation (4688 / Sysmon 1)
	ensure("Image", "NewProcessName", "ExePath")
	ensure("CommandLine", "_CommandLine", "CommandLine")
	ensure("ParentImage", "ParentProcessName", "ParentPath")
	ensure("ParentCommandLine", "ParentCommandLine", "ParentDetails")
	ensure("ProcessId", "ProcessId", "PID")
	ensure("ParentProcessId", "ParentProcessId", "ParentPID")
	ensure("IntegrityLevel", "TokenElevationType", "Integrity")
	ensure("User", "SubjectUserName", "User", "AccountName")
	ensure("LogonId", "SubjectLogonId", "LogonId")

	// Registry (Sysmon 12/13/14)
	ensure("TargetObject", "Path", "KeyPath", "Object")
	ensure("Details", "Value", "Data", "Details")

	// File Activity (Sysmon 11/23/26)
	ensure("TargetFilename", "Path", "Destination")

	// Network
	ensure("SourceIp", "LocalIP", "Source")
	ensure("DestinationIp", "RemoteIP", "Destination")
	ensure("SourcePort", "LocalPort")
	ensure("DestinationPort", "RemotePort")
	ensure("Protocol", "Protocol")

	// 2. Identify Category to filter rules
	cat := ""
	eid := fmt.Sprintf("%v", obj["EventID"])
	switch eid {
	case "4688", "1":
		cat = "process_creation"
	case "4624", "4625", "2":
		cat = "network_connection" // simplification
	case "4663", "11", "23", "26":
		cat = "file_event"
	case "12", "13", "14":
		cat = "registry_event"
	}

	// Also check artifact type
	if cat == "" {
		switch ev.Artifact {
		case "Registry":
			cat = "registry_event"
		case "Prefetch":
			cat = "process_creation"
		}
	}

	// 3. Evaluate matching rules
	evaluate := func(indices []int) *ActiveRule {
		for _, idx := range indices {
			ar := e.Rules[idx]
			result, err := ar.Evaluator.Matches(context.Background(), obj)
			if err == nil && result.Match {
				return &ar
			}
		}
		return nil
	}

	// First check categorical rules
	if cat != "" {
		if matched := evaluate(e.RulesByCat[cat]); matched != nil {
			return matched
		}
	}

	// Then check global/uncategorized rules
	return evaluate(e.GlobalRules)
}
