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
	Rule      sigma.Rule
	Evaluator *evaluator.RuleEvaluator
}

// EngineV2 is the new Sigma engine using the industry standard library
type EngineV2 struct {
	Rules []ActiveRule
}

// NewEngineV2 initializes the engine with bundled YAML rules and optional external rules via FS
func NewEngineV2(ruleFS fs.FS, rootDir string) (*EngineV2, error) {
	var activeRules []ActiveRule

	// Helper to load rule
	load := func(content []byte, name string) {
		rule, err := sigma.ParseRule(content)
		if err != nil {
			// fmt.Printf("Error parsing rule %s: %v\n", name, err)
			return
		}
		activeRules = append(activeRules, ActiveRule{
			Rule:      rule,
			Evaluator: evaluator.ForRule(rule),
		})
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
		Rules: activeRules,
	}, nil
}

// Evaluate checks an event against all loaded rules
func (e *EngineV2) Evaluate(ev model.TimelineEvent) *ActiveRule {
	// 1. Adapter: Convert TimelineEvent to map for Sigma
	// We need to map our schema to Sigma's standard schema (sysmon-like)
	obj := make(map[string]interface{})

	// Copy all Details first
	for k, v := range ev.Details {
		obj[k] = v
	}

	// Helper to ensure field existence
	ensure := func(target, source string) {
		if v, ok := ev.Details[source]; ok && v != "-" {
			obj[target] = v
		}
	}

	// Standard Mappings
	// EventID is needed as string or int? sigma-go handles string usually
	ensure("EventID", "EventID")

	// Process Creation Mappings
	ensure("Image", "NewProcessName")
	ensure("CommandLine", "CommandLine")
	ensure("ParentImage", "ParentProcessName")
	ensure("ParentCommandLine", "ParentDetails") // heuristics

	// Registry Mappings
	ensure("TargetObject", "Path")
	// ensure("Details", "ValueName") // Context dependent

	// 2. Evaluate
	for _, ar := range e.Rules {
		// Basic filter: EventID check inside the rule?
		// sigma-go evaluator handles the logsource matching automatically if fields are present
		// But we might want to skip non-matching log sources for performance?
		// sigma-go does this check.

		// Check category match if possible (e.g. process_creation -> 4688)
		// We rely on the rule's selection logic.

		result, err := ar.Evaluator.Matches(context.Background(), obj)
		if err == nil && result.Match {
			return &ar
		}
	}

	return nil
}
