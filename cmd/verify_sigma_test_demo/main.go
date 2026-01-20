package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"gtrace/internal/engine"
	"gtrace/internal/plugin"
	"gtrace/internal/storage"
	"gtrace/pkg/model"
)

func main() {
	fmt.Println("Starting Sigma Verification on test_demo (CLI Mode)...")

	// 1. Setup Storage
	casePath := filepath.Join(os.TempDir(), "gtrace_verify_cli")
	os.RemoveAll(casePath)
	if err := os.MkdirAll(casePath, 0755); err != nil {
		panic(err)
	}

	store, err := storage.NewFileStorage(casePath)
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	if err := store.InitCase(ctx, casePath); err != nil {
		panic(err)
	}

	// 2. Setup Plugins
	registry := plugin.NewDefaultRegistry()

	// 3. Setup Pipeline
	// Logger that prints to stdout
	logger := func(format string, args ...interface{}) {
		fmt.Printf("[Pipeline] "+format+"\n", args...)
	}

	pipeline := engine.NewPipeline(store, registry.Parsers(), registry.Analyzers(), logger)

	// 4. Run Triage
	evidencePath := "/Users/test/exploit/gtrace/test_demo"
	fmt.Printf("Triaging: %s\n", evidencePath)

	err = pipeline.Triage(ctx, evidencePath, map[string]interface{}{
		"max_events": 10000,
	}, nil)

	if err != nil {
		panic(fmt.Errorf("Triage failed: %v", err))
	}

	fmt.Println("Triage complete. Querying for alerts...")

	// 5. Query Results
	events, err := store.QueryTimeline(ctx, &model.TimelineFilter{MaxResults: 10000})
	if err != nil {
		panic(err)
	}

	alertCount := 0
	for _, ev := range events {
		if alert, ok := ev.Details["_Alert"]; ok {
			alertCount++
			fmt.Printf("\n[ALERT] %s\n", ev.EventTime.Format("2006-01-02 15:04:05"))
			fmt.Printf("  Rule:    %s\n", alert)
			fmt.Printf("  Level:   %s\n", ev.Details["_AlertLevel"])
			fmt.Printf("  Subject: %s\n", ev.Subject)
			fmt.Printf("  Details: %v\n", ev.Details)
		}
	}

	fmt.Printf("\nTotal Alerts Found: %d\n", alertCount)
}
