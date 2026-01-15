package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"gtrace/internal/engine"
	"gtrace/internal/plugin"
	"gtrace/internal/storage"
	"gtrace/pkg/model"
)

func main() {
	evidencePath := flag.String("evidence", "", "Path to evidence (file or directory)")
	caseDir := flag.String("case", "", "Path to case directory (output)")
	flag.Parse()

	if *evidencePath == "" || *caseDir == "" {
		fmt.Println("Usage: lumina -evidence <path> -case <path>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	start := time.Now()
	log.Printf("Starting Lumina Triage on %s...", *evidencePath)

	// 1. Initialize Storage
	store, err := storage.NewFileStorage(*caseDir)
	if err != nil {
		log.Fatalf("Failed to init storage: %v", err)
	}
	if err := store.InitCase(context.Background(), *caseDir); err != nil {
		log.Fatalf("Failed to init case structure: %v", err)
	}

	// 2. Initialize Plugins
	reg := plugin.NewDefaultRegistry()
	log.Printf("Loaded %d parsers, %d analyzers", len(reg.Parsers()), len(reg.Analyzers()))

	// 3. Initialize Engine
	pipe := engine.NewPipeline(store, reg.Parsers(), reg.Analyzers(), func(format string, args ...interface{}) {
		log.Printf(format, args...)
	})

	// 4. Run Triage (Collection + Parsing)
	ctx := context.Background()
	log.Println("Running Triage Phase...")
	if err := pipe.Triage(ctx, *evidencePath, nil); err != nil {
		log.Printf("Triage completed with errors: %v", err)
	} else {
		log.Println("Triage Phase Completed successfully.")
	}

	// 5. Run Analysis
	log.Println("Running Analysis Phase...")
	// Fetch all events for analysis (MVP style)
	allEvents, err := store.QueryTimeline(ctx, &model.TimelineFilter{MaxResults: 10000})
	if err != nil {
		log.Printf("Warning: Failed to query timeline for analysis: %v", err)
	}

	// Run Analyzers
	if len(allEvents) > 0 {
		if err := pipe.Analyze(ctx, reg.Analyzers(), allEvents, nil); err != nil {
			log.Printf("Analysis completed with errors: %v", err)
		} else {
			log.Println("Analysis Phase Completed successfully.")
		}
	} else {
		log.Println("No events to analyze.")
	}

	duration := time.Since(start)
	log.Printf("All done in %s. Check output in %s", duration, *caseDir)
}
