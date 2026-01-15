package app

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"gtrace/internal/engine"
	"gtrace/internal/plugin"
	"gtrace/internal/storage"
	"gtrace/pkg/model"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct
type App struct {
	ctx      context.Context
	pipeline *engine.Pipeline
	store    *storage.FileStorage
	registry *plugin.Registry
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
}

// GetDefaultCasePath returns a sensible default path for the current OS.
func (a *App) GetDefaultCasePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "lumina_case")
	}

	switch runtime.GOOS {
	case "windows":
		// On Windows, use Documents/LuminaCase or Temp
		// Using Temp for now to match behavior but Home is better for persistence
		return filepath.Join(os.TempDir(), "lumina_case")
	default:
		// On *nix, use /tmp/lumina_case for now
		// Actually let's use home dir if available to be nice
		return filepath.Join(home, ".lumina_case")
	}
}

// Log emits a log event with a source category
func (a *App) Log(source string, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("[%s] %s", source, msg)
	if a.ctx != nil {
		wailsRuntime.EventsEmit(a.ctx, "log:entry", map[string]string{
			"source":  source,
			"message": msg,
			"ts":      time.Now().Format(time.RFC3339),
		})
	}
}

// Helper for internal simple logging
func (a *App) log(format string, args ...interface{}) {
	a.Log("System", format, args...)
}

// OpenCase initializes the case storage.
func (a *App) OpenCase(casePath string) error {
	a.log("Opening case at %s", casePath)
	s, err := storage.NewFileStorage(casePath)
	if err != nil {
		return err
	}
	if err := s.InitCase(a.ctx, casePath); err != nil {
		return err
	}
	a.store = s

	// Init engine
	a.registry = plugin.NewDefaultRegistry()
	a.pipeline = engine.NewPipeline(a.store, a.registry.Parsers(), a.registry.Analyzers(), func(format string, args ...interface{}) {
		a.Log("Pipeline", format, args...)
	})

	a.log("Case initialized successfully")
	return nil
}

// ResetCase wipes the current case data.
func (a *App) ResetCase() error {
	if a.store == nil {
		return fmt.Errorf("case not open")
	}
	return a.store.Reset(a.ctx)
}

// StartTriage runs the triage process on an evidence path.
// If evidencePath is empty, it attempts Live Triage on detected system paths.
// components: List of artifact types to collect (e.g. "EventLogs", "Registry", "Prefetch"). Empty means all.
// options: Configuration map (e.g. "max_events": 5000, "days": 7)
func (a *App) StartTriage(evidencePath string, components []string, options map[string]interface{}) error {
	if a.pipeline == nil {
		return fmt.Errorf("case not open")
	}

	// Progress callback
	progressFunc := func(current, total int) {
		percentage := 0
		if total > 0 {
			percentage = int(float64(current) / float64(total) * 100)
		}
		// Emit event to frontend
		// Payload: { current: 1, total: 10, percent: 10 }
		wailsRuntime.EventsEmit(a.ctx, "triage:progress", map[string]interface{}{
			"current": current,
			"total":   total,
			"percent": percentage,
		})
	}

	if evidencePath == "" {
		a.log("Starting Live Triage... Components: %v, Options: %v", components, options)
		return a.pipeline.TriageLive(a.ctx, components, options, progressFunc)
	}

	a.log("Starting Triage on %s", evidencePath)
	return a.pipeline.Triage(a.ctx, evidencePath, progressFunc)
}

// RunAnalysis executes analyzers.
func (a *App) RunAnalysis() (int, error) {
	if a.pipeline == nil || a.store == nil {
		return 0, fmt.Errorf("case not open")
	}
	// Fetch all events
	events, err := a.store.QueryTimeline(a.ctx, &model.TimelineFilter{MaxResults: 10000})
	if err != nil {
		return 0, err
	}

	if err := a.pipeline.Analyze(a.ctx, a.registry.Analyzers(), events, nil); err != nil {
		return 0, err
	}

	// Count findings
	findings, _ := a.store.QueryFindings(a.ctx)
	return len(findings), nil
}

// GetTimeline returns timeline events for the frontend grid.
func (a *App) GetTimeline(limit int) ([]model.TimelineEvent, error) {
	if a.store == nil {
		return nil, fmt.Errorf("case not open")
	}
	events, err := a.store.QueryTimeline(a.ctx, &model.TimelineFilter{MaxResults: limit})
	if events == nil {
		events = []model.TimelineEvent{}
	}
	return events, err
}

// GetFindings returns findings for the dashboard.
func (a *App) GetFindings() ([]model.Finding, error) {
	if a.store == nil {
		return nil, fmt.Errorf("case not open")
	}
	return a.store.QueryFindings(a.ctx)
}

// Greet returns a greeting for the given name
func (a *App) Greet(name string) string {
	return fmt.Sprintf("Hello %s, It's show time!", name)
}
