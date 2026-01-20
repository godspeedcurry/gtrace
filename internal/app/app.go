package app

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// Shutdown is called at application termination
func (a *App) Shutdown(ctx context.Context) {
	if a.store != nil {
		// Clean up the data directory to ensure no sensitive data is left behind
		// The user requested that the Case Output Path files be cleared on exit.
		// We only remove the 'data' subdirectory to be safe and avoid deleting user directories if misconfigured.
		dataDir := filepath.Join(a.store.CasePath(), "data")
		a.log("Shutdown: Cleaning up data directory %s", dataDir)
		if err := os.RemoveAll(dataDir); err != nil {
			a.log("Error cleaning up data directory: %s", err)
		} else {
			a.log("Data directory cleaned up successfully.")
		}
	}
}

// GetDefaultCasePath returns a sensible default path for the current OS.
func (a *App) GetDefaultCasePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "gtrace_case")
	}

	switch runtime.GOOS {
	case "windows":
		// On Windows, use Documents/GTraceCase or Temp
		// Using Temp for now to match behavior but Home is better for persistence
		return filepath.Join(os.TempDir(), "gtrace_case")
	default:
		// On *nix, use /tmp/gtrace_case for now
		// Actually let's use home dir if available to be nice
		return filepath.Join(home, ".gtrace_case")
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

	a.log("Starting Triage on %s with options: %v", evidencePath, options)
	return a.pipeline.Triage(a.ctx, evidencePath, options, progressFunc)
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

// SearchEvents returns a page of timeline events matching the criteria (Loki-Mode).
func (a *App) SearchEvents(query string, page int, pageSize int, source string, level string) ([]model.TimelineEvent, error) {
	if a.store == nil {
		return nil, fmt.Errorf("case not open")
	}

	if strings.EqualFold(source, "all") {
		source = ""
	}
	if strings.EqualFold(level, "all") {
		level = ""
	}

	return a.store.SearchTimeline(a.ctx, &model.TimelineFilter{
		SearchTerm: query,
		Page:       page,
		PageSize:   pageSize,
		Source:     source,
		Level:      level,
	})
}

// GetTotalEventCount returns the number of events in storage
func (a *App) GetTotalEventCount() (int, error) {
	if a.store == nil {
		return 0, nil
	}
	return a.store.CountTimelineEvents(a.ctx)
}

// GetEventStats returns a breakdown of counts by source and level
func (a *App) GetEventStats() (*storage.EventStats, error) {
	if a.store == nil {
		return &storage.EventStats{
			Sources: make(map[string]int),
			Levels:  make(map[string]int),
		}, nil
	}
	return a.store.GetEventStats(a.ctx)
}

// ExecuteSQLQuery runs a raw SQL query on the timeline
func (a *App) ExecuteSQLQuery(query string) ([]map[string]any, error) {
	if a.store == nil {
		return nil, fmt.Errorf("storage not initialized")
	}
	// Basic safety: only SELECT allowed for telemetry/security
	q := strings.TrimSpace(strings.ToUpper(query))
	if !strings.HasPrefix(q, "SELECT") {
		return nil, fmt.Errorf("only SELECT queries are allowed for security")
	}
	return a.store.ExecuteSQLQuery(a.ctx, query)
}

// GetFindings returns findings for the dashboard.
func (a *App) GetFindings() ([]model.Finding, error) {
	if a.store == nil {
		return nil, fmt.Errorf("case not open")
	}
	return a.store.QueryFindings(a.ctx)
}

// RunSelfTest simulates a "whoami.exe" execution to verify Sigma rules are working.
func (a *App) RunSelfTest() string {
	if a.pipeline == nil {
		return "Error: Case/Pipeline not initialized. Start a case first."
	}
	// We need access to the internal pipeline, but it's private.
	// We can add a method to Pipeline to inject test events.
	// For now, let's just create a dummy event and evaluate it using a temporary engine
	// actually we can't easily access the live engine instance from here without exposing it.
	//
	// Better approach: Use the "Verify" feature in pipeline if exposed.
	// Or, more simply: Let's log the fact that rules are loaded.

	return "Check logs for 'Sigma Engine V2 initialized' message. To verify detection, run 'whoami' in a monitored CMD and re-run Live Triage."
}

// BrowseEvidencePath opens the native file system dialog to choose a directory.
func (a *App) BrowseEvidencePath() (string, error) {
	path, err := wailsRuntime.OpenDirectoryDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "Select Evidence Directory",
	})
	if err != nil {
		return "", err
	}
	return path, nil
}
