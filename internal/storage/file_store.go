package storage

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"gtrace/pkg/model"
)

// FileStorage persists artifacts, timeline, and findings into JSONL files inside the case directory.
// This avoids external dependencies while keeping data portable and auditable.
type FileStorage struct {
	casePath string
	mu       sync.Mutex
}

// NewFileStorage creates a file-backed storage rooted at a case path.
func NewFileStorage(casePath string) (*FileStorage, error) {
	if casePath == "" {
		return nil, fmt.Errorf("case path required")
	}
	return &FileStorage{casePath: casePath}, nil
}

func (f *FileStorage) dataDir() string {
	return filepath.Join(f.casePath, "data")
}

// CasePath returns the base directory for the case.
func (f *FileStorage) CasePath() string {
	return f.casePath
}

func (f *FileStorage) ensureFiles() error {
	if err := os.MkdirAll(f.dataDir(), 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	files := []string{"artifacts.jsonl", "timeline.jsonl", "findings.jsonl", "evidence.jsonl"}
	for _, name := range files {
		p := filepath.Join(f.dataDir(), name)
		if _, err := os.Stat(p); err != nil {
			if os.IsNotExist(err) {
				if err := os.WriteFile(p, []byte(""), 0o644); err != nil {
					return fmt.Errorf("init file %s: %w", name, err)
				}
				continue
			}
			return err
		}
	}
	return nil
}

func (f *FileStorage) InitCase(ctx context.Context, casePath string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if casePath != "" && casePath != f.casePath {
		f.casePath = casePath
	}
	return f.ensureFiles()
}

// Reset clears all data in the case.
func (f *FileStorage) Reset(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Remove data dir and recreate
	if err := os.RemoveAll(f.dataDir()); err != nil {
		return err
	}
	return f.ensureFiles()
}

func (f *FileStorage) RegisterEvidence(ctx context.Context, loc EvidenceLocation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	record := map[string]any{
		"path":       loc.Path,
		"size_bytes": loc.SizeBytes,
		"is_dir":     loc.IsDir,
	}
	return f.appendJSONL("evidence.jsonl", record)
}

func (f *FileStorage) SaveArtifacts(ctx context.Context, artifacts []model.Artifact) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range artifacts {
		if err := f.appendJSONL("artifacts.jsonl", a); err != nil {
			return err
		}
	}
	return nil
}

func (f *FileStorage) SaveTimeline(ctx context.Context, events []model.TimelineEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range events {
		if err := f.appendJSONL("timeline.jsonl", e); err != nil {
			return err
		}
	}
	return nil
}

func (f *FileStorage) SaveFindings(ctx context.Context, findings []model.Finding) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, fi := range findings {
		if err := f.appendJSONL("findings.jsonl", fi); err != nil {
			return err
		}
	}
	return nil
}

func (f *FileStorage) QueryTimeline(ctx context.Context, filter *model.TimelineFilter) ([]model.TimelineEvent, error) {
	if filter == nil {
		return nil, fmt.Errorf("filter required")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	path := filepath.Join(f.dataDir(), "timeline.jsonl")
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var events []model.TimelineEvent
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var ev model.TimelineEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		if filter.Artifact != "" && ev.Artifact != filter.Artifact {
			continue
		}
		if filter.TimeStart != nil && ev.EventTime.Before(*filter.TimeStart) {
			continue
		}
		if filter.TimeEnd != nil && ev.EventTime.After(*filter.TimeEnd) {
			continue
		}
		events = append(events, ev)
		// Don't break early! We need to sort first to get the *latest* events globally.
		// if filter.MaxResults > 0 && len(events) >= filter.MaxResults { break }
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Sort Descending (Newest First)
	sort.Slice(events, func(i, j int) bool {
		return events[i].EventTime.After(events[j].EventTime)
	})

	// Slice top N
	if filter.MaxResults > 0 && len(events) > filter.MaxResults {
		events = events[:filter.MaxResults]
	}

	return events, nil
}

func (f *FileStorage) QueryFindings(ctx context.Context) ([]model.Finding, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := filepath.Join(f.dataDir(), "findings.jsonl")
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var findings []model.Finding
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var fi model.Finding
		if err := json.Unmarshal(scanner.Bytes(), &fi); err != nil {
			continue
		}
		findings = append(findings, fi)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}

func (f *FileStorage) appendJSONL(name string, v any) error {
	if err := f.ensureFiles(); err != nil {
		return err
	}
	path := filepath.Join(f.dataDir(), name)
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	return nil
}
