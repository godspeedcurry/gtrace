package storage

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync" // Removed sort

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

// NewStreamWriter creates a buffered writer for efficient bulk ingestion.
// Caller is responsible for calling closeFunc.
func (f *FileStorage) NewStreamWriter(name string) (writeFunc func(v any) error, closeFunc func() error, err error) {
	// Don't lock entire duration, just setup
	f.mu.Lock()
	if err := f.ensureFiles(); err != nil {
		f.mu.Unlock()
		return nil, nil, err
	}
	path := filepath.Join(f.dataDir(), name)
	f.mu.Unlock()

	// TRUNCATE the file for new analysis stream.
	// We want a fresh timeline for every run.
	file, err := os.OpenFile(path, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, nil, err
	}

	bw := bufio.NewWriter(file)

	writeFunc = func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if _, err := bw.Write(b); err != nil {
			return err
		}
		if err := bw.WriteByte('\n'); err != nil {
			return err
		}
		return nil
	}

	closeFunc = func() error {
		if err := bw.Flush(); err != nil {
			file.Close()
			return err
		}
		return file.Close()
	}

	return writeFunc, closeFunc, nil
}

func (f *FileStorage) SearchTimeline(ctx context.Context, filter *model.TimelineFilter) ([]model.TimelineEvent, error) {
	if filter == nil {
		return nil, fmt.Errorf("filter required")
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	path := filepath.Join(f.dataDir(), "timeline.jsonl")
	file, err := os.Open(path)
	if err != nil {
		// If file doesn't exist, return empty
		if os.IsNotExist(err) {
			return []model.TimelineEvent{}, nil
		}
		return nil, err
	}
	defer file.Close()

	var events []model.TimelineEvent
	scanner := bufio.NewScanner(file)
	// Handle huge lines
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024) // 10MB max

	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 100
	}

	offset := (page - 1) * pageSize
	skipped := 0 // Matched but skipped due to pagination
	count := 0   // Matched and collected

	// Trim search term
	filter.SearchTerm = strings.TrimSpace(filter.SearchTerm)
	termBytes := []byte(strings.ToLower(filter.SearchTerm))
	hasTerm := len(termBytes) > 0

	// Special Filters parsing (e.g. "eid:4688")
	var explicitEID string
	var cleanTerm = filter.SearchTerm

	if strings.HasPrefix(strings.ToLower(cleanTerm), "eid:") {
		explicitEID = strings.TrimPrefix(strings.ToLower(cleanTerm), "eid:")
		hasTerm = false // Disable generic grep, use specific logic
	} else if strings.HasPrefix(strings.ToLower(cleanTerm), "id:") {
		explicitEID = strings.TrimPrefix(strings.ToLower(cleanTerm), "id:")
		hasTerm = false
	}

	// If explicit EID, we might want to grep for it too to avoid unmarshal cost
	// But "EventID" is in Details... "EventID":"4688"
	var eidBytes []byte
	if explicitEID != "" {
		eidBytes = []byte(explicitEID)
	}

	// fmt.Printf("DEBUG SEARCH: Term='%s' Source='%s' EID='%s'\n", filter.SearchTerm, filter.Source, explicitEID)

	for scanner.Scan() {
		// Check cancellation
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		line := scanner.Bytes()
		lowerLine := bytes.ToLower(line)

		// 1. Fast Filter (Loki Mode)
		// Optimization: Case-insensitive grep before Unmarshal
		// We trust that if EID is explicitly requested, "4688" MUST appear in the line.
		if explicitEID != "" {
			if !bytes.Contains(lowerLine, eidBytes) {
				continue
			}
		} else if hasTerm {
			if !bytes.Contains(lowerLine, termBytes) {
				continue
			}
		}

		var ev model.TimelineEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}

		// 2. Structured Filters
		if explicitEID != "" {
			val, ok := ev.Details["EventID"]
			// Robust comparison: handle string/int/float types from JSON interface{}
			if !ok || fmt.Sprintf("%v", val) != explicitEID {
				continue
			}
		}

		// Prevent unused var error for eidBytes (temporary hack or logic restoration)
		_ = eidBytes

		// 2. Structured Filters
		if filter.Artifact != "" && ev.Artifact != filter.Artifact {
			continue
		}

		// Case-insensitive Source check
		if filter.Source != "" && !strings.EqualFold(ev.Source, filter.Source) {
			continue
		}

		if filter.TimeStart != nil && ev.EventTime.Before(*filter.TimeStart) {
			continue
		}
		if filter.TimeEnd != nil && ev.EventTime.After(*filter.TimeEnd) {
			continue
		}

		// 3. Pagination
		if skipped < offset {
			skipped++
			continue
		}

		events = append(events, ev)
		count++

		if count >= pageSize {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return events, nil
}

// Legacy wrapper
func (f *FileStorage) QueryTimeline(ctx context.Context, filter *model.TimelineFilter) ([]model.TimelineEvent, error) {
	// Use new SearchTimeline logic
	return f.SearchTimeline(ctx, filter)
}

// CountTimelineEvents returns the total number of events in storage.
func (f *FileStorage) CountTimelineEvents(ctx context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Optimization: Just count lines
	path := filepath.Join(f.dataDir(), "timeline.jsonl")
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	// bufio.Scanner max token size might be issue for huge lines, but events are usually small.
	// However, for pure line counting, simple read is safer/faster if we don't parse JSON.
	// Using scanner is fine for now.
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		count++
	}
	return count, scanner.Err()
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
