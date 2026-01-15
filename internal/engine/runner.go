package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type Job struct {
	ID     string
	Name   string
	Params map[string]string
}

type ProgressEvent struct {
	JobID   string
	Message string
	Percent float64
	Err     error
}

// JobRunner executes background tasks with progress and cancellation support.
type JobRunner interface {
	Enqueue(job Job) (string, error)
	Run(ctx context.Context, jobID string) error
	Cancel(jobID string) error
	Progress(jobID string) (<-chan ProgressEvent, error)
}

// InMemoryRunner is a simple worker placeholder for early prototyping.
type InMemoryRunner struct {
	mu       sync.Mutex
	jobs     map[string]Job
	progress map[string]chan ProgressEvent
}

func NewInMemoryRunner() *InMemoryRunner {
	return &InMemoryRunner{
		jobs:     make(map[string]Job),
		progress: make(map[string]chan ProgressEvent),
	}
}

func (r *InMemoryRunner) Enqueue(job Job) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if job.ID == "" {
		job.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	if _, exists := r.jobs[job.ID]; exists {
		return "", errors.New("job already exists")
	}
	r.jobs[job.ID] = job
	r.progress[job.ID] = make(chan ProgressEvent, 4)
	return job.ID, nil
}

func (r *InMemoryRunner) Run(ctx context.Context, jobID string) error {
	r.mu.Lock()
	job, ok := r.jobs[jobID]
	updates, upOk := r.progress[jobID]
	r.mu.Unlock()
	if !ok || !upOk {
		return errors.New("job not found")
	}

	select {
	case updates <- ProgressEvent{JobID: jobID, Message: "started", Percent: 0}:
	default:
	}

	// Simulate quick completion; real implementation would invoke parser/analyzer pipeline.
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	progress := 0.0
	for progress < 100 {
		select {
		case <-ctx.Done():
			updates <- ProgressEvent{JobID: jobID, Message: "cancelled", Percent: progress, Err: ctx.Err()}
			return ctx.Err()
		case <-ticker.C:
			progress += 25
			if progress > 100 {
				progress = 100
			}
			updates <- ProgressEvent{JobID: jobID, Message: job.Name, Percent: progress}
		}
	}

	return nil
}

func (r *InMemoryRunner) Cancel(jobID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ch, ok := r.progress[jobID]; ok {
		ch <- ProgressEvent{JobID: jobID, Message: "cancelled", Percent: 0, Err: errors.New("cancelled")}
		close(ch)
		delete(r.progress, jobID)
		delete(r.jobs, jobID)
		return nil
	}
	return errors.New("job not found")
}

func (r *InMemoryRunner) Progress(jobID string) (<-chan ProgressEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ch, ok := r.progress[jobID]
	if !ok {
		return nil, errors.New("job not found")
	}
	return ch, nil
}
