package storage

import (
	"context"
	"errors"
	"sync"

	"gtrace/pkg/model"
)

// Storage defines persistence for artifacts, timeline, findings, and case metadata.
type Storage interface {
	InitCase(ctx context.Context, casePath string) error
	RegisterEvidence(ctx context.Context, loc EvidenceLocation) error
	SaveArtifacts(ctx context.Context, artifacts []model.Artifact) error
	SaveTimeline(ctx context.Context, events []model.TimelineEvent) error
	SaveFindings(ctx context.Context, findings []model.Finding) error
	QueryTimeline(ctx context.Context, filter *model.TimelineFilter) ([]model.TimelineEvent, error)
	QueryFindings(ctx context.Context) ([]model.Finding, error)
}

// EvidenceLocation is a minimal record of imported evidence paths.
type EvidenceLocation struct {
	Path      string
	SizeBytes int64
	IsDir     bool
}

// sqliteStub is a lightweight in-memory placeholder until real DB wiring exists.
type sqliteStub struct {
	mu        sync.Mutex
	events    []model.TimelineEvent
	artifacts []model.Artifact
	findings  []model.Finding
}

// NewSQLiteStub returns a placeholder that satisfies Storage without external deps.
func NewSQLiteStub() Storage {
	return &sqliteStub{
		events:    make([]model.TimelineEvent, 0),
		artifacts: make([]model.Artifact, 0),
		findings:  make([]model.Finding, 0),
	}
}

func (s *sqliteStub) InitCase(ctx context.Context, casePath string) error {
	return nil
}

func (s *sqliteStub) RegisterEvidence(ctx context.Context, loc EvidenceLocation) error {
	return nil
}

func (s *sqliteStub) SaveArtifacts(ctx context.Context, artifacts []model.Artifact) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.artifacts = append(s.artifacts, artifacts...)
	return nil
}

func (s *sqliteStub) SaveTimeline(ctx context.Context, events []model.TimelineEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, events...)
	return nil
}

func (s *sqliteStub) SaveFindings(ctx context.Context, findings []model.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findings = append(s.findings, findings...)
	return nil
}

func (s *sqliteStub) QueryTimeline(ctx context.Context, filter *model.TimelineFilter) ([]model.TimelineEvent, error) {
	if filter == nil {
		return nil, errors.New("filter required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]model.TimelineEvent(nil), s.events...), nil
}

func (s *sqliteStub) QueryFindings(ctx context.Context) ([]model.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]model.Finding(nil), s.findings...), nil
}
