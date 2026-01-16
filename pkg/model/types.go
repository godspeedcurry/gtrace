package model

import "time"

// EvidenceRef links a record back to the source evidence for auditability.
type EvidenceRef struct {
	SourcePath string `json:"source_path"`
	Offset     int64  `json:"offset,omitempty"`
	Size       int64  `json:"size,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
}

// Hashes captures common digests for IOC matching.
type Hashes struct {
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

type Artifact struct {
	ID          string            `json:"id"`
	Host        string            `json:"host,omitempty"`
	User        string            `json:"user,omitempty"`
	Type        string            `json:"type"`
	Source      string            `json:"source,omitempty"`
	Path        string            `json:"path,omitempty"`
	Created     *time.Time        `json:"created,omitempty"`
	Modified    *time.Time        `json:"modified,omitempty"`
	Accessed    *time.Time        `json:"accessed,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Hashes      Hashes            `json:"hashes,omitempty"`
	EvidenceRef EvidenceRef       `json:"evidence_ref"`
}

type TimelineEvent struct {
	ID          string            `json:"id"`
	EventTime   time.Time         `json:"event_time"`
	UTCOffset   int               `json:"utc_offset,omitempty"`
	Source      string            `json:"source"`
	Artifact    string            `json:"artifact"`
	Action      string            `json:"action"`
	Subject     string            `json:"subject,omitempty"`
	Details     map[string]string `json:"details,omitempty"`
	Confidence  string            `json:"confidence,omitempty"`
	EvidenceRef EvidenceRef       `json:"evidence_ref"`
	IOCHits     []string          `json:"ioc_hits,omitempty"`
}

type Finding struct {
	ID           string        `json:"id"`
	Severity     string        `json:"severity"`
	Title        string        `json:"title"`
	Description  string        `json:"description,omitempty"`
	RuleID       string        `json:"rule_id,omitempty"`
	EvidenceRefs []EvidenceRef `json:"evidence_refs,omitempty"`
	IOCs         []IOCMaterial `json:"iocs,omitempty"`
}

type IOCMaterial struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Note  string `json:"note,omitempty"`
}

// TimelineFilter narrows timeline queries.
type TimelineFilter struct {
	Host       string
	User       string
	Artifact   string
	IOC        string
	TimeStart  *time.Time
	TimeEnd    *time.Time
	MaxResults int

	// Pagination & Search
	SearchTerm string
	Page       int
	PageSize   int
	Source     string
}
