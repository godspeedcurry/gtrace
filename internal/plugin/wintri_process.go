package plugin

import (
	"context"
	"encoding/csv"
	"io"
	"os"
	"strings"
	"time"

	"gtrace/pkg/model"
	"gtrace/pkg/pluginsdk"
)

// WintriProcessParser parses Process_List.csv from WINTri
type WintriProcessParser struct{}

func (p *WintriProcessParser) Manifest() pluginsdk.Manifest {
	return pluginsdk.Manifest{
		Name:      "wintri-process-parser",
		Version:   "1.0.0",
		Type:      "parser",
		Platforms: []string{"windows"},
		Input: pluginsdk.IODecl{
			Kind: "file",
			MIME: "text/csv",
		},
		Output: pluginsdk.IODecl{
			Artifact: "process-list",
		},
	}
}

func (p *WintriProcessParser) CanParse(filename string, header []byte) bool {
	return strings.HasSuffix(strings.ToLower(filename), "process_list.csv")
}

func (p *WintriProcessParser) Parse(ctx context.Context, in pluginsdk.ParseRequest) (*pluginsdk.ParseResponse, error) {
	f, err := os.Open(in.EvidencePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := csv.NewReader(f)

	// Read Header
	headers, err := reader.Read()
	if err != nil {
		return nil, err
	}

	colMap := make(map[string]int)
	for i, h := range headers {
		colMap[strings.ToLower(h)] = i
	}

	var events []model.TimelineEvent

	// CreationDate format example: 20250114000305.123456+000
	const timeLayout = "20060102150405.000000-070"

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			break // skip bad lines
		}

		pid := getCol(record, colMap, "processid")
		name := getCol(record, colMap, "processname")
		cmdline := getCol(record, colMap, "commandline")
		dateStr := getCol(record, colMap, "creationdate")

		var ts time.Time
		// Try parsing time
		// WMI often returns dates like 20250114120000.000000+000
		if len(dateStr) > 21 {
			// Simplistic trim just to parse main part if +000 format varies
			// But let's try standard WMI layout first
			t, err := time.Parse("20060102150405.000000-070", dateStr)
			if err == nil {
				ts = t
			} else {
				// Fallback or ignore
				ts = time.Now()
			}
		}

		evt := model.TimelineEvent{
			ID:        "proc-" + pid + "-" + dateStr, // not unique, but MVP ok
			EventTime: ts,
			Source:    "wintri-process",
			Artifact:  "process",
			Action:    "EXECUTION",
			Subject:   name,
			Details: map[string]string{
				"pid":     pid,
				"cmdline": cmdline,
			},
			EvidenceRef: model.EvidenceRef{
				SourcePath: in.EvidencePath,
			},
		}
		events = append(events, evt)
	}

	return &pluginsdk.ParseResponse{
		Events: events,
		// No artifacts for processes? Or maybe create Artifact for the CSV itself?
		// Engine handles file artifact. We return detailed events.
	}, nil
}

func getCol(record []string, m map[string]int, name string) string {
	if idx, ok := m[name]; ok && idx < len(record) {
		return record[idx]
	}
	return ""
}
