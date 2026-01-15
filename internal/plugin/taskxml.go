package plugin

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gtrace/pkg/model"
	"gtrace/pkg/pluginsdk"
)

// TaskXMLParser parses Windows Task Scheduler XML files found in System32/Tasks.
type TaskXMLParser struct{}

func (p *TaskXMLParser) Manifest() pluginsdk.Manifest {
	return pluginsdk.Manifest{
		Name:      "win-task-xml-parser",
		Version:   "1.0.0",
		Type:      "parser",
		Platforms: []string{"windows"},
		Input: pluginsdk.IODecl{
			Kind: "file",
			MIME: "text/xml",
		},
		Output: pluginsdk.IODecl{
			Artifact: "scheduled_task",
		},
	}
}

func (p *TaskXMLParser) CanParse(path string, header []byte) bool {
	// Typically files in C:\Windows\System32\Tasks don't have extension, or contain XML header
	// Checking header is most reliable
	if len(header) > 5 && strings.Contains(string(header), "<?xml") {
		// Also strict path check to avoid parsing random XMLs?
		// But in triage pipeline we usually feed reliable paths.
		// Let's check for <Task root element too? Maybe too expensive for header check.
		// Just rely on Triege logic feeding us tasks, or "Tasks" folder check.
		clean := strings.ToLower(filepath.Clean(path))
		if strings.Contains(clean, "system32\\tasks") {
			return true
		}
	}
	return false
}

// XML Structures for Task Scheduler 1.2+
type Task struct {
	RegistrationInfo RegistrationInfo `xml:"RegistrationInfo"`
	Triggers         Triggers         `xml:"Triggers"`
	Actions          Actions          `xml:"Actions"`
}

type RegistrationInfo struct {
	Author      string `xml:"Author"`
	Description string `xml:"Description"`
	Date        string `xml:"Date"` // Creation Date
}

type Triggers struct {
	// Catch-all for sub-elements since there are many trigger types
	Raw string `xml:",innerxml"`
}

type Actions struct {
	Exec []ExecAction `xml:"Exec"`
}

type ExecAction struct {
	Command   string `xml:"Command"`
	Arguments string `xml:"Arguments"`
}

// TODO: Handle ComHandler actions for advanced persistence analysis

func (p *TaskXMLParser) Parse(ctx context.Context, in pluginsdk.ParseRequest) (*pluginsdk.ParseResponse, error) {
	content, err := os.ReadFile(in.EvidencePath)
	if err != nil {
		return nil, err
	}

	// Some Task XMLs have UTF-16 encoding which standard Go xml.Unmarshal hates if preamble is missing or specific.
	// But usually file system ones are UTF-16 LE.
	// We might need to convert. Let's try direct first, catch error.

	// Convert UTF-16 LE to UTF-8 if needed
	if len(content) > 2 && content[0] == 0xFF && content[1] == 0xFE {
		content = []byte(cleanupUTF16(content))
		// Note cleanupUTF16 from utils.go works on bytes -> string.
		// We can cast back.
	}

	var task Task
	if err := xml.Unmarshal(content, &task); err != nil {
		return nil, fmt.Errorf("xml parse failed: %w", err)
	}

	var events []model.TimelineEvent

	// Create Event
	// Use File Mod time as "Task Modified" time
	info, _ := os.Stat(in.EvidencePath)
	modTime := time.Now()
	if info != nil {
		modTime = info.ModTime()
	}

	// Collect Commands
	for _, exec := range task.Actions.Exec {
		cmd := exec.Command
		args := exec.Arguments

		events = append(events, model.TimelineEvent{
			ID:        fmt.Sprintf("task-%s-%d", filepath.Base(in.EvidencePath), modTime.UnixNano()),
			EventTime: modTime, // Task Modification Time
			Source:    "TaskScheduler",
			Artifact:  "ScheduledTask",
			Action:    "Persistence Configured",
			Subject:   cmd, // The malicious binary
			Details: map[string]string{
				"arguments":   args,
				"task_name":   filepath.Base(in.EvidencePath),
				"author":      task.RegistrationInfo.Author,
				"description": task.RegistrationInfo.Description,
				"triggers":    simplifyTriggers(task.Triggers.Raw),
			},
			EvidenceRef: model.EvidenceRef{
				SourcePath: in.EvidencePath,
			},
		})
	}

	return &pluginsdk.ParseResponse{
		Events: events,
	}, nil
}

func simplifyTriggers(raw string) string {
	// Very basic summary
	summary := []string{}
	if strings.Contains(raw, "BootTrigger") {
		summary = append(summary, "AtBoot")
	}
	if strings.Contains(raw, "LogonTrigger") {
		summary = append(summary, "AtLogon")
	}
	if strings.Contains(raw, "TimeTrigger") {
		summary = append(summary, "Scheduled")
	}
	if len(summary) == 0 {
		return "Other/Manual"
	}
	return strings.Join(summary, ", ")
}
