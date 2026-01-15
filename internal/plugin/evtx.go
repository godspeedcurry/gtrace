package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"gtrace/pkg/model"
	"gtrace/pkg/pluginsdk"
	"log"
	"path/filepath" // Added strconv
	"strconv"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/evtx"
)

type EvtxParser struct{}

func (p *EvtxParser) Manifest() pluginsdk.Manifest {
	return pluginsdk.Manifest{
		Name:      "win-evtx-parser",
		Version:   "1.0.0",
		Type:      "parser",
		Platforms: []string{"windows"},
		Input: pluginsdk.IODecl{
			Kind: "file",
			MIME: "application/octet-stream",
		},
		Output: pluginsdk.IODecl{
			Artifact: "event_log",
		},
	}
}

func (p *EvtxParser) CanParse(path string, header []byte) bool {
	if len(header) >= 8 && string(header[:8]) == "ElfFile\x00" {
		return true
	}
	return strings.HasSuffix(strings.ToLower(path), ".evtx")
}

// Interest Filter map
var interestingEvents = map[int64]string{
	// System
	7045: "Service Installed",

	// Security
	4688: "Process Created",
	4689: "Process Terminated",
	4624: "Logon Success", // High Volume!
	4625: "Logon Failed",
	4720: "User Created",
	4726: "User Deleted",
	4698: "Task Created",
	4702: "Task Updated",
	4768: "Kerberos TGT Request",        // Ticket Granting Ticket
	4769: "Kerberos TGS Request",        // Ticket Granting Service (Service Ticket)
	4672: "Special Privileges Assigned", // Admin Login

	// TaskScheduler
	106: "Task Registered",
	129: "Task Created",
	200: "Task Action Started",

	// RDP
	21: "RDP Session Logon",
	25: "RDP Session Reconnect",

	// Defender
	1116: "Malware Detected",
	1117: "Malware Action Taken",
	5001: "Real-time Protection Disabled",
}

func (p *EvtxParser) Parse(ctx context.Context, in pluginsdk.ParseRequest) (*pluginsdk.ParseResponse, error) {
	log.Printf("DEBUG: EVTX Parser started for %s", in.EvidencePath)
	f, err := openFileShared(in.EvidencePath)
	if err != nil {
		log.Printf("DEBUG: EVTX Failed to open %s: %v", in.EvidencePath, err)
		return nil, err
	}
	defer f.Close()

	// Velocidex evtx parser handles chunks
	chunks, err := evtx.GetChunks(f)
	if err != nil {
		log.Printf("DEBUG: EVTX failed to get chunks for %s: %v", in.EvidencePath, err)
		return nil, fmt.Errorf("evtx get chunks: %w", err)
	}
	log.Printf("DEBUG: EVTX found %d chunks in %s", len(chunks), in.EvidencePath)

	var events []model.TimelineEvent

	// Default Limits
	maxEvents := 5000
	if val, ok := in.Metadata["max_events"]; ok {
		if v, err := strconv.Atoi(val); err == nil && v > 0 {
			maxEvents = v
		}
	}

	// Time Filter (Days to look back)
	days := 30
	if val, ok := in.Metadata["days"]; ok {
		if v, err := strconv.Atoi(val); err == nil && v > 0 {
			days = v
		}
	}
	cutoffTime := time.Now().AddDate(0, 0, -days)
	log.Printf("DEBUG: EVTX Config - MaxEvents: %d, Days: %d (Cutoff: %s)", maxEvents, days, cutoffTime.Format(time.RFC3339))

	// STRATEGY: Iterate Backwards (Tail) to get the most recent events first.
	count := 0
	unknownCount := 0

	// Iterate Chunks in REVERSE order
	// EVTX appends new chunks to the end.
	for i := len(chunks) - 1; i >= 0; i-- {
		if count >= maxEvents {
			break
		}

		chunk := chunks[i]

		// Correct usage: Header.FirstEventRecID
		records, err := chunk.Parse(int(chunk.Header.FirstEventRecID))
		if err != nil {
			log.Printf("DEBUG: EVTX error parsing chunk %d (ID %d): %v", i, chunk.Header.FirstEventRecID, err)
			// Try fallback to search?
			continue
		}

		if len(records) == 0 {
			// Debug why
			log.Printf("DEBUG: Chunk %d (ID %d) returned 0 records. LastID: %d", i, chunk.Header.FirstEventRecID, chunk.Header.LastEventRecID)
			continue
		}

		// log.Printf("DEBUG: Chunk %d has %d records", i, len(records))

		// Parse records in REVERSE order too (Newest -> Oldest in chunk)
		for j := len(records) - 1; j >= 0; j-- {
			record := records[j]
			// Check Time Filter (Early Exit)
			// EVTX records in chunk are chronological? Actually usually yes.
			// We iterate chunk REVERSE (Newest -> Oldest).
			evtTime := windowsFiletimeToGo(record.Header.FileTime)
			if evtTime.Before(cutoffTime) {
				// Optimization: If we hit a log older than cutoff, and we are iterating backwards,
				// then all remaining logs in this chunk (and previous chunks) are also too old.
				// We can stop everything.
				return &pluginsdk.ParseResponse{Events: events}, nil
			}

			if count >= maxEvents {
				break
			}

			// ... Logic continues ...
			// The evtx library parses the binary XML into this structure.
			eventDict, ok := record.Event.(*ordereddict.Dict)
			if !ok {
				log.Printf("DEBUG: record.Event is not *ordereddict.Dict, got %T", record.Event)
				continue
			}

			// UNWRAP ROOT 'Event' KEY
			// Sometimes the dict is { "Event": { "System": ... } }
			for _, k := range eventDict.Keys() {
				if strings.HasSuffix(k, "Event") {
					if child, ok := eventDict.Get(k); ok {
						if childDict, ok := child.(*ordereddict.Dict); ok {
							eventDict = childDict
						}
					}
					break
				}
			}

			// Extract standard System fields
			// Event/System/EventID
			// Event/System/TimeCreated/SystemTime

			// DEBUG: Print keys to see namespace
			// log.Printf("DEBUG: Event Keys: %v", eventDict.Keys())

			var sysRaw interface{}
			var foundSys bool
			for _, k := range eventDict.Keys() {
				if strings.HasSuffix(k, "System") {
					sysRaw, _ = eventDict.Get(k)
					foundSys = true
					break
				}
			}

			if !foundSys {
				// Try direct get just in case
				sysRaw, foundSys = eventDict.Get("System")
			}

			if !foundSys {
				log.Printf("DEBUG: System key missing. Available: %v", eventDict.Keys())
				continue
			}

			sysDict, ok := sysRaw.(*ordereddict.Dict)
			if !ok {
				log.Printf("DEBUG: System key missing or not dict")
				continue
			}

			// Get EventID
			log.Printf("DEBUG: System Keys: %v", sysDict.Keys())

			var eidRaw interface{}
			var foundEID bool
			for _, k := range sysDict.Keys() {
				if strings.HasSuffix(k, "EventID") {
					eidRaw, _ = sysDict.Get(k)
					foundEID = true
					log.Printf("DEBUG: Found EventID key: %s", k)
					break
				}
			}
			if !foundEID {
				eidRaw, _ = sysDict.Get("EventID") // Try direct
			}
			// log.Printf("DEBUG: eidRaw: %v (%T)", eidRaw, eidRaw)

			var eid int64
			switch v := eidRaw.(type) {
			case int64:
				eid = v
			case uint64:
				eid = int64(v)
			case int:
				eid = int64(v)
			case float64:
				eid = int64(v) // JSON unmarshal might be float
			case string:
				// EVTX values often come as strings
				if val, err := strconv.ParseInt(v, 10, 64); err == nil {
					eid = val
				} else {
					log.Printf("DEBUG: Failed to parse EventID string '%s': %v", v, err)
				}
			case *ordereddict.Dict:
				// Universal Extraction via JSON Round-Trip
				// This handles strict integer types, floats, and strings automatically via json.Number
				if b, err := json.Marshal(v); err == nil {
					var container struct {
						Value json.Number `json:"Value"`
					}
					// Unmarshal to extract "Value" safely
					if err := json.Unmarshal(b, &container); err == nil {
						if val, err := container.Value.Int64(); err == nil {
							eid = val
						}
					}
				}

				// Fallback: If Value was missing or extraction failed, check implicit keys
				if eid == 0 {
					// Try empty key "" which often holds text content
					if val, ok := v.GetString(""); ok {
						if iVal, err := strconv.ParseInt(val, 10, 64); err == nil {
							eid = iVal
						}
					}
				}
			default:
				log.Printf("DEBUG: Unknown EID type %T: %v", eidRaw, eidRaw)
			}

			// Debug: Show first few EIDs to verify file content
			if count < 1000 {
				if eid != 0 {
					// log.Printf("DEBUG: Found Valid EID %d", eid)
				}
			}

			// Time extraction is reliable from Record Header (FileTime)
			// evtTime already calculated at top of loop for filtering

			// Details
			props := make(map[string]string)

			// Extract Channel/Computer from System dict
			if ch, ok := sysDict.GetString("Channel"); ok {
				props["Channel"] = ch
			}
			if comp, ok := sysDict.GetString("Computer"); ok {
				props["Computer"] = comp
			}
			props["EventID"] = fmt.Sprintf("%d", eid)

			// Flatten EventData
			// Event/EventData/*
			if eventDataRaw, ok := eventDict.Get("EventData"); ok {
				if eventDataDict, ok := eventDataRaw.(*ordereddict.Dict); ok {
					for _, k := range eventDataDict.Keys() {
						val, _ := eventDataDict.Get(k)
						props[k] = fmt.Sprintf("%v", val)
					}
				}
			}

			// --- INTELLIGENT NOISE REDUCTION ---
			// This must happen AFTER props are populated.
			if eid == 4624 || eid == 4625 {
				user, _ := props["TargetUserName"]

				// 1. Filter Machine Accounts (ending in $)
				if strings.HasSuffix(user, "$") {
					continue
				}
				// 2. Filter System Accounts - aggressive filter for Triage
				if user == "SYSTEM" || user == "NETWORK SERVICE" || user == "LOCAL SERVICE" || user == "DWM-1" || user == "UMFD-0" {
					continue
				}
			}

			desc, interesting := interestingEvents[eid]
			if !interesting {
				if unknownCount >= 1000 {
					continue
				}
				desc = fmt.Sprintf("Event %d", eid)
				unknownCount++
			}

			// --- KERBEROS ENRICHMENT ---
			if eid == 4768 || eid == 4769 {
				// Highlight RC4 Encryption (0x17 or 23) -> Potential Kerberoasting or Weak Security
				etype, _ := props["TicketEncryptionType"]
				if etype == "0x17" || etype == "23" {
					props["_Alert"] = "Weak RC4 Encryption Detected (Kerberoasting?)"
				}
			}

			// Sometimes data is in UserData (e.g. 7045)
			if userDataRaw, ok := eventDict.Get("UserData"); ok {
				if userDataDict, ok := userDataRaw.(*ordereddict.Dict); ok {
					for _, k := range userDataDict.Keys() {
						val, _ := userDataDict.Get(k)
						props["UserData."+k] = fmt.Sprintf("%v", val)
					}
				}
			}

			// Heuristic Subject
			subject := ""
			// Task Scheduler
			if s, ok := props["TaskName"]; ok {
				subject = s
			}
			// Service Install
			if s, ok := props["ServiceName"]; ok {
				subject = s
			}
			// Logon
			if s, ok := props["TargetUserName"]; ok {
				subject = s
			}

			events = append(events, model.TimelineEvent{
				ID:        fmt.Sprintf("evtx-%d-%d", eid, record.Header.RecordID),
				EventTime: evtTime,
				Source:    "EventLog",
				Artifact:  filepath.Base(in.EvidencePath),
				Action:    desc,
				Subject:   subject,
				Details:   props,
				EvidenceRef: model.EvidenceRef{
					SourcePath: in.EvidencePath,
				},
			})
			count++
		}
	}

	return &pluginsdk.ParseResponse{
		Events: events,
	}, nil
}
