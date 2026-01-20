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

// extractFileName extracts the filename from a path, handling both Windows and Unix paths
func extractFileName(path string) string {
	// Handle Windows paths (backslash)
	if idx := strings.LastIndex(path, "\\"); idx != -1 {
		return path[idx+1:]
	}
	// Handle Unix paths (forward slash)
	if idx := strings.LastIndex(path, "/"); idx != -1 {
		return path[idx+1:]
	}
	return path
}

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
	// --- SYSTEM ---
	1:    "System Time Changed",
	12:   "System Started (Kernel)",
	13:   "System Shutdown (Kernel)",
	14:   "Password Changed",
	24:   "Time Zone Changed",
	41:   "System Rebooted (Unexpected)",
	104:  "Log Fetched/Cleared",
	109:  "Shutdown Intent (Kernel-Power)",
	1074: "System Sleep/Hibernation",
	6005: "Event Log Service Started",
	6006: "Event Log Service Stopped",
	6008: "Unexpected Shutdown",
	6009: "OS Version Detected",
	6013: "System Uptime",
	7000: "Service Start Failed",
	7009: "Service Timeout",
	7023: "Service Error",
	7024: "Service Error",
	7034: "Service Crashed",
	7036: "Service State Change",
	7040: "Service Start Type Change",
	7045: "Service Installed",

	// --- SECURITY (Logon/Auth) ---
	4608: "Windows Started",
	4609: "Windows Shutdown",
	4616: "System Time Changed",
	4624: "Logon Success",
	4625: "Logon Failed",
	4634: "Logoff",
	4647: "User Initiated Logoff",
	4648: "Logon with Explicit Creds",
	4672: "Admin/Special Logon",
	4776: "Credential Validation",
	4800: "Workstation Locked",
	4801: "Workstation Unlocked",

	// --- SECURITY (Account Management) ---
	4720: "User Created",
	4722: "User Enabled",
	4723: "User Password Change Attempt",
	4724: "User Password Reset Attempt",
	4725: "User Disabled",
	4726: "User Deleted",
	4728: "Member Added to Global Group",
	4729: "Member Removed from Global Group",
	4732: "Member Added to Local Group",
	4733: "Member Removed from Local Group",
	4735: "Security Group Modified",
	4738: "User Account Modified",
	4740: "Account Locked Out",
	4756: "Member Added to Universal Group",
	4757: "Member Removed from Universal Group",
	4767: "Account Unlocked",
	4797: "Blank Password Check",
	4798: "Local Group Enumerated",
	4799: "Local Group Member Enumerated",

	// --- SECURITY (Process) ---
	4688: "Process Created",
	4689: "Process Terminated",
	4696: "Primary Token Assigned",

	// --- SECURITY (Objects/Shares) ---
	4656: "Handle Requested",
	4658: "Handle Closed",
	4663: "Object Access",
	4690: "Handle Duplicated",
	5140: "Network Share Accessed",
	5145: "Network Share Object Checked",

	// --- SECURITY (Policy/Audit) ---
	1102: "Audit Log Cleared",
	4719: "Audit Policy Changed",
	4902: "Audit Policy Table Created",
	4907: "Auditing Settings Changed",

	// --- TASKS ---
	4698: "Task Created",
	4699: "Task Deleted",
	4700: "Task Enabled",
	4701: "Task Disabled",
	4702: "Task Updated",
	106:  "Task Registered",
	129:  "Task Process Created",
	140:  "Task Updated",
	141:  "Task Deleted",
	200:  "Task Action Started",

	// --- RDP (TerminalServices-LocalSessionManager) ---
	21: "RDP Session Logon",
	22: "RDP Shell Start",
	23: "RDP Logoff",
	25: "RDP Reconnect",
	39: "RDP Disconnect",

	// --- RDP (RemoteConnectionManager) ---
	1149: "RDP Auth Succeeded",

	// --- DEFENDER ---
	1000: "Defender Error",
	1001: "Defender Scan Complete",
	1116: "Malware Detected",
	1117: "Malware Action Taken",
	5000: "Real-time Protection Enabled",
	5001: "Real-time Protection Disabled",
	5007: "Defender Config Changed",

	// --- POWERSHELL ---
	4103: "PS Module Logging",
	4104: "PS Script Block",
	800:  "PS Pipeline Exec",

	// --- MISC / NOISE ---
	5379: "Credential Manager Read",
	4826: "Boot Config Loaded",
}

// Helper to determine category
func getEventCategory(eid int64) string {
	switch eid {
	// Logon/Auth
	case 4624, 4625, 4672, 4768, 4769, 21, 25, 24, 1149:
		return "Logon"
	// Account Management
	case 4720, 4726, 4728, 4729, 4732, 4733, 4756:
		return "Account"
	// Execution
	case 4688, 4689:
		return "Process"
	// Persistence / Tasks
	case 4698, 4699, 4700, 4701, 4702, 106, 129, 140, 141, 200, 7045:
		return "Persistence"
	// System / Service
	case 6005, 6006, 7036, 7040, 12, 13, 109, 41, 6:
		return "System"
	// Defense Evasion
	case 1102, 1116, 1117, 5001:
		return "Security"
	default:
		return "General"
	}
}

func (p *EvtxParser) Parse(ctx context.Context, in pluginsdk.ParseRequest) (*pluginsdk.ParseResponse, error) {
	// log.Printf("DEBUG: EVTX Parser started for %s", in.EvidencePath)
	f, err := openFileShared(in.EvidencePath)
	if err != nil {
		// log.Printf("DEBUG: EVTX Failed to open %s: %v", in.EvidencePath, err)
		return nil, err
	}
	defer f.Close()

	// Velocidex evtx parser handles chunks
	chunks, err := evtx.GetChunks(f)
	if err != nil {
		// log.Printf("DEBUG: EVTX failed to get chunks for %s: %v", in.EvidencePath, err)
		return nil, fmt.Errorf("evtx get chunks: %w", err)
	}
	// log.Printf("DEBUG: EVTX found %d chunks in %s", len(chunks), in.EvidencePath)

	var events []model.TimelineEvent

	// Default Limits - Very generous to ensure we don't miss events
	maxEvents := 100000
	if val, ok := in.Metadata["max_events"]; ok {
		if v, err := strconv.Atoi(val); err == nil && v > 0 {
			maxEvents = v
		}
	}

	// Time Filter (Days to look back) - Default to 10 years
	days := 3650
	if val, ok := in.Metadata["days"]; ok {
		if v, err := strconv.Atoi(val); err == nil && v > 0 {
			days = v
		}
	}
	cutoffTime := time.Now().AddDate(0, 0, -days)
	log.Printf("EVTX Parser: MaxEvents=%d, Days=%d, Cutoff=%s", maxEvents, days, cutoffTime.Format(time.RFC3339))

	// STRATEGY: Iterate Backwards (Tail) to get the most recent events first.
	count := 0
	unknownCount := 0
	totalScanned := 0
	scanLimit := maxEvents * 50 // Don't scan more than 50x the requested limit to prevent infinite scanning on huge files
	if scanLimit < 500000 {
		scanLimit = 500000
	} // Minimum scan floor

	// Iterate Chunks in REVERSE order
	// EVTX appends new chunks to the end.
	totalChunks := len(chunks)
	for i := totalChunks - 1; i >= 0; i-- {
		if count >= maxEvents {
			break
		}

		// Safety Break for huge files
		if totalScanned > scanLimit {
			// log.Printf("DEBUG: Hit scan limit of %d events. Stopping.", scanLimit)
			break
		}

		// Progress Callback (every 5% or 100 chunks)
		if in.ProgressCallback != nil && (totalChunks-i)%100 == 0 {
			processed := totalChunks - i
			percent := int(float64(processed) / float64(totalChunks) * 100)
			in.ProgressCallback(percent)
		}

		chunk := chunks[i]

		// Correct usage: Header.FirstEventRecID
		records, err := chunk.Parse(int(chunk.Header.FirstEventRecID))
		if err != nil {
			// log.Printf("DEBUG: EVTX error parsing chunk %d (ID %d): %v", i, chunk.Header.FirstEventRecID, err)
			// Try fallback to search?
			continue
		}

		if len(records) == 0 {
			// Debug why
			// log.Printf("DEBUG: Chunk %d (ID %d) returned 0 records. LastID: %d", i, chunk.Header.FirstEventRecID, chunk.Header.LastEventRecID)
			continue
		}

		// // log.Printf("DEBUG: Chunk %d has %d records", i, len(records))

		// Parse records in REVERSE order too (Newest -> Oldest in chunk)
		for j := len(records) - 1; j >= 0; j-- {
			totalScanned++
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
				// log.Printf("DEBUG: record.Event is not *ordereddict.Dict, got %T", record.Event)
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
			// // log.Printf("DEBUG: Event Keys: %v", eventDict.Keys())

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
				// log.Printf("DEBUG: System key missing. Available: %v", eventDict.Keys())
				continue
			}

			sysDict, ok := sysRaw.(*ordereddict.Dict)
			if !ok {
				// log.Printf("DEBUG: System key missing or not dict")
				continue
			}

			// Get EventID
			// log.Printf("DEBUG: System Keys: %v", sysDict.Keys())

			var eidRaw interface{}
			var foundEID bool
			for _, k := range sysDict.Keys() {
				if strings.HasSuffix(k, "EventID") {
					eidRaw, _ = sysDict.Get(k)
					foundEID = true
					// log.Printf("DEBUG: Found EventID key: %s", k)
					break
				}
			}
			if !foundEID {
				eidRaw, _ = sysDict.Get("EventID") // Try direct
			}
			// // log.Printf("DEBUG: eidRaw: %v (%T)", eidRaw, eidRaw)

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
					// log.Printf("DEBUG: Failed to parse EventID string '%s': %v", v, err)
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
				// log.Printf("DEBUG: Unknown EID type %T: %v", eidRaw, eidRaw)
			}

			// Debug: Show first few EIDs to verify file content
			if count < 1000 {
				if eid != 0 {
					// // log.Printf("DEBUG: Found Valid EID %d", eid)
				}
			}

			// Time extraction is reliable from Record Header (FileTime)
			// evtTime already calculated at top of loop for filtering

			// Details
			props := make(map[string]string)
			props["Category"] = getEventCategory(eid)

			// Extract Channel/Computer from System dict
			if ch, ok := sysDict.GetString("Channel"); ok {
				props["Channel"] = ch
			}
			if comp, ok := sysDict.GetString("Computer"); ok {
				props["Computer"] = comp
			}
			props["EventID"] = fmt.Sprintf("%d", eid)

			// Extract Level (1=Critical, 2=Error, 3=Warning, 4=Info)
			if lvlRaw, ok := sysDict.Get("Level"); ok {
				var lvl int
				switch v := lvlRaw.(type) {
				case int:
					lvl = v
				case int64:
					lvl = int(v)
				case uint64:
					lvl = int(v)
				}
				if lvl > 0 {
					switch lvl {
					case 1:
						props["_AlertLevel"] = "Critical"
					case 2:
						props["_AlertLevel"] = "High" // Error
					case 3:
						props["_AlertLevel"] = "Medium" // Warning
					}
					props["Level"] = fmt.Sprintf("%d", lvl)
				}
			}

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

			// NOISE REDUCTION: 4907 (Audit Settings)
			// Windows Updates (TiWorker) generate thousands of these.
			if eid == 4907 {
				procName, _ := props["ProcessName"]
				if strings.Contains(strings.ToLower(procName), "tiworker.exe") || strings.Contains(strings.ToLower(procName), "trustedinstaller") {
					continue
				}
			}

			desc, interesting := interestingEvents[eid]
			if !interesting {
				if unknownCount >= 1000 {
					continue
				}
				desc = "Unknown" // Keep Action clean (Event ID is in Details)
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

			// Heuristic Subject - Make it meaningful for each event type
			subject := ""

			// 4688: Process Creation - Show the process name
			if eid == 4688 {
				if s, ok := props["NewProcessName"]; ok && s != "" {
					// Extract just the filename from the full path (handle both / and \)
					subject = extractFileName(s)
				}
				// If CommandLine exists, add it to a special field for easy access
				if cmd, ok := props["CommandLine"]; ok && cmd != "" && cmd != "-" {
					props["_CommandLine"] = cmd // Prefix with _ to show prominently
				}
				if parent, ok := props["ParentProcessName"]; ok && parent != "" {
					props["_ParentProcess"] = extractFileName(parent)
				}
			}

			// 4689: Process Termination
			if eid == 4689 {
				if s, ok := props["ProcessName"]; ok && s != "" {
					subject = filepath.Base(s)
				}
			}

			// Task Scheduler
			if subject == "" {
				if s, ok := props["TaskName"]; ok && s != "" {
					subject = s
				}
			}
			// Service Install
			if subject == "" {
				if s, ok := props["ServiceName"]; ok && s != "" {
					subject = s
				}
			}
			// Logon events
			if subject == "" {
				if s, ok := props["TargetUserName"]; ok && s != "" {
					subject = s
				}
			}
			// Object Access
			if subject == "" {
				if s, ok := props["ObjectName"]; ok && s != "" {
					// Shorten long paths
					if len(s) > 60 {
						subject = "..." + s[len(s)-57:]
					} else {
						subject = s
					}
				}
			}
			// Fallback: Use SubjectUserName if nothing else
			if subject == "" {
				if s, ok := props["SubjectUserName"]; ok && s != "" && s != "-" {
					subject = s
				}
			}

			ev := model.TimelineEvent{
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
			}

			if in.StreamCallback != nil {
				in.StreamCallback(ev)
			} else {
				events = append(events, ev)
			}
			count++
		}
	}

	return &pluginsdk.ParseResponse{
		Events: events,
	}, nil
}
