package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"gtrace/internal/analysis"
	"gtrace/internal/plugin"
	"gtrace/internal/rules"
	"gtrace/internal/storage"
	"gtrace/pkg/model"
	"gtrace/pkg/pluginsdk"
)

// Pipeline orchestrates parser/analyzer plugins over evidence paths.
type Pipeline struct {
	store     storage.Storage
	parsers   []pluginsdk.ParserPlugin
	analyzers []pluginsdk.AnalyzerPlugin
	logger    func(string, ...interface{})
}

// NewPipeline constructs a pipeline bound to storage and parser set.
func NewPipeline(store storage.Storage, parsers []pluginsdk.ParserPlugin, analyzers []pluginsdk.AnalyzerPlugin, logger func(string, ...interface{})) *Pipeline {
	// Self-healing: Cleanup any leftovers from previous crashed sessions
	go cleanupOrphanedDumps(logger)

	return &Pipeline{
		store:     store,
		parsers:   parsers,
		analyzers: analyzers,
		logger:    logger,
	}
}

func cleanupOrphanedDumps(logger func(string, ...interface{})) {
	// Look for files matching gtrace_dump_*.hve in TempDir
	pattern := filepath.Join(os.TempDir(), "gtrace_dump_*.hve")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return
	}
	for _, f := range matches {
		err := os.Remove(f)
		if logger != nil {
			if err == nil {
				logger("Cleaned up orphaned temp file: %s", f)
			} else {
				logger("Failed to cleanup orphaned file %s: %v", f, err)
			}
		}
	}
}

func (p *Pipeline) log(format string, args ...interface{}) {
	if p.logger != nil {
		p.logger(format, args...)
	}
}

// Triage walks evidencePath and runs matching parsers against found files concurrently.
func (p *Pipeline) Triage(ctx context.Context, evidencePath string, options map[string]interface{}, progressCb func(current, total int)) error {
	p.log("Starting Triage on specific path: %s, Options: %v", evidencePath, options)
	if evidencePath == "" {
		return fmt.Errorf("evidence path required")
	}

	// Identify candidate files
	var candidates []string
	info, err := os.Stat(evidencePath)
	if err != nil {
		p.log("Error stating evidence path: %v", err)
		return err
	}

	if info.IsDir() {
		p.log("Walking directory: %s", evidencePath)
		err = filepath.WalkDir(evidencePath, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				p.log("Walk error %s: %v", path, err)
				return nil
			}
			if d.IsDir() {
				return nil
			}
			candidates = append(candidates, path)
			return nil
		})
		if err != nil {
			return err
		}
	} else {
		candidates = append(candidates, evidencePath)
	}

	p.log("Found %d candidate files", len(candidates))
	return p.runTriage(ctx, candidates, options, progressCb)
}

// TriageLive automatically finds and processes known artifacts from the live system.
func (p *Pipeline) TriageLive(ctx context.Context, components []string, options map[string]interface{}, progressCb func(current, total int)) error {
	p.log("Starting Live Triage detection... Options: %v", options)
	if runtime.GOOS != "windows" {
		p.log("Warning: Live Triage on non-Windows system; paths may not exist.")
	}

	p.log("TriageLive started. Components requested: %v", components)
	// Helper to check if component is enabled
	isEnabled := func(name string) bool {
		// If components slice is nil, we assume ALL are enabled (legacy/default behavior)
		// If components slice is non-nil but empty, it means user selected NOTHING.
		if components == nil {
			return true
		}
		for _, c := range components {
			if strings.EqualFold(c, name) {
				return true
			}
		}
		return false
	}

	var searchPaths []string

	if isEnabled("Prefetch") {
		p.log("  [+] Prefetch component selected")
		searchPaths = append(searchPaths, `C:\Windows\Prefetch`)
	}

	if isEnabled("Registry") {
		p.log("  [+] Registry component selected")
		searchPaths = append(searchPaths,
			`C:\Windows\System32\config\SYSTEM`,
			`C:\Windows\System32\config\SOFTWARE`,
			`C:\Windows\System32\config\SAM`,
			`C:\Windows\System32\config\SECURITY`,
			`C:\Windows\System32\config\Amcache.hve`,
		)

		// User Profiles: NTUSER.DAT
		userProfiles, _ := filepath.Glob(`C:\Users\*\NTUSER.DAT`)
		if len(userProfiles) > 0 {
			p.log("  [+] Found %d NTUSER.DAT hives", len(userProfiles))
			searchPaths = append(searchPaths, userProfiles...)
		}

		// Always try to dump the Current User (HKCU) explicitly
		searchPaths = append(searchPaths, "LIVE_HKCU")
	}

	if isEnabled("Tasks") {
		p.log("  [+] Tasks component selected")
		searchPaths = append(searchPaths, `C:\Windows\System32\Tasks`)
	}

	if isEnabled("EventLogs") {
		p.log("  [+] EventLogs component selected")
		searchPaths = append(searchPaths,
			`C:\Windows\System32\winevt\Logs\Security.evtx`,
			`C:\Windows\System32\winevt\Logs\System.evtx`,
			`C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx`,
			`C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`,
		)
	}

	// ...
	if isEnabled("JumpLists") {
		jumpLists, _ := filepath.Glob(`C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms`)
		if len(jumpLists) > 0 {
			searchPaths = append(searchPaths, jumpLists...)
		}
	}

	// Virtual Artifacts
	if isEnabled("Network") {
		searchPaths = append(searchPaths, "LIVE_NETWORK")
	}
	if isEnabled("WMI") {
		searchPaths = append(searchPaths, "LIVE_WMI")
	}
	if isEnabled("Browser") {
		searchPaths = append(searchPaths, "LIVE_BROWSER")
	}

	var candidates []string
	for _, sp := range searchPaths {
		if sp == "LIVE_HKCU" || sp == "LIVE_NETWORK" || sp == "LIVE_WMI" || sp == "LIVE_BROWSER" {
			candidates = append(candidates, sp)
			continue
		}
		// ...

		p.log("Checking live artifact path: %s", sp)
		info, err := os.Stat(sp)
		if err != nil {
			p.log("  -> Not found or inaccessible: %v", err)
			continue
		}
		if info.IsDir() {
			p.log("  -> Found Directory, walking...")
			countBefore := len(candidates)
			filepath.WalkDir(sp, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				candidates = append(candidates, path)
				return nil
			})
			p.log("  -> Added %d files from %s", len(candidates)-countBefore, sp)
		} else {
			p.log("  -> Found File")
			candidates = append(candidates, sp)
		}
	}

	if len(candidates) == 0 {
		p.log("CRITICAL: No live artifacts found. Check permissions or selection.")
		return fmt.Errorf("no live artifacts found (check permissions or selection)")
	}

	p.log("Total candidates for processing: %d", len(candidates))
	return p.runTriage(ctx, candidates, options, progressCb)
}

func (p *Pipeline) runTriage(ctx context.Context, candidates []string, options map[string]interface{}, progressCb func(current, total int)) error {
	total := len(candidates)
	if progressCb != nil {
		progressCb(0, total)
	}

	// Channels
	// We separate Events stream from logical File result
	responseChan := make(chan *pluginsdk.ParseResponse, total)
	eventsChan := make(chan model.TimelineEvent, 5000) // Buffer for bursty events

	numWorkers := 4
	jobs := make(chan string, total)

	// Stream Writer
	// We need to coordinate writing. Since we have multiple parsers running,
	// checking if writer is ready is needed.
	// Actually, we can start the writer immediately.
	writeErrChan := make(chan error, 1)

	// Global Max Events Limit
	globalMaxEvents := 100000 // Default
	if options != nil {
		if val, ok := options["max_events"]; ok {
			if v, err := strconv.Atoi(fmt.Sprintf("%v", val)); err == nil && v > 0 {
				globalMaxEvents = v
			}
		}
	}
	p.log("Pipeline: Global MaxEvents Limit = %d", globalMaxEvents)

	// Initialize Sigma Engine
	sigmaEng, err := analysis.NewEngineV2(rules.WindowsRules, "sigma_rules_repo/rules/windows")
	if err != nil {
		p.log("Pipeline: Failed to initialize Sigma Engine: %v", err)
	} else {
		p.log("Pipeline: Sigma Engine V2 initialized with %d rules", len(sigmaEng.Rules))
	}

	go func() {
		defer close(writeErrChan)
		defer func() {
			if r := recover(); r != nil {
				p.log("CRITICAL: Panic in Timeline Writer: %v", r)
			}
		}()

		// Create efficient buffered writer for timeline
		writeEvent, closeEvents, err := p.store.NewStreamWriter("timeline.jsonl")
		if err != nil {
			writeErrChan <- err
			// Drain eventsChan to prevent deadlock
			for range eventsChan {
			}
			return
		}
		defer closeEvents()

		// Counters for balanced collection
		writtenCount := 0
		bulkCounts := make(map[string]int) // Track EventLog, Registry, Prefetch separately
		bulkLimit := globalMaxEvents

		for ev := range eventsChan {
			// 1. Identify category for fairness
			cat := "Other"
			if strings.EqualFold(ev.Source, "EventLog") {
				cat = "EventLog"
			} else if strings.EqualFold(ev.Source, "Registry") || strings.EqualFold(ev.Artifact, "Registry") {
				cat = "Registry"
			} else if strings.EqualFold(ev.Artifact, "Prefetch") || strings.EqualFold(ev.Source, "Prefetch") {
				cat = "Prefetch"
			}

			// 2. Apply Limits
			isBulk := (cat == "EventLog" || cat == "Registry" || cat == "Prefetch")
			if isBulk {
				// Global Cap
				if writtenCount >= bulkLimit {
					continue
				}
				// Fairness Cap: One category shouldn't take > 60% of total budget
				// if there are multiple candidates. This prevents EVTX from drowning out Registry/Prefetch.
				if bulkCounts[cat] >= (bulkLimit * 6 / 10) {
					continue
				}
			}

			// Run Sigma Checks (Only for EventLogs and Registry to save time and prevent panics)
			// ...
			// (Keep existing Sigma logic)
			if sigmaEng != nil && (cat == "EventLog" || cat == "Registry") {
				if matched := sigmaEng.Evaluate(ev); matched != nil {
					if ev.Details == nil {
						ev.Details = make(map[string]string)
					}
					// Mark the event
					ev.Details["_Alert"] = matched.Title
					ev.Details["_AlertLevel"] = matched.Level
					ev.Details["_AlertRuleID"] = matched.ID
					ev.Details["_AlertDescription"] = matched.Description
					// Add MITRE ATT&CK tags if available
					if len(matched.Tags) > 0 {
						ev.Details["_Mitre"] = strings.Join(matched.Tags, ", ")
					}
				}
			}

			if err := writeEvent(ev); err != nil {
				p.log("Error writing event: %v", err)
			}
			writtenCount++
			if isBulk {
				bulkCounts[cat]++
			}
			if writtenCount%500 == 0 {
				p.log("Pipeline Progress: Written %d events...", writtenCount)
			}
		}
		p.log("Pipeline: Finalizing. Total events written = %d (limit was %d)", writtenCount, globalMaxEvents)
		writeErrChan <- nil
	}()

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for file := range jobs {
				var resp *pluginsdk.ParseResponse
				var err error
				p.log("[W%d] Processing %s...", workerID, file)
				func() {
					defer func() {
						if r := recover(); r != nil {
							err = fmt.Errorf("PANIC parsing %s: %v", file, r)
							p.log("[W%d] PANIC: %v", workerID, err)
						}
					}()

					// Define stream callback
					streamCb := func(ev model.TimelineEvent) {
						eventsChan <- ev
					}

					resp, err = p.processFile(ctx, file, options, streamCb)
				}()

				if err == nil && resp != nil {
					p.log("[W%d] SUCCESS %s", workerID, file)
					responseChan <- resp
				} else {
					if err != nil {
						p.log("[W%d] ERROR %s: %v", workerID, file, err)
					}
					responseChan <- nil
				}
			}
		}(w)
	}

	// Artifact Saver (Keep legacy logic for Artifacts/Findings which are small)
	doneArtifacts := make(chan struct{})
	go func() {
		var artifactBatch []model.Artifact
		processed := 0

		for resp := range responseChan {
			processed++
			if resp != nil {
				// 1. Handle events that were NOT streamed (legacy/bulk plugins)
				for _, ev := range resp.Events {
					eventsChan <- ev
				}

				// 2. Handle artifacts
				if len(resp.Artifacts) > 0 {
					artifactBatch = append(artifactBatch, resp.Artifacts...)
				}
			}

			if len(artifactBatch) >= 100 {
				if err := p.store.SaveArtifacts(ctx, artifactBatch); err != nil {
					p.log("Artifact save error: %v", err)
				}
				artifactBatch = artifactBatch[:0]
			}

			if progressCb != nil && (processed%5 == 0 || processed == total) {
				progressCb(processed, total)
			}
		}
		if len(artifactBatch) > 0 {
			p.store.SaveArtifacts(ctx, artifactBatch)
		}
		close(doneArtifacts)
	}()

	for _, file := range candidates {
		jobs <- file
	}
	close(jobs)
	wg.Wait()
	close(responseChan)
	close(eventsChan) // Signals writer to finish

	<-doneArtifacts
	if err := <-writeErrChan; err != nil {
		return err
	}

	return nil
}

// processFile handles a single file: identification, parsing.
func (p *Pipeline) processFile(ctx context.Context, file string, options map[string]interface{}, streamCb func(model.TimelineEvent)) (*pluginsdk.ParseResponse, error) {
	var targetFile string
	var tempFile string

	// Pre-processing for Windows Live Artifacts (Registry Dumping)
	if runtime.GOOS == "windows" {
		// Virtual Artifact: Network (Command Based)
		if file == "LIVE_NETWORK" {
			if streamCb != nil {
				// We need to adapt the callback: CollectNetwork expects func(model.TimelineEvent)
				// streamCb is already func(model.TimelineEvent)
				if err := plugin.CollectNetwork(ctx, streamCb); err != nil {
					p.log("Error collecting Network info: %v", err)
				}
			}
			return &pluginsdk.ParseResponse{}, nil
		}
		// Virtual Artifact: WMI (COM Based)
		if file == "LIVE_WMI" {
			if streamCb != nil {
				if err := plugin.CollectWMIPersistence(ctx, streamCb); err != nil {
					p.log("Error collecting WMI persistence: %v", err)
				}
			}
			return &pluginsdk.ParseResponse{}, nil
		}
		// Virtual Artifact: Browser History (SQLite)
		if file == "LIVE_BROWSER" {
			if streamCb != nil {
				if err := plugin.CollectBrowserHistory(ctx, streamCb); err != nil {
					p.log("Error collecting Browser History: %v", err)
				}
			}
			return &pluginsdk.ParseResponse{}, nil
		}

		// Case 1: Special Virtual Artifact for Current User
		if file == "LIVE_HKCU" {
			dumpPath := filepath.Join(os.TempDir(), fmt.Sprintf("gtrace_dump_HKCU_%d.hve", time.Now().UnixNano()))
			if err := performRegSave("HKEY_CURRENT_USER", dumpPath); err != nil {
				p.log("Failed to dump HKCU: %v", err)
				return nil, nil
			}
			// HKCU is essentially an NTUSER.DAT, so we parse it as such
			targetFile = dumpPath
			tempFile = dumpPath
			file = "NTUSER.DAT" // Pretend to be NTUSER.DAT for parser detection
		} else {
			// Case 2: System Hives (SYSTEM, SAM, etc)
			isHive, hiveKey := isSystemHive(file)
			if isHive {
				// Sanitize hive name for filename (HKLM\SYSTEM -> HKLM_SYSTEM)
				safeName := strings.ReplaceAll(hiveKey, "\\", "_")
				dumpPath := filepath.Join(os.TempDir(), fmt.Sprintf("gtrace_dump_%s_%d.hve", safeName, time.Now().UnixNano()))

				if err := performRegSave(hiveKey, dumpPath); err != nil {
					p.log("Failed to dump hive %s: %v", hiveKey, err)
					// Fallback to direct read attempt
					targetFile = file
				} else {
					targetFile = dumpPath
					tempFile = dumpPath
				}
			} else {
				// Case 3: Regular Files (including unlocked NTUSER.DAT, and LOCKED .evtx/.pf)
				ext := strings.ToLower(filepath.Ext(file))
				if ext == ".evtx" || ext == ".pf" || ext == ".dat" {
					// We suspect these might be locked. Try to copy.
					dumpPath := filepath.Join(os.TempDir(), fmt.Sprintf("gtrace_dump_file_%d%s", time.Now().UnixNano(), filepath.Ext(file)))

					// Try copy
					errCopy := copyLockedFile(file, dumpPath)

					// Verify copy success
					validCopy := false
					if errCopy == nil {
						if info, errStat := os.Stat(dumpPath); errStat == nil && info.Size() > 0 {
							validCopy = true
						} else {
							// Copy said ok, but file is missing or empty
							p.log("Copy locked file apparent success but produced empty/missing file: %s (Orig: %s)", dumpPath, file)
						}
					} else {
						// This is expected for locked files sometimes
						p.log("Warning: Failed to copy locked file %s (Reason: %v). Will attempt direct read.", file, errCopy)
					}

					if validCopy {
						targetFile = dumpPath
						tempFile = dumpPath
					} else {
						// Fallback to direct read
						targetFile = file
					}
				} else {
					targetFile = file
				}
			}
		}
	} else {
		targetFile = file
	}

	if tempFile != "" {
		defer os.Remove(tempFile)
	}

	// Read header for magic byte detection
	var header []byte
	f, err := os.Open(targetFile)
	if err == nil {
		buf := make([]byte, 16)
		n, _ := f.Read(buf)
		header = buf[:n]
		f.Close()
	} else {
		// Log open failure?
		// p.log("Failed to open %s: %v", file, err)
		return nil, nil // treat as skip
	}

	parser := p.findParserFor(file, header) // Use original filename for matcher (extension based)
	if parser == nil {
		// p.log("Skipping %s (No parser matched)", filepath.Base(file))
		return nil, nil // Skip unknown files
	}

	// Convert options to string map for Metadata
	meta := make(map[string]string)
	for k, v := range options {
		meta[k] = fmt.Sprintf("%v", v)
	}

	// Wrap callback to fixup source paths if needed
	var wrappedCb func(model.TimelineEvent)
	if streamCb != nil {
		wrappedCb = func(ev model.TimelineEvent) {
			// Always try to fixup Artifact if it looks like a dump file
			if strings.Contains(ev.Artifact, "gtrace_dump_file_") || (tempFile != "" && ev.Artifact == filepath.Base(targetFile)) {
				ev.Artifact = filepath.Base(file)
			}

			if tempFile != "" {
				ev.EvidenceRef.SourcePath = file
				// Fix Source if it's missing or generic
				if ev.Source == "File" || ev.Source == "" {
					ev.Source = inferSource(file)
				}
			}
			streamCb(ev)
		}
	}

	resp, err := parser.Parse(ctx, pluginsdk.ParseRequest{
		EvidencePath:   targetFile,
		Metadata:       meta,
		StreamCallback: wrappedCb,
		ProgressCallback: func(percent int) {
			// We can emit app events here if we have context?
			// But processFile is deep inside.
			// We can log for now, or find a way to emit "triage:progress" fine-grained.
			// Current architecture progressCb handles TOTAL files (1/N).
			// We can emit a specific "parsing_progress" event?
			// Or we just update the log?
			// Let's rely on EventEmit via a new mechanism if possible, but App struct holds the context.
			// Pipeline struct holds a logger.
			// Let's log it for debug first.
			p.log("[PARSER] %s Progress: %d%%", filepath.Base(file), percent)
		},
	})
	if err != nil {
		return nil, err
	}

	// Fixup Artifacts SourcePaths and Artifact names if we used a temp file
	if tempFile != "" && resp != nil {
		for i := range resp.Artifacts {
			resp.Artifacts[i].EvidenceRef.SourcePath = file
		}
		for i := range resp.Events {
			resp.Events[i].EvidenceRef.SourcePath = file
			if strings.Contains(resp.Events[i].Artifact, "gtrace_dump_file_") || (tempFile != "" && resp.Events[i].Artifact == filepath.Base(targetFile)) {
				resp.Events[i].Artifact = filepath.Base(file)
			}
			if resp.Events[i].Source == "File" || resp.Events[i].Source == "" {
				resp.Events[i].Source = inferSource(file)
			}
		}
	}

	return resp, nil
}

func isSystemHive(path string) (bool, string) {
	// Simple check: is it in config folder?
	// C:\Windows\System32\config\SYSTEM
	clean := filepath.Clean(path)
	// Case insensitive check is hard in Go without overhead, assuming standard paths
	// We just check base name
	base := filepath.Base(clean)

	// Map filename to Registry Hive Key Name for "reg save"
	// SYSTEM -> HKLM\SYSTEM
	// SOFTWARE -> HKLM\SOFTWARE
	// SAM -> HKLM\SAM
	// SECURITY -> HKLM\SECURITY
	// Amcache.hve -> This is trickier. It's usually loaded at HKLM\Amcache if live? Or not loaded?
	// Windows 8+ loads Amcache.hve at HKLM\Amcache? No, usually not exposed directly unless we load it.
	// Wait, standard Hives (SYSTEM, SOFTWARE) are loaded.
	// Amcache is loaded by the OS but maybe not visible in RegEdit at root.
	// Actually Amcache is notoriously locked. "reg save" might not work for Amcache if valid key not found.
	// But SYSTEM/SOFTWARE definitely work.

	switch base {
	case "SYSTEM", "system":
		return true, "HKLM\\SYSTEM"
	case "SOFTWARE", "software":
		return true, "HKLM\\SOFTWARE"
	case "SAM", "sam":
		return true, "HKLM\\SAM"
	case "SECURITY", "security":
		return true, "HKLM\\SECURITY"
		// Amcache.hve is usually not mounted at a known HKLM key available for easy "reg save".
		// Velociraptor uses raw NTFS parsing for this reason.
		// However, we can TRY. Sometimes it's not locked if process execution is low?
		// Or we skip Amcache Live for now if "reg save" fails.
	}
	return false, ""
}

func (p *Pipeline) findParserFor(path string, header []byte) pluginsdk.ParserPlugin {
	for _, parser := range p.parsers {
		if parser.CanParse(path, header) {
			return parser
		}
	}
	return nil
}

func inferSource(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToUpper(filepath.Base(path))

	switch {
	case ext == ".evtx":
		return "EventLog"
	case ext == ".pf":
		return "Prefetch"
	case base == "AMCACHE.HVE":
		return "Amcache"
	case base == "SYSTEM" || base == "SOFTWARE" || base == "SAM" || base == "SECURITY" || base == "NTUSER.DAT":
		return "Registry"
	case strings.Contains(path, "Tasks"):
		return "Tasks"
	default:
		return "File"
	}
}

// Analyze applies analyzer plugins on stored timeline and produces findings.
func (p *Pipeline) Analyze(ctx context.Context, analyzers []pluginsdk.AnalyzerPlugin, timeline []model.TimelineEvent, iocs []model.IOCMaterial) error {
	for _, analyzer := range analyzers {
		resp, err := analyzer.Analyze(ctx, pluginsdk.AnalyzeRequest{
			Timeline: timeline,
			IOCs:     iocs,
		})
		if err != nil {
			return fmt.Errorf("analyzer %s: %w", analyzer.Manifest().Name, err)
		}
		if err := p.store.SaveFindings(ctx, resp.Findings); err != nil {
			return err
		}
	}
	return nil
}
