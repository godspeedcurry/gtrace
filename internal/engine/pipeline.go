package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

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
	// Look for files matching lumina_dump_*.hve in TempDir
	pattern := filepath.Join(os.TempDir(), "lumina_dump_*.hve")
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
func (p *Pipeline) Triage(ctx context.Context, evidencePath string, progressCb func(current, total int)) error {
	p.log("Starting Triage on specific path: %s", evidencePath)
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
	return p.runTriage(ctx, candidates, nil, progressCb)
}

// TriageLive automatically finds and processes known artifacts from the live system.
func (p *Pipeline) TriageLive(ctx context.Context, components []string, options map[string]interface{}, progressCb func(current, total int)) error {
	p.log("Starting Live Triage detection... Options: %v", options)
	if runtime.GOOS != "windows" {
		p.log("Warning: Live Triage on non-Windows system; paths may not exist.")
	}

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
		searchPaths = append(searchPaths, `C:\Windows\Prefetch`)
	}

	if isEnabled("Registry") {
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
			searchPaths = append(searchPaths, userProfiles...)
		}

		// Always try to dump the Current User (HKCU) explicitly
		searchPaths = append(searchPaths, "LIVE_HKCU")
	}

	if isEnabled("Tasks") {
		searchPaths = append(searchPaths, `C:\Windows\System32\Tasks`)
	}

	if isEnabled("EventLogs") {
		searchPaths = append(searchPaths,
			`C:\Windows\System32\winevt\Logs\Security.evtx`,
			`C:\Windows\System32\winevt\Logs\System.evtx`,
			`C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx`,
			`C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`,
		)
	}

	if isEnabled("JumpLists") {
		jumpLists, _ := filepath.Glob(`C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms`)
		if len(jumpLists) > 0 {
			searchPaths = append(searchPaths, jumpLists...)
		}
	}

	var candidates []string
	for _, sp := range searchPaths {
		if sp == "LIVE_HKCU" {
			candidates = append(candidates, sp)
			continue
		}

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

	responseChan := make(chan *pluginsdk.ParseResponse, total)
	numWorkers := 4
	jobs := make(chan string, total)

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for file := range jobs {
				var resp *pluginsdk.ParseResponse
				var err error
				func() {
					defer func() {
						if r := recover(); r != nil {
							err = fmt.Errorf("PANIC parsing %s: %v", file, r)
							p.log("[W%d] PANIC: %v", workerID, err)
						}
					}()
					// p.log("[W%d] Processing %s", workerID, file) // Verbose!
					resp, err = p.processFile(ctx, file, options)
				}()

				if err == nil && resp != nil {
					p.log("[W%d] SUCCESS %s (Events: %d)", workerID, file, len(resp.Events))
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

	// Collector / Writer Goroutine
	writeDone := make(chan error)
	go func() {
		defer close(writeDone)
		var eventBatch []model.TimelineEvent
		var artifactBatch []model.Artifact
		processed := 0

		flush := func() error {
			if len(eventBatch) > 0 {
				if err := p.store.SaveTimeline(ctx, eventBatch); err != nil {
					return err
				}
				eventBatch = eventBatch[:0]
			}
			if len(artifactBatch) > 0 {
				if err := p.store.SaveArtifacts(ctx, artifactBatch); err != nil {
					return err
				}
				artifactBatch = artifactBatch[:0]
			}
			return nil
		}

		for resp := range responseChan {
			processed++
			if resp != nil {
				if len(resp.Events) > 0 {
					eventBatch = append(eventBatch, resp.Events...)
				}
				if len(resp.Artifacts) > 0 {
					artifactBatch = append(artifactBatch, resp.Artifacts...)
				}
			}
			// Batch flush condition
			if len(eventBatch) >= 1000 || len(artifactBatch) >= 100 {
				if err := flush(); err != nil {
					p.log("Flush error: %v", err)
				}
			}
			// UI update
			if progressCb != nil && (processed%5 == 0 || processed == total) {
				progressCb(processed, total)
			}
		}
		flush()
	}()

	for _, file := range candidates {
		jobs <- file
	}
	close(jobs)
	wg.Wait()
	close(responseChan)
	<-writeDone
	return nil
}

// processFile handles a single file: identification, parsing.
func (p *Pipeline) processFile(ctx context.Context, file string, options map[string]interface{}) (*pluginsdk.ParseResponse, error) {
	var targetFile string
	var tempFile string

	// Pre-processing for Windows Live Artifacts (Registry Dumping)
	if runtime.GOOS == "windows" {
		// Case 1: Special Virtual Artifact for Current User
		if file == "LIVE_HKCU" {
			dumpPath := filepath.Join(os.TempDir(), fmt.Sprintf("lumina_dump_HKCU_%d.hve", time.Now().UnixNano()))
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
				dumpPath := filepath.Join(os.TempDir(), fmt.Sprintf("lumina_dump_%s_%d.hve", safeName, time.Now().UnixNano()))

				if err := performRegSave(hiveKey, dumpPath); err != nil {
					p.log("Failed to dump hive %s: %v", hiveKey, err)
					// Fallback to direct read attempt
					targetFile = file
				} else {
					targetFile = dumpPath
					tempFile = dumpPath
				}
			} else {
				// Case 3: Regular Files (including unlocked NTUSER.DAT)
				targetFile = file
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
	if options != nil {
		for k, v := range options {
			meta[k] = fmt.Sprintf("%v", v)
		}
	}

	resp, err := parser.Parse(ctx, pluginsdk.ParseRequest{
		EvidencePath: targetFile,
		Metadata:     meta,
	})
	if err != nil {
		return nil, err
	}

	// Fixup Source in events to point into original file if we used a temp file
	if tempFile != "" {
		for i := range resp.Events {
			resp.Events[i].Source = "REGISTRY" // Generic tag or specific?
		}
		// Fix Artifacts
		for i := range resp.Artifacts {
			resp.Artifacts[i].EvidenceRef.SourcePath = file
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
