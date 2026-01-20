# GTrace: Next-Gen DFIR Triage Platform

## Project Status: Active Development
We have successfully transitioned the `gtrace` project into **GTrace**, a Go-based, architecturally sound DFIR triage tool.

### Accomplished
1. **Core Architecture**: implemented a clean architecture with `Engine`, `Plugin`, `Storage` decoupling.
2. **Plugin System**: Refactored `ParserPlugin` to support dynamic content-based detection (`CanParse`).
3. **Storage**: Implemented a JSONL storage backend.
4. **Parsers Implemented**:
    - **[NEW] Prefetch (.pf)**: Native Go parser for Windows 10/11 (Version 30) and Legacy (Version 23). Extracts Run Count, Last Run Time, and Executable Name.
    - **[NEW] WINTri Process List**: Parses `Process_List.csv` from WINTri collection.
    - **LNK Stub**: Basic identification of LNK files.
5. **Tooling**: `tools/generate_mock_data.go` to simulate WINTri exports for testing.
6. **GUI**: Wails-based frontend (Svelte) available in `gtrace-gui.app`.

## Roadmap & Next Steps

### Phase 1.2: Registry Artifacts (ShimCache/Amcache)
> [!NOTE]
> ShimCache and Amcache reside inside Registry Hives (`SYSTEM`, `Amcache.hve`). Parsing them requires a dedicated Registry Hive parser (e.g., `registry` package).

- [x] Integrate a Registry Hive parser (`www.velocidex.com/golang/regparser`).
- [x] Implement `ShimCacheParser`: Open `SYSTEM` hive -> Navigate to `ControlSet001\Control\Session Manager\AppCompatCache` -> Parse binary blob.
- [x] Implement `AmcacheParser`: Open `Amcache.hve` -> Traverse `Root\File` keys.

### Phase 2: GUI Enhancements
- [x] Add "Findings" Dashboard (High/Medium/Low alerts).
- [x] Add Timeline Filtering (Filter by Source: "Prefetch" vs "Process").
- [x] **[NEW] Advanced SQL Query Engine**: In-memory SQLite interface for "invincible" data exploration.
- [x] **[NEW] Timeline UI Redesign**: Modern, compact toolbars and dynamic filter controls.

### Phase 3: Analysis Logic
- [x] **Execution Anomaly**: Correlate "Process Execution" with "Prefetch" existence. (Did a process run without a prefetch entry? - Anti-Forensics?)

### Phase 4: NTFS Artifacts (Planned)
- [ ] Integrate MFT Parser (`www.velocidex.com/golang/go-ntfs`).
- [ ] Integrate USN Journal Parser.
