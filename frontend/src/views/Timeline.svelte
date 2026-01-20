<script>
    import { timeline, selectedEvent } from '../stores.js';
    import { onMount, onDestroy } from 'svelte';
    import { GetTotalEventCount, SearchEvents, GetEventStats, ExecuteSQLQuery } from '../../wailsjs/go/app/App.js';
    import CodeMirror from "svelte-codemirror-editor";
    import { sql, SQLite } from "@codemirror/lang-sql";
    import { oneDark } from "@codemirror/theme-one-dark";

    let searchTerm = "";
    let filterSource = "all";
    let filterLevel = "all";
    let sqlMode = false;
    let sqlQuery = "SELECT * FROM timeline LIMIT 100";
    let sqlResults = [];
    let sqlColumns = [];
    let totalStorageCount = 0;
    let sourceStats = {};
    let levelStats = {};
    
    // Pagination
    let currentPage = 1;
    let pageSize = 100;
    let hasNextPage = true;
    let sortField = "event_time";
    let sortDirection = "desc";

    let lastError = "";

    // SQL Schema for Autocomplete
    const sqlConfig = sql({
        dialect: SQLite,
        schema: {
            "timeline": [
                { label: "id", detail: "INT" },
                { label: "event_time", detail: "TIME" },
                { label: "source", detail: "TEXT" },
                { label: "artifact", detail: "TEXT" },
                { label: "action", detail: "TEXT" },
                { label: "subject", detail: "TEXT" },
                { label: "details_json", detail: "JSON" },
                { label: "details", detail: "TEXT" }
            ]
        },
        upperCaseKeywords: true
    });

    async function loadData() {
        try {
            lastError = "";
            totalStorageCount = await GetTotalEventCount();
            const stats = await GetEventStats();
            sourceStats = stats.sources || {};
            levelStats = stats.levels || {};
            await fetchPage();
        } catch(e) {
            console.error("Load Error:", e);
            lastError = "Failed to load data: " + e;
        }
    }

    onMount(async () => {
        loadData();
    });
    
    async function fetchPage() {
        try {
            lastError = "";
            if (sqlMode) {
                const results = await ExecuteSQLQuery(sqlQuery);
                sqlResults = results || [];
                if (sqlResults.length > 0) {
                    sqlColumns = Object.keys(sqlResults[0]);
                } else {
                    sqlColumns = [];
                }
                $timeline = []; // Clear normal timeline
                hasNextPage = false;
            } else {
                const events = await SearchEvents(searchTerm, currentPage, pageSize, filterSource, filterLevel);
                $timeline = events || [];
                hasNextPage = ($timeline.length === pageSize);
                sqlResults = [];
            }
        } catch (e) {
            console.error("Search Error:", e);
            lastError = e;
            $timeline = [];
            sqlResults = [];
        }
    }
    
    // Reactivity
    // Debounce search? For now simple reactive
    let timeout;
    function debounceLoad() {
        clearTimeout(timeout);
        timeout = setTimeout(() => {
            currentPage = 1; // Reset to page 1 on filter change
            fetchPage();
        }, 300);
    }
    
    $: if (searchTerm !== undefined) debounceLoad();
    $: if (filterSource) { currentPage = 1; fetchPage(); }
    $: if (filterLevel) { currentPage = 1; fetchPage(); }
    $: if (pageSize) { currentPage = 1; fetchPage(); }
    
    // Note: sorting is now implicit (Time Desc) from backend. 
    // Client side sort of the PAGE is still possible if desired, but let's keep it simple.
    // If user clicks sort headers, we could re-sort the current page?
    // Or ask backend? Backend only supports Time Desc (Loki mode).
    // Let's effectively disable sorting for now or only sort the view page.
    
    function toggleSort(field) {
        // Only sort the current page in memory
        sortField = field;
        sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
        $timeline = $timeline.sort((a, b) => {
             let valA = a[field] || "";
             let valB = b[field] || "";
             if (field === 'event_time') {
                 // Date comparison
                 return sortDirection === 'asc' ? 
                    new Date(valA) - new Date(valB) :
                    new Date(valB) - new Date(valA);
             }
             if (valA < valB) return sortDirection === 'asc' ? -1 : 1;
             if (valA > valB) return sortDirection === 'asc' ? 1 : -1;
             return 0;
        });
    }

    onMount(loadData);

    // --- SMART SCHEMA DEFINITIONS ---
    const eventSchemas = {
        '4688': [{ k: '_CommandLine', label: 'Cmd' }, { k: '_ParentProcess', label: 'Parent' }],
        '4624': [{ k: 'LogonType', label: 'Type' }, { k: 'IpAddress', label: 'IP' }],
        '4625': [{ k: 'LogonType', label: 'Type' }, { k: 'FailureReason' }],
        '4648': [{ k: 'TargetServerName', label: 'Target' }],
        '4672': [{ k: 'PrivilegeList', label: 'Privs' }],
        '4720': [{ k: 'AccountName', label: 'User' }],
        '4728': [{ k: 'MemberName', label: 'Member' }, { k: 'TargetUserName', label: 'Group' }],
        '7045': [{ k: 'ServiceName', label: 'Svc' }, { k: 'ImagePath', label: 'Img' }],
        '7036': [{ k: 'param1', label: 'Svc' }, { k: 'param2', label: 'State' }],
        '1': [{ k: 'Image', label: 'Proc' }, { k: 'CommandLine', label: 'Cmd' }],
        '3': [{ k: 'Image', label: 'Proc' }, { k: 'DestinationIp', label: 'DstIP' }],
        // Virtual / Scraped
        'Browser': [{ k: 'URL' }, { k: 'Title' }],
        'Network': [{ k: 'LocalIP', label: 'Local' }, { k: 'RemoteIP', label: 'Remote' }, { k: 'Protocol', label: 'Proto' }],
        'WMI': [{ k: 'Name' }, { k: 'Query' }, { k: 'CommandLine', label: 'Cmd' }, { k: 'Filter' }, { k: 'Consumer' }]
    };

    function getDisplayFields(event) {
        if (!event.details) return [];
        let fields = [];
        const eid = event.details.EventID;
        const source = event.source;
        
        // Priority 1: Use schema if defined (either by EID or by Source)
        const schema = eventSchemas[eid] || eventSchemas[source];
        if (schema) {
            if (event.details.Category) fields.push({ k: 'Cat', v: event.details.Category });
            schema.forEach(def => {
                const val = event.details[def.k];
                if (val && val !== '-') {
                    // Truncate long values
                    const displayVal = (val + '').length > 80 ? (val + '').substring(0, 77) + '...' : val;
                    fields.push({ k: def.label || def.k, v: displayVal });
                }
            });
        } 
        // Priority 2: Registry events (manual fallback)
        else if (event.source === 'Registry') {
            if (event.details.Path) fields.push({ k: 'Path', v: event.details.Path });
            if (event.details.ValueName) fields.push({ k: 'Val', v: event.details.ValueName });
        }
        
        // Priority 3: Show _ prefixed fields (our special fields)
        if (fields.length === 0) {
            Object.entries(event.details).forEach(([k, v]) => {
                if (k.startsWith('_') && k !== '_Alert' && v && v !== '-') {
                    const displayVal = (v + '').length > 80 ? (v + '').substring(0, 77) + '...' : v;
                    fields.push({ k: k.substring(1), v: displayVal });
                }
            });
        }
        
        // Priority 4: Fallback to first few fields
        if (fields.length === 0) {
            Object.entries(event.details).slice(0, 3).forEach(([k, v]) => {
                if (k !== '_Alert' && k !== 'EventID' && (v + '').length < 60) fields.push({ k: k, v: v });
            });
        }
        return fields;
    }
    
    $: sourcesList = Array.from(new Set([
        'EventLog', 'Registry', 'Prefetch', 'Tasks', 'LNK', 'JumpLists', 'Amcache', 'Browser', 'Network', 'WMI',
        ...Object.keys(sourceStats)
    ]))
    .filter(s => sourceStats[s] > 0)
    .sort();

    // Column Resizing Logic
    let columnWidths = { time: 180, source: 140, eid: 80, action: 250, subject: 250 };
    let resizingCol = null;
    let startX = 0; let startWidth = 0;
    function startResize(e, col) { resizingCol = col; startX = e.clientX; startWidth = columnWidths[col]; window.addEventListener('mousemove', doResize); window.addEventListener('mouseup', stopResize); e.target.classList.add('active'); }
    function doResize(e) { if (!resizingCol) return; const diff = e.clientX - startX; columnWidths[resizingCol] = Math.max(50, startWidth + diff); }
    function stopResize() { resizingCol = null; window.removeEventListener('mousemove', doResize); window.removeEventListener('mouseup', stopResize); document.querySelectorAll('.resizer').forEach(el => el.classList.remove('active')); }
    onDestroy(() => { window.removeEventListener('mousemove', doResize); window.removeEventListener('mouseup', stopResize); });

    function nextPage() { currentPage++; fetchPage(); }
    function prevPage() { if (currentPage > 1) currentPage--; fetchPage(); }
    // function setPage(p) - removed as we don't know total pages
</script>

<div class="view-container">
    <div class="toolbar-glass">
        <div class="search-section" class:sql-props={sqlMode}>
            <div class="input-wrapper">
                <div class="icon-zone">
                    {#if sqlMode}
                        <span class="sql-badge">SQL</span>
                    {:else}
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                    {/if}
                </div>
                
                {#if sqlMode}
                    <div class="sql-editor-wrapper">
                        <CodeMirror 
                            bind:value={sqlQuery} 
                            lang={sqlConfig}
                            theme={oneDark}
                            styles={{
                                "&": { background: "transparent !important", height: "100%" },
                                ".cm-scroller": { fontFamily: "'JetBrains Mono', monospace", fontSize: "0.85rem", lineHeight: "1.5" },
                                ".cm-content": { caretColor: "#38bdf8" },
                                ".cm-gutters": { display: "none" },
                                ".cm-tooltip-autocomplete": {
                                    backgroundColor: "#1e293b !important",
                                    border: "1px solid #38bdf8 !important",
                                    borderRadius: "6px !important",
                                    boxShadow: "0 4px 12px rgba(0,0,0,0.5) !important",
                                    fontFamily: "'JetBrains Mono', monospace",
                                    zIndex: "1000 !important"
                                },
                                ".cm-tooltip-autocomplete > ul > li": {
                                    padding: "4px 8px !important",
                                    color: "#94a3b8 !important"
                                },
                                ".cm-tooltip-autocomplete > ul > li[aria-selected]": {
                                    backgroundColor: "rgba(56, 189, 248, 0.2) !important",
                                    color: "#f1f5f9 !important",
                                    borderLeft: "2px solid #38bdf8"
                                },
                                ".cm-completionLabel": {
                                    fontWeight: "bold"
                                }
                            }}
                            on:keydown={(e) => { 
                                if(e.detail.key === 'Enter' && !e.detail.shiftKey) { 
                                    e.preventDefault(); 
                                    fetchPage(); 
                                }
                            }}
                        />
                    </div>
                {:else}
                    <input class="text-input" bind:value={searchTerm} placeholder="Search events..." on:keydown={(e) => e.key === 'Enter' && fetchPage()} />
                {/if}

                <div class="actions-zone">
                     <button class="mode-switch" class:active={sqlMode} on:click={() => { sqlMode = !sqlMode; fetchPage(); }} title="Toggle Search Mode">
                        {sqlMode ? 'Standard Search' : 'Switch to SQL'}
                    </button>
                    {#if sqlMode}
                         <button class="run-btn" on:click={fetchPage}>RUN</button>
                    {/if}
                </div>
            </div>
        </div>
        
        <div class="filter-controls">
            <!-- Source Filter -->
            <div class="compact-select">
                <span class="label">SOURCE</span>
                <select bind:value={filterSource}>
                    <option value="all">ALL</option>
                    {#each sourcesList as source}
                        <option value={source}>
                            {source.toUpperCase()} {sourceStats[source] ? `(${sourceStats[source].toLocaleString()})` : ''}
                        </option>
                    {/each}
                </select>
                <div class="chevron">▾</div>
            </div>

            <!-- Level Filter -->
            <div class="compact-select">
                <span class="label">LEVEL</span>
                <div class="level-indicator {filterLevel}"></div>
                <select bind:value={filterLevel}>
                    <option value="all">ALL</option>
                    {#each ['critical', 'high', 'medium', 'low'] as lv}
                        {#if levelStats[lv] > 0}
                            <option value={lv}>
                                {lv.toUpperCase()} ({levelStats[lv].toLocaleString()})
                            </option>
                        {/if}
                    {/each}
                </select>
                <div class="chevron">▾</div>
            </div>

            <button class="refresh-btn" on:click={loadData} title="Refresh Live Data">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 4v6h-6"></path><path d="M1 20v-6h6"></path><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>
            </button>
        </div>

        <div class="stats-pills">
            <div class="stat-pill">
                <span class="label">PAGE</span>
                <span class="val">{currentPage}</span>
            </div>
            <div class="stat-pill highlight">
                <span class="label">TOTAL</span>
                <span class="val">{totalStorageCount}</span>
            </div>
        </div>
    </div>
    
    {#if lastError && lastError.includes('case not open')}
        <div class="empty-state" style="flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; color: #64748b; gap: 16px;">
            <div style="font-size: 3rem; opacity: 0.5;">📋</div>
            <div style="font-size: 1.1rem; font-weight: 500; color: #94a3b8;">Ready to Analyze</div>
            <div style="max-width: 400px; text-align: center; line-height: 1.5;">
                No case is currently active. Go to the <strong>Dashboard</strong> to start a new Live Triage or load an offline case.
            </div>
            <a href="#/dashboard" style="color: #38bdf8; text-decoration: none; border: 1px solid #38bdf8; padding: 8px 16px; border-radius: 6px; font-size: 0.9rem; margin-top: 8px;">Go to Dashboard</a>
        </div>
    {:else if lastError}
        <div class="error-banner" style="background: #451a1a; color: #fca5a5; padding: 12px 24px; font-size: 0.9rem; border-bottom: 1px solid #7f1d1d; display: flex; align-items: center; gap: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
            <span>{lastError}</span>
        </div>
    {/if}
    
    <div class="table-frame">
        {#if sqlMode && sqlResults.length > 0}
            <div class="table-scroll-container">
                <table class="timeline-table sql-table">
                    <thead>
                        <tr>
                            {#each sqlColumns as col}
                                <th>{col.toUpperCase()}</th>
                            {/each}
                        </tr>
                    </thead>
                    <tbody>
                        {#each sqlResults as row}
                            <tr>
                                {#each sqlColumns as col}
                                    <td class="sql-cell" title={row[col]}>
                                        {row[col]}
                                    </td>
                                {/each}
                            </tr>
                        {/each}
                    </tbody>
                </table>
            </div>
        {:else if $timeline.length > 0}
            <table class="timeline-table" id="timeline-main-table">
                <thead>
                    <tr>
                        <th style="width: {columnWidths.time}px" on:click={() => toggleSort('event_time')}>
                            Time {sortField === 'event_time' ? (sortDirection === 'asc' ? '↑' : '↓') : ''}
                            <div class="resizer" on:mousedown|preventDefault|stopPropagation={(e) => startResize(e, 'time')}></div>
                        </th>
                        <th style="width: {columnWidths.source}px" on:click={() => toggleSort('source')}>
                            Source {sortField === 'source' ? (sortDirection === 'asc' ? '↑' : '↓') : ''}
                            <div class="resizer" on:mousedown|preventDefault|stopPropagation={(e) => startResize(e, 'source')}></div>
                        </th>
                        <th style="width: {columnWidths.eid}px" on:click={() => toggleSort('eid')}>
                            ID {sortField === 'eid' ? (sortDirection === 'asc' ? '↑' : '↓') : ''}
                            <div class="resizer" on:mousedown|preventDefault|stopPropagation={(e) => startResize(e, 'eid')}></div>
                        </th>
                        <th style="width: {columnWidths.action}px" on:click={() => toggleSort('action')}>
                            Action {sortField === 'action' ? (sortDirection === 'asc' ? '↑' : '↓') : ''}
                            <div class="resizer" on:mousedown|preventDefault|stopPropagation={(e) => startResize(e, 'action')}></div>
                        </th>
                        <th style="width: {columnWidths.subject}px" on:click={() => toggleSort('subject')}>
                            Subject {sortField === 'subject' ? (sortDirection === 'asc' ? '↑' : '↓') : ''}
                            <div class="resizer" on:mousedown|preventDefault|stopPropagation={(e) => startResize(e, 'subject')}></div>
                        </th>
                        <th>Details snippet</th>
                    </tr>
                </thead>
                <tbody>
                    {#each $timeline as event}
                        <tr 
                            class:alert-critical={event.details && event.details._AlertLevel === 'critical'}
                            class:alert-high={event.details && event.details._AlertLevel === 'high'}
                            class:alert-medium={event.details && event.details._AlertLevel === 'medium'}
                            class:alert-low={event.details && event.details._AlertLevel === 'low'}
                            on:click={() => $selectedEvent = event}
                        >
                            <td class="mono time">{new Date(event.event_time).toLocaleString()}</td>
                            <td>
                                <div class="source-container">
                                    <span class="tag {event.source.toLowerCase().replace(/ /g, '')}">{event.source}</span>
                                    {#if event.artifact && event.artifact !== event.source}
                                        <span class="artifact-name" title={event.evidence_ref?.source_path}>{event.artifact}</span>
                                    {/if}
                                </div>
                            </td>
                            <td class="action-cell">
                                {#if event.details && event.details.EventID}
                                    <span class="eid-badge">{event.details.EventID}</span>
                                {/if}
                            </td>
                            <td class="action-cell">
                                <div class="action-wrapper">
                                    <span class="action-text">{event.action}</span>
                                    {#if event.details && event.details._Alert}
                                        <div class="alert-premium {event.details._AlertLevel || 'medium'}">
                                            <div class="glow"></div>
                                            <span class="icon">󱐋</span>
                                            <span class="text">{event.details._Alert}</span>
                                        </div>
                                    {/if}
                                </div>
                            </td>

                            <td class="subject" title={event.subject}>{event.subject || ''}</td>
                            <td class="details-preview">
                                <div class="pills">
                                    {#if event.details && typeof event.details === 'object'}
                                        {#each getDisplayFields(event) as field}
                                              <div class="pill">
                                                <span class="k">{field.k}</span>
                                                <span class="v" title={field.v}>{field.v}</span>
                                            </div>
                                        {/each}
                                    {/if}
                                </div>
                            </td>
                        </tr>
                    {/each}
                </tbody>
            </table>
        {:else}
            <div class="empty-state-table">
                <div style="font-size: 2rem; margin-bottom: 12px; opacity: 0.5;">🔍</div>
                <div>No events matched your search.</div>
            </div>
        {/if}
    </div>

    <div class="footer">
        <div class="page-info">
            Showing Page {currentPage}
            {#if totalStorageCount > 0} 
                (Total Storage: {totalStorageCount})
            {/if}
        </div>
        <div class="pagination-controls">
            <button on:click={prevPage} disabled={currentPage === 1}>‹ Prev</button>
            <span class="page-current">Page {currentPage}</span>
            <button on:click={nextPage} disabled={!hasNextPage}>Next ›</button>
            
            <select bind:value={pageSize} class="size-selector">
                <option value={50}>50 / page</option>
                <option value={100}>100 / page</option>
                <option value={500}>500 / page</option>
                <option value={1000}>1000 / page</option>
            </select>
        </div>
    </div>
</div>

<style>
    .view-container {
        display: flex;
        flex-direction: column;
        height: 100%;
        overflow: hidden;
    }

    .toolbar-glass {
        padding: 12px 24px;
        background: rgba(11, 14, 20, 0.8);
        backdrop-filter: blur(12px);
        border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        display: flex;
        gap: 20px;
        align-items: center;
        position: sticky;
        top: 0;
        z-index: 100;
    }

    .search-section {
        flex: 1;
        max-width: 600px;
        transition: all 0.3s;
    }
    .search-section.sql-props {
        max-width: 800px;
    }

    .input-wrapper {
        display: flex;
        align-items: center;
        background: rgba(30, 41, 59, 0.5);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        padding: 4px;
        transition: all 0.3s;
        box-shadow: inset 0 1px 3px rgba(0,0,0,0.2);
    }
    .input-wrapper:focus-within {
        background: rgba(30, 41, 59, 0.8);
        border-color: #38bdf8;
        box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.15);
    }

    .icon-zone {
        padding: 0 12px;
        display: flex;
        align-items: center;
        justify-content: center;
        color: #38bdf8;
    }

    .sql-badge {
        font-family: 'JetBrains Mono', monospace;
        font-weight: 800;
        font-size: 0.7rem;
        background: #38bdf8;
        color: #0f172a;
        padding: 2px 6px;
        border-radius: 4px;
    }

    /* CodeMirror Overrides */
    .sql-editor-wrapper {
        flex: 1;
        overflow: visible !important; /* Critical for autocomplete to be seen */
        border-radius: 6px;
        min-height: 38px;
        display: flex;
        align-items: center;
        position: relative; /* Anchor for tooltips */
    }
    :global(.cm-editor) {
        outline: none !important;
        overflow: visible !important;
    }
    :global(.cm-scroller) {
        overflow: visible !important;
    }
    :global(.cm-focused) {
        outline: none !important;
    }

    /* Standard Inputs */
    .text-input {
        flex: 1;
        background: transparent;
        border: none;
        padding: 8px 0;
        color: #f1f5f9;
        font-size: 0.9rem;
        outline: none;
        min-width: 0;
    }
    .sql-input {
        font-family: 'JetBrains Mono', monospace;
        color: #7dd3fc;
    }

    .actions-zone {
        display: flex;
        align-items: center;
        gap: 8px;
        padding-right: 4px;
    }

    .mode-switch {
        background: transparent;
        border: none;
        color: #64748b;
        font-size: 0.75rem;
        font-weight: 600;
        cursor: pointer;
        padding: 6px 12px;
        border-radius: 8px;
        transition: all 0.2s;
        white-space: nowrap;
    }
    .mode-switch:hover {
        background: rgba(255,255,255,0.05);
        color: #94a3b8;
    }
    .mode-switch.active {
        color: #38bdf8;
    }

    .run-btn {
        background: #38bdf8;
        color: #0f172a;
        border: none;
        font-weight: 800;
        font-size: 0.7rem;
        padding: 6px 12px;
        border-radius: 6px;
        cursor: pointer;
        transition: all 0.2s;
    }
    .run-btn:hover {
        background: #0ea5e9;
        transform: translateY(-1px);
    }

    /* Legacy cleanups */
    .search-box, .search-box svg, .search-box input, .sql-prefix, .mode-toggle {
        display: none; 
    }

    .filter-controls {
        display: flex;
        align-items: center;
        gap: 12px;
    }

    .pill-group {
        display: flex;
        background: rgba(30, 41, 59, 0.5);
        padding: 3px;
        border-radius: 24px;
        border: 1px solid rgba(255, 255, 255, 0.08);
        align-items: center;
    }

    .pill-group button {
        background: transparent;
        border: none;
        color: #94a3b8;
        padding: 5px 14px;
        border-radius: 20px;
        font-size: 0.75rem;
        cursor: pointer;
        font-weight: 600;
        transition: all 0.2s;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    .pill-group button.active {
        background: #38bdf8;
        color: #0b0e14;
        box-shadow: 0 2px 8px rgba(56, 189, 248, 0.4);
    }

    .custom-select-wrapper, .level-select-wrapper {
        position: relative;
        display: flex;
        align-items: center;
    }

    .custom-select-wrapper select, .level-select-wrapper select {
        appearance: none;
        background: transparent;
        border: none;
        padding: 5px 24px 5px 12px;
        color: #cbd5e1;
        font-size: 0.75rem;
        font-weight: 600;
        cursor: pointer;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        outline: none;
    }

    .custom-select-wrapper::after, .level-select-wrapper::after {
        content: '▾';
        position: absolute;
        right: 8px;
        color: #64748b;
        pointer-events: none;
        font-size: 0.7rem;
    }

    .level-select-wrapper {
        padding-left: 10px;
    }

    .compact-select {
        position: relative;
        display: flex;
        align-items: center;
        background: rgba(30, 41, 59, 0.5);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 8px;
        padding: 0 8px;
        height: 36px;
        min-width: 140px;
    }
    .compact-select:hover {
        background: rgba(30, 41, 59, 0.8);
        border-color: rgba(255, 255, 255, 0.2);
    }
    .compact-select .label {
        font-size: 0.65rem;
        color: #64748b;
        font-weight: 700;
        margin-right: 6px;
        letter-spacing: 0.05em;
    }
    .compact-select select {
        appearance: none;
        background: transparent;
        border: none;
        color: #e2e8f0;
        font-size: 0.8rem;
        font-weight: 600;
        cursor: pointer;
        padding-right: 16px;
        outline: none;
        flex: 1;
    }
    .compact-select .chevron {
        pointer-events: none;
        font-size: 0.7rem;
        color: #64748b;
        margin-left: 4px;
    }

    .level-indicator {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        margin-right: 6px;
        background: #64748b;
    }
    .level-indicator.critical { background: #ef4444; box-shadow: 0 0 6px #ef4444; }
    .level-indicator.high { background: #f97316; box-shadow: 0 0 6px #f97316; }
    .level-indicator.medium { background: #eab308; box-shadow: 0 0 6px #eab308; }
    .level-indicator.low { background: #3b82f6; box-shadow: 0 0 6px #3b82f6; }

    /* Clean up old selectors */
    .pill-group, .custom-select-wrapper, .level-select-wrapper, .level-dot {
        display: none;
    }
    
    .refresh-btn {
        background: rgba(30, 41, 59, 0.5);
        border: 1px solid rgba(255, 255, 255, 0.08);
        color: #38bdf8;
        width: 34px;
        height: 34px;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 50%;
        cursor: pointer;
        transition: all 0.3s;
    }
    .refresh-btn:hover {
        background: #38bdf8;
        color: #0b0e14;
        transform: rotate(180deg);
        box-shadow: 0 0 12px rgba(56, 189, 248, 0.3);
    }

    .stats-pills {
        margin-left: auto;
        display: flex;
        gap: 8px;
    }

    .stat-pill {
        display: flex;
        align-items: center;
        gap: 8px;
        background: rgba(15, 23, 42, 0.6);
        padding: 4px 12px;
        border-radius: 16px;
        border: 1px solid rgba(255,255,255,0.03);
    }
    .stat-pill .label { font-size: 0.6rem; font-weight: 800; color: #64748b; }
    .stat-pill .val { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: #38bdf8; }
    .stat-pill.highlight { border-color: rgba(56, 189, 248, 0.2); background: rgba(56, 189, 248, 0.05); }

    .table-frame {
        /* Flexbox magic to ensure scrollbars stay within the view */
        flex-grow: 1;
        height: 0; 
        min-height: 0;
        overflow: auto; /* Handles both X and Y */
        background: #0f172a;
        position: relative;
        width: 100%;
    }

    table {
        width: max-content; /* Allow table to grow as wide as needs to be */
        min-width: 100%;
        border-collapse: collapse;
        font-size: 0.9rem;
        table-layout: auto; /* Allow columns to adapt to content */
    }

    th {
        position: sticky !important;
        top: 0;
        background: #0f172a; /* Darker header background matching app */
        color: #94a3b8;
        font-weight: 600;
        text-align: left;
        padding: 10px 16px;
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        z-index: 20; /* Higher z-index to stay above content */
        border-bottom: 1px solid #334155;
        border-right: 1px solid #334155; /* Visible separator */
        user-select: text;
    }
    th:last-child { border-right: none; }

    td {
        padding: 8px 16px;
        border-bottom: 1px solid #1e293b;
        border-right: 1px solid #1e293b; /* Visible separator */
        color: #cbd5e1;
        vertical-align: middle;
        white-space: nowrap; /* Prevent wrapping */
        text-align: left; /* Force left alignment */
        /* Removed overflow hidden/ellipsis to allow full text viewing via scroll */
        user-select: text;
    }
    td:last-child { border-right: none; }

    tr { cursor: pointer; transition: background 0.1s; }
    tr:hover { background: rgba(56, 189, 248, 0.05); }

    .mono { font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: #94a3b8; }
    
    .subject {
        max-width: 250px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.85rem;
        color: #e2e8f0;
    }

    .empty-message { text-align: center; padding: 40px; color: #64748b; }

    /* Cyber Tag Styles */
    .tag { 
        padding: 2px 10px; 
        border-radius: 100px; 
        font-size: 0.65rem; 
        font-weight: 700; 
        text-transform: uppercase; 
        letter-spacing: 0.08em; 
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: rgba(148, 163, 184, 0.05);
        color: #94a3b8;
        border: 1px solid rgba(148, 163, 184, 0.1);
    }
    .tag::before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: currentColor; box-shadow: 0 0 6px currentColor; }
    
    .tag.eventlog { color: #818cf8; border-color: rgba(129, 140, 248, 0.2); background: rgba(129, 140, 248, 0.05); }
    .tag.registry { color: #fbbf24; border-color: rgba(251, 191, 36, 0.2); background: rgba(251, 191, 36, 0.05); }
    .tag.prefetch { color: #38bdf8; border-color: rgba(56, 189, 248, 0.2); background: rgba(56, 189, 248, 0.05); }
    .tag.network  { color: #34d399; border-color: rgba(52, 211, 153, 0.2); background: rgba(52, 211, 153, 0.05); }
    .tag.wmi      { color: #a78bfa; border-color: rgba(167, 139, 250, 0.2); background: rgba(167, 139, 250, 0.05); }
    .tag.browser  { color: #f472b6; border-color: rgba(244, 114, 182, 0.2); background: rgba(244, 114, 182, 0.05); }

    .action-wrapper { display: flex; align-items: center; gap: 4px; }

    .alert-premium {
        position: relative;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 2px 10px;
        border-radius: 4px;
        font-size: 0.7rem;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0.03em;
        overflow: hidden;
    }
    
    .alert-premium.critical { color: #ff0000; background: rgba(255, 0, 0, 0.1); border: 1px solid rgba(255, 0, 0, 0.3); }
    .alert-premium.high     { color: #ff8800; background: rgba(255, 136, 0, 0.1); border: 1px solid rgba(255, 136, 0, 0.3); }
    .alert-premium.medium   { color: #ffcc00; background: rgba(255, 204, 0, 0.1); border: 1px solid rgba(255, 204, 0, 0.3); }
    .alert-premium.low      { color: #00ccff; background: rgba(0, 204, 255, 0.1); border: 1px solid rgba(0, 204, 255, 0.3); }

    .alert-premium .glow {
        position: absolute;
        width: 150%; height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
        left: -150%;
        animation: alert-sweep 3s infinite;
    }

    @keyframes alert-sweep {
        0% { left: -150%; }
        100% { left: 150%; }
    }

    .pills { display: flex; gap: 8px; overflow: hidden; height: 1.8em; align-items: center; }
    .pill { 
        background: rgba(30, 41, 59, 0.4); 
        padding: 3px 10px; 
        border-radius: 4px; 
        font-size: 0.72rem; 
        color: #e2e8f0; 
        border: 1px solid rgba(255, 255, 255, 0.05); 
        white-space: nowrap; 
        font-family: 'JetBrains Mono', monospace; 
        transition: all 0.2s;
    }
    .pill:hover { border-color: rgba(56, 189, 248, 0.4); background: rgba(30, 41, 59, 0.8); }
    .pill .k { color: #64748b; margin-right: 6px; font-weight: 500; font-size: 0.65rem; }

    /* Alert Row Refinement */
    tr { border-left: 2px solid transparent; }
    tr:hover { background: rgba(255, 255, 255, 0.02); }

    .alert-critical { background: rgba(220, 38, 38, 0.05) !important; border-left-color: #dc2626; }
    .alert-high     { background: rgba(234, 88, 12, 0.05) !important; border-left-color: #ea580c; }
    .alert-medium   { background: rgba(202, 138, 4, 0.05) !important; border-left-color: #ca8a04; }
    .alert-low      { background: rgba(37, 99, 235, 0.05) !important; border-left-color: #2563eb; }

    
    .alert-badge { 
        display: inline-block; margin-left: 8px; background: #ef4444; color: white; 
        font-size: 0.6rem; padding: 1px 4px; border-radius: 3px; font-weight: 700; vertical-align: middle;
    }

    th { position: relative; } /* Ensure resizer positioning works */
    
    .resizer {
        position: absolute;
        top: 0;
        right: 0;
        width: 4px;
        height: 100%;
        cursor: col-resize;
        background: transparent;
        transition: background 0.2s;
        z-index: 20;
    }
    .resizer:hover, .resizer.active {
        background: #38bdf8;
    }
    .source-container { display: flex; flex-direction: column; gap: 2px; align-items: flex-start; }
    .artifact-name { font-size: 0.7rem; color: #64748b; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 100%; }
    .eid-badge {
        display: inline-block;
        background: #1e293b;
        color: #94a3b8;
        border: 1px solid #334155;
        border-radius: 4px;
        padding: 2px 6px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.75rem;
        margin-right: 8px;
        min-width: 36px;
        text-align: center;
    }
    .action-text { color: #e2e8f0; font-weight: 500; }

    .footer {
        padding: 12px 24px;
        background: #0b0e14;
        border-top: 1px solid #1e293b;
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-shrink: 0;
    }
    .page-info { color: #64748b; font-size: 0.85rem; font-family: 'JetBrains Mono', monospace; }
    .pagination-controls { display: flex; align-items: center; gap: 8px; }
    .pagination-controls button {
        background: #1e293b;
        border: 1px solid #334155;
        color: #94a3b8;
        padding: 4px 10px;
        border-radius: 4px;
        cursor: pointer;
        transition: all 0.2s;
        font-family: inherit;
    }
    .pagination-controls button:hover:not(:disabled) {
        background: #38bdf8; color: #0f172a; border-color: #38bdf8;
    }
    .pagination-controls button:disabled {
        opacity: 0.5; cursor: not-allowed;
    }
    .page-current { color: #e2e8f0; font-size: 0.9rem; margin: 0 8px; font-variant-numeric: tabular-nums; }
    .size-selector {
        background: #1e293b;
        color: #94a3b8;
        border: 1px solid #334155;
        border-radius: 4px;
        padding: 4px;
        margin-left: 12px;
        font-size: 0.85rem;
        outline: none;
    }
    
    .icon-btn {
        background: transparent;
        border: none;
        color: #94a3b8;
        cursor: pointer;
        padding: 4px;
        border-radius: 4px;
        transition: all 0.2s;
    }
    .icon-btn:hover {
        background: #334155;
        color: white;
    }

    /* Custom Scrollbar for Table Frame */
    .table-frame::-webkit-scrollbar {
        width: 10px;
        height: 10px;
    }
    .table-frame::-webkit-scrollbar-track {
        background: #0f172a;
        border-left: 1px solid #1e293b;
    }
    .table-frame::-webkit-scrollbar-thumb {
        background: #334155;
        border-radius: 5px;
        border: 2px solid #0f172a; /* Creates padding effect */
    }
    .table-frame::-webkit-scrollbar-thumb:hover {
        background: #475569;
    }
    .table-frame::-webkit-scrollbar-corner {
        background: #0f172a;
    }

    /* Alert Row Styles */
    /* Note: Use global qualifier or ensure data is rendered by Svelte for these to apply */
    .alert-critical { background: rgba(220, 38, 38, 0.25) !important; }
    .alert-critical td:first-child { border-left: 3px solid #dc2626; }
    
    .alert-high { background: rgba(234, 88, 12, 0.2) !important; }
    .alert-high td:first-child { border-left: 3px solid #ea580c; }
    
    .alert-medium { background: rgba(202, 138, 4, 0.15) !important; }
    .alert-medium td:first-child { border-left: 3px solid #ca8a04; }
    
    .alert-low { background: rgba(37, 99, 235, 0.1) !important; }
    .alert-low td:first-child { border-left: 3px solid #2563eb; }

    /* Alert Pills in Action Column */
    .alert-pill {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        padding: 2px 8px;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 700;
        margin-left: 8px;
        white-space: nowrap;
        box-shadow: 0 1px 2px rgba(0,0,0,0.2);
    }
    
    .alert-pill .marker { font-size: 0.8rem; }

    .alert-pill.critical { background: #fee2e2; color: #991b1b; border: 1px solid #f87171; }
    .alert-pill.high { background: #ffedd5; color: #9a3412; border: 1px solid #fdba74; }
    .alert-pill.medium { background: #fef9c3; color: #854d0e; border: 1px solid #fde047; }
    .alert-pill.low { background: #dbeafe; color: #1e40af; border: 1px solid #93c5fd; }
    .sql-prefix {
        background: #0ea5e9;
        color: white;
        font-size: 0.7rem;
        font-weight: 800;
        padding: 2px 6px;
        border-radius: 4px;
        margin-right: 8px;
    }
    .mode-toggle {
        background: #1e293b;
        color: #38bdf8;
        border: 1px solid #334155;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
        cursor: pointer;
        transition: all 0.2s;
        margin-left: 8px;
    }
    .mode-toggle:hover {
        background: #38bdf8;
        color: #0f172a;
    }
    .sql-table {
        table-layout: auto !important;
    }
    .sql-cell {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem !important;
        white-space: pre !important;
        max-width: 400px;
        overflow: hidden;
        text-overflow: ellipsis;
        color: #94a3b8 !important;
    }
    .table-scroll-container {
        width: 100%;
        overflow-x: auto;
    }
    .empty-state-table {
        padding: 100px;
        text-align: center;
        color: #64748b;
        font-size: 1.1rem;
    }
</style>
