<script>
    import { timeline, selectedEvent } from '../stores.js';
    import { onMount, onDestroy } from 'svelte';
    import { GetTotalEventCount, SearchEvents } from '../../wailsjs/go/app/App.js';

    let searchTerm = "";
    let filterSource = "all";
    let totalStorageCount = 0;
    
    // Pagination
    let currentPage = 1;
    let pageSize = 100;
    let hasNextPage = true;
    let sortField = "event_time";
    let sortDirection = "desc";

    let lastError = "";

    async function loadData() {
        try {
            lastError = "";
            totalStorageCount = await GetTotalEventCount();
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
            const events = await SearchEvents(searchTerm, currentPage, pageSize, filterSource);
            $timeline = events || [];
            hasNextPage = ($timeline.length === pageSize);
            lastError = "";
        } catch (e) {
            console.error("Search Error:", e);
            lastError = "Search failed: " + e;
            $timeline = [];
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
        '3': [{ k: 'Image', label: 'Proc' }, { k: 'DestinationIp', label: 'DstIP' }]
    };

    function getDisplayFields(event) {
        if (!event.details) return [];
        let fields = [];
        const eid = event.details.EventID;
        
        // Priority 1: Use schema if defined
        if (eid && eventSchemas[eid]) {
            if (event.details.Category) fields.push({ k: 'Cat', v: event.details.Category });
            eventSchemas[eid].forEach(def => {
                const val = event.details[def.k];
                if (val && val !== '-') {
                    // Truncate long values
                    const displayVal = (val + '').length > 80 ? (val + '').substring(0, 77) + '...' : val;
                    fields.push({ k: def.label || def.k, v: displayVal });
                }
            });
        } 
        // Priority 2: Registry events
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
    
    $: sources = ['all', 'EventLog', 'Registry', 'Prefetch', 'Tasks', 'LNK', 'JumpLists', 'Amcache'];

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
    <div class="toolbar">
        <div class="search-box">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
            <input bind:value={searchTerm} placeholder="Search events... (Tip: use eid:4688 for exact ID)" />
        </div>
        
        <div class="filter-group">
            <button class:active={filterSource === 'all'} on:click={() => filterSource = 'all'}>All</button>
            <button class:active={filterSource === 'EventLog'} on:click={() => filterSource = 'EventLog'}>EVTX</button>
            <button class:active={filterSource === 'Registry'} on:click={() => filterSource = 'Registry'}>Registry</button>
            
            <div class="divider"></div>

            <select bind:value={filterSource}>
                <option value="all">More Sources...</option>
                {#each sources as source}
                    {#if source !== 'all' && source !== 'EventLog' && source !== 'Registry'}
                        <option value={source}>{source}</option>
                    {/if}
                {/each}
            </select>
        </div>
        
        <div class="count" style="display: flex; align-items: center; gap: 10px;">
            <button class="icon-btn" on:click={loadData} title="Refresh Data">
                🔄
            </button>
            <span>
                Showing Page {currentPage}
                {#if totalStorageCount > 0} 
                    of {totalStorageCount} events
                {/if}
            </span>
        </div>
    </div>
    
    
    {#if lastError && lastError.includes('case not open')}
        <div class="info-banner" style="background: #1e3a5f; color: #7dd3fc; padding: 16px; font-size: 0.9rem; border-bottom: 1px solid #38bdf8; display: flex; align-items: center; gap: 12px;">
            <span style="font-size: 1.5rem;">📋</span>
            <span>No analysis data yet. Please go to <strong>Dashboard</strong> and click <strong>Start Analysis</strong> to begin.</span>
        </div>
    {:else if lastError}
        <div class="error-banner" style="background: #ef444422; color: #fca5a5; padding: 8px; font-size: 0.9rem; border-bottom: 1px solid #ef4444;">
            {lastError}
        </div>
    {/if}
    
    <div class="table-frame">
        <table>
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
                            <span class="action-text">{event.action}</span>
                            {#if event.details && event.details._Alert}
                                <div class="alert-pill {event.details._AlertLevel || 'medium'}">
                                    <span class="marker">⚡</span> {event.details._Alert}
                                </div>
                            {/if}
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
                {#if $timeline.length === 0}
                    <tr>
                        <td colspan="6" class="empty-state">No events found</td>
                    </tr>
                {/if}
            </tbody>
        </table>
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

    .toolbar {
        padding: 16px 24px;
        border-bottom: 1px solid #1e293b;
        background: #0b0e14;
        display: flex;
        gap: 16px;
        align-items: center;
    }

    .search-box {
        position: relative;
        flex: 1;
        max-width: 400px;
    }

    .search-box svg {
        position: absolute;
        left: 12px;
        top: 50%;
        transform: translateY(-50%);
        color: #64748b;
    }

    .search-box input {
        width: 100%;
        background: #151b27;
        border: 1px solid #334155;
        padding: 10px 10px 10px 40px;
        border-radius: 8px;
        color: white;
        font-size: 0.9rem;
        box-sizing: border-box;
        color: white;
        font-size: 0.9rem;
    }
    
    .search-box input:focus {
        border-color: #38bdf8;
        outline: none;
    }

    .filter-group {
        display: flex;
        align-items: center;
        gap: 8px;
        background: #151b27;
        padding: 4px;
        border-radius: 8px;
        border: 1px solid #334155;
    }

    .filter-group button {
        background: transparent;
        border: none;
        color: #94a3b8;
        padding: 6px 12px;
        border-radius: 6px;
        font-size: 0.85rem;
        cursor: pointer;
        font-weight: 500;
        transition: all 0.2s;
    }
    
    .filter-group button:hover { color: #e2e8f0; background: rgba(255,255,255,0.05); }
    
    .filter-group button.active {
        background: #38bdf8;
        color: #0f172a;
        font-weight: 700;
    }
    
    .divider {
        width: 1px;
        height: 20px;
        background: #334155;
        margin: 0 4px;
    }

    select {
        background: #151b27;
        border: 1px solid #334155;
        border-radius: 6px;
        padding: 6px 8px;
        color: #e2e8f0;
        font-size: 0.85rem;
        outline: none;
        cursor: pointer;
    }
    select:hover { border-color: #38bdf8; }
    
    option {
        background: #151b27;
        color: white;
    }

    .count {
        margin-left: auto;
        color: #64748b;
        font-size: 0.85rem;
        font-family: 'JetBrains Mono', monospace;
    }

    .table-frame {
        flex: 1;
        overflow: auto;
        background: #0f172a; /* Slightly readable bg */
    }

    table {
        width: 100%;
        border-collapse: collapse;
        font-size: 0.9rem;
        table-layout: fixed; /* Critical for column resizing */
    }

    th {
        position: sticky;
        top: 0;
        background: #1e293b;
        color: #94a3b8;
        font-weight: 600;
        text-align: left;
        padding: 12px 16px;
        font-size: 0.8rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        z-index: 10;
        box-shadow: 0 1px 0 #334155;
    }

    td {
        padding: 10px 16px;
        border-bottom: 1px solid #1e293b;
        color: #cbd5e1;
        vertical-align: middle;
    }

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

    /* Tags matching previous styles roughly but cleaner */
    .tag { padding: 4px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; display: inline-block; }
    .tag.process { background: rgba(34, 197, 94, 0.1); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.2); }
    .tag.prefetch { background: rgba(14, 165, 233, 0.1); color: #38bdf8; border: 1px solid rgba(14, 165, 233, 0.2); }
    .tag.file { background: rgba(236, 72, 153, 0.1); color: #f472b6; border: 1px solid rgba(236, 72, 153, 0.2); }
    /* Generic fallback */
    .tag { background: rgba(148, 163, 184, 0.1); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.2); }

    .pills { display: flex; gap: 6px; overflow: hidden; height: 1.5em; }
    .pill { background: #1e293b; padding: 2px 6px; border-radius: 4px; font-size: 0.75rem; color: #94a3b8; border: 1px solid #334155; white-space: nowrap; font-family: 'JetBrains Mono', monospace; }
    .pill .k { color: #64748b; margin-right: 4px; }

    .alert-row { background: rgba(239, 68, 68, 0.08) !important; }
    .alert-row:hover { background: rgba(239, 68, 68, 0.12) !important; }
    .alert-row td { border-bottom-color: rgba(239, 68, 68, 0.2); }
    
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

    /* Alert Row Styles - The "Handle" for analysts */
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
</style>
