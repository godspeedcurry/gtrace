<script>
    import { timeline, selectedEvent } from '../stores.js';
    
    let searchTerm = "";
    let filterSource = "all";
    
    // Sorting
    let sortField = "event_time";
    let sortDirection = "desc"; // or 'asc'

    function toggleSort(field) {
        if (sortField === field) {
            sortDirection = sortDirection === "asc" ? "desc" : "asc";
        } else {
            sortField = field;
            sortDirection = "desc"; // Default new sort to desc
        }
    }

    $: filteredTimeline = $timeline.filter(e => {
        if (filterSource !== 'all' && e.source !== filterSource) return false;
        if (!searchTerm) return true;
        const term = searchTerm.toLowerCase();
        
        // Safety checks for null fields
        const time = e.event_time || "";
        const source = e.source || "";
        const action = e.action || "";
        const subject = e.subject || "";
        
        return (
            time.toLowerCase().includes(term) ||
            source.toLowerCase().includes(term) ||
            action.toLowerCase().includes(term) ||
            subject.toLowerCase().includes(term)
        );
    }).sort((a, b) => {
        let valA = a[sortField] || "";
        let valB = b[sortField] || "";
        
        // Special case for time? ISO strings sort correctly as strings.
        
        if (valA < valB) return sortDirection === "asc" ? -1 : 1;
        if (valA > valB) return sortDirection === "asc" ? 1 : -1;
        return 0;
    });

    $: sources = ['all', ...new Set($timeline.map(e => e.source))];
    
    // Column Resizing Logic
    let columnWidths = {
        time: 180,
        source: 120,
        action: 200,
        subject: 250
    };
    
    let resizingCol = null;
    let startX = 0;
    let startWidth = 0;

    function startResize(e, col) {
        resizingCol = col;
        startX = e.clientX;
        startWidth = columnWidths[col];
        window.addEventListener('mousemove', doResize);
        window.addEventListener('mouseup', stopResize);
        e.target.classList.add('active');
    }

    function doResize(e) {
        if (!resizingCol) return;
        const diff = e.clientX - startX;
        // Min width 50px
        columnWidths[resizingCol] = Math.max(50, startWidth + diff);
    }

    function stopResize() {
        resizingCol = null;
        window.removeEventListener('mousemove', doResize);
        window.removeEventListener('mouseup', stopResize);
        document.querySelectorAll('.resizer').forEach(el => el.classList.remove('active'));
    }

    import { onDestroy } from 'svelte';
    onDestroy(() => {
        window.removeEventListener('mousemove', doResize);
        window.removeEventListener('mouseup', stopResize);
    });

    // --- SMART SCHEMA DEFINITIONS ---
    const eventSchemas = {
        // Process Creation
        '4688': [
            { k: 'NewProcessName', label: 'Proc' },
            { k: 'CommandLine', label: 'Cmd' },
            { k: 'ParentProcessName', label: 'Parent' }
        ],
        // Logon
        '4624': [
            { k: 'TargetUserName', label: 'User' },
            { k: 'LogonType', label: 'Type' },
            { k: 'IpAddress', label: 'IP' }
        ],
        '4625': [
            { k: 'TargetUserName', label: 'User' },
            { k: 'FailureReason', label: 'Reason' },
            { k: 'IpAddress', label: 'IP' }
        ],
        // Special Logons
        '4672': [{ k: 'SubjectUserName', label: 'AdminUser' }],
        // Kerberos
        '4768': [{ k: 'TargetUserName', label: 'User' }, { k: 'TicketEncryptionType', label: 'Enc' }],
        '4769': [{ k: 'TargetUserName', label: 'User' }, { k: 'ServiceName', label: 'Svc' }],
        // Object Access
        '4663': [{ k: 'ObjectName', label: 'Obj' }, { k: 'AccessMask', label: 'Mask' }, { k: 'ProcessName', label: 'Proc' }],
        // Scheduled Tasks
        '4698': [{ k: 'TaskName', label: 'Task' }],
        '4702': [{ k: 'TaskName', label: 'Task' }],
        // Services
        '7045': [{ k: 'ServiceName', label: 'Svc' }, { k: 'ImagePath', label: 'Img' }],
        '7036': [{ k: 'param1', label: 'Svc' }, { k: 'param2', label: 'State' }]
    };

    function getDisplayFields(event) {
        if (!event.details) return [];
        
        let fields = [];
        const eid = event.details.EventID; // From EVTX parser
        
        if (eid && eventSchemas[eid]) {
            // Use Schema
            eventSchemas[eid].forEach(def => {
                if (event.details[def.k]) {
                    fields.push({ k: def.label, v: event.details[def.k] });
                }
            });
        } else if (event.source === 'Registry') {
            // Registry Schema (Generic)
            if (event.details.Path) fields.push({ k: 'Path', v: event.details.Path });
            if (event.details.ValueName) fields.push({ k: 'Val', v: event.details.ValueName });
        }
        
        // Fallback: If no schema matched or fields found, show generic top 3
        if (fields.length === 0) {
            Object.entries(event.details).slice(0, 3).forEach(([k, v]) => {
                if (k !== '_Alert' && k !== 'EventID' && (v + '').length < 60) {
                    fields.push({ k: k, v: v }); // Keep original key
                }
            });
        }
        return fields;
    }

</script>
<div class="view-container">
    <div class="toolbar">
        <div class="search-box">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
            <input bind:value={searchTerm} placeholder="Search events..." />
        </div>
        
        <div class="filter-group">
            <button class:active={filterSource === 'all'} on:click={() => filterSource = 'all'}>All</button>
            <button class:active={filterSource === 'EventLog'} on:click={() => filterSource = 'EventLog'}>EVTX</button>
            <button class:active={filterSource === 'Registry'} on:click={() => filterSource = 'Registry'}>Registry</button>
            
            <div class="divider"></div>

            <select bind:value={filterSource}>
                <option value="all">More Sources...</option>
                {#each sources as source}
                    {#if source !== 'EventLog' && source !== 'Registry'}
                        <option value={source}>{source}</option>
                    {/if}
                {/each}
            </select>
        </div>
        
        <div class="count">{filteredTimeline.length} events</div>
    </div>

    <div class="table-frame">
        <table>
            <thead>
                <tr>
                    <th style="width: {columnWidths.time}px" on:click={() => toggleSort('event_time')}>
                        Time {sortField === 'event_time' ? (sortDirection === 'asc' ? '↑' : '↓') : ''}
                        <div class="resizer" on:mousedown|stopPropagation={(e) => startResize(e, 'time')}></div>
                    </th>
                    <th style="width: {columnWidths.source}px" on:click={() => toggleSort('source')}>
                        Source {sortField === 'source' ? (sortDirection === 'asc' ? '↑' : '↓') : ''}
                        <div class="resizer" on:mousedown|stopPropagation={(e) => startResize(e, 'source')}></div>
                    </th>
                    <th style="width: {columnWidths.action}px" on:click={() => toggleSort('action')}>
                        Action {sortField === 'action' ? (sortDirection === 'asc' ? '↑' : '↓') : ''}
                        <div class="resizer" on:mousedown|stopPropagation={(e) => startResize(e, 'action')}></div>
                    </th>
                    <th style="width: {columnWidths.subject}px" on:click={() => toggleSort('subject')}>
                        Subject {sortField === 'subject' ? (sortDirection === 'asc' ? '↑' : '↓') : ''}
                        <div class="resizer" on:mousedown|stopPropagation={(e) => startResize(e, 'subject')}></div>
                    </th>
                    <th>Details snippet</th>
                </tr>
            </thead>
            <tbody>
                {#each filteredTimeline as event}
                    <tr 
                        class:alert-row={event.details && event.details._Alert}
                        on:click={() => $selectedEvent = event}
                    >
                        <td class="mono time">{new Date(event.event_time).toLocaleString()}</td>
                        <td>
                            <span class="tag {event.source.toLowerCase().replace(/ /g, '')}">{event.source}</span>
                        </td>
                        <td class="action-cell">
                            {event.action}
                            {#if event.details && event.details._Alert}
                                <span class="alert-badge">⚠️ {event.details._Alert}</span>
                            {/if}
                        </td>
                        <td class="subject" title={event.subject}>{event.subject}</td>
                        <td class="details-preview">
                            <div class="pills">
                                {#if event.details && typeof event.details === 'object'}
                                    {#each getDisplayFields(event) as field}
                                          <span class="pill"><span class="k">{field.k}:</span> {field.v}</span>
                                    {/each}
                                {/if}
                            </div>
                        </td>
                    </tr>
                {/each}
                {#if filteredTimeline.length === 0}
                    <tr>
                        <td colspan="5" class="empty-message">No events found matching your criteria.</td>
                    </tr>
                {/if}
            </tbody>
        </table>
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
        background: transparent;
        border: none;
        padding: 6px 8px;
        color: #94a3b8;
        font-size: 0.85rem;
        outline: none;
        cursor: pointer;
    }
    select:hover { color: #e2e8f0; }

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
</style>
