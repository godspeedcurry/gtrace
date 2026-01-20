<script>
    import { onMount, onDestroy } from 'svelte';
    import { inputMode, casePath, evidencePath, overwriteCase, analysisStatus, isAnalyzing, currentView, timeline, findings, logs } from '../stores.js';
    import { StartTriage, RunAnalysis, GetTimeline, GetFindings, OpenCase, GetDefaultCasePath, BrowseEvidencePath, GetSystemInfo } from '../../wailsjs/go/app/App.js';
    import { EventsOn } from '../../wailsjs/runtime/runtime.js';

    // System Info
    let systemInfo = null;
    
    // Progress Tracking
    let progress = 0;
    let progressLabel = "";

    onMount(async () => {
        // Listen for Triage Progress
        EventsOn("triage:progress", (data) => {
             // { current: 1, total: 10, percent: 10 }
             progress = data.percent;
             progressLabel = `${data.percent}%`;
        });

        // Only fetch system info in Live mode ideally, but it's cheap so fetch always
        try {
            systemInfo = await GetSystemInfo();
        } catch (e) {
            console.log("Failed to get system info", e);
        }
    });

    // Live Analysis Options
    let selectedComponents = {
        'EventLogs': true,
        'Registry': true,
        'Prefetch': true,
        'Tasks': true,
        'JumpLists': true,
        'Network': true,
        'WMI': true,
        'Browser': true
    };
    
    // Advanced Options
    let maxEvents = 20000;
    let daysLookback = 90;
    let depthMode = 'deep'; // 'triage', 'standard', 'deep', 'custom'

    async function browse() {
        try {
            const path = await BrowseEvidencePath();
            if (path) {
                $evidencePath = path;
            }
        } catch (e) {
            console.error(e);
        }
    }

    function updateDepth(mode) {
        depthMode = mode;
        if (mode === 'triage') {
            maxEvents = 1000;
            daysLookback = 7;
        } else if (mode === 'standard') {
            maxEvents = 5000;
            daysLookback = 30;
        } else if (mode === 'deep') {
            maxEvents = 20000;
            daysLookback = 90;
        }
        // Custom leaves it alone
    }

    // Watch for manual editing to switch to custom
    function onManualChange() {
        if (depthMode !== 'custom') depthMode = 'custom';
    }

    function toggleSelection(state) {
        for (const key in selectedComponents) {
            selectedComponents[key] = state;
        }
    }

    async function start() {
        if ($isAnalyzing) return;
        
        $isAnalyzing = true;
        // Reset data
        $timeline = [];
        $findings = [];
        $logs = [];
        
        try {
            // 1. Prepare Case Path
            if (!$casePath) {
                $casePath = await GetDefaultCasePath();
            }
            
            // 2. Initialize Backend (Open Case)
            $analysisStatus = "Initializing Case...";
            await OpenCase($casePath);

            // 3. Execute Analysis
            
            const options = {
                "max_events": parseInt(maxEvents),
                "days": parseInt(daysLookback)
            };

            if ($inputMode === 'live') {
                $analysisStatus = "Triaging System...";
                
                // Convert map to array
                const components = Object.keys(selectedComponents).filter(k => selectedComponents[k]);
                logs.update(l => [...l, {source: "Frontend", message: `Starting Triage with components: ${JSON.stringify(components)}`, ts: new Date().toISOString()}]);
                await StartTriage("", components, options); 
            } else {
                $analysisStatus = "Processing Evidence...";
                await StartTriage($evidencePath, [], options); 
            }

            // 4. Run Analyzers (Detection Logic)
            $analysisStatus = "Analyzing Artifacts...";
            await RunAnalysis(); 
            
            $analysisStatus = "Fetching Results...";
            $timeline = await GetTimeline(parseInt(maxEvents)); // Pass user-defined limit
            $findings = await GetFindings();
            $analysisStatus = "Ready";
            
            // Auto switch to timeline on success
            $currentView = 'timeline';

        } catch (err) {
            $analysisStatus = "Error: " + err;
            logs.update(l => [...l, {source: "Error", message: String(err), ts: new Date().toISOString()}]);
        } finally {
            $isAnalyzing = false;
        }
    }
</script>

<div class="dashboard-container">
    <div class="scroll-wrapper">
        <div class="content-width">
            <header>
                <h1>New Investigation</h1>
                {#if systemInfo && $inputMode === 'live'}
                    <div class="system-info-pill">
                        <span class="host">{systemInfo.hostname}</span>
                        <span class="sep">•</span>
                        <span class="detail">{systemInfo.ip}</span>
                        <span class="sep">•</span>
                        <span class="detail">{systemInfo.os} ({systemInfo.arch})</span>
                    </div>
                {/if}
                <p>Select your analysis source to begin.</p>
            </header>

    <div class="cards-row">
        <!-- Live Mode Card -->
        <div class="option-card" class:selected={$inputMode === 'live'} on:click={() => $inputMode = 'live'}>
            <div class="icon-circle">
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
            </div>
            <h3>Live System</h3>
            <p>Perform a triage on the currently running machine. Requires Administrator privileges.</p>
            <div class="badge">Forensic Triage</div>
        </div>

        <!-- Offline Mode Card -->
        <div class="option-card" class:selected={$inputMode === 'offline'} on:click={() => $inputMode = 'offline'}>
            <div class="icon-circle">
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
            </div>
            <h3>Offline Evidence</h3>
            <p>Analyze collected artifacts (EVTX, Registry, Prefetch) from an external source.</p>
            <div class="badge">Post-Mortem</div>
        </div>
    </div>

    <div class="config-panel">
        {#if $inputMode === 'live'}
             <div class="input-group">
                <div class="section-header">
                    <div class="section-label">Select Artifacts</div>
                    <div class="trace-actions">
                        <button class="text-btn" on:click={() => toggleSelection(true)}>All</button>
                        <span class="sep">/</span>
                        <button class="text-btn" on:click={() => toggleSelection(false)}>None</button>
                    </div>
                </div>
                <div class="checklist">
                    <label><input type="checkbox" bind:checked={selectedComponents['EventLogs']}> Event Logs</label>
                    <label><input type="checkbox" bind:checked={selectedComponents['Registry']}> Registry</label>
                    <label><input type="checkbox" bind:checked={selectedComponents['Prefetch']}> Prefetch</label>
                    <label><input type="checkbox" bind:checked={selectedComponents['Tasks']}> Tasks</label>
                    <label><input type="checkbox" bind:checked={selectedComponents['JumpLists']}> JumpLists</label>
                    <label><input type="checkbox" bind:checked={selectedComponents['Network']}> Network (Live)</label>
                    <label><input type="checkbox" bind:checked={selectedComponents['WMI']}> WMI Persistence</label>
                    <label><input type="checkbox" bind:checked={selectedComponents['Browser']}> Browser Scraper</label>
                </div>
            </div>
        {/if}

        {#if $inputMode === 'offline'}
            <div class="input-group">
                <div class="section-label">Evidence Path</div>
                <div class="input-wrapper">
                    <input bind:value={$evidencePath} placeholder="/path/to/artifacts" type="text" />
                    <button class="browse-btn" on:click={browse}>
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><folder></folder><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
                        Browse
                    </button>
                </div>
                <small>Directory containing artifacts.</small>
            </div>
        {/if}

        <div class="input-group">
            <div class="section-label">Analysis Depth</div>
            <div class="depth-presets">
                <button class:active={depthMode === 'triage'} on:click={() => updateDepth('triage')}>
                    <strong>Quick Triage</strong>
                    <span>1k Events / 7d</span>
                </button>
                <button class:active={depthMode === 'standard'} on:click={() => updateDepth('standard')}>
                    <strong>Standard</strong>
                    <span>5k Events / 30d</span>
                </button>
                <button class:active={depthMode === 'deep'} on:click={() => updateDepth('deep')}>
                    <strong>Deep Dive</strong>
                    <span>20k Events / 90d</span>
                </button>
                <button class:active={depthMode === 'custom'} on:click={() => updateDepth('custom')}>
                    <strong>Custom</strong>
                    <span>Manual Config</span>
                </button>
            </div>
        </div>

        <div class="row">
            <div class="input-group flex-1">
                <div class="section-label">Max Events</div>
                <input type="number" bind:value={maxEvents} on:input={onManualChange} min="1000" max="1000000" step="1000" />
            </div>
            <div class="input-group flex-1">
                <div class="section-label">Lookback Days</div>
                <input type="number" bind:value={daysLookback} on:input={onManualChange} min="1" max="3650" />
            </div>
        </div>

        <div class="row">
            <div class="input-group flex-1">
                <div class="section-label">Case Output Path (Optional)</div>
                <input bind:value={$casePath} placeholder="Auto-generated if empty" type="text" />
            </div>
            
            <div class="toggle-group">
                <label class="switch">
                    <input type="checkbox" bind:checked={$overwriteCase}>
                    <span class="slider round"></span>
                </label>
                <span>Overwrite existing case</span>
            </div>
        </div>
    </div>

        </div>
    </div>

    <div class="action-bar">
        <div class="content-width">
            <div class="action-stack">
                <button class="primary-btn" on:click={start} disabled={$isAnalyzing || ($inputMode === 'offline' && !$evidencePath)}>
                    {#if $isAnalyzing}
                        <span class="spinner"></span> 
                        <span>Processing... {progressLabel}</span>
                    {:else}
                        Start Analysis <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
                    {/if}
                </button>

                {#if $isAnalyzing}
                    <div class="progress-rail">
                        <div class="progress-fill" style="width: {progress}%"></div>
                    </div>
                {/if}
            </div>
        </div>
    </div>
</div>

<style>
    .dashboard-container {
        display: flex;
        flex-direction: column;
        height: 100%;
        width: 100%;
        overflow: hidden;
        padding: 0;
        margin: 0;
    }

    .scroll-wrapper {
        flex: 1;
        overflow-y: auto;
        width: 100%;
    }

    .content-width {
        max-width: 900px;
        min-width: 600px;
        margin: 0 auto;
        padding: 24px 40px;
    }

    .action-bar {
        background: #0b0e14;
        border-top: 1px solid #1e293b;
        padding: 0;
        flex-shrink: 0;
        z-index: 10;
        box-shadow: 0 -4px 6px -1px rgba(0, 0, 0, 0.1);
    }

    header {
        margin-bottom: 24px;
        text-align: center;
    }

    h1 {
        font-size: 2.5rem;
        margin: 0 0 8px 0;
        background: linear-gradient(to right, #ffffff, #94a3b8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800;
        letter-spacing: -0.025em;
    }

    p {
        color: #64748b;
        font-size: 1.1rem;
    }

    .system-info-pill {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: rgba(30, 41, 59, 0.4);
        border: 1px solid #334155;
        padding: 4px 12px;
        border-radius: 99px;
        margin-bottom: 12px;
        font-size: 0.9rem;
        color: #94a3b8;
    }
    .system-info-pill .host { color: #e2e8f0; font-weight: 600; }
    .system-info-pill .sep { color: #475569; }
    .system-info-pill .detail { color: #94a3b8; font-family: monospace; }

    .cards-row {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 16px;
        margin-bottom: 20px;
    }

    .option-card {
        background: rgba(30, 41, 59, 0.3);
        border: 2px solid transparent;
        padding: 20px;
        border-radius: 12px;
        cursor: pointer;
        transition: all 0.2s ease;
        position: relative;
        overflow: hidden;
    }

    .option-card:hover {
        background: rgba(30, 41, 59, 0.6);
        transform: translateY(-2px);
    }

    .option-card.selected {
        background: rgba(56, 189, 248, 0.05);
        border-color: #38bdf8;
        box-shadow: 0 0 20px rgba(56, 189, 248, 0.1);
    }

    .icon-circle {
        width: 48px;
        height: 48px;
        background: #1e293b;
        border-radius: 12px;
        display: flex;
        align-items: center;
        justify-content: center;
        margin-bottom: 16px;
        color: #94a3b8;
    }

    .option-card.selected .icon-circle {
        background: #38bdf8;
        color: white;
    }

    .option-card h3 {
        margin: 0 0 8px 0;
        color: #e2e8f0;
        font-size: 1.25rem;
    }

    .option-card p {
        font-size: 0.9rem;
        margin: 0;
        line-height: 1.5;
    }

    .badge {
        position: absolute;
        top: 16px;
        right: 16px;
        font-size: 0.7rem;
        background: #1e293b;
        padding: 4px 8px;
        border-radius: 99px;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        font-weight: 600;
        color: #64748b;
    }

    .config-panel {
        background: #151b27;
        border: 1px solid #1e293b;
        padding: 32px;
        border-radius: 16px;
        margin-bottom: 32px;
    }

    .input-group {
        display: flex;
        flex-direction: column;
        gap: 8px;
        margin-bottom: 16px;
    }
    
    .input-group:last-child { margin-bottom: 0; }

    label, .section-label {
        font-size: 0.85rem;
        color: #94a3b8;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    input[type="text"], input[type="number"] {
        background: #0b0e14;
        border: 1px solid #334155;
        padding: 14px 16px;
        border-radius: 8px;
        color: white;
        font-size: 1rem;
        width: 100%;
        box-sizing: border-box;
        transition: border-color 0.2s;
        flex: 1; /* allow it to grow in flex container */
    }

    .section-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .trace-actions {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 0.8rem;
    }

    .text-btn {
        background: none;
        border: none;
        color: #64748b;
        cursor: pointer;
        padding: 2px 6px;
        font-size: 0.8rem;
        transition: color 0.2s;
        text-transform: uppercase;
        font-weight: 600;
        letter-spacing: 0.05em;
    }
    .text-btn:hover { color: #38bdf8; }
    .trace-actions .sep { color: #334155; }

    .input-wrapper {
        display: flex;
        gap: 12px;
        align-items: center;
        width: 100%;
    }

    .browse-btn {
        background: #1e293b;
        border: 1px solid #334155;
        color: #94a3b8;
        padding: 0 20px;
        height: 50px; /* Match input height roughly */
        border-radius: 8px;
        cursor: pointer;
        font-weight: 600;
        display: flex;
        align-items: center;
        gap: 8px;
        transition: all 0.2s;
    }
    .browse-btn:hover {
        background: #334155;
        color: white;
        border-color: #475569;
    }
    
    input[type="text"]:focus, input[type="number"]:focus {
        border-color: #38bdf8;
        outline: none;
        box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.1);
    }

    small { color: #475569; }

    .row { display: flex; gap: 24px; align-items: flex-end; margin-bottom: 24px; }
    .flex-1 { flex: 1; }
    .row .input-group { margin-bottom: 0; }

    .toggle-group {
        display: flex;
        align-items: center;
        gap: 12px;
        padding-bottom: 8px;
    }

    .toggle-group span { color: #e2e8f0; font-size: 0.95rem; }

    /* Custom Switch */
    .switch {
        position: relative;
        display: inline-block;
        width: 44px;
        height: 24px;
    }
    .switch input { opacity: 0; width: 0; height: 0; }
    .slider {
        position: absolute;
        cursor: pointer;
        top: 0; left: 0; right: 0; bottom: 0;
        background-color: #334155;
        transition: .4s;
    }
    .slider:before {
        position: absolute;
        content: "";
        height: 18px;
        width: 18px;
        left: 3px;
        bottom: 3px;
        background-color: white;
        transition: .4s;
    }
    input:checked + .slider { background-color: #38bdf8; }
    input:checked + .slider:before { transform: translateX(20px); }
    .slider.round { border-radius: 34px; }
    .slider.round:before { border-radius: 50%; }

    .checklist {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 12px;
        margin: 16px 0;
        background: #0f172a;
        padding: 16px;
        border-radius: 8px;
        border: 1px solid #334155;
    }
    .checklist label {
        display: flex;
        align-items: center;
        gap: 8px;
        color: #e2e8f0;
        font-size: 0.9rem;
        cursor: pointer;
        text-transform: none;
        letter-spacing: normal;
        font-weight: 400;
    }
    
    .primary-btn {
        background: linear-gradient(135deg, #0ea5e9, #2563eb);
        color: white;
        border: none;
        padding: 16px 48px;
        border-radius: 8px;
        font-size: 1.1rem;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.2s;
        display: inline-flex;
        align-items: center;
        justify-content: center; /* Center content */
        gap: 12px;
        box-shadow: 0 4px 6px -1px rgba(14, 165, 233, 0.2);
    }

    .primary-btn:hover:not(:disabled) {
        transform: translateY(-2px);
        box-shadow: 0 10px 15px -3px rgba(14, 165, 233, 0.3);
    }

    .primary-btn:disabled {
        opacity: 0.7;
        cursor: not-allowed;
        filter: grayscale(1);
    }

    .depth-presets {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 12px;
        margin-bottom: 24px;
    }

    .depth-presets button {
        background: #0f172a;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 12px;
        text-align: center;
        cursor: pointer;
        display: flex;
        flex-direction: column;
        gap: 4px;
        transition: all 0.2s;
    }

    .depth-presets button strong {
        color: #e2e8f0;
        font-size: 0.9rem;
        display: block;
    }

    .depth-presets button span {
        color: #64748b;
        font-size: 0.75rem;
    }

    .depth-presets button:hover {
        background: rgba(255,255,255,0.05);
        border-color: #475569;
    }

    .depth-presets button.active {
        background: rgba(56, 189, 248, 0.1);
        border-color: #38bdf8;
    }
    .depth-presets button.active strong { color: #38bdf8; }
    .depth-presets button.active span { color: #bae6fd; }

    .spinner {
        width: 20px;
        height: 20px;
        border: 2px solid rgba(255,255,255,0.3);
        border-top-color: white;
        border-radius: 50%;
        animation: spin 1s linear infinite;
        display: inline-block;
    }
    @keyframes spin { 100% { transform: rotate(360deg); } }

    .action-stack {
        display: flex;
        flex-direction: column;
        gap: 12px;
        width: 100%;
        max-width: 400px; /* Limit width */
        margin: 0 auto;   /* Center element since it is inside a larger block */
    }

    .progress-rail {
        width: 100%;
        height: 6px;
        background: #1e293b;
        border-radius: 3px;
        overflow: hidden;
    }

    .progress-fill {
        height: 100%;
        background: linear-gradient(90deg, #38bdf8, #2563eb);
        transition: width 0.3s ease-out;
        box-shadow: 0 0 10px rgba(56, 189, 248, 0.5);
    }
</style>
