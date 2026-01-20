<script>
    import { onMount } from 'svelte';
    import { EventsOn } from '../wailsjs/runtime/runtime.js';
    import { currentView, logs, analysisStatus, analysisProgress, selectedEvent } from './stores.js';
    
    // Components
    import Sidebar from './components/Sidebar.svelte';
    
    // Views
    import Dashboard from './views/Dashboard.svelte';
    import Timeline from './views/Timeline.svelte';
    import Findings from './views/Findings.svelte';
    import Logs from './views/Logs.svelte';

    onMount(() => {
        // Setup Wails backend listeners
        EventsOn("log:entry", (entry) => {
            logs.update(l => [...l, entry]);
        });
        
        // Legacy/Fallback for simple strings
        EventsOn("log:debug", (msg) => {
             logs.update(l => [...l, {
                 source: "System",
                 message: msg,
                 ts: new Date().toISOString()
             }]);
        });

        EventsOn("progress", (p) => {
            analysisProgress.set(p);
        });

        EventsOn("status", (s) => {
            analysisStatus.set(s);
        });
        
        // Initial clean status
        analysisStatus.set("Ready");
    });
</script>

<main class="app-shell">
    <Sidebar />
    
    <div class="content-area">
        {#if $currentView === 'dashboard'}
            <Dashboard />
        {:else if $currentView === 'timeline'}
            <Timeline />
        {:else if $currentView === 'logs'}
            <Logs />
        {/if}
    </div>

    <!-- Event Detail Modal Overlay -->
    {#if $selectedEvent}
        <div class="modal-backdrop" on:click={() => $selectedEvent = null}>
            <div class="modal-panel" on:click|stopPropagation>
                <div class="modal-header">
                    <h2>Event Details</h2>
                    <button class="close-btn" on:click={() => $selectedEvent = null}>&times;</button>
                </div>
                
                <div class="event-meta">
                    <div class="meta-item">
                        <label>Time</label>
                        <span>{$selectedEvent.event_time}</span>
                    </div>
                    <div class="meta-item">
                        <label>Source</label>
                        <span class="hl">{$selectedEvent.source}</span>
                    </div>
                    <div class="meta-item">
                        <label>Action</label>
                        <span>{$selectedEvent.action}</span>
                    </div>
                </div>

                <div class="json-viewer">
                    <pre>{JSON.stringify($selectedEvent.details, null, 2)}</pre>
                </div>
            </div>
        </div>
    {/if}
</main>

<style>
    :global(body) { 
        margin: 0; 
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        background-color: #0b0e14;
        color: #e2e8f0;
        -webkit-font-smoothing: antialiased;
        overflow: hidden; /* App should handle scrolling internally */
    }

    /* Google Fonts import would go in index.html, assume Inter is available or fallback to system */

    .app-shell {
        display: flex;
        height: 100vh;
        width: 100vw;
        overflow: hidden;
    }

    .content-area {
        flex: 1;
        background: #0b0e14;
        position: relative;
        overflow: auto;
        display: flex;
        flex-direction: column;
    }

    /* Modal Styles */
    .modal-backdrop {
        position: fixed;
        top: 0; left: 0; right: 0; bottom: 0;
        background: rgba(2, 6, 23, 0.85);
        backdrop-filter: blur(8px);
        z-index: 1000;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 40px;
    }

    .modal-panel {
        background: #0b1120;
        width: 100%;
        max-width: 900px;
        max-height: 85vh;
        border-radius: 12px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        box-shadow: 0 0 50px rgba(0, 0, 0, 0.6), 0 0 2px rgba(56, 189, 248, 0.2);
        display: flex;
        flex-direction: column;
        overflow: hidden;
    }

    .modal-header {
        padding: 16px 24px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        display: flex;
        justify-content: space-between;
        align-items: center;
        background: #0f172a;
    }

    .modal-header h2 { 
        margin: 0; 
        font-size: 0.95rem; 
        text-transform: uppercase; 
        letter-spacing: 0.1em; 
        color: #94a3b8;
        font-weight: 800;
    }
    .close-btn { 
        background: rgba(255,255,255,0.03); 
        border: 1px solid rgba(255,255,255,0.05); 
        color: #64748b; 
        font-size: 1.2rem; 
        cursor: pointer; 
        width: 32px; height: 32px;
        border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        transition: all 0.2s;
    }
    .close-btn:hover { color: #f1f5f9; background: #ef4444; border-color: #ef4444; }

    .event-meta {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 24px;
        padding: 24px;
        background: rgba(15, 23, 42, 0.5);
        border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }

    .meta-item label { 
        display: block; 
        font-size: 0.65rem; 
        color: #64748b; 
        text-transform: uppercase; 
        font-weight: 800; 
        margin-bottom: 6px; 
    }
    .meta-item span { 
        font-size: 0.85rem; 
        color: #f1f5f9; 
        font-family: 'JetBrains Mono', monospace; 
    }
    .meta-item span.hl { color: #38bdf8; font-weight: 700; text-shadow: 0 0 8px rgba(56, 189, 248, 0.3); }

    .json-viewer {
        flex: 1;
        overflow: auto;
        padding: 24px;
        background: #020617;
        border: 1px solid rgba(255, 255, 255, 0.02);
        margin: 12px;
        border-radius: 8px;
    }

    pre {
        margin: 0;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.82rem;
        color: #94a3b8;
        line-height: 1.6;
    }

    :global(.json-key) { color: #818cf8; }
    :global(.json-string) { color: #34d399; }
    :global(.json-number) { color: #fbbf24; }
</style>
