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
        background: rgba(0, 0, 0, 0.7);
        backdrop-filter: blur(4px);
        z-index: 100;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 40px;
    }

    .modal-panel {
        background: #0f172a;
        width: 100%;
        max-width: 800px;
        max-height: 90vh;
        border-radius: 16px;
        border: 1px solid #334155;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        display: flex;
        flex-direction: column;
        overflow: hidden;
    }

    .modal-header {
        padding: 24px;
        border-bottom: 1px solid #1e293b;
        display: flex;
        justify-content: space-between;
        align-items: center;
        background: #151b27;
    }

    .modal-header h2 { margin: 0; font-size: 1.25rem; }
    .close-btn { 
        background: none; border: none; color: #94a3b8; font-size: 2rem; cursor: pointer; padding: 0; line-height: 1;
    }
    .close-btn:hover { color: white; }

    .event-meta {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 16px;
        padding: 24px;
        background: #1e293b;
    }

    .meta-item label { display: block; font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; font-weight: 700; margin-bottom: 4px; }
    .meta-item span { font-size: 0.95rem; color: white; }
    .meta-item span.hl { color: #38bdf8; font-weight: 600; }

    .json-viewer {
        flex: 1;
        overflow: auto;
        padding: 24px;
        background: #020617;
    }

    pre {
        margin: 0;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.85rem;
        color: #a5b4fc;
        line-height: 1.5;
    }
</style>
