<script>
    import { logs } from '../stores.js';
    import { afterUpdate } from 'svelte';

    let container;
    let selectedSource = 'All';

    // Auto-scroll to bottom
    afterUpdate(() => {
        if (container) {
            container.scrollTop = container.scrollHeight;
        }
    });

    $: sources = ['All', ...new Set($logs.map(l => l.source))];
    $: filteredLogs = selectedSource === 'All' 
        ? $logs 
        : $logs.filter(l => l.source === selectedSource);
</script>

<div class="layout">
    <div class="sidebar">
        <h4>Sources</h4>
        {#each sources as source}
            <button class:active={selectedSource === source} on:click={() => selectedSource = source}>
                {source}
            </button>
        {/each}
    </div>

    <div class="logs-container" bind:this={container}>
        {#each filteredLogs as log}
            <div class="log-entry">
                <span class="ts">[{new Date(log.ts).toLocaleTimeString()}]</span>
                <span class="source" class:hl={log.source !== 'System'}>[{log.source}]</span>
                <span class="msg">{log.message}</span>
            </div>
        {/each}
        {#if filteredLogs.length === 0}
            <div class="empty">No logs for this source.</div>
        {/if}
    </div>
</div>

<style>
    .layout {
        display: flex;
        height: 100%;
        background: #0b0e14;
    }

    .sidebar {
        width: 200px;
        border-right: 1px solid #1e293b;
        padding: 16px;
        background: #0f172a;
        display: flex;
        flex-direction: column;
        gap: 8px;
    }

    .sidebar h4 {
        margin: 0 0 12px 0;
        color: #64748b;
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    .sidebar button {
        background: transparent;
        border: none;
        color: #94a3b8;
        padding: 8px 12px;
        text-align: left;
        border-radius: 6px;
        cursor: pointer;
        font-size: 0.9rem;
    }

    .sidebar button:hover {
        background: rgba(255,255,255,0.05);
        color: #e2e8f0;
    }

    .sidebar button.active {
        background: #1e293b;
        color: #38bdf8;
        font-weight: 600;
    }

    .logs-container {
        flex: 1;
        padding: 24px;
        overflow-y: auto;
        font-family: 'JetBrains Mono', 'Menlo', 'Monaco', monospace;
        font-size: 0.85rem;
        color: #94a3b8;
    }

    .log-entry {
        margin-bottom: 6px;
        display: flex;
        gap: 12px;
        line-height: 1.5;
        border-bottom: 1px solid #1e293b;
        padding-bottom: 4px;
    }

    .ts { color: #475569; user-select: none; white-space: nowrap; }
    .source { color: #64748b; font-weight: 600; white-space: nowrap; }
    .source.hl { color: #a5b4fc; } /* Highlight non-system sources */
    .msg { color: #e2e8f0; white-space: pre-wrap; word-break: break-word; }
    
    .empty { color: #475569; font-style: italic; padding: 20px; }
</style>
