<script>
    import { findings } from '../stores.js';

    function getSeverity(f) {
        try {
           return (f && f.severity) ? f.severity.toLowerCase() : 'info';
        } catch (e) { return 'info'; }
    }
</script>

<div class="view-container">
    <div class="header">
        <h2>Security Findings</h2>
        <span class="count">{$findings.length} detected</span>
    </div>

    <div class="grid">
        {#each $findings || [] as finding}
          {#if finding}
            <div class="card {getSeverity(finding)}">
                <div class="card-top">
                    <span class="severity-badge {getSeverity(finding)}">{finding.severity || 'INFO'}</span>
                </div>
                <h3>{finding.title || 'Untitled'}</h3>
                <p>{finding.description || ''}</p>
                {#if finding.details}
                    <div class="details-snippet">
                        {finding.details}
                    </div>
                {/if}
            </div>
          {/if}
        {/each}

        {#if $findings.length === 0}
            <div class="empty-state">
                <div class="icon">✓</div>
                <h3>No Critical Findings</h3>
                <p>The analysis didn't detect any predefined high-severity patterns.</p>
            </div>
        {/if}
    </div>
</div>

<style>
    .view-container {
        padding: 32px;
        height: 100%;
        overflow-y: auto;
        box-sizing: border-box;
    }

    .header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 24px;
        padding-bottom: 16px;
        border-bottom: 1px solid #1e293b;
    }

    h2 { margin: 0; color: #f1f5f9; font-size: 1.5rem; }
    .count { background: #1e293b; padding: 4px 12px; border-radius: 99px; font-size: 0.85rem; color: #94a3b8; font-weight: 600; }

    .grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
        gap: 24px;
    }

    .card {
        background: #151b27;
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 24px;
        display: flex;
        flex-direction: column;
        transition: transform 0.2s, box-shadow 0.2s;
    }

    .card:hover {
        transform: translateY(-4px);
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
        border-color: #475569;
    }

    .card.high { border-left: 4px solid #ef4444; }
    .card.medium { border-left: 4px solid #f59e0b; }
    
    .card-top { margin-bottom: 12px; }

    .severity-badge {
        font-size: 0.7rem;
        padding: 4px 10px;
        border-radius: 6px;
        text-transform: uppercase;
        font-weight: 700;
        letter-spacing: 0.05em;
    }
    
    .severity-badge.high { background: rgba(239, 68, 68, 0.1); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.2); }
    .severity-badge.medium { background: rgba(245, 158, 11, 0.1); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.2); }

    h3 {
        margin: 0 0 12px 0;
        font-size: 1.15rem;
        color: #e2e8f0;
        font-weight: 600;
        line-height: 1.4;
    }

    p {
        color: #94a3b8;
        font-size: 0.95rem;
        line-height: 1.6;
        margin: 0;
        flex: 1;
    }

    .details-snippet {
        margin-top: 16px;
        background: #0b0e14;
        padding: 12px;
        border-radius: 8px;
        font-size: 0.8rem;
        font-family: 'JetBrains Mono', monospace;
        color: #cbd5e1;
        border: 1px solid #1e293b;
        word-break: break-all;
    }

    .empty-state {
        grid-column: 1 / -1;
        text-align: center;
        padding: 60px;
        background: rgba(30, 41, 59, 0.2);
        border-radius: 16px;
        border: 2px dashed #334155;
    }

    .empty-state .icon {
        width: 64px;
        height: 64px;
        background: #1e293b;
        color: #10b981;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 32px;
        margin: 0 auto 16px;
    }
</style>
