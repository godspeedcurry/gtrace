<script>
    import { currentView, analysisStatus } from '../stores.js';

    function setView(view) {
        $currentView = view;
    }
</script>

<aside>
    <div class="logo">
        <div class="icon">G</div>
        <span>GTrace</span>
    </div>

    <nav>
        <button class:active={$currentView === 'dashboard'} on:click={() => setView('dashboard')}>
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
            Dashboard
        </button>
        <button class:active={$currentView === 'timeline'} on:click={() => setView('timeline')}>
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
            Timeline
        </button>
        <button class:active={$currentView === 'logs'} on:click={() => setView('logs')}>
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path></svg>
            Logs
        </button>
    </nav>

    <div class="status-panel">
        <small>STATUS</small>
        <div class="status-text" title={$analysisStatus}>
            <div class="indicator" class:ready={$analysisStatus === 'Ready'} class:error={$analysisStatus.startsWith('Error')}></div>
            {$analysisStatus}
        </div>
    </div>
</aside>

<style>
    aside {
        width: 240px;
        background: #0b0e14; /* Match body bg, but maybe slightly different */
        border-right: 1px solid #1e293b;
        display: flex;
        flex-direction: column;
        padding: 24px;
        height: 100vh;
        box-sizing: border-box;
    }

    .logo {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 40px;
        font-weight: 800;
        font-size: 1.25rem;
        color: white;
        letter-spacing: -0.025em;
    }

    .logo .icon {
        width: 32px;
        height: 32px;
        background: linear-gradient(135deg, #38bdf8, #2563eb);
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        box-shadow: 0 0 15px rgba(56, 189, 248, 0.3);
    }

    nav {
        display: flex;
        flex-direction: column;
        gap: 8px;
        flex: 1;
    }

    button {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 12px 16px;
        background: transparent;
        border: none;
        border-radius: 8px;
        color: #94a3b8;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        text-align: left;
        font-size: 0.95rem;
    }

    button:hover {
        background: rgba(30, 41, 59, 0.5);
        color: #e2e8f0;
    }

    button.active {
        background: rgba(56, 189, 248, 0.1);
        color: #38bdf8;
    }

    button svg {
        opacity: 0.7;
    }

    button.active svg {
        opacity: 1;
    }

    .status-panel {
        background: #151b27;
        padding: 16px;
        border-radius: 12px;
        border: 1px solid #1e293b;
    }

    .status-panel small {
        color: #64748b;
        font-size: 0.65rem;
        font-weight: 700;
        letter-spacing: 0.05em;
        display: block;
        margin-bottom: 8px;
    }

    .status-text {
        font-size: 0.85rem;
        color: #e2e8f0;
        display: flex;
        align-items: center;
        gap: 8px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }

    .indicator {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #f59e0b; /* processing/default */
        box-shadow: 0 0 8px rgba(245, 158, 11, 0.4);
    }

    .indicator.ready {
        background: #10b981;
        box-shadow: 0 0 8px rgba(16, 185, 129, 0.4);
    }

    .indicator.error {
        background: #ef4444;
        box-shadow: 0 0 8px rgba(239, 68, 68, 0.4);
    }
</style>
