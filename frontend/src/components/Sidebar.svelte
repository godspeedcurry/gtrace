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
        padding: 10px 16px;
        background: transparent;
        border: none;
        border-radius: 6px;
        color: #64748b;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        text-align: left;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        position: relative;
    }

    button:hover {
        background: rgba(56, 189, 248, 0.03);
        color: #e2e8f0;
    }

    button.active {
        background: rgba(56, 189, 248, 0.08);
        color: #38bdf8;
        box-shadow: inset 0 0 10px rgba(56, 189, 248, 0.05);
    }

    button.active::before {
        content: '';
        position: absolute;
        left: 0;
        top: 20%;
        height: 60%;
        width: 3px;
        background: #38bdf8;
        border-radius: 0 4px 4px 0;
        box-shadow: 0 0 10px #38bdf8;
    }

    button svg {
        opacity: 0.5;
        transition: opacity 0.3s;
    }

    button.active svg {
        opacity: 1;
        filter: drop-shadow(0 0 5px rgba(56, 189, 248, 0.5));
    }

    .status-panel {
        background: rgba(30, 41, 59, 0.3);
        padding: 14px;
        border-radius: 12px;
        border: 1px solid rgba(255, 255, 255, 0.03);
        margin-top: auto;
    }

    .status-panel small {
        color: #475569;
        font-size: 0.6rem;
        font-weight: 800;
        letter-spacing: 0.1em;
        display: block;
        margin-bottom: 10px;
    }

    .status-text {
        font-size: 0.75rem;
        color: #94a3b8;
        display: flex;
        align-items: center;
        gap: 10px;
        font-family: 'JetBrains Mono', monospace;
    }

    .indicator {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background: #f59e0b;
        box-shadow: 0 0 10px rgba(245, 158, 11, 0.6);
        animation: pulse 2s infinite;
    }

    .indicator.ready {
        background: #10b981;
        box-shadow: 0 0 10px rgba(16, 185, 129, 0.6);
        animation: none;
    }

    .indicator.error {
        background: #ef4444;
        box-shadow: 0 0 10px rgba(239, 68, 68, 0.6);
    }

    @keyframes pulse {
        0% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.5; transform: scale(1.2); }
        100% { opacity: 1; transform: scale(1); }
    }
</style>
