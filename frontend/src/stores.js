import { writable } from 'svelte/store';

// Application Mode
export const inputMode = writable('live'); // 'live' | 'offline'

// Analysis Data
export const timeline = writable([]);
export const findings = writable([]);
export const logs = writable([]);

// Analysis State
export const analysisStatus = writable("Initializing...");
export const analysisProgress = writable(0);
export const isAnalyzing = writable(false);

// Case Configuration
export const casePath = writable("");
export const evidencePath = writable("");
export const overwriteCase = writable(true);

// UI State
export const currentView = writable('dashboard'); // 'dashboard', 'timeline', 'findings', 'logs'
export const selectedEvent = writable(null);
