# GTrace

[English](README_EN.md) | [中文文档](README.md)
 
A next-generation, cross-platform DFIR (Digital Forensics & Incident Response) Triage Workbench.
Connects the dots between **Execution**, **Existence**, and **Access** artifacts to visualize attack timelines instantly.
 
## 🌟 Key Features
 
*   **Live Live Triage**: Run directly on a suspect machine (Administrator required) to automatically extract execution evidence.
*   **Live Registry Analysis**: Automatically dumps and parses locked Registry Hives (`SYSTEM`, `SAM`, `SOFTWARE`, `HKCU`).
*   **Timeline Visualization**: Unifies disjointed artifacts into a single chronological view.
*   **Interactive Findings**: Detects anomalies like "Simulated Execution" (ShimCache but no Prefetch).
 
## 📊 Artifact Capabilities Matrix
 
| Artifact | Source | Evidence Type | Default: PC (Win10/11) | Default: Server (2016+) | What it tells you |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Prefetch** | `C:\Windows\Prefetch\*.pf` | Execution | ✅ **ON** | ❌ **OFF** (Note 1) | Program execution count & time. |
| **ShimCache** | `HKLM\SYSTEM` | Existence | ✅ **ON** | ✅ **ON** | File existence & modification time. |
| **Amcache** | `C:\Windows\System32\config\Amcache.hve` | Identity | ✅ **ON** | ✅ **ON** | SHA-1 hashes & compilation time. |
| **UserAssist** | `HKCU\Software\...\UserAssist` | User Interaction | ✅ **ON** | ✅ **ON** | GUI-based program execution. |
| **Jumplist** | `AutomaticDestinations-ms` | Access | ✅ **ON** | ✅ **ON** | Recent file access history. |
| **Network** | `netstat` / `arp` / `ipconfig` | Communication | ✅ **ON** | ✅ **ON** | Active connections, ARP cache, Interface config (GBK supported). |
| **Browser** | Chrome/Edge History | Access | ✅ **ON** | ✅ **ON** | Browser history and downloads. |
| **WMI** | WMI Repository | Persistence | ✅ **ON** | ✅ **ON** | WMI Filter/Consumer persistence mechanisms. |
| **Process** | Memory | State | ✅ **N/A** | ✅ **N/A** | Currently running processes. |
 
> **Note 1 (Server Prefetch)**: Windows Server disables Prefetch by default to save I/O. It is only enabled if the server is a Domain Controller or explicitly configured via Registry.
 
## 🚀 Quick Start (Live Triage)
 
1.  **Build** (Requires Go 1.21+ & Wails):
    ```bash
    wails build -platform windows/amd64
    ```
2.  **Deploy**: Copy `build/bin/gtrace.exe` to the target machine.
3.  **Run**: Right-click -> **Run as Administrator**.
4.  **Triaging**:
    *   Leave "Evidence Path" **EMPTY** to trigger **Live Triage Mode**.
    *   Click "Start Triage".
    *   Wait for the timeline to populate.
 
## 🛠 Project Layout
 
- `cmd/gtrace`: Main GUI entry point.
- `internal/engine`: Analysis pipeline & job runner.
- `internal/plugin`: Parser implementations (based on Velocidex).
- `pkg/model`: Data models.
- `frontend`: Svelte+Vite frontend application.

## ⚠️ Requirements

*   **OS**: Windows 10/11/Server 2016+ (for Live Triage). macOS/Linux (for Offline Analysis).
*   **Privileges**: **Administrator** rights required for Live Registry extraction (reg save) and raw disk access.

---
*Built with Wails & Svelte.*
