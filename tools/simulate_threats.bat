@echo off
echo [+] GTrace Detection & Fairness Tester
echo [!] This script will generate artifacts for Sigma rules and volume testing.

:: 1. Trigger Sigma: whoami execution (Medium)
echo [*] Triggering 'Whoami' detection...
whoami > nul

:: 2. Trigger Sigma: Suspicious PowerShell (High)
echo [*] Triggering 'Encoded PowerShell' detection...
powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand V2hvYW1p

:: 3. Trigger Sigma: Persistent Task (High)
echo [*] Triggering 'Scheduled Task' detection...
schtasks /create /tn "GTrace_Test_Task" /tr "calc.exe" /sc once /st 23:59 /f > nul
schtasks /delete /tn "GTrace_Test_Task" /f > nul

:: 4. Trigger Sigma: Registry Modification (Medium)
echo [*] Triggering 'Registry Mod' detection...
reg add "HKCU\Software\GTraceTest" /v "MaliciousKey" /t REG_SZ /d "DetectionTest" /f > nul

:: 5. Volume Test: Generate massive dummy events to test Fairness Cap
echo [*] Generating 1000 noisy events in Application Log (tests fairness cap)...
for /L %%i in (1,1,1000) do (
    eventcreate /t INFORMATION /id 999 /l APPLICATION /d "GTrace volume test event %%i" > nul
)

echo [!] Done. Now run GTrace.exe, select 'EventLogs', 'Registry', 'Tasks', 'WMI', and 'Network'.
echo [!] Verification Checkpoints:
echo     1. Timeline should show Red/Yellow alerts for whoami, powershell, and schtasks.
echo     2. Even if EVTX hits 3000 events, you should still see 'GTraceTest' registry events.
echo     3. Network and WMI data should be present regardless of the 5000 limit.
pause
