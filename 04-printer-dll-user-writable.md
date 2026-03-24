# Printer Service DLL Loaded from User-Writable Paths

## Metadata

| Field | Value |
|---|---|
| **Author** | Jacob Skoog |
| **Created** | 2026-03-21 |
| **Platform** | Microsoft Defender XDR - Advanced Hunting |
| **MITRE ATT&CK** | T1574.002 - Hijack Execution Flow: DLL Side-Loading |
| **MITRE ATT&CK** | T1068 - Exploitation for Privilege Escalation |
| **Severity** | High |
| **Data Sources** | DeviceImageLoadEvents |
| **Minimum Role** | Security Reader |

## Description

Detects DLLs loaded by the Windows Print Spooler service (`spoolsv.exe`) or the Print Isolation Host (`PrintIsolationHost.exe`) from user-writable paths. The Print Spooler has historically been a rich target for privilege escalation (PrintNightmare and related vulnerabilities). Attackers can place malicious DLLs in writable directories that the spooler will load, gaining SYSTEM-level code execution.

This is a focused variant of the generic DLL load query, specifically targeting printer-related processes.

## Query

```kql
// Title: Printer Service DLL Load from User-Writable Paths
// MITRE: T1574.002, T1068
// Description: Detects spoolsv.exe or PrintIsolationHost.exe loading DLLs from
//              user-writable paths. Targets PrintNightmare-style attacks and spooler
//              DLL hijacking.
// Author: Jacob Skoog
let PrinterProcesses = dynamic(["spoolsv.exe", "printisolationhost.exe"]);
let UserWritablePaths = dynamic(["c:\\users", "c:\\programdata", "c:\\windows\\temp", "c:\\temp"]);
let LegitPrinterDriverPaths = dynamic([
    "c:\\programdata\\microsoft\\windows nt\\printers"
]);
DeviceImageLoadEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ (PrinterProcesses)
| where FileName endswith ".dll"
| where FolderPath has_any (UserWritablePaths)
| where not(FolderPath has_any (LegitPrinterDriverPaths))
| project Timestamp, DeviceName, FileName, FolderPath, SHA256,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessAccountName
| sort by Timestamp desc
```

## Triage Notes

- Any hit from this query in a production environment should be treated as high priority. Legitimate printer drivers are typically installed to `C:\Windows\System32\spool\drivers\` or the staging path under ProgramData, not to arbitrary user-writable locations.
- Check the `SHA256` against threat intelligence feeds and VirusTotal.
- Investigate whether the Print Spooler service needs to be running on the affected device. Many servers and workstations do not need it. Disabling the spooler where not needed eliminates this entire attack surface.
- If the DLL is in a user profile directory (`C:\Users\*`), determine which user account owns the directory and whether their session was active at the time.

## Coverage Notes

This query complements but does not replace patching for CVE-2021-34527 (PrintNightmare) and related spooler vulnerabilities. It provides detection for both known and novel spooler DLL hijacking techniques.

## Related Queries

- [DLL Loaded by SYSTEM from User-Writable Paths](03-generic-dll-load-user-writable.md)
