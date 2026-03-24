# DLL Loaded by SYSTEM from User-Writable Paths

## Metadata

| Field | Value |
|---|---|
| **Author** | Jacob Skoog |
| **Created** | 2026-03-21 |
| **Platform** | Microsoft Defender XDR - Advanced Hunting |
| **MITRE ATT&CK** | T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking |
| **MITRE ATT&CK** | T1574.002 - Hijack Execution Flow: DLL Side-Loading |
| **Severity** | High |
| **Data Sources** | DeviceImageLoadEvents |
| **Minimum Role** | Security Reader |

## Description

Detects DLL files loaded by SYSTEM-level processes from user-writable directories. When a process running as SYSTEM loads a DLL from a location that standard users can write to, it creates a privilege escalation opportunity. An attacker can place a malicious DLL in the writable path, and the SYSTEM process will load and execute it with full privileges.

This is a broad detection meant to surface DLL hijacking and side-loading across all SYSTEM processes. For printer-specific DLL hijacking, see the dedicated Printer DLL query.

## Query

```kql
// Title: SYSTEM DLL Load from User-Writable Paths
// MITRE: T1574.001, T1574.002
// Description: Detects DLL loads by SYSTEM-context processes from paths that standard
//              users can write to. Broad detection for DLL hijacking and side-loading.
// Author: Jacob Skoog
let UserWritablePaths = dynamic(["c:\\users", "c:\\programdata", "c:\\windows\\temp", "c:\\temp"]);
let KnownSafeDLLPaths = dynamic([
    "c:\\programdata\\microsoft\\windows defender",
    "c:\\programdata\\microsoft\\windows defender advanced threat protection"
]);
DeviceImageLoadEvents
| where Timestamp > ago(24h)
| where InitiatingProcessAccountName =~ "system"
    or InitiatingProcessIntegrityLevel =~ "System"
| where FolderPath has_any (UserWritablePaths)
| where FolderPath !has_any (KnownSafeDLLPaths)
| where FileName endswith ".dll"
| summarize
    LoadCount = count(),
    DistinctDevices = dcount(DeviceName),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    SampleProcesses = make_set(InitiatingProcessFileName, 5)
    by FileName, FolderPath
| where DistinctDevices < 10
| sort by DistinctDevices asc, LoadCount asc
```

## Triage Notes

- This query is intentionally broad and will require environment-specific tuning. Expect to add exclusions for legitimate software that installs components in ProgramData.
- Low `DistinctDevices` count combined with a SYSTEM-level load from `C:\Users\*` is the highest-signal combination.
- Check the DLL's digital signature status. Unsigned DLLs in these locations loaded by SYSTEM are worth investigating.
- Cross-reference the `InitiatingProcessFileName` with the DLL name. Some applications legitimately side-load DLLs from their own writable installation directories.
- Consider correlating with `DeviceFileEvents` to identify when the DLL was written to disk and by which process/user.

## Tuning Recommendations

Add environment-specific exclusions to `KnownSafeDLLPaths` as you baseline. Common additions include paths for:

- Endpoint management agents (SCCM, Intune, etc.)
- Backup software
- Monitoring agents
- AV/EDR components other than Defender

## Related Queries

- [Printer DLL in User-Writable Paths](04-printer-dll-user-writable.md)
- [Service EXE in User-Writable Paths](08-service-exe-user-writable.md)
