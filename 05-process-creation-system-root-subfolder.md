# SYSTEM Process Execution from Root-Level Subfolders

## Metadata

| Field | Value |
|---|---|
| **Author** | Jacob Skoog |
| **Created** | 2026-03-21 |
| **Platform** | Microsoft Defender XDR - Advanced Hunting |
| **MITRE ATT&CK** | T1574 - Hijack Execution Flow |
| **MITRE ATT&CK** | T1036.005 - Masquerading: Match Legitimate Name or Location |
| **Severity** | Medium-High |
| **Data Sources** | DeviceProcessEvents |
| **Minimum Role** | Security Reader |

## Description

Detects processes running at SYSTEM integrity level from non-standard root-level directories on the C: drive. Legitimate SYSTEM processes typically execute from well-known locations like `C:\Windows`, `C:\Program Files`, or `C:\ProgramData`. Execution from other root-level paths (e.g., `C:\Tools`, `C:\Scripts`, `C:\Packages`) often indicates misconfigured services, software with poor installation practices, or potentially malicious binaries placed in writable locations.

Directories created at the root of C: often have permissive ACLs, making them attractive targets for attackers seeking to hijack execution flow.

## Query

```kql
// Title: SYSTEM Process Execution from Root-Level Subfolders
// MITRE: T1574, T1036.005
// Description: Detects SYSTEM-integrity process execution from non-standard root-level
//              directories. These locations often have permissive ACLs and indicate
//              misconfiguration or malicious placement.
// Author: Jacob Skoog
let StandardRootPaths = dynamic([
    "c:\\program files",
    "c:\\program files (x86)",
    "c:\\windows",
    "c:\\programdata",
    "c:\\users"
]);
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessIntegrityLevel =~ "System"
| where FolderPath matches regex @"(?i)^c:\\[^\\]+\\"
| where not(FolderPath has_any (StandardRootPaths))
| extend RootFolder = extract(@"(?i)(c:\\[^\\]+)", 1, FolderPath)
| summarize
    ExecutionCount = count(),
    DistinctDevices = dcount(DeviceName),
    DistinctProcesses = make_set(FileName, 10),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    SamplePaths = make_set(FolderPath, 5)
    by RootFolder
| sort by DistinctDevices asc, ExecutionCount asc
```

## Triage Notes

- Common legitimate hits include third-party agent software installed to paths like `C:\Agent`, `C:\Monitoring`, or `C:\Backup`. These should be baselined and excluded once validated.
- Focus investigation on root folders that appear on very few devices (low `DistinctDevices`), as these are more likely to be anomalous.
- Check directory ACLs on flagged root folders. If standard users can write to them, the combination with SYSTEM execution creates a privilege escalation vector.
- Cross-reference with the Unquoted Service Paths query to see if any services point to these non-standard directories.

## Expanded Coverage

Consider also monitoring other drive letters if your environment has additional volumes:

```kql
// Extended version covering all drive letters
| where FolderPath matches regex @"(?i)^[a-z]:\\[^\\]+\\"
| where not(FolderPath has_any (StandardRootPaths))
```

## Related Queries

- [Unquoted Service Paths](01-unquoted-service-paths.md)
- [Service EXE in User-Writable Paths](08-service-exe-user-writable.md)
