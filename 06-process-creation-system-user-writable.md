# SYSTEM Process Execution from User-Writable Paths

## Metadata

| Field | Value |
|---|---|
| **Author** | Jacob Skoog |
| **Created** | 2026-03-21 |
| **Platform** | Microsoft Defender XDR - Advanced Hunting |
| **MITRE ATT&CK** | T1574 - Hijack Execution Flow |
| **MITRE ATT&CK** | T1068 - Exploitation for Privilege Escalation |
| **Severity** | High |
| **Data Sources** | DeviceProcessEvents |
| **Minimum Role** | Security Reader |

## Description

Detects executable processes running at SYSTEM integrity level from user-writable directories (`C:\Users`, `C:\ProgramData`). This is a core privilege escalation indicator. If a SYSTEM-level service or task executes a binary from a path that a standard user can modify, the user can replace or manipulate that binary to gain SYSTEM privileges.

## Query

```kql
// Title: SYSTEM Process Execution from User-Writable Paths
// MITRE: T1574, T1068
// Description: Detects SYSTEM-integrity processes executing from directories writable
//              by standard users. Core privilege escalation detection.
// Author: Jacob Skoog
let UserWritablePaths = dynamic(["c:\\users", "c:\\programdata", "c:\\windows\\temp", "c:\\temp"]);
let DefenderExclusions = dynamic([
    "MpCmdRun.exe",
    "MpDlpService.exe",
    "MpDefenderCoreService.exe",
    "MsSense.exe",
    "SenseCncProxy.exe",
    "SenseIR.exe",
    "MsMpEng.exe"
]);
let DefenderPaths = dynamic([
    "c:\\programdata\\microsoft\\windows defender",
    "c:\\programdata\\microsoft\\windows defender advanced threat protection"
]);
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessIntegrityLevel =~ "System"
| where FolderPath has_any (UserWritablePaths)
| where FileName !in~ (DefenderExclusions)
| where not(FolderPath has_any (DefenderPaths))
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine,
    SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine,
    AccountName
| sort by Timestamp desc
```

## Triage Notes

- The most suspicious results come from `C:\Users\<username>\*` paths combined with SYSTEM execution. This strongly suggests a user-planted binary being executed with elevated privileges.
- Check the `InitiatingProcessFileName` to understand the execution chain. Key parent processes to note:
  - `services.exe` = service execution (check service configuration)
  - `svchost.exe` = scheduled task or service host (check task scheduler)
  - `wmiprvse.exe` = WMI-based execution (check WMI subscriptions)
- Legitimate software that commonly triggers this: SCCM/Intune agents, some AV products, monitoring tools, and poorly packaged enterprise software.
- Build and maintain an exclusion list specific to your environment. Start with the Defender exclusions above and add validated entries over time.

## Tuning Template

```kql
// Add validated exclusions here as you baseline your environment
let EnvironmentExclusions = dynamic([
    // "SomeAgent.exe",
    // "BackupService.exe"
]);
```

## Related Queries

- [DLL Loaded by SYSTEM from User-Writable Paths](03-generic-dll-load-user-writable.md)
- [Batch Files Executed by SYSTEM from User-Writable Paths](02-bat-files-system-user-writable.md)
- [Service EXE in User-Writable Paths](08-service-exe-user-writable.md)
