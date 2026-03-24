# Batch Files Executed by SYSTEM from User-Writable Paths

## Metadata

| Field | Value |
|---|---|
| **Author** | Jacob Skoog |
| **Created** | 2026-03-21 |
| **Platform** | Microsoft Defender XDR - Advanced Hunting |
| **MITRE ATT&CK** | T1059.003 - Command and Scripting Interpreter: Windows Command Shell |
| **MITRE ATT&CK** | T1574 - Hijack Execution Flow |
| **Severity** | High |
| **Data Sources** | DeviceProcessEvents |
| **Minimum Role** | Security Reader |

## Description

Detects `cmd.exe` running batch files (`.bat`, `.cmd`) at SYSTEM integrity level from user-writable locations. This pattern can indicate privilege escalation where an attacker places a malicious batch file in a location that a SYSTEM-level process or scheduled task will execute.

Common attack scenarios include writable service paths, misconfigured scheduled tasks, and startup scripts pointing to user-controlled directories.

## Query

```kql
// Title: SYSTEM Batch File Execution from User-Writable Paths
// MITRE: T1059.003, T1574
// Description: Detects cmd.exe executing .bat or .cmd files at SYSTEM integrity from
//              user-writable paths. Indicates potential privilege escalation via planted
//              batch files.
// Author: Jacob Skoog
let UserWritablePaths = dynamic(["c:\\users", "c:\\programdata", "c:\\windows\\temp", "c:\\temp"]);
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessIntegrityLevel =~ "System"
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has_any (".bat", ".cmd")
| where FolderPath has_any (UserWritablePaths)
    or ProcessCommandLine has_any (UserWritablePaths)
| extend ScriptPath = extract(@'(?i)(?:\/c|\/k|")\s*"?([^"]+\.(?:bat|cmd))', 1, ProcessCommandLine)
| project Timestamp, DeviceName, ProcessCommandLine, ScriptPath,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessAccountName, FolderPath
| sort by Timestamp desc
```

## Triage Notes

- Check the `InitiatingProcessFileName` to understand what spawned the batch execution. If it is `svchost.exe`, `services.exe`, or `schtasks.exe`, investigate the corresponding service or task configuration.
- Legitimate hits can come from software installers, SCCM/Intune scripts, or backup agents. Build a baseline of known-good script paths and consider adding them to an exclusion list after validation.
- If the batch file still exists on disk, retrieve and analyze its contents.
- Correlate with `DeviceFileEvents` to find when the batch file was created and by whom.

## Related Queries

- [Script Files Created by SYSTEM in User-Writable Paths](07-script-files-created-by-system-user-writable.md)
- [Process Creation by SYSTEM in User-Writable Paths](06-process-creation-system-user-writable.md)
