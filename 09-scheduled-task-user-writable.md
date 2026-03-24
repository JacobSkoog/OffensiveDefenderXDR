# Scheduled Task Execution from User-Writable Paths

## Metadata

| Field | Value |
|---|---|
| **Author** | Jacob Skoog |
| **Created** | 2026-03-21 |
| **Platform** | Microsoft Defender XDR - Advanced Hunting |
| **MITRE ATT&CK** | T1053.005 - Scheduled Task/Job: Scheduled Task |
| **MITRE ATT&CK** | T1574 - Hijack Execution Flow |
| **Severity** | High |
| **Data Sources** | DeviceProcessEvents |
| **Minimum Role** | Security Reader |

## Description

Detects processes spawned by `schtasks.exe` running as SYSTEM from user-writable paths. Attackers commonly abuse scheduled tasks for persistence and privilege escalation. A task running as SYSTEM that executes a binary from a user-writable location allows any user with write access to that path to escalate privileges by replacing the target binary.

## Query

```kql
// Title: Scheduled Task SYSTEM Execution from User-Writable Paths
// MITRE: T1053.005, T1574
// Description: Detects SYSTEM-context process execution triggered by scheduled tasks
//              from user-writable directories. Indicates potential privilege escalation
//              via task hijacking.
// Author: Jacob Skoog
let UserWritablePaths = dynamic(["c:\\users", "c:\\programdata", "c:\\windows\\temp", "c:\\temp"]);
DeviceProcessEvents
| where Timestamp > ago(24h)
| where AccountName =~ "system" or ProcessIntegrityLevel =~ "System"
| where InitiatingProcessFileName =~ "svchost.exe"
    or InitiatingProcessFileName =~ "schtasks.exe"
    or InitiatingProcessCommandLine has "Schedule"
| where FolderPath has_any (UserWritablePaths)
| extend TaskContext = case(
    InitiatingProcessFileName =~ "svchost.exe" and InitiatingProcessCommandLine has "Schedule", "TaskSchedulerEngine",
    InitiatingProcessFileName =~ "schtasks.exe", "schtasks.exe direct",
    "Other"
    )
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine,
    SHA256, TaskContext, InitiatingProcessFileName,
    InitiatingProcessCommandLine, AccountName
| sort by Timestamp desc
```

## Triage Notes

- Check what scheduled task corresponds to the execution. Use `schtasks /query /fo LIST /v` on the device or query the task configuration via MDE Live Response.
- Tasks with `TaskContext = "schtasks.exe direct"` where a non-admin user created a SYSTEM task are especially suspicious (this usually requires admin privileges, so it could indicate prior compromise).
- Common false positives: Windows Update tasks, Defender scan tasks, SCCM deployment tasks, and GPO-deployed software installation tasks.
- Investigate the `FolderPath` ACLs. A SYSTEM task pointing to a path writable by standard users is a vulnerability regardless of current exploitation.

## Extended Detection

To also catch task creation events (not just execution), consider adding this companion query:

```kql
// Title: Scheduled Task Created Pointing to User-Writable Path
// Description: Detects creation of scheduled tasks that reference user-writable directories.
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any (UserWritablePaths)
| project Timestamp, DeviceName, ProcessCommandLine, AccountName,
    InitiatingProcessFileName
```

## Related Queries

- [SYSTEM Process Execution from User-Writable Paths](06-process-creation-system-user-writable.md)
- [Script Files Created by SYSTEM in User-Writable Paths](07-script-files-created-by-system-user-writable.md)
