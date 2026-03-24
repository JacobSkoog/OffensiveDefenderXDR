# Script Files Created by SYSTEM in User-Writable Paths

## Metadata

| Field | Value |
|---|---|
| **Author** | Jacob Skoog |
| **Created** | 2026-03-21 |
| **Platform** | Microsoft Defender XDR - Advanced Hunting |
| **MITRE ATT&CK** | T1059 - Command and Scripting Interpreter |
| **MITRE ATT&CK** | T1105 - Ingress Tool Transfer |
| **MITRE ATT&CK** | T1036 - Masquerading |
| **Severity** | Medium-High |
| **Data Sources** | DeviceFileEvents |
| **Minimum Role** | Security Reader |

## Description

Detects script files (`.cmd`, `.bat`, `.ps1`, `.vbs`, `.js`, `.wsf`) created by SYSTEM-context processes in user-writable directories. While some legitimate system operations create scripts in these locations (e.g., GPO logon scripts, software deployment), this activity can also indicate an attacker staging scripts for later execution or a compromised SYSTEM process writing malicious payloads.

## Query

```kql
// Title: Script File Creation by SYSTEM in User-Writable Paths
// MITRE: T1059, T1105, T1036
// Description: Detects SYSTEM-context processes creating script files in directories
//              writable by standard users. May indicate staging of malicious scripts
//              or persistence mechanisms.
// Author: Jacob Skoog
let UserWritablePaths = dynamic(["c:\\users", "c:\\programdata", "c:\\windows\\temp", "c:\\temp"]);
let ScriptExtensions = dynamic([".cmd", ".bat", ".ps1", ".vbs", ".js", ".wsf", ".hta"]);
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType == "FileCreated"
| where InitiatingProcessAccountName =~ "system"
    or InitiatingProcessIntegrityLevel =~ "System"
| where FolderPath has_any (UserWritablePaths)
| where FileName has_any (ScriptExtensions)
| where FileName !endswith ".ps1xml"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    InitiatingProcessAccountName
| sort by Timestamp desc
```

## Triage Notes

- Check the `InitiatingProcessFileName` to understand what SYSTEM process is writing scripts. Common legitimate sources include:
  - `svchost.exe` (GPO processing, Windows Update)
  - `ccmexec.exe` (SCCM agent)
  - `msiexec.exe` (MSI installations)
- Script files written to user profile directories by SYSTEM are more suspicious than those in ProgramData, since user profiles are more tightly associated with user activity.
- If the script still exists, retrieve and review its contents via MDE Live Response.
- `.hta` files created by SYSTEM are always worth investigating since HTA is a common attacker payload format and rarely used legitimately in modern environments.

## Related Queries

- [Batch Files Executed by SYSTEM from User-Writable Paths](02-bat-files-system-user-writable.md)
- [SYSTEM Process Execution from User-Writable Paths](06-process-creation-system-user-writable.md)
