# Unquoted Service Paths

## Metadata

| Field | Value |
|---|---|
| **Author** | Jacob Skoog |
| **Created** | 2026-03-21 |
| **Platform** | Microsoft Defender XDR - Advanced Hunting |
| **MITRE ATT&CK** | T1574.009 - Hijack Execution Flow: Path Interception by Unquoted Path |
| **Severity** | Medium |
| **Data Sources** | DeviceRegistryEvents, DeviceProcessEvents |
| **Minimum Role** | Security Reader |

## Description

Detects Windows services with unquoted ImagePath values that contain spaces. When a service path is unquoted and includes spaces, Windows will attempt to resolve the path by trying each space-delimited segment as a potential executable location. An attacker who can write to one of these intermediate paths can hijack service execution.

This detection consists of three complementary queries:

1. **Inventory query** - Finds all currently registered services with unquoted paths (point-in-time snapshot).
2. **Change detection query** - Catches new or modified service registrations with unquoted paths.
3. **Execution query** - Detects actual process execution that may result from unquoted path exploitation.

## Queries

### 1A - Inventory: Existing Unquoted Service Paths

```kql
// Title: Unquoted Service Path - Inventory
// MITRE: T1574.009
// Description: Identifies existing services with unquoted ImagePath values containing spaces.
//              Use for periodic hygiene sweeps. Results should be triaged and remediated.
// Author: Jacob Skoog
DeviceRegistryEvents
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"
| where RegistryValueName == "ImagePath"
| where RegistryValueData has " "
    and not(RegistryValueData startswith "\"")
    and not(RegistryValueData startswith "\\??\\")
| where RegistryValueData !startswith "C:\\Windows\\system32\\"
    and RegistryValueData !startswith "C:\\Windows\\SysWOW64\\"
| extend ServiceName = extract(@"Services\\([^\\]+)", 1, RegistryKey)
| summarize
    LastSeen = max(Timestamp),
    arg_max(Timestamp, RegistryValueData)
    by DeviceName, ServiceName
| project LastSeen, DeviceName, ServiceName, ImagePath = RegistryValueData
| sort by DeviceName asc, ServiceName asc
```

### 1B - Change Detection: New or Modified Unquoted Service Paths

```kql
// Title: Unquoted Service Path - Change Detection
// MITRE: T1574.009
// Description: Detects new or modified service registrations where ImagePath is unquoted
//              and contains spaces. May indicate an attacker planting a vulnerable service.
// Author: Jacob Skoog
DeviceRegistryEvents
| where Timestamp > ago(24h)
| where ActionType == "RegistryValueSet"
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"
| where RegistryValueName == "ImagePath"
| where RegistryValueData has " "
    and not(RegistryValueData startswith "\"")
    and not(RegistryValueData startswith "\\??\\")
| extend ServiceName = extract(@"Services\\([^\\]+)", 1, RegistryKey)
| project Timestamp, DeviceName, ServiceName, ImagePath = RegistryValueData,
    InitiatingProcessFileName, InitiatingProcessAccountName
| sort by Timestamp desc
```

### 1C - Execution: Process Spawned via Unquoted Path Resolution

```kql
// Title: Unquoted Service Path - Exploitation Execution
// MITRE: T1574.009
// Description: Detects process execution potentially caused by unquoted service path resolution.
//              Looks for services.exe spawning processes where the command line is unquoted
//              and contains spaces.
// Author: Jacob Skoog
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName =~ "services.exe"
| where FileName endswith ".exe"
| where ProcessCommandLine has " "
    and not(ProcessCommandLine startswith "\"")
    and not(ProcessCommandLine startswith "'")
| where FolderPath !startswith "C:\\Windows\\"
    and FolderPath !startswith "C:\\Program Files\\"
    and FolderPath !startswith "C:\\Program Files (x86)\\"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine,
    ProcessIntegrityLevel, AccountName
| sort by Timestamp desc
```

## Triage Notes

- The inventory query (1A) will produce results in most environments. Not every unquoted service path is exploitable. Exploitation requires write access to an intermediate directory in the path.
- Prioritize paths where the space occurs early (e.g., `C:\Program Files\Some App\service.exe` is the classic case, but only exploitable if `C:\Program.exe` can be written).
- Cross-reference with file system ACLs where possible to determine actual exploitability.
- The change detection query (1B) is the highest-signal alert. New unquoted services appearing in production should always be investigated.
- Consider feeding 1A results into a remediation workflow to quote the paths proactively.
