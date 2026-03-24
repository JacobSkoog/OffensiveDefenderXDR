# Service Binary Execution from User-Writable Paths

## Metadata

| Field | Value |
|---|---|
| **Author** | Jacob Skoog |
| **Created** | 2026-03-21 |
| **Platform** | Microsoft Defender XDR - Advanced Hunting |
| **MITRE ATT&CK** | T1574.010 - Hijack Execution Flow: Services File Permissions Weakness |
| **MITRE ATT&CK** | T1543.003 - Create or Modify System Process: Windows Service |
| **Severity** | High |
| **Data Sources** | DeviceProcessEvents |
| **Minimum Role** | Security Reader |

## Description

Detects service binaries launched by the Windows Service Control Manager (`services.exe`) from user-writable directories. This is a direct indicator of misconfigured service paths or deliberate privilege escalation via service binary replacement. When `services.exe` is the parent process, the child was started as a Windows service, and if the binary resides in a writable location, any user with write access can replace it to gain the service's execution context (typically SYSTEM).

## Query

```kql
// Title: Service Binary Execution from User-Writable Paths
// MITRE: T1574.010, T1543.003
// Description: Detects services.exe spawning processes from directories writable by
//              standard users. Strong indicator of service binary hijacking or
//              misconfigured service paths.
// Author: Jacob Skoog
let UserWritablePaths = dynamic(["c:\\users", "c:\\programdata", "c:\\windows\\temp", "c:\\temp"]);
let DefenderPaths = dynamic([
    "c:\\programdata\\microsoft\\windows defender",
    "c:\\programdata\\microsoft\\windows defender advanced threat protection"
]);
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName =~ "services.exe"
| where FolderPath has_any (UserWritablePaths)
| where not(FolderPath has_any (DefenderPaths))
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine,
    SHA256, ProcessIntegrityLevel, AccountName
| sort by Timestamp desc
```

## Triage Notes

- This query has a high signal-to-noise ratio. Any service binary executing from `C:\Users\*` is almost certainly misconfigured or malicious.
- `C:\ProgramData` hits are more common and may be legitimate. Focus on subdirectories that are not vendor-specific application directories.
- Use the `SHA256` to check the binary against threat intelligence and to verify whether it matches the expected software.
- Cross-reference with the Unquoted Service Paths query. A service with both an unquoted path and a binary in a writable location is doubly exploitable.
- Check service configuration with `sc qc <ServiceName>` via MDE Live Response to see the configured account, start type, and full path.

## Companion: Identify the Service Name

If you get results from the main query, use this follow-up to identify which service corresponds to the binary:

```kql
// Title: Service Registry Lookup for Writable Path Binaries
// Description: Finds the service name for a known binary path from the main query results.
DeviceRegistryEvents
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"
| where RegistryValueName == "ImagePath"
| where RegistryValueData has "<insert_path_or_filename_here>"
| extend ServiceName = extract(@"Services\\([^\\]+)", 1, RegistryKey)
| project Timestamp, DeviceName, ServiceName, RegistryValueData
```

## Related Queries

- [Unquoted Service Paths](01-unquoted-service-paths.md)
- [SYSTEM Process Execution from User-Writable Paths](06-process-creation-system-user-writable.md)
- [SYSTEM Process Execution from Root-Level Subfolders](05-process-creation-system-root-subfolder.md)
