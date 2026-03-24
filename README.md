# OffensiveDefenderXDR - Privilege Escalation Detection Queries

A collection of Microsoft Defender XDR Advanced Hunting queries focused on detecting Windows local privilege escalation vectors. These queries are designed for proactive threat hunting and can be adapted into scheduled detection rules.

Defender XDR / KQL implementation of Offensive SIEM.

## Query Index

| # | Query | MITRE ATT&CK | Severity | Data Source |
|---|---|---|---|---|
| 01 | [Unquoted Service Paths](01-unquoted-service-paths.md) | T1574.009 | Medium | DeviceRegistryEvents, DeviceProcessEvents |
| 02 | [Batch Files Executed by SYSTEM from User-Writable Paths](02-bat-files-system-user-writable.md) | T1059.003, T1574 | High | DeviceProcessEvents |
| 03 | [DLL Loaded by SYSTEM from User-Writable Paths](03-generic-dll-load-user-writable.md) | T1574.001, T1574.002 | High | DeviceImageLoadEvents |
| 04 | [Printer Service DLL from User-Writable Paths](04-printer-dll-user-writable.md) | T1574.002, T1068 | High | DeviceImageLoadEvents |
| 05 | [SYSTEM Process Execution from Root-Level Subfolders](05-process-creation-system-root-subfolder.md) | T1574, T1036.005 | Medium-High | DeviceProcessEvents |
| 06 | [SYSTEM Process Execution from User-Writable Paths](06-process-creation-system-user-writable.md) | T1574, T1068 | High | DeviceProcessEvents |
| 07 | [Script Files Created by SYSTEM in User-Writable Paths](07-script-files-created-by-system-user-writable.md) | T1059, T1105 | Medium-High | DeviceFileEvents |
| 08 | [Service Binary Execution from User-Writable Paths](08-service-exe-user-writable.md) | T1574.010, T1543.003 | High | DeviceProcessEvents |
| 09 | [Scheduled Task Execution from User-Writable Paths](09-scheduled-task-user-writable.md) | T1053.005, T1574 | High | DeviceProcessEvents |

## Common Patterns Across All Queries

All improved queries share these patterns:

- Structured comment headers with MITRE mapping, description, and author
- Time scoping via `Timestamp > ago(24h)` for scheduled detection use
- User-writable paths defined as reusable `let` variables
- Case-insensitive exact matching (`=~`, `in~`) instead of loose substring matching (`contains`, `has`)
- Defender component exclusions where applicable
- SHA256 hashes in output where available for threat intel correlation

## Deployment Notes

These queries are written for interactive hunting but can be converted to custom detection rules in Defender XDR. When doing so:

- Adjust the `ago()` time window to match your detection rule frequency
- Add an `AlertEvidence` entity mapping for the `DeviceName` column
- Set the alert severity to match the documented severity in each query
- Consider consolidating related queries (e.g., 03 and 04) into a single rule with differentiated alert titles

## Author

Jacob Skoog
