# Queries

## Unquoted Service Paths
```KQL
DeviceRegistryEvents  
|where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"  
| where RegistryValueName == "ImagePath"  
| where RegistryValueData contains " " and not(RegistryValueData startswith "\"")  
| summarize count() by DeviceName  
  
DeviceRegistryEvents  
| where ActionType == "RegistryValueSet"  
| where RegistryKey startswith @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"  
| where RegistryValueName == "ImagePath"  
| where RegistryValueData contains " " and not(RegistryValueData startswith "\"")  
| project Timestamp, DeviceName, RegistryKey, RegistryValueData  
  
DeviceProcessEvents  
| where FileName endswith ".exe"  
| where ProcessCommandLine contains " " and ProcessCommandLine contains "c:" and not(ProcessCommandLine startswith "\"")  
| where InitiatingProcessFileName == "services.exe" or ProcessCommandLine contains "ImagePath"  
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessAccountName
```


## Bat files in user writable paths

```KQL
DeviceProcessEvents
| where ProcessIntegrityLevel has "System" and
        FileName has "cmd.exe" and
        ProcessCommandLine contains ".bat" and
        (ProcessCommandLine contains "c:\\users" or ProcessCommandLine contains "c:\\ProgramData" )
```


## Generic DLL Load in user writable paths

```KQL
DeviceImageLoadEvents
| where InitiatingProcessAccountName has "system" and
         (FolderPath contains "c:\\users" or FolderPath contains "c:\\ProgramData" ) and
         FileName contains ".dll"
```


## Printer DLL in user writable paths

```KQL
DeviceImageLoadEvents
| where InitiatingProcessAccountName has "system" and
         (FolderPath contains "c:\\users" or FolderPath contains "c:\\ProgramData" ) and // (FolderPath notcontains "c:\\Windows\\System32\\" and FolderPath notcontains "c:\\Program Files" ) and
         FileName contains ".dll" and
        (InitiatingProcessFileName contains "spoolsv.exe" or InitiatingProcessFileName contains "printisolationhost.exe") 
```


## Process Creation by system in root subfolder

```KQL
DeviceProcessEvents
| where ProcessIntegrityLevel contains "System" and
        (FolderPath notcontains "c:\\Program Files" and FolderPath notcontains "c:\\Windows" and FolderPath notcontains "c:\\Users" and FolderPath notcontains "c:\\ProgramData") and
        FolderPath contains "c:\\"
```

 
## Process creation by system in user writable path 

```KQL
DeviceProcessEvents| where ProcessIntegrityLevel has "System" and
        (FolderPath contains "c:\\users" or FolderPath contains "c:\\ProgramData" ) and
         FileName !in ("MpCmdRun.exe","MpDlpService.exe", "MpDefenderCoreService.exe") and
         FolderPath notcontains "C:\\ProgramData\\Microsoft\\Windows Defender"
```


## Scheduled task from user writable path

```KQL
DeviceProcessEvents
| where InitiatingProcessFileName has "schtasks.exe" and
         (FolderPath contains "c:\\users" or FolderPath contains "c:\\Windows\\Temp" or FolderPath contains "c:\\ProgramData" ) and
         AccountName has "system"
```


## Script files created by system in user writable path

```KQL
DeviceFileEvents
| where ActionType == "FileCreated" and
        InitiatingProcessAccountName contains "system" and
        (FileName contains ".cmd" or FileName contains ".bat" or FileName contains ".ps1" or FileName contains ".vbs") and
        (FolderPath contains "c:\\users" or FolderPath contains "c:\\ProgramData" )
```


## Service exe in user writable paths

```KQL
DeviceProcessEvents
| where ProcessIntegrityLevel contains "system" and
        InitiatingProcessFileName contains "services.exe" and
        (FolderPath contains "c:\\ProgramData" or FolderPath contains "c:\\Users")
```
