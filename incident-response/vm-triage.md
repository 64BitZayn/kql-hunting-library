# VM / endpoint triage queries (Microsoft Defender for Endpoint)

Quick queries I used during incident response to scope what happened on one machine. Set `vmName` to the device name as it appears in Defender (`DeviceName`), and widen or narrow the time range with `lookback`.

## 1. Accepted Inbound Connections on a VM

```kql
let vmName = "<device-name>";
let lookback = 7d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where DeviceName == vmName
| where ActionType == "InboundConnectionAccepted"
| project Timestamp, DeviceName, LocalIP, LocalPort, RemoteIP, RemotePort, Protocol, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

## 2. Successful Connection on a VM

```kql
let vmName = "<device-name>";
let lookback = 7d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where DeviceName == vmName
| where ActionType == "ConnectionSuccess"
| project Timestamp, DeviceName, LocalIP, LocalPort, RemoteIP, RemotePort, Protocol, InitiatingProcessFileName, InitiatingProcessAccountName, ActionType
| order by Timestamp desc
```

## 3. Any Scripts Running/Ran on a VM

```kql
let vmName = "<device-name>";
let lookback = 7d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where DeviceName == vmName
| where FileName endswith ".ps1" or FileName endswith ".bat" or FileName endswith ".cmd" or FileName endswith ".sh" or FileName endswith ".py" or FileName  endswith ".vbs"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName, ProcessId
| order by Timestamp desc
```

## 4. Check Logins into VM

```kql
let vmName = "<device-name>";
let lookback = 7d;
DeviceLogonEvents
| where Timestamp > ago(lookback)
| where DeviceName == vmName
| where LogonType == "RemoteInteractive" or LogonType == "Network"
//| where LogonType == "Success"
| project Timestamp, DeviceName, AccountName, LogonType
| order by Timestamp desc
```

## 5. Check created scheduled tasks on VM

```kql
let vmName = "<device-name>";
let lookback = 7d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where DeviceName == vmName
| where FileName == "schtasks.exe" and ProcessCommandLine has "create"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName, ProcessId
| order by Timestamp desc
```

## 6. Check Registry Changes in a VM

```kql
let vmName = "<device-name>";
let lookback = 7d;
| where DeviceName == vmName
DeviceRegistryEvents
| where Timestamp > ago(lookback)
| where DeviceName == vmName
| where ActionType == "RegistryValueSet" or ActionType == "RegistryKeyCreated"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

## 7. Modifications in critical directories

```kql
let vmName = "VM NAME";
let lookback = 7d;
DeviceFileEvents
| where Timestamp > ago(lookback)
| where DeviceName == vmName
| where ActionType == "FileModified"
| where FolderPath startswith @"C:\Windows" or FolderPath startswith @"C:\Program Files" or FolderPath startswith @"C:\Users\Public"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

## 8. Privilege Escalation Attempts

```kql
let vmName = "VM NAME";
let lookback = 7d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where DeviceName == vmName
| where InitiatingProcessFileName in ("whoami.exe", "net.exe", "net1.exe", "tasklist.exe", "taskmgr.exe", "sc.exe", "wmic.exe", "powershell.exe", "cmd.exe", "at.exe", "schtasks.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName, ProcessId
| order by Timestamp desc
```

## 9. DLL Injection Attempts

```kql
let vmName = "VM NAME";
let lookback = 7d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where DeviceName == vmName
| where ActionType == "DllLoaded" and InitiatingProcessFileName in ("rundll32.exe", "regsvr32.exe")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessAccountName, ProcessId
| order by Timestamp desc
```

## 10. Check for Anomalous File Creation in Sensitive Directories

```kql
let vmName = "VM NAME";
let lookback = 7d;
DeviceFileEvents
| where Timestamp > ago(lookback)
| where DeviceName == vmName
| where ActionType == "FileCreated"
| where FolderPath startswith @"C:\Windows\System32" or FolderPath startswith @"C:\Windows\SysWOW64" or FolderPath startswith @"C:\ProgramData"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

## 11. Check for Credential Dumping Tools

```kql
let vmName = "VM NAME";
let lookback = 7d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where DeviceName == vmName
| where FileName in ("mimikatz.exe", "procdump.exe", "lsass.exe", "dllhost.exe", "taskmgr.exe", "powershell.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName, ProcessId
| order by Timestamp desc
```

## 12. Check for Suspicious WMI Activity

```kql
let vmName = "VM NAME";
let lookback = 7d;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where DeviceName == vmName
| where ProcessCommandLine has "wmic" or FileName == "wmiprvse.exe"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName, ProcessId
| order by Timestamp desc
```

## 13. Check for connection on a specific Port

```kql
let vmName = "<device-name>";
let PortNumber = 31337;
let lookback = 7d;
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where DeviceName == vmName
| where Protocol == "Tcp" // DeviceNetworkEvents reports "Tcp"/"Udp"
| where RemotePort == PortNumber or LocalPort == PortNumber
| summarize Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by RemoteIP, RemotePort, LocalPort, InitiatingProcessFileName
| order by Connections desc
```

## 14. Check for File Deletions in Sensitive Directories

```kql
let vmName = "<device-name>";
let lookback = 7d;
DeviceFileEvents
| where Timestamp > ago(lookback)
| where DeviceName == vmName
| where ActionType == "FileDeleted"
| where FolderPath startswith @"C:\Windows\System32" or FolderPath startswith @"C:\Windows\SysWOW64" or FolderPath startswith @"C:\ProgramData"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
```
