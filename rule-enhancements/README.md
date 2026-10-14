# Enhancing built-in Microsoft Sentinel rules

Out-of-the-box analytics rules often fire with too little context to triage quickly. These are enhanced versions I wrote to add **who, from where, and which parent process** to the alert, so the analyst doesn't have to pivot by hand.

> The base rules are Microsoft Sentinel built-ins. The enhancements are mine.

## 1. Base64-encoded Windows process command lines

Adds the parent process, the user, and the logon session, which ties the encoded command to an interactive or service logon.

```kql
SecurityEvent
| where EventID == 4688
| where isnotempty(CommandLine)
| where CommandLine has_any ("TVqQAAMAAAAEAAA",       // base64 of a PE header ("MZ...")
                             "UEsDBBQAAAAIAAAAAE",    // base64 of a ZIP header ("PK...")
                             "YmFzZTY0IGVuY29kaW5n")  // "base64 encoding"
| extend HostName  = tostring(split(Computer, '.')[0]),
         DnsDomain = strcat_array(array_slice(split(Computer, '.'), 1, -1), '.')
| project TimeGenerated, HostName, DnsDomain,
          User = strcat(SubjectDomainName, "\\", SubjectUserName), SubjectLogonId,
          ParentProcessName, NewProcessName, CommandLine
```

## 2. Security event log cleared (Event ID 1102)

Adds who cleared the log and which process ran in that logon session just before it. That process is usually the clearing tool (`wevtutil`, PowerShell, ...).

```kql
let cleared = SecurityEvent
    | where EventID == 1102
    | project ClearedAt = TimeGenerated, Computer, SubjectUserName, SubjectDomainName, SubjectLogonId;
cleared
| join kind=leftouter (
    SecurityEvent
    | where EventID == 4688
    | project ProcTime = TimeGenerated, Computer, SubjectLogonId, NewProcessName, CommandLine
  ) on Computer, SubjectLogonId
| where isnull(ProcTime) or ProcTime between ((ClearedAt - 5m) .. ClearedAt)
| summarize ProcessesBeforeClear = make_set(strcat(NewProcessName, " ", CommandLine), 10)
          by ClearedAt, Computer, User = strcat(SubjectDomainName, "\\", SubjectUserName), SubjectLogonId
| extend HostName = tostring(split(Computer, '.')[0])
```

## 3. Process lookup on one device (Defender for Endpoint)

A template for "what ran on this box with this name?" during triage.

```kql
let device = "<device-name>";
let pattern = ".exe";            // a file name, extension or command-line fragment
DeviceProcessEvents
| where Timestamp > ago(1d)
| where DeviceName has device
| where FileName has pattern or ProcessCommandLine has pattern or InitiatingProcessCommandLine has pattern
| project Timestamp, DeviceName, AccountName, FileName, ProcessId, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

**Why rewrite rather than copy the originals?** My first drafts pulled the parent command line with `toscalar(...)` inside `extend`. `toscalar` returns a single value for the whole table, not one per row, so every alert showed the *same* parent. The versions above take parent fields from the event itself (`ParentProcessName` in 4688) or join on the logon session instead.
