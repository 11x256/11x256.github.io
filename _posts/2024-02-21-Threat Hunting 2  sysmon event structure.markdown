---
title: "Threat Hunting with sysmon 101 part 2: Process creation event"
date: 2024-02-21 11:40:00 +0200
categories: Threat_hunting
description: Threat hunting with sysmon 
tags: Threat hunting sysmon Threat-hunting windows logs ELK
published: true
---
# **Introduction**

In this article, we'll explore the structure of process creation event (event_id == 1).

# Process creation event
The process creation event, typically denoted as Event ID 1 in Sysmon, is a critical aspect of system monitoring and security analysis. When a new process is spawned on a Windows system, Sysmon captures and logs detailed information about this event, providing valuable insights into the execution of programs and potential security threats. Here's a comprehensive description of the process creation event:

- **Event ID**: The event ID for process creation in Sysmon is 1. This ID serves as a unique identifier to differentiate process creation events from other types of events logged by Sysmon.

- **Timestamp**: The timestamp indicates the exact date and time when the process creation event occurred. This timing information is crucial for correlating events, establishing timelines during forensic investigations, and identifying patterns of suspicious activity.

- **Process Information**:
  - **Process Name**: The name of the newly created process, which provides insight into the executable or application being launched.
  - **Process ID (PID)**: A unique identifier assigned to the newly created process by the operating system. PID helps in tracking and referencing the process throughout its lifecycle.
  - **ProcessGuid**: is a unique value for this process across a domain to make event correlation easier. PID is not unique, and it can be reused on the same,which can cause confusion in investigations. Thats why microsoft added the process guid field, which is a unique alternative to the PID.
  - **Parent Process Name**: The name of the parent process that initiated the creation of the new process. Understanding the parent process can reveal the origin of the execution chain.
  - **Parent Process ID (PPID)**: The PID of the parent process. Knowing the PPID allows analysts to map the relationship between the parent and child processes.
  - **ParentProcessGuid**: Same as ProcessGuid, but for the parent process. Relying on PID and PPID to map relationships between process will not be accurate in all cases. GUIDs should be used instead.
  - **Command Line**: The command line parameters used to launch the new process, if available. Command line information provides additional context about the execution environment and potential malicious intent.
  - **Hash of the Executable File**: The cryptographic hash (e.g., SHA-256) of the executable file corresponding to the new process. Hash values enable file integrity verification and facilitate the identification of known malware or suspicious binaries.

- **Security Information**:
  - **User**: The user account under which the new process was created. User context is essential for determining privileges, permissions, and potential unauthorized activity.
  - **Logon ID**: A unique identifier associated with the user's logon session. Logon ID helps in linking process creation events to specific user sessions, aiding in user attribution and accountability.

# Example of a process creation event
Lets use this command to get one event with event_id ==1 (process creation event).  
`(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 1).message`
This would print output like this:
```
Process Create:
RuleName: -
UtcTime: 2024-02-22 00:02:08.800
ProcessGuid: {e3b07ee5-8f00-65d6-e605-000000000400}
ProcessId: 4736
Image: C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
FileVersion: 121.0.2277.128
Description: Microsoft Edge
Product: Microsoft Edge
Company: Microsoft Corporation
OriginalFileName: msedge.exe
CommandLine: "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --default-search-provider=? --out-pipe-name=MSEdgeDefault59f0370dh8777h49afh8f81h26e48962a41d
CurrentDirectory: C:\Windows\ImmersiveControlPanel\
User: DESKTOP-D3OJRQ4\abdo-pc
LogonGuid: {e3b07ee5-78ab-65d6-a79d-020000000000}
LogonId: 0x29DA7
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA256=09246B7D443CA032967573CE80EE41F96ECFDBF9B2F8EBCE7B8EB5C3E89C831B
ParentProcessGuid: {e3b07ee5-78ad-65d6-5200-000000000400}
ParentProcessId: 3688
ParentImage: C:\Windows\System32\sihost.exe
ParentCommandLine: sihost.exe
ParentUser: DESKTOP-D3OJRQ4\abdo-pc
PS C:\Users\abdo-pc\Downloads\Sysmon> 
```

Some of the fields in the output are more important than other from the prespective of threat hunting, for example, commandline can have valuable information , as we will see in the next post.