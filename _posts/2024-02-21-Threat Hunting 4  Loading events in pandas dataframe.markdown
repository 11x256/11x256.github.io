---
title: "Threat Hunting with sysmon 101 part 3: Command line investigation"
date: 2024-02-21 11:40:00 +0200
categories: Threat_hunting
description: Threat hunting with sysmon 
tags: Threat hunting sysmon Threat-hunting windows logs ELK
published: false
---

In this article, we'll look at Mitre technique T1059.001 [text](https://attack.mitre.org/techniques/T1059/001/). 

# Overview of T1059.001
T1059.001 is categorized under the Execution tactic in the MITRE ATT&CK framework. It involves the use of command-line interfaces (CLIs) or scripting interpreters to execute commands or scripts, which can be leveraged by adversaries for various purposes, including lateral movement, privilege escalation, and data exfiltration. Common command-line interfaces and scripting interpreters utilized by adversaries include PowerShell, Command Prompt (cmd.exe), Bash, Python, and others.

The example we have here will be a powershell shell command that is used to download and execute a powershell script hosted on github. The downloaded script in a test script that will just open notepad.exe when executed.
 