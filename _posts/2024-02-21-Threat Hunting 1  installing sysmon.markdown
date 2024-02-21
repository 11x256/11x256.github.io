---
title: "Threat Hunting with sysmon 101 part 1 sysmon installation"
date: 2024-02-21 11:40:00 +0200
categories: Threat_hunting
description: Threat hunting with sysmon 
tags: Threat hunting sysmon Threat-hunting windows logs ELK
published: true
---
# **Introduction**

In this article, we'll explore Sysmon, install it, and ensure its working properly.

# What is Sysmon?
Sysmon, short for System Monitor, is a powerful Windows system service and device driver that monitors and logs system activity to the Windows event log. Developed by Microsoft's Sysinternals team, Sysmon provides detailed information about process creations, network connections, file modifications, registry modifications, and more. It is commonly used for security monitoring, threat detection, and forensic analysis on Windows systems.

# Installing Sysmon
To install Sysmon on a Windows system, follow these steps:

1. **Download Sysmon**: Visit the official Sysinternals Sysmon page to download the latest version of Sysmon
[Download from here](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
![download!](/assets/images/th1/1.png)

2. **Extract the ZIP file**: After downloading Sysmon, extract the contents of the ZIP file to a folder on your computer.

3. **Open Command Prompt**: Open Command Prompt with administrative privileges. You can do this by searching for "cmd" in the Start menu, right-clicking on "Command Prompt," and selecting "Run as administrator."

4. **Navigate to the Sysmon directory**: Use the cd command to navigate to the directory where you extracted the Sysmon files.

5. **Install Sysmon**: Run the following command to install Sysmon: `sysmon.exe -i -accepteula`
This command installs Sysmon as a Windows service and accepts the end-user license agreement (EULA).


6. **Verify installation**: You can verify that Sysmon has been installed correctly by checking the Windows Event Viewer. Look for event logs with the source "Microsoft-Windows-Sysmon" to confirm that Sysmon is running and logging events.

