# Threat Hunt Report: Unauthorised TOR Usage
- [Scenario Creation]()

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)

- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario
Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyse related security incidents to mitigate potential risks. If any use of TOR is found, notify management.  

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken
### 1. Searched the `DeviceFileEvents` Table
Looked at the DeviceFileEvents table for any files with the FileName that contains “tor”.  
The first suspicious log was at `2026-07-03T12:54:36.4967777Z`, marking the download of “tor-browser-windows-x86_64-portable-15.0.17.exe” (SHA256:`13d3e0a229443b643c683de1615456ace7632f4d801b62720a9390ad953f8c80`) an installer, into the Downloads folder by user “gregsz”. Following the download multiple Tor related .txt files have been created as well straight after the download of the installer. Lastly at `2026-07-03T13:25:35.6944602Z` a new file has been created `tor-shopping-list.txt.lnk` (SHA256:`1bc832c185dab6136a3843a82028dabe3969254f6352dbc17450a5a7ab8736a1`).  

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where FileName contains "tor"
| project Timestamp, DeviceName,InitiatingProcessAccountName, ActionType, FileName, FolderPath, SHA256
| order by Timestamp asc
```
<img width="1426" height="575" alt="Képernyőkép 2026-07-04 130752" src="https://github.com/user-attachments/assets/ec138274-44f4-4778-a627-0aa6b3056175" />  
  
---

### 2. Searched the `DeviceProcessEvents` Table
Searched the DeviceProcessEvents table for any events which contained the string name of the previously found file “tor-browser-windows-x86_64-portable-15.0.17.exe”. The results show that at 2026-07-03T12:57:21.7051939Z user “gregsz” has used the command “tor-browser-windows-x86_64-portable-15.0.17.exe  /S” which has initiated a silent installation of TOR.  

**Query used to locate event:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where AccountName == "gregsz"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.17.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

<img width="1640" height="885" alt="Képernyőkép 2026-07-04 133523" src="https://github.com/user-attachments/assets/2906a393-7b4c-444d-89b5-6c24bb969f95" />  

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution
Examined the DeviceProcessEvents table further for evidence of TOR browser execution. The logs showed that starting from 2026-07-03T12:57:57.5948971Z the user has opened the browser “firefox.exe” (SHA256: 241366fae863e43e7a046b66c820c12771f030b6b4590cf5fb2646a4f44de074) under the folder path “C:\Users\GregSz\Desktop\Tor Browser\Browser\firefox.exe”, suggesting that it is not normal firefox browser. Afterwards several other instances of firefox.exe have spawned in with an instance of “tor.exe” as well at 2026-07-03T12:58:13.1611513Z.  

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where AccountName == "gregsz"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
