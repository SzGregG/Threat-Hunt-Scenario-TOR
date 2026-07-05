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
The first suspicious log was at `2026-07-03T12:54:36.4967777Z`, marking the download of “tor-browser-windows-x86_64-portable-15.0.17.exe” (SHA256:`13d3e0a229443b643c683de1615456ace7632f4d801b62720a9390ad953f8c80`) an installer, into the Downloads folder by user “gregsz”. Following the download multiple Tor related .txt files have been created as well straight after the download of the installer. Lastly at `2026-07-03T13:25:35.6944602Z` a new file has been created `tor-shopping-list.txt.txt` (SHA256:`90b980de6081605bd54d7aa9a725cefbf5131158de3b4ec03c4624a732d75651`).  

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
Searched the DeviceProcessEvents table for any events which contained the string name of the previously found file `tor-browser-windows-x86_64-portable-15.0.17.exe`. The results show that at `2026-07-03T12:57:21.7051939Z` user “gregsz” has used the command `tor-browser-windows-x86_64-portable-15.0.17.exe  /S` which has initiated a silent installation of TOR.  

**Query used to locate event:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where AccountName == "gregsz"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.17.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

<img width="1392" height="349" alt="Képernyőkép 2026-07-05 033411" src="https://github.com/user-attachments/assets/54bbd475-3ef3-4953-8ac1-d19afe1148f1" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution
Examined the DeviceProcessEvents table further for evidence of TOR browser execution. The logs showed that starting from 2026-07-03T12:57:57.5948971Z the user has opened the browser `firefox.exe` (SHA256: `241366fae863e43e7a046b66c820c12771f030b6b4590cf5fb2646a4f44de074`) under the folder path `C:\Users\GregSz\Desktop\Tor Browser\Browser\firefox.exe`, suggesting that it is not normal firefox browser. Afterwards several other instances of `firefox.exe` have spawned in with an instance of `tor.exe` as well at `2026-07-03T12:58:13.1611513Z`.  

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where AccountName == "gregsz"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1640" height="885" alt="Képernyőkép 2026-07-04 133523" src="https://github.com/user-attachments/assets/2906a393-7b4c-444d-89b5-6c24bb969f95" />  

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections
Investigated the DeviceNetworkEvents table to see if any connections have been made by the user on known ports used by tor. At `2026-07-03T12:58:48.634357Z` the first connection was established successfully by the user “gregsz” on the device “threat-hunt-lab” to the RemoteIP `190.120.229.2` on port `443`. The connection was initiated by the process `tor.exe` (folder path: `c:\users\gregsz\desktop\tor browser\browser\torbrowser\tor\tor.exe`). Later on more connections are also established to RemoteIPs `87.106.168.172` and `64.65.1.130`, both on port `443`.  

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| where Timestamp >= datetime(2026-07-03T12:57:57.5948971Z)
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1392" height="349" alt="Képernyőkép 2026-07-05 033411" src="https://github.com/user-attachments/assets/661dc70f-25cf-4dcb-b931-4e3fbda4c1d3" />


## Chronological Event Timeline 
### 1. File Download - TOR Installer

- **Timestamp:** `2026-07-03T12:54:36.4967777Z`
- **Event:** The user "gregsz" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.17.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\GregSz\Downloads\tor-browser-windows-x86_64-portable-15.0.17.exe`
- **SHA256 hash:** `13d3e0a229443b643c683de1615456ace7632f4d801b62720a9390ad953f8c80`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-07-03T12:57:21.7051939Z`
- **Event:** The user "gregsz" executed the file `tor-browser-windows-x86_64-portable-15.0.17.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.17.exe /S`
- **File Path:** `C:\Users\GregSz\Downloads\tor-browser-windows-x86_64-portable-15.0.17.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-07-03T12:57:57.5948971Z`
- **Event:** User "gregsz" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\GregSz\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-07-03T12:58:48.634357Z`
- **Event:** A network connection to IP `190.120.229.2` on port `443` by user "gregsz" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\gregsz\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-07-03T12:58:51.563233Z` - Connected to `87.106.168.172` on port `443`.
  - `2026-07-03T12:59:18.1641931Z` - Local connection to `64.65.1.130` on port `443`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "gregsz" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-07-03T13:25:35.6944602Z`
- **Event:** The user "gregsz" created a file named `tor-shopping-list.txt.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\GregSz\Desktop\tor-shopping-list.txt.txt`
- **SHA256 hash:** `90b980de6081605bd54d7aa9a725cefbf5131158de3b4ec03c4624a732d75651`

---
## Summary

The user "gregsz" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `gregsz`. The device was isolated, and the user's direct manager was notified.

---
