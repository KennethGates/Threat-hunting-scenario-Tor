# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/KennethGates/Threat-hunting-scenario-Tor/blob/main/threat-hunting-scenario-tor-event-creation.md)
  
## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

 Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered
what looks like the user “kennygatz” downloaded a tor installer, did something that resulted in many
tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on
the desktop at this time. These events began at: 2025-08-21T15:10:56.6220488Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "ken2-edr-test"
| where InitiatingProcessAccountName == "kennygatz"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-08-21T15:10:56.6220488Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1140" height="344" alt="Screenshot 2025-08-22 at 4 51 52 PM" src="https://github.com/user-attachments/assets/39895638-9b62-458f-87e6-38e3413e187c" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.6.exe". Based on the logs returned, at `August 21, 2025, at 11:10 AM`, an employee on the " ken2-edr-test" device ran the file `"tor-browser-windows-x86_64-portable-14.5.6.exe"` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "ken2-edr-test"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.6.exe"
|project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1152" height="157" alt="Screenshot 2025-08-22 at 4 59 18 PM" src="https://github.com/user-attachments/assets/bec247f5-91aa-4542-bfa6-6743055ef690" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "KennyGatz" actually opened the TOR browser. There was evidence that they did open it at `2025-08-21T15:28:26.9899619Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "ken2-edr-test"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe", "start-tor-browser.exe",  "torbrowser-install.exe", "tor-browser-setup.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1132" height="345" alt="Screenshot 2025-08-22 at 5 03 12 PM" src="https://github.com/user-attachments/assets/acac91ba-d9ca-4086-b0d4-41fe1fcb85cd" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `August 21, 2025, at 11:28 AM`, an employee on the "ken2-edr-test" device successfully established a connection to the remote IP address `127.0.0.1` on port `9151`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "ken2-edr-test" 
| where InitiatingProcessAccountName !=  "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9050", "9051", "9150", "9151")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc 
```
<img width="1152" height="280" alt="Screenshot 2025-08-22 at 5 05 09 PM" src="https://github.com/user-attachments/assets/c6d3087c-8d15-48de-ba1d-aab122172b0c" />

---

## Chronological Event Timeline

### 1. File Download - TOR Installer
Timestamp: 2025-08-21T15:10:56.6220488Z
Event: The user "kennygatz" downloaded a file named tor-browser-windows-x86_64-portable-14.5.6.exe into the Downloads folder. Shortly after, the file was marked as deleted (likely due to extraction/installation).
Action: File download detected.
File Path: C:\Users\kennygatz\Downloads\tor-browser-windows-x86_64-portable-14.5.6.exe

### 2. Process Execution - TOR Browser Installation
Timestamp: 2025-08-21T15:10:57Z
Event: The user "kennygatz" executed the installer tor-browser-windows-x86_64-portable-14.5.6.exe in silent mode, initiating the background installation of the TOR Browser.
Action: Process creation detected.
Command: tor-browser-windows-x86_64-portable-14.5.6.exe /S
File Path: C:\Users\kennygatz\Downloads\tor-browser-windows-x86_64-portable-14.5.6.exe

### 3. Process Execution - TOR Browser Launch
Timestamp: 2025-08-21T15:28:26.9899619Z
Event: The user "kennygatz" launched the TOR Browser. Subsequent processes including firefox.exe (frontend) and tor.exe (routing process) were created, confirming the browser was successfully launched.
Action: Process creation of TOR browser-related executables detected.
File Path: C:\Users\kennygatz\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe

### 4. Network Connection - TOR Network
Timestamp: 2025-08-21T15:28:31Z
Event: The process firefox.exe initiated a local connection to 127.0.0.1 on port 9151, establishing communication with the TOR control service. This confirms the TOR client was active.
Action: Connection success.
Process: firefox.exe
File Path: C:\Users\kennygatz\Desktop\Tor Browser\Browser\firefox.exe

### 5. Additional Network Connections - TOR Browser Activity
Timestamps:
2025-08-21T15:28:33Z - Connection to external sites observed over port 443.
2025-08-21T15:29:02Z - Local connection to 127.0.0.1 on port 9151 persisted.
Event: Additional TOR network connections were established, confirming ongoing anonymized browsing activity by user "kennygatz".
Action: Multiple successful TOR-related connections detected.

### 6. File Creation - TOR Shopping List
Timestamp: 2025-08-21T15:32:47Z
Event: The user "kennygatz" created a file named tor-shopping-list.txt on the Desktop, potentially indicating notes or a list related to TOR usage.
Action: File creation detected.
File Path: C:\Users\kennygatz\Desktop\tor-shopping-list.txt

---

## Summary

The user "kennygatz" on the "ken2-edr-test" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint "ken2-edr-test" by the user "kennygatz". The device was isolated, and the user's direct manager was notified.

---
