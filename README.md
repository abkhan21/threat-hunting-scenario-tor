# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/abkhan21/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

------------------------

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

We ran a targeted KQL query against the DeviceFileEvents table to identify file activity associated with Tor Browser on device abbas-test-vm-m. The search focused on Tor executables (tor.exe, torbrowser.exe, firefox.exe), known Tor-related folder paths (for example, \Tor Browser\, \TorBrowser\), and Tor network ports (9001, 9030, 9050, 9051, 9150, 9151), which are commonly used for Tor relays, directory services, SOCKS proxy, and control connections. By projecting columns such as ActionType, FileName, FolderPath, InitiatingProcessFileName, and CommandLine, the query was designed to uncover evidence of Tor Browser installation, execution, and potential usage activity.

The results confirmed execution of the Tor Browser portable installer (tor-browser-windows-x86_64-portable-14.5.6.exe), creation of its core components (firefox.exe, plugin-container.exe, updater.exe, DLLs), modification of browser profile/configuration files (prefs.js, cookies.sqlite, places.sqlite), and creation of bundled text files (tor.txt, 000_README.txt, openssl.txt, etc.), all of which indicate that Tor Browser was actively installed and used.

**Query:**

```kql
let TargetDevice = "abbas-test-vm-m";
let TorFileNames = dynamic(["tor.exe","torbrowser.exe","firefox.exe"]);
let TorPathHints = dynamic(["\\Tor Browser\\","\\TorBrowser\\","\\Tor\\","/Tor Browser/","/TorBrowser/","/Tor/"]);
let TorPorts = dynamic([9001,9030,9050,9051,9150,9151]); // ORPort, DirPort, SOCKS, Control, Tor Browser defaults
let TorDomains = dynamic(["torproject.org","dist.torproject.org","www.torproject.org","aus1.torproject.org"]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where DeviceName =~ TargetDevice
| where FileName in~ (TorFileNames)
   or array_length(TorPathHints) > 0 and has_any(FolderPath, TorPathHints)
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**Query Explanation:**

We used a KQL query targeting the DeviceFileEvents table, scoped to device abbas-test-vm-m. The query was designed to look for file activity related to Tor Browser by filtering on:

	•	Known Tor executables (tor.exe, torbrowser.exe, firefox.exe)
	•	Tor-related folder path hints (e.g., \Tor Browser\, \TorBrowser\)
	•	Included columns for ActionType, FileName, FolderPath, InitiatingProcessFileName, and command-line details to help determine how files were created, modified, or executed.

**What We Were Looking For:**

Evidence of Tor Browser installation or use — specifically file creation, modification, or execution events tied to Tor executables or paths within the last 14 days.

**What We Discovered:**

	•	Execution of the Tor Browser portable installer (tor-browser-windows-x86_64-portable-14.5.6.exe).
	•	Creation of core Tor Browser components such as firefox.exe, plugin-container.exe, updater.exe, and related DLLs under C:\Users\azureuser\Desktop\Tor Browser\Browser\.
	•	Modification of profile/configuration files (prefs.js, cookies.sqlite, places.sqlite), which indicates the Tor Browser was actively launched and used.
	•	Creation of text files (tor.txt, 000_README.txt, openssl.txt, etc.) as part of the installation, confirming a complete extraction of the Tor Browser bundle.
 
**Supporting Evidence:**

- [DeviceFileEvents Results CSV](https://github.com/abkhan21/threat-hunting-scenario-tor/blob/main/AdvancedHuntingResults-(%7BDeviceFileEvents%7D)%20-%20Abbas%20Khan.csv)

------------------------

### 2. Searched the `DeviceProcessEvents` Table

We ran a targeted KQL query against the DeviceProcessEvents table to identify process execution activity related to Tor Browser on device abbas-test-vm-m. The search focused on Tor executables (tor.exe, torbrowser.exe, firefox.exe), Tor-related folder paths (for example, \Tor Browser\, \TorBrowser\), and Firefox processes launched specifically from the Tor Browser bundle. By projecting columns such as FileName, ProcessCommandLine, FolderPath, InitiatingProcessFileName, and InitiatingProcessCommandLine, the query was designed to uncover evidence of Tor Browser execution, process lineage, and user interaction.

The results confirmed execution of tor.exe from the Tor Browser directory, as well as multiple instances of firefox.exe being launched with supporting child processes (-contentproc), consistent with active Tor Browser usage. Explorer.exe was also observed as a parent process, indicating the browser was manually launched by the user from the Desktop.

**Query:**

```kql
let TargetDevice = "abbas-test-vm-m";
let TorFileNames = dynamic(["tor.exe","torbrowser.exe","firefox.exe"]);
let TorPathHints = dynamic(["\\Tor Browser\\","\\TorBrowser\\","\\Tor\\","/Tor Browser/","/TorBrowser/","/Tor/"]);
let TorPorts = dynamic([9001,9030,9050,9051,9150,9151]); // ORPort, DirPort, SOCKS, Control, Tor Browser defaults
let TorDomains = dynamic(["torproject.org","dist.torproject.org","www.torproject.org","aus1.torproject.org"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where DeviceName =~ TargetDevice
| where FileName in~ (TorFileNames)
   or (FileName =~ "firefox.exe" and ProcessVersionInfoProductName has "Tor" or FolderPath has_any (TorPathHints))
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, FolderPath,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, ProcessId, InitiatingProcessId
| order by Timestamp desc
```

**Query Explanation:**

We ran a KQL query against the DeviceProcessEvents table scoped to device abbas-test-vm-m.
The query targeted:
	•	Known Tor executables (tor.exe, torbrowser.exe, firefox.exe)
	•	Tor-related folder paths (e.g., \Tor Browser\, \TorBrowser\)
	•	Firefox processes that originated specifically from the Tor Browser bundle rather than a standard system installation.
 
We projected columns such as FileName, ProcessCommandLine, FolderPath, InitiatingProcessFileName, and InitiatingProcessCommandLine to determine the execution chain and process lineage.
What We Were Looking For:
	•	Evidence of Tor Browser execution, process spawning behavior, and relationships between the Tor launcher (tor.exe) and the associated Firefox processes.

**What We Discovered:**

	•	tor.exe was executed from C:\Users\azureuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\ with configuration arguments (-f).
	•	firefox.exe was launched multiple times from the Tor Browser directory, confirming user execution of the Tor Browser’s bundled Firefox instance.
	•	Numerous child Firefox processes with the -contentproc command line were spawned, consistent with normal Tor Browser operation during an active browsing session.
	•	Explorer.exe was observed as a parent process, which aligns with the user manually launching the Tor Browser from the Desktop.
 
**Supporting Evidence:**

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

------------------------

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

------------------------

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

------------------------

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

------------------------

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

------------------------

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

------------------------
