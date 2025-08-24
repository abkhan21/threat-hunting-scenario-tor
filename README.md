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

- [DeviceFileEvents-TOR Related Files Results CSV](https://github.com/abkhan21/threat-hunting-scenario-tor/blob/main/AdvancedHuntingResults-(%7BDeviceFileEvents%7D)%20-%20Abbas%20Khan.csv)

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

- [DeviceProcessEvents-TOR Activity Results CSV](https://github.com/abkhan21/threat-hunting-scenario-tor/blob/main/AdvancedHuntingResults-(%7BDeviceProcessEvents%7D).csv)


------------------------

### 3. Searched the `DeviceNetworkEvents` Table for TOR-related Network Activity

We ran a targeted KQL query against the DeviceNetworkEvents table to identify network activity related to Tor Browser on device abbas-test-vm-m. The search focused on known Tor ports (9001, 9030, 9050, 9051, 9150, 9151), which are typically used for Tor relays, directory services, SOCKS proxy, and control connections, as well as processes associated with Tor Browser (tor.exe, firefox.exe) and Tor-related domains (torproject.org, dist.torproject.org). By projecting fields such as InitiatingProcessFileName, RemoteIP, RemotePort, and RemoteUrl, the query was designed to uncover evidence of Tor network usage initiated from the workstation.
The results showed outbound connections from Tor Browser processes to ports commonly associated with Tor bootstrap and relay activity, confirming that the device attempted to connect to the Tor network and that the browser was actively used to bypass network controls.

**Query used to locate events:**

```kql
let TargetDevice = "abbas-test-vm-m";
let TorFileNames = dynamic(["tor.exe","torbrowser.exe","firefox.exe"]);
let TorPathHints = dynamic(["\\Tor Browser\\","\\TorBrowser\\","\\Tor\\","/Tor Browser/","/TorBrowser/","/Tor/"]);
let TorPorts = dynamic([9001,9030,9050,9051,9150,9151]); // ORPort, DirPort, SOCKS, Control, Tor Browser defaults
let TorDomains = dynamic(["torproject.org","dist.torproject.org","www.torproject.org","aus1.torproject.org"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where DeviceName =~ TargetDevice
| where RemotePort in (TorPorts)
   or (InitiatingProcessFileName in~ (TorFileNames))
   or (InitiatingProcessFileName =~ "firefox.exe" and InitiatingProcessFolderPath has_any (TorPathHints))
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath,
          LocalIP, LocalPort, RemoteIP, RemotePort, RemoteUrl, Protocol, InitiatingProcessCommandLine
| order by Timestamp desc
```

**Query Explanation:**

We ran a KQL query against the DeviceNetworkEvents table scoped to device abbas-test-vm-m. The query was designed to identify potential Tor Browser network activity by filtering on:

	•	Known Tor network ports (9001, 9030, 9050, 9051, 9150, 9151) which are commonly used for Tor relays, directory services, SOCKS proxy connections, and control channels.
	•	Processes associated with Tor Browser (tor.exe, torbrowser.exe, firefox.exe) to determine if outbound connections were initiated by these executables.
	•	Tor-related domains (torproject.org, dist.torproject.org, www.torproject.org, aus1.torproject.org) to capture evidence of downloads, updates, or bootstrap activity.
We projected columns such as InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteIP, RemotePort, RemoteUrl, and Protocol to link process execution with network activity.

**What We Were Looking For:**

 Evidence of outbound connections from Tor Browser processes to Tor bootstrap nodes, relays, or related infrastructure — confirming not just installation or execution, but actual Tor network usage.
 
	•	prefs.js / prefs-1.js → Updated when a user changes settings or when the browser writes runtime configurations.
	•	cookies.sqlite → Stores cookies, which are only created/modified during web sessions.
	•	formhistory.sqlite → Tracks form entries; only updated if a user interacts with websites.
	•	places.sqlite → Contains browsing history and bookmarks; it is written to when URLs are visited.

 
**What We Discovered:**

	•	Outbound connections were observed from firefox.exe and tor.exe associated with the Tor Browser directory.
	•	Connections targeted Tor-related ports (SOCKS and relay ports), which aligns with expected Tor Browser bootstrap and relay behavior.
	•	Network traffic showed that the device attempted to establish communication over Tor, further confirming active use of the browser to bypass standard network controls.
 
**Supporting Evidence:**
- [DeviceNetworkEvents-TOR Network Activity Results CSV](https://github.com/abkhan21/threat-hunting-scenario-tor/blob/main/AdvancedHuntingResults-(%7BDeviceNetworkEvents%7D).csv)


------------------------

### 4. Searched the DeviceFileEvents Table for .txt Artifacts

We decided to pivot and search for .txt artifacts based on discoveries from earlier steps. The Tor Browser installation itself created multiple .txt files, confirming that text files are associated with Tor’s package. Combined with evidence of manual execution of the browser (via Explorer.exe) and confirmed network activity over Tor ports, it became important to identify whether any additional text files had been created or modified by the user. Such artifacts could provide context around the purpose of the Tor usage.

**Query used to locate events:**

```kql
let TargetDevice = "abbas-test-vm-m";
let Lookback = 14d;
DeviceFileEvents
| where Timestamp > ago(Lookback)
| where DeviceName =~ TargetDevice
| where ActionType in~ ("FileCreated","FileDeleted","FileRenamed","FileModified")
| where tolower(FileName) endswith ".txt"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType,
         FileName, FolderPath, SHA1,
         InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

**Query Explanation:**
We ran a KQL query against the DeviceFileEvents table scoped to device abbas-test-vm-m. The query was designed to capture all .txt file activity (created, modified, renamed, or deleted) within the last 14 days. By projecting fields such as ActionType, FileName, FolderPath, and InitiatingProcessFileName, the query helped identify both text files bundled with the Tor Browser installation and any additional user-generated text files that could provide context around Tor usage.

**What We Were Looking For:**
Potential text artifacts that could supplement evidence of Tor Browser installation and usage, especially those that might indicate direct user interaction.

**What We Discovered:**

	•	Several .txt files created as part of the Tor Browser bundle, including 000_README.txt, tor.txt, openssl.txt, lyrebird.txt, and conjure.txt, confirming full extraction of the package.
	•	User-generated text files on the Desktop such as New Text Document.txt and tor-shopping-list.txt.
	•	tor-shopping-list.txt was later opened with Notepad.exe, demonstrating deliberate user interaction. While the filename alone does not prove intent, it raises the risk profile of the incident and warrants further forensic review.

- [DeviceFileEvents-Suspicious Files Results CSV](https://github.com/abkhan21/threat-hunting-scenario-tor/blob/main/AdvancedHuntingResults-(%7BDeviceFileEvents%7D)-2.csv)


------------------------

## Chronological Event Timeline 

### 1. Tor Browser Installation

- **Timestamp:** `2025-08-21 13:00:48 – 13:00:54 UTC`
- **Event:** The user "azureuser" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.6.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.5.6.exe`

### 2. Creation of Suspicious .txt Files

- **Timestamp:** `2025-08-21 15:53 – 15:55 UTC`
- **Event:** User azureuser created and opened  `tor-shopping-list.txt`, showing activity beyond installation. While not direct evidence of illicit actions, the filename raises the risk profile and warrants investigation.
- **Action:** User-created/modified .txt artifacts.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

### 3. Initial Tor Browser Execution

- **Timestamp:** `2025-08-21 15:29 – 17:01 UTC`
- **Event:** Execution of Tor Browser (firefox.exe).
- **Action:** Multiple profile and preference files created/modified, including prefs.js, prefs-1.js, cookies.sqlite, formhistory.sqlite, and places.sqlite. Indicates Tor Browser was launched and actively used for browsing.
- **File Path:** `:\Users\azureuser\Desktop\Tor Browser\Browser\TorBrowser\Data\profile\`

### 4. Sustained Tor Browsing Session

- **Timestamp:** `2025-08-21 17:00 – 17:05 UTC`
- **Event:** Sustained browsing session.
- **Action:** Continuous file modifications of session/profile databases confirmed ongoing use of Tor Browser.
- **Process:** firefox.exe (launched from the Tor Browser bundle)
- **File Path:** `C:\Users\azureuser\Desktop\Tor Browser\Browser\TorBrowser\Data\profile\`


------------------------

## Summary

The investigation confirms that Tor Browser was downloaded, installed, and actively used on workstation `abbas-test-vm-m` by account azureuser. Installation was initiated via the Tor Browser portable installer `(tor-browser-windows-x86_64-portable-14.5.6.exe)`. Subsequent execution of firefox.exe inside the Tor Browser directory and modification of browser profile files strongly indicate that the user engaged in browsing through the Tor network. This aligns with the suspicious encrypted traffic patterns and validates management’s concerns of unauthorized use of Tor to bypass security controls.
In addition, findings show user interaction beyond Tor installation. A file named `tor-shopping-list.txt` was created and opened on the Desktop, which may suggest preparation for or interest in dark web activity. While there is no direct evidence that purchases or illicit actions took place, the context of this file increases the risk profile of the incident and warrants escalation and further investigation to determine intent and potential impact.

------------------------

## Response Taken

TOR usage was confirmed on the endpoint `abbas-test-vm-m` by the user `azureuser`. The device was isolated, and the user's direct manager was notified.

**Documented IoCs:**

	•	File path: C:\Users\azureuser\Desktop\Tor Browser\Browser\
	•	Executables: tor-browser-windows-x86_64-portable-14.5.6.exe, firefox.exe, plugin-container.exe
	•	Notable file: tor-shopping-list.txt
	•	User: azureuser on abbas-test-vm-m
 
**Recommended actions:**

	•	Containment – Isolate the endpoint from the corporate network to prevent further Tor usage or possible data exfiltration.
	•	Forensics – Securely collect and preserve the Tor Browser directory and related .txt files. Analyze places.sqlite and cookies.sqlite for evidence of browsing behavior. The contents of tor-shopping-list.txtshould •	be reviewed to understand its context and significance.
	•	Escalation – Notify Legal, HR, and senior management due to the elevated risk associated with Tor usage and the presence of the tor-shopping-list.txt file. Consider law enforcement involvement only if forensic evidence confirms attempted or actual illegal activity.
	•	User Handling – Restrict or suspend the azureuser account pending further investigation. Conduct a formal HR/security interview after forensic preservation, ensuring the user is given an opportunity to provide context.
	•	Network Controls – Block Tor-related ports (9001, 9030, 9050, 9051, 9150, 9151) and domains. Implement detection rules for anonymizer tools.
	•	Policy Enforcement – Remove the unauthorized Tor Browser installation and apply WDAC/AppLocker rules to prevent reinstallation. Re-emphasize acceptable use policies.
	•	Awareness/Training – Provide awareness sessions on the risks of anonymizers, dark web access, and corporate liability. Notify management of confirmed TOR usage by azureuser for situational awareness.


------------------------
