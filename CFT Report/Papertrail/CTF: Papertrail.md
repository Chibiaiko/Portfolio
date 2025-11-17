
## CTF: Papertrail by Alexis McGuire



# CTF: Papertrail Threat Analysis Report

👩‍💻**Analyst:** Alexis McGuire  
📅**Start:** 2025-11-09 JST  
📅**End:** 2025-11-16 JST  
✅**Completed:** 2025-11-12 JST

📄**Report Generated:** 2025-11-13 JST

---

## Executive Summary 📝

Between 2025-10-01 – 2025-10-15, multiple machines in the department, particularly `gab-intern-vm`, were targeted in a structured simulated attack campaign. The adversary leveraged suspicious program execution, defense tampering, privilege discovery, persistence mechanisms, artifact staging, exfiltration simulation, and cover artifacts to achieve their objectives. Each flag represents a key stage of the attack chain, from initial execution to anti-forensics attempts, and highlights critical detection opportunities across process, file, registry, and network telemetry.

---


## Timeline of Observed Activity (UTC)

| Flag🚩  | Time (UTC)              | Action Observed                     | Evidence Source      | Key Evidence                               |
| ------- | ----------------------- | ----------------------------------- | -------------------- | ------------------------------------------ |
| Flag 1  | 2025-10-06T12:49:22Z    | Initial Execution Detection         | DeviceProcessEvents  | CLI parameter `-ExecutionPolicy`           |
| Flag 2  | 2025-10-09T12:34:59Z    | Defense Disabling                   | DeviceFileEvents     | `DefenderTamperArtifact.lnk`               |
| Flag 3  | 2025-10-09T12:50:40Z    | Quick Data Probe                    | DeviceFileEvents     | PowerShell Clipboard command               |
| Flag 4  | 2025-10-09T12:51:44Z    | Host Context Recon                  | DeviceProcessEvents  | `qwinsta` session enumeration              |
| Flag 5  | 2025-10-09T12:51:18Z    | Storage Surface Mapping             | DeviceProcessEvents  | `wmic logicaldisk get name,freespace,size` |
| Flag 6  | 2025-10-09T12:51:18Z    | Connectivity & Name Resolution      | DeviceProcessEvents  | Parent `RuntimeBroker.exe`                 |
| Flag 7  | 2025-10-09T12:50:59Z    | Interactive Session Discovery       | DeviceProcessEvents  | Unique ID `2533274790397065`               |
| Flag 8  | 2025-10-09T12:51:57Z    | Runtime Application Inventory       | DeviceProcessEvents  | `tasklist.exe`                             |
| Flag 9  | 2025-10-09T12:52:14Z    | Privilege Surface Check             | DeviceProcessEvents  | `whoami`                                   |
| Flag 10 | 2025-10-09T12:50–13:05Z | Proof-of-Access & Egress Validation | DeviceNetworkEvents  | `www.msftconnecttest.com`                  |
| Flag 11 | 2025-10-09T12:52:00Z    | Bundling / Staging Artifacts        | DeviceFileEvents     | `C:\Users\Public\ReconArtifacts.zip`       |
| Flag 12 | 2025-10-09T12:50–13:05Z | Outbound Transfer Attempt           | DeviceNetworkEvents  | IP `100.29.147.161`                        |
| Flag 13 | 2025-10-09T12:50–13:30Z | Scheduled Re-Execution Persistence  | DeviceProcessEvents  | `SupportToolUpdater`                       |
| Flag 14 | 2025-10-09T12:50–13:30Z | Autorun Fallback Persistence        | DeviceRegistryEvents | `RemoteAssistUpdater`                      |
| Flag 15 | 2025-10-09T12:50–13:30Z | Planted Narrative / Cover Artifact  | DeviceFileEvents     | `SupportChat_log.lnk`                      |



## Starting Point – Identifying the Initial System 🕵

**Objective:**  
Determine where to begin hunting based on provided indicators, such as unusual downloads, executables, or tools touched on affected intern machines during early October.

**Host of Interest (Starting Point):** `gab-intern-vm`  

**Why:** Suspicious activity originating from Downloads and 7z archives; anchor point for investigating subsequent stages.

**KQL Query Used:**

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine contains "exe"
| where FolderPath contains "7z"
| summarize EventCount = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, FileName
| project DeviceName, FileName, EventCount, FirstSeen, LastSeen
| sort by FirstSeen asc
```

📌**Findings:**  
![Affected Machine](https://github.com/Chibiaiko/Chibiaiko/blob/main/Images/Affected%20Machine%201.png)

---

# 🚩Flag-by-Flag Findings

---
### 🚩Flag 1 – Initial Execution Detection
📄**Summary:** Identify the first anomalous program execution, indicating the entry point of the    compromise.

🎯**Object:** First suspicious command execution

📌**Finding (answer):** `-ExecutionPolicy`

🔍**Evidence:**
- Host: gab-intern-vm
- Timestamp: 2025-10-06T12:49:22Z
- Process: powershell.exe
- CommandLine: `-ExecutionPolicy Bypass -NoProfile -File ...`
    

**KQL Used:**

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName contains "gab-intern-vm"
| where InitiatingProcessCommandLine contains "exe"
| where FolderPath contains "7z"
| project Timestamp, DeviceName, FolderPath, InitiatingProcessCommandLine
| sort by Timestamp desc
```

💭**Why it matters:** Anchors the timeline and helps trace the parent/child process chain.

📌**Findings:**  
![Flag 1 Findings](https://github.com/Chibiaiko/Chibiaiko/blob/main/Images/Flag%201%20Findings.png)

---

### 🚩Flag 2 – Defense Disabling
📄**Summary:** Detect attempts to tamper with security defenses.

🎯**Object:** Security artifact creation

📌**Finding (answer):** `DefenderTamperArtifact.lnk`

🔍**Evidence:**
- Host: gab-intern-vm
- Timestamp: 2025-10-09T12:34:59Z
- Process: DeviceFileEvents
- EventCount: 1
    

**KQL Used:**

```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName contains "gab-intern-vm"
| where ActionType in ("FileCreated", "FileModified", "FileOpened") 
| where FileName contains "tamper"
| summarize EventCount = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, FileName
| project DeviceName, FileName, EventCount, FirstSeen, LastSeen
| sort by FirstSeen asc
```

💭**Why it matters:** Tamper attempts indicate adversaries are trying to evade detection.

📌**Findings:**  
![Flag 2 Findings.png](https://github.com/Chibiaiko/Chibiaiko/blob/main/Images/Flag%202%20Findings.png)

---

### 🚩Flag 3 – Quick Data Probe
📄**Summary:** Detect rapid checks of sensitive or transient data.

🎯**Object:** Clipboard access

📌**Finding (answer):** `"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`

🔍**Evidence:**
- Host: gab-intern-vm
- Timestamp: 2025-10-09T12:50:40Z
- Process: powershell.exe
- CommandLine: `"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`
    

**KQL Used:**

```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName contains "gab-intern-vm"
| where InitiatingProcessCommandLine contains "clipboard"
```

💭**Why it matters:** Quick probes can capture sensitive information with minimal traces.

📌**Findings:**  
![Flag 3 Findings.png](https://github.com/Chibiaiko/Chibiaiko/blob/main/Images/Flag%203%20Findings.png)

---

### 🚩Flag 4 – Host Context Recon
📄**Summary:** Identify attempts to gather host or user session information.

🎯**Object:** Session enumeration

📌**Finding (answer):** Last recon attempt at `2025-10-09T12:51:44.3425653Z`

🔍**Evidence:**
- Host: gab-intern-vm
- Timestamp: 2025-10-09T12:51:44.3425653Z
- Process: qwinsta.exe
- CommandLine: `qwinsta`
     

**KQL Used:**

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName contains "gab-intern-vm"
| where ProcessCommandLine contains "qwinsta"
```

💭**Why it matters:** Recon attempts reveal the attacker’s knowledge of system state and sessions.

📌**Findings:**  
![Flag 4 Findings.png](https://github.com/Chibiaiko/Chibiaiko/blob/main/Images/Flag%204%20Findings.png)

---

### 🚩Flag 5 – Storage Surface Mapping
📄**Summary:** Detect enumeration of local or network storage for data discovery. 

🎯**Object:** Disk information collection

📌**Finding (answer):** `"cmd.exe" /c wmic logicaldisk get name,freespace,size`

🔍**Evidence:**
- Host: gab-intern-vm
- Timestamp: 2025-10-09T12:51:18.5628399Z
- Process: cmd.exe
- CommandLine: `"cmd.exe" /c wmic logicaldisk get name,freespace,size`
    

**KQL Used:**

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName contains "gab-intern-vm"
| where ProcessCommandLine contains "wmic"
```

💭**Why it matters:** Maps potential data for exfiltration.

📌**Findings:**  
![Flag 5 Findings.png](https://github.com/Chibiaiko/Chibiaiko/blob/main/Images/Flag%205%20Findings.png)

---

### 🚩Flag 6 – Connectivity & Name Resolution Check
📄**Summary:** Identify network reachability tests or DNS validation.

🎯**Object:** Parent process initiating network checks

📌**Finding (answer):** Parent `RuntimeBroker.exe`

🔍**Evidence:**
- Host: gab-intern-vm
- Timestamp: 2025-10-09T12:51:18.3848072Z
- Process: wmic.exe
- CommandLine: `wmic logicaldisk get name,freespace,size`
    

**KQL Used:**

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName contains "gab-intern-vm"
| where ProcessCommandLine contains "wmic"
| project Timestamp, ProcessCommandLine, InitiatingProcessParentFileName
```

💭**Why it matters:** Confirms attacker can reach network destinations.

📌**Findings:**  
![Flag 6 Findings.png](https://github.com/Chibiaiko/Chibiaiko/blob/main/Images/Flag%206%20Findings.png)

---

### 🚩Flag 7 – Interactive Session Discovery
📄**Summary:** Detect attempts to discover active sessions.

🎯**Object:** Active session enumeration

📌**Finding (answer):** Initiating Process Unique ID `2533274790397065`

🔍**Evidence:**
- Host: gab-intern-vm
- Timestamp: 2025-10-09T12:50:59.3449917Z
- Process: qwinsta.exe
- CommandLine: `qwinsta`
    

**KQL Used:**

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName contains "gab-intern-vm"
| where ProcessCommandLine contains "qwinsta"
| project Timestamp, DeviceName, FileName, InitiatingProcessCommandLine, InitiatingProcessUniqueId, ProcessUniqueId
```

💭**Why it matters:** Helps attackers identify high-value sessions.

📌**Findings:**  
![Flag 7 Findings.png](https://github.com/Chibiaiko/Chibiaiko/blob/main/Images/Flag%207%20Findings.png)

---

### 🚩Flag 8 – Runtime Application Inventory
📄**Summary:** Detect process enumeration for targeting.

🎯**Object:** Process list snapshot

📌**Finding (answer):** `tasklist.exe`    

🔍**Evidence:**
- Host: gab-intern-vm
- Timestamp: 2025-10-09T12:51:57.6866149Z
- Process: tasklist.exe
- CommandLine: `tasklist`
    

**KQL Used:**

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName contains "gab-intern-vm"
| where ProcessCommandLine contains "tasklist"
| project Timestamp, DeviceName, FileName, InitiatingProcessCommandLine, InitiatingProcessUniqueId, ProcessUniqueId
```

💭**Why it matters:** Identifies running processes to choose targets and avoid detection.

📌**Findings:**  
![Flag 8 Findings.png](https://github.com/Chibiaiko/Chibiaiko/blob/main/Images/Flag%208%20Findings.png)

---

### 🚩Flag 9 – Privilege Surface Check
📄**Summary:** Detect attempts to enumerate privileges of current actor.

🎯**Object:** Privilege discovery

📌**Finding (answer):** `2025-10-09T12:52:14.3135459Z`

🔍**Evidence:**
- Host: gab-intern-vm
- Timestamp: 2025-10-09T12:52:14.3135459Z
- Process: whoami.exe
- CommandLine: `whoami`
    

**KQL Used:**

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName contains "gab-intern-vm"
| where ProcessCommandLine contains "whoami" 
| sort by Timestamp asc
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, ProcessId
| take 1
```

💭**Why it matters:** Determines if privilege escalation is required for further activity.

📌**Findings:**  
![Flag 9 Findings.png](https://github.com/Chibiaiko/Chibiaiko/blob/main/Images/Flag%209%20Findings.png)

---

### 🚩Flag 10 – Proof-of-Access & Egress Validation
📄**Summary:** Identify attempts to confirm outbound reachability and host access.

🎯**Object:** Outbound connectivity test

📌**Finding (answer):** `www.msftconnecttest.com`

🔍**Evidence:**
- Host: gab-intern-vm
- Timestamp: 2025-10-09 12:50–13:05Z
- Process: 8824
- RemoteIP: `23.218.218.182
    

**KQL Used:**

```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2025-10-09 12:50:00) .. datetime(2025-10-09 13:05:00))
| where DeviceName contains "gab-intern-vm"
| where InitiatingProcessId == 8824
| where RemoteUrl != ""
| project Timestamp, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp asc
```

💭**Why it matters:** Confirms actor can reach external destinations for potential exfiltration.

📌**Findings:**  
![Flag 10 Findings.png](https://github.com/Chibiaiko/Chibiaiko/blob/main/Images/Flag%2010%20Findings.png)

---

### 🚩Flag 11 – Bundling / Staging Artifacts
📄**Summary:** Detect preparation of files for exfiltration.

🎯**Object:** File consolidation

📌**Finding (answer):** `C:\Users\Public\ReconArtifacts.zip`

🔍**Evidence:**
- Host: gab-intern-vm
- Timestamp: 2025-10-09T12:52:00Z
- Process: FileCreated
- FileName: `ReconArtifacts.zip`
    

**KQL Used:**

```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName contains "gab-intern-vm"
| where FileName endswith ".zip" or FileName endswith ".7z" or FileName endswith ".rar"
| where ActionType == "FileCreated"
| where Timestamp between (datetime(2025-10-09 12:52:00) .. datetime(2025-10-09 13:00:00))
| project Timestamp, DeviceName, FolderPath, FileName
```

💭**Why it matters:** Staging files simplifies exfiltration and correlates back to recon activity.

📌**Findings:**  
![Flag 11 Findings.png](https://github.com/Chibiaiko/Chibiaiko/blob/main/Images/Flag%2011%20Findings.png)

---

### 🚩Flag 12 – Outbound Transfer Attempt
📄**Summary:** Identify attempts to move data off-host (simulated).

🎯**Object:** Outbound connection

📌**Finding (answer):** IP `100.29.147.161`

🔍**Evidence:**
- Host: gab-intern-vm
- Timestamp: 2025-10-09 12:50–13:05Z
- Process: 8824
- RemoteUrl: `httpbin.org
    

**KQL Used:**

```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2025-10-09 12:50:00) .. datetime(2025-10-09 13:05:00))
| where DeviceName contains "gab-intern-vm"
| where InitiatingProcessId == 8824
| where RemoteUrl != ""
| project Timestamp, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp asc
```

💭**Why it matters:** Proof of intent for data exfiltration.

📌**Findings:**  
![Flag 12 Findings.png](https://github.com/Chibiaiko/Chibiaiko/blob/main/Images/Flag%2012%20Findings.png)

---

### 🚩Flag 13 – Scheduled Re-Execution Persistence
📄**Summary:** Detect persistence via scheduled tasks.

🎯**Object:** Recurring execution

📌**Finding (answer):** `SupportToolUpdater`

🔍**Evidence:**
- Host: gab-intern-vm
- Timestamp: 2025-10-09 12:50–13:30Z
- Process: schtasks.exe
- ProcessCommandLine: `"schtasks.exe" /Query /TN SupportToolUpdater
    

**KQL Used:**

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-10-09 12:50:00) .. datetime(2025-10-09 13:30:00))
| where DeviceName contains "gab-intern-vm"
| where FileName == "schtasks.exe" or ProcessCommandLine contains "schtasks"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

💭**Why it matters:** Recurring execution increases resilience of malicious activity.

📌**Findings:**  
![Flag 13 Findings.png](https://github.com/Chibiaiko/Chibiaiko/blob/main/Images/Flag%2013%20Findings.png)

---

### 🚩Flag 14 – Autorun Fallback Persistence
📄**Summary:** Detect persistence via registry autoruns.

🎯**Object:** Registry run key

📌**Finding (answer):** `RemoteAssistUpdater`

🔍**Evidence:**
- Host: gab-intern-vm
- Timestamp: 2025-10-09–10
- Process: DeviceRegistryEvents
- Note: `⚠️ If table returned nothing: RemoteAssistUpdater`
     

**KQL Used:**

```kql
DeviceRegistryEvents
| where Timestamp between (datetime(2025-10-09) .. datetime(2025-10-10))
| where DeviceName contains "gab-intern-vm"
| where RegistryValueName contains "Remote" or RegistryValueData contains "Remote"
| project Timestamp, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```

💭**Why it matters:** Registry persistence survives reboots and evades simple detection.

📌**Findings:**  
![Flag 14 Findings.png](https://github.com/Chibiaiko/Chibiaiko/blob/main/Images/Flag%2014%20Findings.png)


---

### 🚩Flag 15 – Planted Narrative / Cover Artifact
📄**Summary:** Detect artifacts left to simulate or cover adversary activity.

🎯**Object:** Covering artifact

📌**Finding (answer):** `SupportChat_log.lnk`

🔍**Evidence:**
- Host: gab-intern-vm
- Timestamp: 2025-10-09 12:50–13:30Z
- Process: FileCreated
- FolderPath: `C:\Users\g4bri3lintern\AppData\Roaming\Microsoft\Windows\Recent\SupportChat_log.lnk
    

**KQL Used:**

```kql
DeviceFileEvents
| where Timestamp between (datetime(2025-10-09 12:50:00) .. datetime(2025-10-09 13:30:00))
| where DeviceName contains "gab-intern-vm"
| where FolderPath contains "\\Recent\\"
```

💭**Why it matters:** Final stage of adversary simulation; demonstrates anti-forensic or misdirection attempts.

📌**Findings:**  
![Flag 15 Findings.png](https://github.com/Chibiaiko/Chibiaiko/blob/main/Images/Flag%2015%20Findings.png)

---
## MITRE ATT&CK — Quick Map (flags → techniques)

> Note: `mappings are the closest, commonly used ATT&CK techniques for the observed activity. Some actions cover multiple sub‑techniques; I show the main technique ID and a one‑line rationale.`

| Flag🚩                                        | ATT&CK Technique (ID)                                                                 | Rationale💡                                                                                                                     |
| --------------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Flag 1 — Initial Execution                    | **T1059.001 — PowerShell**                                                            | PowerShell execution with `-ExecutionPolicy` indicates script-based command interpreter use.                                    |
| Flag 2 — Defense Disabling                    | **T1562 — Impair Defenses (T1562.001 Disable/Modify Tools)**                          | Creation of a tamper artifact (`DefenderTamperArtifact.lnk`) indicates attempts to change or simulate security controls.        |
| Flag 3 — Quick Data Probe                     | **T1056 — Input Capture**                                                             | Clipboard access via PowerShell is an input-capture style data probe for transient secrets.                                     |
| Flag 4 — Host Context Recon                   | **T1082 — System Information Discovery**                                              | `qwinsta` and similar commands are used to gather host/session context.                                                         |
| Flag 5 — Storage Surface Mapping              | **T1083 — File and Directory Discovery**                                              | WMIC logical disk queries and similar commands enumerate storage surfaces.                                                      |
| Flag 6 — Connectivity & Name Resolution       | **T1046 — Network Service Scanning / T1016 — System Network Configuration Discovery** | Network or parent-process checks used to validate outbound reachability and name resolution.                                    |
| Flag 7 — Interactive Session Discovery        | **T1133 / T1120 / T1087** (Session / Account discovery)                               | Enumerating active sessions (`qwinsta`) to find interactive users. Mapped to account/session discovery techniques.              |
| Flag 8 — Runtime Application Inventory        | **T1057 — Process Discovery**                                                         | Use of `tasklist.exe` shows a process inventory collection.                                                                     |
| Flag 9 — Privilege Surface Check              | **T1069 / T1087 — Permission Groups / Account Discovery**                             | `whoami` and privilege checks to determine current access/context.                                                              |
| Flag 10 — Proof-of-Access & Egress Validation | **T1041 — Exfiltration Over C2 Channel / T1071 (Application Layer Protocol)**         | Contact to external domains (e.g., `www.msftconnecttest.com`) to validate outbound connectivity — typical step before exfil/C2. |
| Flag 11 — Bundling / Staging Artifacts        | **T1074 — Data Staged**                                                               | Creation of `ReconArtifacts.zip` indicates staging gathered files for transfer.                                                 |
| Flag 12 — Outbound Transfer Attempt           | **T1041 — Exfiltration Over HTTP(S)/Application Protocols**                           | Observed unusual outbound IPs and connections consistent with exfil simulation.                                                 |
| Flag 13 — Scheduled Re-Execution Persistence  | **T1053.005 — Scheduled Task**                                                        | Creation of `SupportToolUpdater` scheduled task to re-run tooling.                                                              |
| Flag 14 — Autorun Fallback Persistence        | **T1547.001 — Registry Run Keys / Startup Folder**                                    | Registry autorun entry `RemoteAssistUpdater` used as fallback persistence.                                                      |
| Flag 15 — Planted Narrative / Cover Artifact  | **T1204 — User Execution / T1036 — Masquerading**                                     | LNK placed in Recent to justify activity (social engineering / masquerade).                                                     |

---

## Recommended Actions — Condensed (prioritized)

Below are short, prioritized actions grouped by immediate containment, remediation, and follow-up hardening/hunt steps.

### Immediate (Contain & Preserve)

1. **Isolate host** `gab-intern-vm` from network (air‑gap or block at network) and preserve forensic artifacts (disk image + memory).

2. **Collect logs & evidence**: export EDR telemetry (DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceRegistryEvents) for the host and relevant time window (2025-10-06 → 2025-10-09 13:30Z).

3. **Quarantine staged artifacts**: quarantine `C:\Users\Public\ReconArtifacts.zip` and similar archives found on other endpoints.

4. **Snapshot scheduled tasks & registry keys** (before deletion) and then disable `SupportToolUpdater` and remove `RemoteAssistUpdater` **after** evidence capture.


### Short-term Remediation (erase footholds safely)

5. **Remove persistence** (in safe order):
    
    - Disable scheduled task `SupportToolUpdater` (record details) → delete.
    - Remove registry autorun `RemoteAssistUpdater` (record key & value) → delete.
    - Remove planted LNK(s) from Recent and investigate their content.

6. **Block suspicious network indicators**: block IP `100.29.147.161` and monitor/block unusual processes connecting to `www.msftconnecttest.com` when initiated by non-system processes.

7. **Reset credentials / tokens** for any accounts used on the affected host (if exposure suspected). Rotate service/account credentials if evidence of credential access.

### Detection & Hunting (tactical)

8. **Deploy detection rules** (high priority):
    
    - PowerShell invocations containing `-ExecutionPolicy` launched from `Downloads` or `7z` folders.
    - PowerShell commands invoking `Get-Clipboard`.
    - Creation of `.zip/.7z/.rar` in public/common folders (e.g., `C:\Users\Public\`).
    - Creation of `.lnk` files in `\Recent\` or `Downloads` with support/help themed names.
    - `schtasks.exe` invocations that create scheduled tasks with support-themed names (e.g., `SupportToolUpdater`, `RemoteAssistUpdater`).
    - Registry run key creations containing “Remote”/“Assist”/“Updater” strings.

9. **Hunt**: search the environment for naming patterns and artifacts: `*desk*`, `*help*`, `*support*`, `*tool*`, `ReconArtifacts.zip`, `SupportChat_log.lnk`, DefenderTamperArtifact.lnk. Expand timeframe to early Oct.

### Prevention & Hardening (strategic)

10. **Restrict execution from Downloads**: implement AppLocker/WDAC rules to block execution from user Downloads and temp archive extraction folders.

11. **Harden PowerShell usage**: enable constrained language mode where possible, enforce script signing, log module and script block telemetry, and block `-ExecutionPolicy Bypass` usage by non-admins.

12. **Least privilege & session controls**: limit local admin use on intern machines and enforce MFA and credential hygiene for remote assistance tools.

13. **Application allowlisting for remote support tools**: only allow approved remote-support vendor binaries and require session logging/approval.

14. **User awareness**: train interns on safe downloads and required approvals for external support sessions.

### Longer-term (policy & response)

15. **Playbook / runbook updates**: add a documented incident playbook for “malicious/unsanctioned remote support” with steps to preserve evidence, remove persistence, and coordinate user notifications.

16. **Telemetry retention & visibility**: ensure process, file, registry, and network telemetry retention windows meet forensic needs (30–90 days or as required).

17. **Periodic hunt & tabletop**: schedule periodic hunts for the above artifacts plus tabletop exercises for remote-assist scenarios.

---
## 🧠 Logical Flow & Analyst Reasoning

| Step  | Flag🚩     | Analyst Reasoning                                                                                                                                                                         | Conclusion / Answer                                                                                                        |
| ----- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| 0 ➝1  | 🚩 Flag 1  | An unfamiliar script surfaced in the user’s Downloads directory. Was this `SupportTool.ps1` executed under the guise of IT diagnostics?                                                   | **Yes** – The execution with `-ExecutionPolicy` indicates the script ran under an elevated or bypassed PowerShell context. |
| 1➝2   | 🚩 Flag 2  | Initial execution often precedes attempts to weaken defenses. Did the operator attempt to tamper with security tools to reduce visibility?                                                | **Yes** – `DefenderTamperArtifact.lnk` shows a staged attempt to simulate tampering.                                       |
| 2➝3   | 🚩 Flag 3  | With protections probed, the next step is quick data checks. Did they sample clipboard contents to see if sensitive material was immediately available?                                   | **Yes** – Clipboard access command confirms opportunistic data probing.                                                    |
| 3➝4   | 🚩 Flag 4  | Attackers rarely stop with clipboard data. Did they expand into broader environmental reconnaissance to understand the host and user context?                                             | **Yes** – `qwinsta` usage reveals host and session enumeration.                                                            |
| 4➝5   | 🚩 Flag 5  | Recon of the system itself is followed by scoping available storage. Did the attacker enumerate drives and shares to see where data might live?                                           | **Yes** – WMIC commands confirm storage mapping.                                                                           |
| 5➝6   | 🚩 Flag 6  | After scoping storage, connectivity is key. Did they query network posture or DNS resolution to validate outbound capability?                                                             | **Yes** – `RuntimeBroker.exe` process confirms network checks.                                                             |
| 6➝7   | 🚩 Flag 7  | Once network posture is confirmed, live session data becomes valuable. Did they check active users or sessions that could be hijacked or monitored?                                       | **Yes** – Active session enumeration with `qwinsta` shows targeting of current users.                                      |
| 7➝8   | 🚩 Flag 8  | Session checks alone aren’t enough — attackers want a full picture of the runtime. Did they enumerate processes to understand active applications and defenses?                           | **Yes** – `tasklist.exe` captures runtime process inventory.                                                               |
| 8➝9   | 🚩 Flag 9  | Process context often leads to privilege mapping. Did the operator query group memberships and privileges to understand access boundaries?                                                | **Yes** – `whoami` confirms privilege enumeration.                                                                         |
| 9➝10  | 🚩 Flag 10 | With host and identity context in hand, attackers often validate egress and capture evidence. Was there an outbound connectivity check coupled with a screenshot or host data collection? | **Yes** – Contact to `www.msftconnecttest.com` shows proof-of-access and egress validation.                                |
| 10➝11 | 🚩 Flag 11 | After recon and evidence collection, staging comes next. Did the operator bundle key artifacts into a compressed archive for easy movement?                                               | **Yes** – `C:\Users\Public\ReconArtifacts.zip` demonstrates artifact bundling.                                             |
| 11➝12 | 🚩 Flag 12 | Staging rarely stops locally — exfiltration is tested soon after. Were outbound HTTP requests attempted to simulate upload of the bundle?                                                 | **Yes** – IP `100.29.147.161` shows attempted simulated outbound transfer.                                                 |
| 12➝13 | 🚩 Flag 13 | Exfil attempts imply intent to return. Did the operator establish persistence through scheduled tasks to ensure continued execution?                                                      | **Yes** – Task `SupportToolUpdater` ensures recurring execution.                                                           |
| 13➝14 | 🚩 Flag 14 | Attackers rarely trust a single persistence channel. Was a registry-based Run key added as a fallback mechanism to re-trigger the script?                                                 | **Yes** – `RemoteAssistUpdater` provides redundant autorun persistence.                                                    |
| 14➝15 | 🚩 Flag 15 | Persistence secured, the final step is narrative control. Did the attacker drop a text log resembling a helpdesk chat to justify these suspicious activities?                             | **Yes** – `SupportChat_log.lnk` serves as a planted explanatory artifact.                                                  |

