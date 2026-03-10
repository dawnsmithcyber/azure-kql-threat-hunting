# 🛡️ Azure Threat Hunting: "VPN Bouncing" & Reconnaissance Analysis

## 📝 Project Overview
This repository documents a proactive threat hunting session conducted within an Azure cloud environment. The investigation utilizes **Kusto Query Language (KQL)** to identify a reconnaissance pattern where an attacker leveraged "VPN Bouncing"—rapidly switching between multiple IP addresses within a specific subnet—to probe for network vulnerabilities and bypass rate-limiting filters.

## 🔍 Investigation Summary
* **Identify:** Spotted a suspicious cluster of traffic originating from the `85.217.149.x` (/24) subnet.
* **Analyze:** Leveraged KQL to filter firewall logs by specific date ranges and IP subnets to determine intent.
* **Verdict:** **100% of the traffic was Denied.** Network Security Groups (NSGs) successfully mitigated the probe at the perimeter.



## ⚠️ Risk Deep-Dive: Port 23 (Telnet) vs. Port 22 (SSH)
The logs revealed repeated attempts to access **Port 23**. From an investigative perspective, understanding the "why" behind the target is critical:

| Feature | Port 23 (Telnet) | Port 22 (SSH) |
| :--- | :--- | :--- |
| **Security** | None (Cleartext) | High (Encrypted) |
| **Risk Profile** | Credentials can be sniffed via MitM | Cryptographic Network Protocol |
| **Recommendation** | Disable immediately | Use for secure remote access |

**Key Insight:** Telnet transmits data in plain text, making it a high-value target for credential theft. This lab reinforces why modern security posture requires transitioning to encrypted alternatives like SSH.

## 🛠️ Technical Methodology (KQL)

### 1. Network Layer: Identifying the "Bouncing" Pattern
The following query was used to verify if the Firewall successfully dropped packets from the suspicious range and to identify which ports were targeted.

```kql
// Check for allowed vs denied traffic from the suspicious subnet
AzureDiagnostics
| where TimeGenerated between (datetime(2026-03-01) .. datetime(2026-03-09))
| where SourceIP startswith "85.217.149"
| summarize Count = count() by Action, SourceIP, DestinationPort
| order by Count desc
2. Identity Layer: Hunting for Pivot Attempts
When an attacker fails at the network layer, they often pivot to the Identity Layer. This query checks if the "bouncing" IPs attempted to brute-force specific user accounts.

Code snippet
// Check if the "bouncing" IPs are targeting specific user accounts
SigninLogs
| where IPAddress startswith "85.217.149"
| where ResultType != 0 // Filter for failed logins (0 is success)
| summarize FailureCount = count(), 
            TargetedAccounts = make_set(UserPrincipalName), 
            DistinctAccountCount = dcount(UserPrincipalName) 
            by IPAddress, ResultDescription
| order by FailureCount desc
```
### 💡 Lessons Learned
🔍 Visibility is Victory: Without centralized logging (Azure Sentinel/Log Analytics), a "VPN bouncing" attack looks like disconnected noise. Visibility allows us to connect the dots and see the actual story.

🤝 Protocol Hygiene: Even if a firewall is blocking traffic, the presence of an unencrypted legacy protocol (Port 23) serves as a beacon inviting further probing.

🧅 Defense in Depth: While the perimeter held, a proactive hunter never assumes the job is done. Monitoring SigninLogs provides the essential second line of defense against identity-based fraud.

------
