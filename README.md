# azure-kql-threat-hunting
Azure KQL Analysis Of Possible Threat ✅
# 🛡️Azure KQL Analysis of "VPN Bouncing" Reconnaissance
📝 Repository Description
Azure Threat Hunting project utilizing KQL to identify VPN Bouncing patterns and analyze the security risks of legacy protocols (Telnet) vs. encrypted standards (SSH).
-----

## 📝 Overview
This repository documents a proactive threat hunting session within an Azure environment. During this lab, I identified a reconnaissance pattern where
an attacker utilized "VPN bouncing"—rapidly switching between multiple IP addresses within the `85.217.149.x` range—to probe for network vulnerabilities.

## 🔍 Investigation Summary
* **Identify:** Spotted a suspicious pattern of traffic originating from a single `/24` subnet.
* **Analyze:** Leveraged **Kusto Query Language (KQL)** to filter firewall logs by specific date ranges and IP subnets.
* **Verdict:** **100% of the traffic was Denied.** The Network Security Groups (NSGs) successfully mitigated the probe at the perimeter.

---

## ⚠️ Risk Deep-Dive: Port 23 (Telnet) vs. Port 22 (SSH)
The logs revealed repeated attempts to access **Port 23**. From a Fraud Hunter’s perspective, understanding the "why" behind the target is critical:

| Feature | Port 23 (Telnet) | Port 22 (SSH) |
| :--- | :--- | :--- |
| **Security** | **None** (Cleartext) | **High** (Encrypted) |
| **Risk Profile** | Credentials can be sniffed via MitM | Cryptographic Network Protocol |
| **Recommendation** | **Disable immediately** | Use for secure remote access |

**Key Insight:** Telnet transmits data in plain text, making it a high-value target for credential theft. This lab reinforced why we prioritize encrypted
alternatives like SSH.

---

## 🕵️ Next Steps: Identity Targeting Query
When an attacker fails to breach the network layer, they often pivot to the **Identity Layer** (User Accounts). 
To hunt for these pivots, I execute the following query to check if the "bouncing" IPs are attempting to brute-force specific usernames:

Check if the "bouncing" IPs are targeting specific user accounts
SigninLogs
| where IPAddress startswith "85.217.149"
| where ResultType != 0 // Filter for failed logins
| summarize 
    FailureCount = count(), 
    TargetedAccounts = make_set(UserPrincipalName), 
    DistinctAccountCount = dcount(UserPrincipalName) 
    by IPAddress, ResultDescription
| order by FailureCount desc
_____
### 💡 Lessons Learned

### 🔍 Visibility is Victory
Without **log aggregation**, a "VPN bouncing" attack looks like disconnected, random noise. Centralized logging (Azure Sentinel/Log Analytics) provides the "bird's-eye view" necessary to connect the dots and see the actual story behind the data. If you can't see the pattern, you can't hunt the threat.

### 🛡️ Protocol Hygiene
This investigation reinforced why we must never leave **Port 23 (Telnet)** open. Even when a firewall is successfully blocking traffic, the mere presence of an unencrypted, legacy protocol is a liability. It serves as a beacon that invites further probing from sophisticated actors. Transitioning to **SSH (Port 22)** isn't just a best practice; it's a requirement for modern security.

### 🏰 Defense in Depth
While the Azure Firewall held the perimeter in this scenario, a "Fraud Hunter" never assumes the job is done. Monitoring **Sign-in Logs** is the essential second line of defense. By pivoting from network logs to identity logs, we ensure that an attacker who failed to breach the network hasn't found a "back door" through identity-based fraud or credential stuffing.

### 📝 Executive Summary
During a proactive hunt in the Azure environment, I identified a reconnaissance pattern involving "VPN Bouncing." An external actor was cycling through multiple IPs within the 85.217.149.x subnet to bypass basic rate-limiting and IP-based reputation filters. The investigation focused on whether this traffic bypassed the Firewall and evaluated the risk profile of targeted ports.

### 🔍 Technical Analysis
1. Identifying the "Bouncing" Pattern
The attacker leveraged a narrow IP range to simulate legitimate distributed traffic. To verify if the Firewall successfully dropped these packets, I executed the following KQL query:

Code snippet
// Check for allowed vs denied traffic from the suspicious subnet
AzureDiagnostics
| where TimeGenerated between (datetime(2026-03-01) .. datetime(2026-03-09))
| where SourceIP startswith "85.217.149"
| summarize Count = count() by Action, SourceIP, DestinationPort
| order by Count desc
Result: All traffic from this range was marked as Deny. No successful ingress was recorded.

2. Protocol Risk Assessment: Port 23 (Telnet)
The logs indicated probes against Port 23. Unlike SSH (Port 22), which uses a cryptographic network protocol to secure data in transit, Telnet transmits data in plain text.

Vulnerability: A "Man-in-the-Middle" (MitM) attack could easily sniff credentials.

Remediation: Ensure Port 23 is closed at the Network Security Group (NSG) level and enforce SSH for all remote management.

### 💡 Key Takeaways
Defense in Depth: Even though the attacker was persistent with IP rotation, the pre-configured Firewall rules prevented a breach.

Visibility is Victory: Knowing how to filter by datetime and IP range allows a hunter to see the "story" behind the logs rather than just raw data.

## 🕵️ Next Move: The "Account Target" Query
Once you know they are knocking on the door, you need to see if they’ve started trying to turn the handle on specific user accounts. After a "bouncing" pattern, your next go-to should be checking Sign-in Logs for failed authentication attempts from those same IPs.

Try this query next:
It looks for "Sign-in failures" (ResultType 50126) or "Account locked" events tied to the suspicious IP range you found.

Code snippet
SigninLogs
| where IPAddress startswith "85.217.149"
| where ResultType != 0  // Filter for failures (0 is success)
| summarize FailureCount = count(), UniqueAccountsTargeted = dcount(UserPrincipalName) by IPAddress, ResultDescription
| order by FailureCount desc
This will tell you if they’ve moved from "probing the firewall" to "brute-forcing Jennifer in Accounting."


