# 🛡️ Task 3: Perform a Basic Vulnerability Scan on Your PC

## 🎯 Objective
Utilize a free vulnerability scanning tool to identify common security issues on a personal Windows computer.

---

## 🛠️ Tools Used

- **Nessus Essentials** (Free version of Tenable Nessus)
  - or
- **OpenVAS Community Edition**

---

## 🧪 Steps Followed

1. Installed Nessus Essentials on Windows.
2. Set scan target to `localhost` (127.0.0.1).
3. Launched a full system vulnerability scan.
4. Waited approximately 45 minutes for the scan to complete.
5. Analyzed scan results in the Nessus dashboard.
6. Identified and documented high/critical vulnerabilities.
7. Captured screenshots of the scan overview and detailed results.

---

## 🐞 Sample Identified Vulnerabilities

- Outdated Microsoft Services (High)
- Open RDP Port 3389 (Medium)
- Missing Security Updates (Critical)

---

## 🩹 Basic Fix Recommendations

- Apply the latest Windows security updates.
- Disable unnecessary services (e.g., RDP).
- Enable Windows Defender Firewall.

---

## 🖼️ Screenshots

Screenshots of the scan results are available in this repository
- Scan overview
- Critical vulnerabilities
- Summary report

---

## 🔐 Notable Windows 11 Vulnerabilities in 2025

Below are some critical vulnerabilities identified in Windows 11 during 2025:

### 1. CVE-2025-29824 – CLFS Zero-Day Exploit
- **Type**: Elevation of Privilege
- **Impact**: Exploited by attackers to gain SYSTEM-level access via the Common Log File System (CLFS) driver.
- **Status**: Patched in April 2025.
- **Reference**: [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/04/08/exploitation-of-clfs-zero-day-leads-to-ransomware-activity/)

### 2. CVE-2025-24076 – DLL Hijacking in Mobile Devices Feature
- **Type**: DLL Hijacking
- **Impact**: Allows attackers to achieve administrative privileges through the "Mobile devices" feature.
- **Status**: Patched in March 2025.
- **Reference**: [Windows Forum](https://windowsforum.com/threads/critical-windows-11-vulnerability-cve-2025-24076-how-hackers-achieve-admin-rights-in-300ms.360975/)

### 3. CVE-2025-21333 – Hyper-V Kernel Vulnerability
- **Type**: Elevation of Privilege
- **Impact**: Enables local attackers to gain SYSTEM privileges via a heap-based buffer overflow in Hyper-V.
- **Status**: Patched in January 2025.
- **Reference**: [Windows Forum](https://windowsforum.com/threads/understanding-cve-2025-21333-critical-hyper-v-vulnerability-explained.349626/)

### 4. CVE-2025-30397 – Windows Scripting Engine Type Confusion
- **Type**: Type Confusion
- **Impact**: Could lead to memory corruption and arbitrary code execution.
- **Status**: Patched in May 2025.
- **Reference**: [Microsoft Security Response Center](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-30397)

### 5. CVE-2025-29840 – Windows Media Stack-Based Buffer Overflow
- **Type**: Buffer Overflow
- **Impact**: Allows remote code execution over a network.
- **Status**: Patched in May 2025.
- **Reference**: [Windows Forum](https://windowsforum.com/threads/cve-2025-29840-critical-windows-media-vulnerability-enabling-remote-code-exploits.366046/)

### 6. CVE-2025-29955 – Hyper-V Improper Input Validation
- **Type**: Denial of Service
- **Impact**: Unauthorized attackers can cause service disruptions.
- **Status**: Patched in May 2025.
- **Reference**: [CVE Details](https://www.cvedetails.com/cve/CVE-2025-29955/)

### 7. CVE-2025-32709 – WinSock Use-After-Free
- **Type**: Use-After-Free
- **Impact**: Potential for privilege escalation through the Ancillary Function Driver for WinSock.
- **Status**: Patched in May 2025.
- **Reference**: [Cybersecurity News](https://cybersecuritynews.com/windows-ancillary-winsock-0-day-vulnerability/)

### 8. CVE-2025-21314 – SmartScreen Spoofing
- **Type**: Security Feature Bypass
- **Impact**: Attackers can execute malicious programs without triggering SmartScreen warnings.
- **Status**: Patched in January 2025.
- **Reference**: [Windows Forum](https://windowsforum.com/threads/cve-2025-21314-smartscreen-spoofing-vulnerability-in-windows-exposed.349523/)

---

## 💡 Outcome

This task provided hands-on experience with vulnerability assessment tools and a better understanding of common system weaknesses. Additionally, it highlighted the importance of staying informed about emerging threats and promptly applying security updates to mitigate potential risks.

---


