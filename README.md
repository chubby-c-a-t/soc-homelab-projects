# SOC Homelab Projects

This repository contains practical security operations homelabs that I have configured, tested and documented independently.

Unlike my investigations using platforms such as TryHackMe and LetsDefend, these projects focus on building environments and implementing detection workflows directly. The work demonstrates practical experience with security telemetry, SIEM configuration, KQL, detection engineering, incident investigation and response automation.

The repository was initially created during my preparation for the Microsoft SC-200 Security Operations Analyst exam, which I have since passed. It will also provide a central location for future SOC and cloud-security homelabs.

---

## Microsoft Sentinel Homelab

This homelab uses a local Windows 11 virtual machine connected to Microsoft Sentinel through Azure Arc and Azure Monitor Agent.

The projects progress from building the underlying telemetry pipeline to implementing an end-to-end detection and automated triage workflow.

| Project | Focus |
| :--- | :--- |
| [01 - Initial Setup](microsoft-sentinel/01-initial-setup/README.md) | Windows security telemetry, Sysmon, PowerShell logging, Azure Arc, Azure Monitor Agent, Log Analytics, Microsoft Sentinel and KQL validation |
| [02 - Failed Logon Detection and Automated Triage](microsoft-sentinel/02-workflow/README.md) | Watchlist enrichment, KQL detection engineering, scheduled analytics rules, entity mapping, incident investigation and Logic Apps automation |

---

## Skills Demonstrated

- Windows Security event collection and analysis
- Sysmon deployment and validation
- PowerShell Script Block Logging
- Azure Arc onboarding and troubleshooting
- Azure Monitor Agent and Data Collection Rules
- Microsoft Sentinel configuration
- Kusto Query Language
- Watchlist enrichment
- Detection engineering
- Scheduled analytics rules
- MITRE ATT&CK mapping
- Account and host entity mapping
- Incident investigation and classification
- Azure Logic Apps playbooks
- Managed identities and role-based access control
