# Microsoft Sentinel Homelab

This repository documents the creation and use of a small Microsoft Sentinel homelab built around a local Windows 11 virtual machine.

The environment was originally created during my preparation for the Microsoft SC-200 Security Operations Analyst exam, which I have since passed. It has been extended to demonstrate practical skills in Windows security telemetry, KQL, detection engineering, watchlist enrichment, incident investigation and security automation with Azure Logic Apps.

---

## Lab Environment

| Component | Implementation |
| :--- | :--- |
| Virtualisation host | Arch Linux desktop using KVM/QEMU and Virtual Machine Manager |
| Monitored endpoint | Windows 11 virtual machine |
| Endpoint telemetry | Windows Security auditing, PowerShell Script Block Logging and Sysmon |
| Hybrid connectivity | Azure Arc-enabled server |
| Data collection | Azure Monitor Agent and Data Collection Rules |
| SIEM | Microsoft Sentinel |
| Log storage and querying | Log Analytics and KQL |
| Enrichment | Microsoft Sentinel watchlists |
| Detection | Scheduled analytics rules and entity mapping |
| Incident response | Microsoft Sentinel incidents and investigation workflow |
| Automation | Azure Logic Apps playbooks |

---

## Projects

| Project | Description |
| :--- | :--- |
| [01 - Initial Setup](01-initial-setup/README.md) | Configuring Windows telemetry, Azure resources, Microsoft Sentinel and Windows Security Events collection |
| [02 - Failed Logon Detection and Automated Triage](02-workflow/README.md) | Enriching failed-logon events with a watchlist, creating a scheduled analytics rule, investigating the generated incident and automating triage with an Azure Logic Apps playbook |
