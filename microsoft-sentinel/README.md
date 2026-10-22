# Microsoft Sentinel Homelab

This project documents the creation and use of a small Microsoft Sentinel homelab built around a local Windows 11 LTSC virtual machine.

The environment is being used to develop practical skills in Windows security telemetry, KQL, detection engineering, threat hunting and incident investigation while preparing for the Microsoft SC-200 exam.

---

## Lab Environment

| Component | Implementation |
| :--- | :--- |
| Virtualisation host | Arch Linux desktop using KVM/QEMU and Virtual Machine Manager |
| Monitored endpoint | Windows 11 LTSC virtual machine |
| Endpoint telemetry | Windows Security auditing, PowerShell Script Block Logging and Sysmon |
| Hybrid connectivity | Azure Arc-enabled server |
| Data collection | Azure Monitor Agent and Data Collection Rules |
| SIEM | Microsoft Sentinel |
| Log storage and querying | Log Analytics and KQL |

---

## Projects

| Project | Description |
| :--- | :--- |
| [01 - Initial Setup](01_initial_setup/README.md) | Configuring Windows telemetry, Azure resources, Microsoft Sentinel and Windows Security Events collection |

