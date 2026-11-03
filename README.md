# 🛡️ Entra-ZeroTouch-IAM-Toolkit

![PowerShell](https://img.shields.io/badge/PowerShell-7.4+-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![Bash](https://img.shields.io/badge/macOS_Bash-POSIX-000000?style=for-the-badge&logo=apple&logoColor=white)
![Microsoft Graph](https://img.shields.io/badge/Microsoft_Graph_API-v1.0-0078D4?style=for-the-badge&logo=microsoft&logoColor=white)
![Security](https://img.shields.io/badge/Zero_Trust-IAM_Automation-2EA44F?style=for-the-badge)

An enterprise Identity & Access Management (IAM) and cross-platform endpoint diagnostic toolkit designed for **Tier 2/3 IT Operations, Executive Support, and Security Operations**.

---

## 🎯 Problem Statement

In fast-paced corporate and financial environments, manual user lifecycle management and endpoint triage introduce two critical operational risks:
1. **Security Gaps During Offboarding:** Manually clicking through Microsoft Entra ID and M365 admin centers often leaves active OAuth refresh tokens, cached mobile sessions, or lingering security group permissions intact.
2. **Slow VIP Ticket Resolution:** Gathering encryption compliance (FileVault/BitLocker), MDM enrollment status, and network telemetry during high-priority deskside escalations takes too long when performed manually.

This repository automates both workflows into repeatable, auditable scripts that output structured logs ready for **ServiceNow** and **Jira Service Management** tickets.

---

## ⚙️ Core Modules

### 1. `Invoke-ZeroTrustOffboarding.ps1` (Microsoft Graph API)
A zero-trust employee offboarding kill-switch for hybrid/cloud environments:
- **Immediate Access Block:** Disables Entra ID sign-in state.
- **Session & Token Revocation:** Executes `Revoke-MgUserSignInSession` to immediately kill active web, desktop, and mobile MFA tokens.
- **Least-Privilege Cleanup:** Audits and strips security groups and distribution lists.
- **License Reclamation:** Removes direct M365 SKU assignments to reduce seat waste.
- **Exchange Delegation:** Converts user mailbox to a Shared Mailbox, hides from GAL, and grants `FullAccess` + `AutoMapping` to the designated manager.
- **Compliance Artifact:** Outputs a timestamped JSON audit record keyed by the ServiceNow/Jira ticket number.

### 2. `macos-vip-endpoint-triage.sh` (macOS Endpoint Telemetry)
A zero-dependency POSIX/Bash diagnostic tool for rapid macOS troubleshooting:
- Verifies **FileVault** full-disk encryption, **System Integrity Protection (SIP)**, and **Gatekeeper** compliance.
- Audits **Jamf / MDM** enrollment profile state.
- Tests active interface routing, DNS resolvers, and gateway latency.
- Identifies runaway CPU/RAM processes causing thermal throttling or application hangs.

---

## 🚀 Usage

### Run the macOS Diagnostic Triage
```bash
chmod +x macos-vip-endpoint-triage.sh
./macos-vip-endpoint-triage.sh
