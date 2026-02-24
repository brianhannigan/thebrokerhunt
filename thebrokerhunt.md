# 🕵️ Threat Hunt Report: The Broker

![Status](https://img.shields.io/badge/Status-Completed-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Microsoft%20Sentinel%20%2B%20MDE-blue)
![Skill](https://img.shields.io/badge/Focus-Threat%20Hunting%20%7C%20IR%20%7C%20KQL-purple)

> **What happened?**  
> A fake “resume” file was opened. It secretly started an attack.  
> The attacker stole credentials, moved to other computers, accessed payroll data, and tried to erase evidence.

---

## 📌 Quick Answers (CTF Flags / Findings)

### Section 1 — Initial Access
- **Initial Payload:** `daniel_richardson_cv.pdf.exe`  
- **Payload SHA256:** `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`
- **Launch Method (Parent Process):** `explorer.exe`
- **Spawned Windows Process:** `notepad.exe`
- **Full Command Line:** `notepad.exe ""`

### Section 2 — Command & Control + Staging
- **C2 Domain:** `cdn.cloud-endpoint.net`
- **C2 Process:** `daniel_richardson_cv.pdf.exe`
- **Staging Domain:** `sync.cloud-endpoint.net`

### Credential Access
- **Registry Hives Targeted:** `SAM, SYSTEM`
- **Local Staging Path:** `C:\Users\Public`
- **Execution Identity:** `sophie.turner`

### Discovery
- **User Context Command:** `whoami.exe`
- **Network Shares Command:** `net.exe view`
- **Privileged Group Queried:** `administrators`

### Remote Tool Persistence (AnyDesk)
- **Remote Tool Installed:** `AnyDesk`
- **AnyDesk SHA256:** `f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532`
- **Download Method:** `certutil.exe`
- **Config File Accessed:** `C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf`
- **Unattended Password Set:** `intrud3r!`
- **Deployed On Hosts:** `as-pc1, as-pc2, as-srv`

### Lateral Movement
- **Failed Remote Tools Tried:** `wmic.exe, PsExec.exe`
- **Target Host (Failed Attempts):** `AS-PC2`
- **Successful Pivot Tool:** `mstsc.exe`
- **Movement Path:** `as-pc1 > as-pc2 > as-srv`
- **Compromised Account Used:** `david.mitchell`
- **Account Activation Parameter:** `active:yes`
- **Activation Performed By:** `david.mitchell`

### Scheduled Task Persistence
- **Task Name:** `MicrosoftEdgeUpdateCheck`
- **Renamed Binary:** `RuntimeBroker.exe`
- **Persistence SHA256:** `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5`
- **Backdoor Account:** `svc_backup`

### Data Access / Staging
- **Sensitive Document:** `BACS_Payments_Dec2025.ods`
- **Editing Artifact:** `.~lock.BACS_Payments_Dec2025.ods#`
- **Access Origin Host:** `as-pc2`
- **Archive Filename:** `Shares.7z`
- **Archive SHA256:** `6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048`

### Anti-Forensics & Memory (Final)
- **Logs Cleared:** `System, Application`
- **Reflective Loading ActionType:** `ClrUnbackedModuleLoaded`
- **Memory Tool:** `SharpChrome`
- **Host Process (Injected Into):** `notepad.exe`

---

## 🧠 The Story (Simple Version)

Think of this like a burglar story:

1. **They tricked someone** into opening a fake resume file.
2. **They called home** (C2) to get instructions.
3. **They stole passwords** from the computer.
4. **They moved to other computers** using Remote Desktop.
5. **They grabbed payroll data** from a file server.
6. **They packed it into a zip-like archive** (`Shares.7z`).
7. **They set up persistence** (AnyDesk + scheduled task + backdoor account).
8. **They tried to hide** by clearing Windows logs.
9. **We still caught them** because Defender/Sentinel kept strong telemetry.

---

## 🗺️ Attack Flow Diagram

```mermaid
flowchart LR
A[User Opens Fake Resume<br>daniel_richardson_cv.pdf.exe] --> B[Initial Access<br>as-pc1]
B --> C[C2 Traffic<br>cdn.cloud-endpoint.net]
B --> D[Staging Domain Used<br>sync.cloud-endpoint.net]

B --> E[Credential Access<br>reg save SAM + SYSTEM]
E --> F[Staged Locally<br>C:\Users\Public]

B --> G[Memory Tool Loaded<br>SharpChrome]
G --> H[Reflective Load<br>ClrUnbackedModuleLoaded]
H --> I[Injected Into<br>notepad.exe]

I --> J[Lateral Movement<br>mstsc.exe]
J --> K[as-pc2]
K --> L[File Server Access<br>BACS_Payments_Dec2025.ods]
L --> M[Archive Created<br>Shares.7z]

M --> N[Persistence Added<br>AnyDesk + Task + svc_backup]
N --> O[Logs Cleared<br>System + Application]
