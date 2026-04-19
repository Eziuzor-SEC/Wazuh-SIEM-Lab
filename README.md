# Wazuh SIEM Home Lab

## Project Overview
This lab demonstrates the deployment of Wazuh, an open-source SIEM and XDR platform, using Docker on a Windows machine. The lab covers agent deployment, attack simulation mapped to MITRE ATT&CK, custom detection rule authoring, and proactive threat hunting using DQL queries.

---

## Tools & Technologies
- Wazuh 4.7.0 (Manager, Indexer, Dashboard)
- Docker Desktop (Single-node deployment)
- Git Bash
- Windows 10 Agent (Eziuzor-Machine)
- PowerShell
- MITRE ATT&CK Framework
- DQL (Dashboard Query Language)

---

## Lab Setup

### Step 1 — Clone Wazuh Docker Repository
```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.7.0
cd wazuh-docker/single-node
```

### Step 2 — Generate SSL Certificates
```bash
docker-compose -f generate-indexer-certs.yml run --rm generator
```

### Step 3 — Deploy Wazuh Containers
```bash
docker-compose up -d
```

### Step 4 — Access Dashboard
Navigate to `https://localhost` and log in with admin credentials.

![Wazuh Dashboard](screenshots/wazuh-dashboard-overview.png)

---

## Windows Agent Deployment
Deployed a Wazuh agent on a Windows 10 machine (Eziuzor-Machine) via PowerShell:

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi -OutFile ${env.tmp}\wazuh-agent; msiexec.exe /i ${env.tmp}\wazuh-agent /q WAZUH_MANAGER='127.0.0.1' WAZUH_AGENT_NAME='Eziuzor-Machine' WAZUH_REGISTRATION_SERVER='127.0.0.1'

NET START WazuhSvc
```

![Active Agent](screenshots/wazuh-agents-active.png)

---

## Attack Simulations

The following simulations were executed via PowerShell to generate security events mapped to MITRE ATT&CK techniques.

| Simulation | Command | MITRE Technique | Detected |
|---|---|---|---|
| Reconnaissance | `whoami`, `net user` | T1087 | Requires custom rule |
| Brute Force | Failed logins via net use | T1110 | Yes - Rule 60122 |
| Suspicious Process | cmd.exe spawning recon commands | T1059 | Partial |
| Privilege Check | `whoami /priv` | T1078 | Requires custom rule |
| Scheduled Task | schtasks /create | T1053.005 | Requires custom rule |
| Registry Modification | reg add Run key | T1547.001 | Yes - Rule 750, 751 |
| Credential Enumeration | net user, wmic useraccount | T1087 | Requires custom rule |
| Event Log Clearing | wevtutil cl System/Security | T1070.001 | Yes - Rule 63103, 63104 |

![Security Alerts](screenshots/wazuh-security-alerts-table.png)

---

## Key Detections

### Defense Evasion — Event Log Clearing (T1070)
Wazuh detected both System and Security log clearing events immediately, mapping them to MITRE T1070 Indicator Removal.

![Defense Evasion](screenshots/wazuh-defense-evasion-alerts.png)

### Persistence — Registry Modification (T1547.001)
Registry modification via the Windows Run key was detected by both built-in Wazuh rules and a custom rule authored during this lab.

![Registry Alerts](screenshots/wazuh-registry-alerts.png)

### Brute Force — Authentication Failures (T1110)
Five consecutive failed login attempts were detected and mapped to T1078 Valid Accounts and T1531.

![Expanded Alert](screenshots/wazuh-alert-expanded.png)

---

## Custom Detection Rule

To address a detection gap where Wazuh did not alert on registry modifications out of the box, a custom rule was authored targeting Windows Event ID 4657.

```xml
<group name="windows,registry,">
  <rule id="100001" level="10">
    <if_group>windows</if_group>
    <field name="win.system.channel">Security</field>
    <field name="win.system.eventID">^4657$</field>
    <description>Registry value modified - Possible persistence via Run key</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
    <group>registry_modification,persistence,</group>
  </rule>
</group>
```

![Custom Rule](screenshots/wazuh-custom-rule.png)

---

## Threat Hunting with DQL

Proactive threat hunting was performed using Wazuh's Dashboard Query Language (DQL) to investigate alerts beyond passive monitoring.

| Query | Purpose | Result |
|---|---|---|
| `agent.name:Eziuzor-Machine` | All alerts from monitored endpoint | 1,783 alerts |
| `rule.mitre.tactic:Defense Evasion` | Hunt for evasion techniques | Log clearing detected |
| `rule.level:5 OR rule.level:6 OR rule.level:7 OR rule.level:8 OR rule.level:9 OR rule.level:10` | High severity alerts only | Multiple Level 5 detections |
| `rule.mitre.tactic:Persistence` | Hunt for persistence mechanisms | Registry activity detected |
| `rule.id:63103` | Specific audit log cleared detection | Confirmed detection |

---

## Detection Gaps & Recommendations

Several simulations did not trigger out-of-the-box Wazuh alerts, highlighting the importance of SIEM tuning in real SOC environments:

- Reconnaissance commands (whoami, net user) require custom rules correlating multiple commands fired in quick succession
- Scheduled task creation requires enabling Windows audit policy for process creation events
- Credential enumeration via wmic requires Sysmon integration for deeper process visibility

These gaps demonstrate that default SIEM configurations are never sufficient and continuous rule tuning is a core SOC responsibility.

---

## Key Takeaways
- Successfully deployed a production-grade SIEM stack using Docker
- Demonstrated end-to-end detection across 6 MITRE ATT&CK tactic categories
- Authored a custom detection rule to close an identified detection gap
- Performed proactive threat hunting using DQL queries
- Identified and documented SIEM detection gaps with remediation recommendations
