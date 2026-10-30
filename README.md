# Home SOC Lab — Wazuh SIEM with Simulated SSH Brute-Force Detection

A home-built Security Operations Center lab using **Wazuh** (open-source SIEM/XDR) to detect a simulated SSH brute-force attack launched from a separate, network-isolated VM.

## Overview

This project simulates a basic SOC workflow: deploy a SIEM, generate malicious activity from an external source, and analyze the resulting alerts the way an analyst would — tracing each alert back to its raw log and understanding its severity.

## Architecture

Host PC (VirtualBox)
│
├── wazuh-server (Ubuntu 22.04)
│ ├── Wazuh manager, indexer, dashboard (all-in-one install)
│ ├── Adapter 1: NAT (internet access)
│ └── Adapter 2: NAT Network “Labnet” → 10.0.3.3
│
└── attacker (Ubuntu 22.04)
├── sshpass-based brute-force simulation
├── Adapter 1: NAT (internet access)
└── Adapter 2: NAT Network “Labnet” → 10.0.3.4


Both VMs sit on an isolated `10.0.3.0/24` network (VirtualBox NAT Network), separate from their individual NAT internet adapters. This let the attacker VM reach the Wazuh server without any route back to the host or outside internet.

## Setup

1. Installed Wazuh 4.14 (all-in-one: manager + indexer + dashboard) via the official install script on Ubuntu Server 22.04.
2. Configured a second network adapter (NAT Network) on both VMs via Netplan to create an isolated attack-target network.
3. Verified connectivity between VMs with `ping` before attacking.
4. Deployed the attack from the `attacker` VM using `sshpass` to simulate 12 failed SSH login attempts against the server.
5. Generated additional non-network events directly on the server (`useradd`) to test local-event detection.

## Attack Simulation

```bash
# From the attacker VM (10.0.3.4)
sudo apt install -y sshpass
for i in $(seq 1 12); do
  sshpass -p 'wrongpass' ssh -o StrictHostKeyChecking=no baduser@10.0.3.3 exit
done
```

```bash
# On the server (10.0.3.3)
sudo useradd testuser
```

## Detections

| Action | Alert (`rule.description`) | Rule ID | Level | Source |
|---|---|---|---|---|
| 12 failed SSH logins, non-existent user | sshd: Attempt to login using a non-existent user | 5710 | 5 | Network (attacker VM) |
| Same, PAM layer | PAM: User login failed | 5503 | 5 | Network (attacker VM) |
| `useradd testuser` | New user added to the system | 5902 | 8 | Local (server) |

**Observation:** account creation (level 8) was scored more severely by Wazuh than repeated failed logins (level 5) — a reminder that volume of failures doesn't always equal highest risk; a successful privilege-affecting action often outranks it.

## File Integrity Monitoring (Stretch Goal)

Configured real-time FIM on `/root/labtest` and tracked a file's full lifecycle — creation, modification, and deletion.

```bash
sudo mkdir -p /root/labtest
sudo bash -c 'echo "sensitive data" > /root/labtest/secret.txt'
sudo bash -c 'echo "tampered" >> /root/labtest/secret.txt'
sudo rm /root/labtest/secret.txt
```

| Action | Alert | Rule ID | Level |
|---|---|---|---|
| File created | File added to the system | 554 | 5 |
| File content changed | Integrity checksum changed | 550 | 7 |
| File removed | File deleted | 553 | 7 |

**Observation:** FIM modify/delete events (level 7) were scored higher than file creation (level 5) — the same pattern seen earlier, where state-changing actions on existing resources outrank passive creation events.

## Custom Wazuh Rule (Stretch Goal)

Created a custom detection rule to escalate severity when SSH brute-force attempts originate specifically from the known attacker VM, rather than relying on the generic rule alone.

**`/var/ossec/etc/rules/local_rules.xml`:**
```xml
<group name="local,syslog,sshd,">
  <rule id="100001" level="12">
    <if_sid>5710</if_sid>
    <srcip>10.0.3.4</srcip>
    <description>CUSTOM: SSH brute-force attempt detected from known attacker VM (10.0.3.4)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>attack,custom_rule,</group>
  </rule>
</group>
```

| Rule | Trigger | Level |
|---|---|---|
| 5710 (default) | Any failed login with invalid username | 5 |
| 100001 (custom) | Failed login with invalid username **from 10.0.3.4 specifically** | 12 |

**Observation:** this demonstrates rule chaining via `if_sid` — building a more specific, higher-priority detection on top of an existing generic one, rather than duplicating logic. In a real environment, `10.0.3.4` would be a known-malicious or watchlisted IP rather than a hardcoded lab address.



## Windows Endpoint with Sysmon (Stretch Goal)

Deployed a Windows 11 VM with Sysmon (SwiftOnSecurity config) and the Wazuh agent, extending detection beyond Linux to cover process creation, registry changes, and PowerShell abuse patterns.

**Setup:**
- Installed Sysmon with the community-maintained SwiftOnSecurity configuration
- Added the `Microsoft-Windows-Sysmon/Operational` channel to the Wazuh agent's `ossec.conf`
- Deployed via the Wazuh agent MSI, enrolled to the same `10.0.3.3` manager

| Alert | Rule ID | Level |
|---|---|---|
| PowerShell process created an executable file in Windows root folder | 92205 | 9 |
| PowerShell used to delete files or directories | 92021 | 3 |
| SecEdit.exe launched from a suspicious location | 92066 | 4 |

### False Positive Triage Example

One alert (rule 92205, level 9, MITRE T1105 "Ingress Tool Transfer") fired when simply opening built-in Windows apps. Investigation of the raw event showed:

- Process: `powershell.exe`
- Target file: `C:\Windows\SystemTemp\__PSScriptPolicyTest_*.ps1`
- User: `NT AUTHORITY\SYSTEM`

This matches PowerShell's built-in script policy self-test, a routine internal check PowerShell performs on startup, not malicious activity. The filename pattern (`__PSScriptPolicyTest_`) and `SYSTEM` context are the key indicators used to rule it out.

**Takeaway:** Sysmon + generic rules can't distinguish benign system behavior from malicious staging when the file-write pattern looks identical. This is the kind of alert a SOC analyst would mark as a false positive after checking the process, target path, and executing user, rather than escalating it.

**Observation:** even routine Windows background activity (opening built-in apps) triggered PowerShell- and SecEdit-related alerts. This highlights a real SOC challenge: Sysmon-based detections are high-fidelity but require tuning and baselining to separate normal system behavior from genuine threats — not every alert means compromise.

## Lessons Learned

#Infrastructure & networking
- Setting up isolated lab networking (NAT Network vs. Host-only vs. Bridged) was the most time-consuming part of the whole project — more so than installing Wazuh itself. The host-only networking driver being unavailable forced a pivot to NAT Network, which turned out to work just as well.
- VirtualBox locks network adapter settings while a VM is running — most "invalid settings" or greyed-out field issues during setup were solved by a full power-off, not a reboot inside the guest OS.
- `ping` round-trip time is a reliable way to tell whether two VMs are actually talking over the network or whether you're accidentally pinging the same machine (sub-0.1ms = self-ping, ~0.3–3ms = real cross-VM traffic).

#Detection fundamentals
- Local events (like `useradd`) don't carry a `data.srcip` field, since there's no network connection involved — only network-originated events like SSH attempts do.
- Severity level isn't just about volume. A single `useradd` (level 8) or a single modified/deleted file under FIM (level 7) outranked dozens of repeated failed SSH logins (level 5). State-changing actions on existing resources are scored higher than passive creation or repeated failed attempts.
- Wazuh's default rule set already maps common Linux auth events to MITRE ATT&CK technique categories (Brute Force, Password Guessing) without any manual rule-writing — the mapping comes out of the box.

#Rule tuning
- Writing a custom rule (`if_sid` + `srcip`) showed how real detection engineering works: rather than duplicating logic, you chain a new rule on top of an existing one to add context (a known-bad source) and escalate severity accordingly.
- Custom rules only take effect after `systemctl restart wazuh-manager` — editing `local_rules.xml` alone does nothing until the manager reloads.

#Sysmon and false positives
- A strict Sysmon config (SwiftOnSecurity) generates high-fidelity alerts, but also flags entirely benign system behavior — opening Notepad and Calculator triggered PowerShell- and SecEdit-related alerts from Windows' own background processes.
- Triage, not just detection, is the real skill: tracing an alert back to its process, target file path, and executing user (`NT AUTHORITY\SYSTEM` in this case) was what separated "looks like malware staging" from "this is PowerShell's routine self-test."
- Sysmon doesn't log to a channel Wazuh monitors by default — `Microsoft-Windows-Sysmon/Operational` has to be added explicitly to `ossec.conf`, unlike System/Application/Security which are monitored out of the box.

#General
- Alert count and severity aren't correlated 1:1 with real risk — a 38-alert brute-force spike mattered less in isolation than a single high-severity account-creation event. Context (source, target, user) is what turns raw alerts into an actual investigation.


