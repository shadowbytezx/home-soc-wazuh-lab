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


## Lessons Learned

- Setting up isolated lab networking (NAT Network vs. Host-only vs. Bridged) was the most time-consuming part — more so than installing Wazuh itself.
- Local events (like `useradd`) don't carry a `data.srcip` field, since there's no network connection involved — only network-originated events like SSH attempts do.
- Wazuh's default rule set already maps common Linux auth events to MITRE ATT&CK technique categories (Brute Force, Password Guessing) without any manual rule-writing.

## Next Steps

- Add a Windows endpoint with Sysmon for broader detection coverage
- Write custom Wazuh rules for lab-specific detections
- Build a saved Wazuh dashboard with failed-login trends, top source IPs, and severity breakdown


