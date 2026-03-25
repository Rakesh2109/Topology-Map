# 🏥 IoMT Medical NIDS Simulator — Complete Learning Guide
**From Basics to Advanced (v3.0 Production-Grade)**

---

## Table of Contents
1. [What Is This Project?](#1-what-is-this-project)
2. [Core Concepts (Prerequisites)](#2-core-concepts)
3. [Project Architecture Overview](#3-project-architecture)
4. [Hospital Network Zones & Routing](#4-hospital-network-zones--routing)
5. [All 38 Devices — Purpose & Function](#5-all-38-devices--purpose--function)
6. [All 24 Attack Scenarios — How They Happen](#6-all-24-attack-scenarios--how-they-happen)
7. [World 1: Mathematical Engine (Deep Dive)](#7-world-1-mathematical-engine)
8. [World 2: Docker Orchestration (Deep Dive)](#8-world-2-docker-orchestration)
9. [Code Architecture (File-by-File)](#9-code-architecture)
10. [Known Drawbacks & Limitations](#10-known-drawbacks--limitations)
11. [Academic References](#11-academic-references)

---

## 1. What Is This Project?

This is a **Network Intrusion Detection System (NIDS) Dataset Generator** designed specifically for **Internet of Medical Things (IoMT)** hospital environments. Instead of collecting real patient network data (which has strict privacy regulations like HIPAA/GDPR), this simulator **mathematically generates** realistic network traffic that mirrors what a real hospital network produces.

### Why Does This Matter?
Machine Learning models for cybersecurity need **massive, labeled datasets** to learn the difference between normal hospital traffic and cyber-attacks. Real hospital data is:
- **Illegal to share** (patient privacy laws)
- **Rare** (hospitals don't willingly get hacked for research)
- **Unbalanced** (99.9% benign, 0.1% attack)

This simulator solves all three problems by generating **controlled, labeled, balanced** datasets on demand.

---

## 2. Core Concepts

### 2.1 What Is a "Flow"?
A **network flow** is a single communication session between two devices. Example:
```
Nurse Station (10.2.3.10) → PACS Server (10.2.1.10) via HTTPS on port 443
Duration: 500ms | Sent: 2400 bytes | Received: 15000 bytes
```
Each flow record contains: Source IP, Destination IP, Ports, Protocol, Bytes, Packets, Duration, TCP Flags, and Labels.

### 2.2 What Is a "Time Window"?
A **time window** groups all flows within a fixed interval (default: 5 seconds) and computes aggregate statistics:
- How many unique IPs were seen?
- How many login failures occurred?
- What was the DICOM query rate?

These window-level features are what ML models actually train on.

### 2.3 What Is NIDS?
A **Network Intrusion Detection System** monitors network traffic and classifies it as `benign` or `attack`. This simulator generates the training data for building such systems.

### 2.4 What Is IoMT?
**Internet of Medical Things** — connected hospital devices: patient monitors, infusion pumps, ventilators, MRI scanners, wearables. These devices have unique security challenges because:
- They run legacy firmware (can't be easily patched)
- They are life-critical (can't be taken offline for updates)
- They use specialized protocols (DICOM, HL7, BLE)

---

## 3. Project Architecture

```
iotm_data/
├── config.py              # 🧠 Brain: Zones, Devices, 24 Attack Definitions, CommMap
├── network_model.py       # 🏗️ Builds the hospital network graph from config
├── traffic_generator.py   # 🚗 Generates realistic benign hospital traffic
├── attack_injector.py     # 💀 Injects 24 attack scenarios with state machines
├── labeling_engine.py     # 🏷️ Labels flows as benign/attack with transition windows
├── time_window.py         # 📊 Aggregates flows into 5-second feature windows
├── dataset_builder.py     # 📦 Orchestrates full dataset generation (train/test split)
├── export.py              # 💾 Exports datasets to CSV/JSON formats
├── main.py                # 🚀 CLI entry point (--generate-dataset, --web, etc.)
├── gui_web.py             # 🌐 Web dashboard backend (Flask-like SSE server)
├── scenario_builder.py    # ✏️ GUI-based custom attack scenario creator
├── gui.py                 # 🖥️ Desktop GUI (tkinter)
├── scripts/
│   ├── docker_orchestrator.py  # 🐳 Converts JSON topology → docker-compose.yml
│   ├── docker_attacker.py      # 💣 Physical attack detonation inside Docker
│   └── pcap_exporter.py        # 📡 Converts CSV flows → binary .pcap files
├── configs/
│   ├── devices/medium_hospital.json   # 38-device hospital topology
│   └── scenarios/                     # Custom attack scenario JSONs
├── docs/
│   └── visualizations/          # Interactive HTML topology diagrams
└── static/                      # Web dashboard frontend (HTML/CSS/JS)
```

### Data Flow Pipeline
```
config.py → network_model.py → traffic_generator.py ──┐
                                                       ├→ dataset_builder.py → CSV
                               attack_injector.py ─────┘       ↓
                               labeling_engine.py ──────→ train.csv + test.csv
                               time_window.py ──────────→ windowed features
```

---

## 4. Hospital Network Zones & Routing

The hospital network is segmented into **6 strict security zones**, each isolated by firewalls. This mirrors real-world hospital network architecture per NIST and IEC 62443 standards.

### Zone Architecture

| Zone | Name | Subnet | Purpose | Security Level |
|------|------|--------|---------|----------------|
| **A** | Internet Edge | `203.0.113.0/24` | External-facing services, VPN termination, web portals | DMZ (Exposed) |
| **B** | Enterprise IT | `10.1.0.0/16` | Active Directory, DNS, DHCP, File Shares, EHR, SOC | High |
| **C** | Clinical Core | `10.2.0.0/16` | PACS, HL7 Engine, FHIR, Nurse Stations, Device Mgmt | Critical |
| **D** | Imaging Subnet | `10.3.0.0/16` | CT Scanners, MRI, Ultrasound, Radiology Workstations | Critical |
| **E** | IoMT Subnet | `10.4.0.0/16` | Patient Monitors, Infusion Pumps, Ventilators, Wearables | Life-Critical |
| **F** | Third-Party | `10.5.0.0/24` | Vendor VPN, Remote Jump Hosts | Restricted |

### Routing Architecture
Traffic between zones passes through a **perimeter firewall** (`fw-perimeter-01`) and/or **edge gateway** (`gw-edge-01`). In the Docker (World 2) version, these are Alpine Linux containers with `NET_ADMIN` capabilities and `ip_forward=1` enabled, acting as real Layer-3 routers.

**Router Types Used:**
- **Edge Gateway (gw-edge-01)**: Acts as the hospital's border router. Handles NAT, VPN termination, and external traffic ingress/egress. In Docker: multi-homed container spanning all bridge networks.
- **Perimeter Firewall (fw-perimeter-01)**: Stateful packet inspection between zones. Controls which subnets can communicate. In Docker: container with `NET_ADMIN` cap and iptables rules.
- **Docker Bridge Networks**: Each zone is an isolated Layer-2 bridge (`br-zone_a`, `br-zone_b`, etc.). Containers on different bridges cannot communicate unless routed through the gateway container.

---

## 5. All 38 Devices — Purpose & Function

### Zone A: Internet Edge (3 devices)

| Device | IP | Role | Purpose |
|--------|----|----|---------|
| `gw-edge-01` | 203.0.113.1 | Gateway | Border router. All external traffic enters/exits here. Handles VPN termination for remote clinicians and vendor access. |
| `fw-perimeter-01` | 203.0.113.2 | Firewall | Stateful firewall inspecting every packet crossing zone boundaries. Enforces ACLs (e.g., Zone E devices cannot reach the internet directly). |
| `web-portal-01` | 203.0.113.10 | Web Portal | Patient-facing web application for appointment booking, lab results, and telehealth. Internet-exposed, high attack surface. |

### Zone B: Enterprise IT (7 devices)

| Device | IP | Role | Purpose |
|--------|----|----|---------|
| `ad-server-01` | 10.1.1.10 | Active Directory | Central authentication server. Every staff login (nurse, doctor, admin) is validated here via LDAP/Kerberos. If compromised, the attacker owns the entire domain. |
| `dns-server-01` | 10.1.1.11 | DNS Server | Resolves internal hostnames. Also serves as NTP source for clock synchronization across all medical devices. |
| `dhcp-server-01` | 10.1.1.12 | DHCP Server | Assigns IP addresses to workstations and mobile devices joining the network. |
| `ehr-frontend-01` | 10.1.2.10 | EHR Frontend | Electronic Health Record web interface. Clinicians access patient charts, lab orders, and medication lists through this system. |
| `file-share-01` | 10.1.3.10 | File Share | SMB/CIFS network drive for hospital documents, policies, and departmental files. Primary target for ransomware encryption. |
| `backup-server-01` | 10.1.3.20 | Backup Server | Automated nightly backup of EHR databases and PACS images. Attackers target this to prevent recovery after ransomware. |
| `soc-collector-01` | 10.1.4.10 | SOC Collector | Security Operations Center log aggregator. Receives Syslog from all critical devices for SIEM analysis. |

### Zone C: Clinical Core (9 devices)

| Device | IP | Role | Purpose |
|--------|----|----|---------|
| `pacs-server-01` | 10.2.1.10 | PACS Server | **Picture Archiving and Communication System.** Stores all medical images (X-rays, CT scans, MRIs). Uses DICOM protocol. The most valuable target (contains PHI). |
| `vna-01` | 10.2.1.20 | VNA | Vendor Neutral Archive. Stores clinical documents/images from multiple vendors in a unified format. |
| `ris-01` | 10.2.1.30 | RIS | Radiology Information System. Manages radiology workflows: scheduling exams, tracking reports, billing. |
| `lis-01` | 10.2.1.40 | LIS | Laboratory Information System. Manages lab test orders, specimen tracking, and result reporting via HL7 messages. |
| `fhir-server-01` | 10.2.2.10 | FHIR Server | **Fast Healthcare Interoperability Resources API.** Modern REST API for exchanging electronic health records. Internet-exposed for third-party app integration. |
| `hl7-engine-01` | 10.2.2.20 | HL7 Engine | Message broker translating HL7v2 ADT (Admit/Discharge/Transfer) messages between clinical systems. |
| `nurse-station-01` | 10.2.3.10 | Nurse Station | Clinical workstation used by nurses to view patient vitals, dispense medications, and update charts. |
| `nurse-station-02` | 10.2.3.11 | Nurse Station | Second nurse workstation (different ward/floor). |
| `device-mgmt-01` | 10.2.4.10 | Device Management | Centralized console for managing firmware updates, SNMP polling, and configuration pushes to all IoMT devices. |

### Zone D: Imaging Subnet (7 devices)

| Device | IP | Role | Purpose |
|--------|----|----|---------|
| `ct-scanner-01` | 10.3.1.10 | CT Scanner | Computed Tomography scanner. Generates DICOM images sent to PACS. Runs embedded Windows/Linux. Cannot be easily patched. |
| `mri-scanner-01` | 10.3.1.20 | MRI Scanner | Magnetic Resonance Imaging system. Generates large DICOM datasets (hundreds of MB per scan). |
| `ultrasound-01` | 10.3.1.30 | Ultrasound | Portable ultrasound device. Connects via both wired ethernet and Wi-Fi. |
| `rad-ws-01` | 10.3.2.10 | Radiology Workstation | High-end workstation where radiologists view and annotate medical images. Dual-homed (Clinical + Imaging). |
| `rad-ws-02` | 10.3.2.11 | Radiology Workstation | Second radiology workstation. |
| `dicom-viewer-01` | 10.3.3.10 | DICOM Viewer | Web-based or desktop DICOM image viewer used by clinicians outside radiology. |
| `img-archive-gw-01` | 10.3.3.20 | Imaging Archive GW | Gateway to long-term imaging archive/cold storage. Handles DICOM C-MOVE for retrieval. |

### Zone E: IoMT Subnet (13 devices)

| Device | IP | Role | Purpose |
|--------|----|----|---------|
| `patient-mon-01` | 10.4.1.10 | Patient Monitor | Bedside vital signs monitor (heart rate, SpO2, blood pressure). Streams telemetry every 1-2 seconds via TCP/BLE. |
| `patient-mon-02` | 10.4.1.11 | Patient Monitor | Second bedside monitor (different patient room). |
| `patient-mon-03` | 10.4.1.12 | Patient Monitor | Third bedside monitor (ICU). |
| `infusion-pump-01` | 10.4.2.10 | Infusion Pump | Delivers precise medication doses to patients. **Life-critical** — a hacked pump could deliver a lethal dose. |
| `infusion-pump-02` | 10.4.2.11 | Infusion Pump | Second infusion pump. |
| `ventilator-01` | 10.4.3.10 | Ventilator | Mechanical ventilator for ICU patients. Uses SSH for management. **Highest criticality** device. |
| `ventilator-02` | 10.4.3.11 | Ventilator | Second ventilator. |
| `mobile-med-app-01` | 10.4.4.10 | Mobile Medical App | Clinician smartphone app for bedside charting. Connects via HTTPS and BLE. |
| `ble-gw-01` | 10.4.5.10 | BLE Gateway | Bluetooth Low Energy gateway aggregating data from wearables and BLE-enabled monitors. |
| `wifi-gw-01` | 10.4.5.20 | Wi-Fi Gateway | Wireless access point for IoMT devices that use Wi-Fi (ultrasound, mobile apps). |
| `telemetry-agg-01` | 10.4.6.10 | Telemetry Aggregator | Central hub that collects, buffers, and forwards all IoMT telemetry data to the clinical systems. |
| `wearable-01` | 10.4.7.10 | Wearable | Patient wristband sensor (heart rate, step count, fall detection). Communicates via BLE only. |
| `wearable-02` | 10.4.7.11 | Wearable | Second wearable device. |

### Zone F: Third-Party Support (2 devices)

| Device | IP | Role | Purpose |
|--------|----|----|---------|
| `vendor-vpn-01` | 10.5.0.10 | Vendor VPN | VPN concentrator for external vendor remote access (e.g., GE Healthcare, Siemens). Time-limited access windows. |
| `vendor-jumphost-01` | 10.5.0.20 | Vendor Jump Host | Bastion server where vendors land after VPN authentication. From here, they SSH/RDP into managed devices. |

---

## 6. All 24 Attack Scenarios — How They Happen

Each attack follows the **MITRE ATT&CK Cyber Kill Chain**: Reconnaissance → Initial Access → Execution → Persistence → Lateral Movement → Exfiltration.

### Reconnaissance & Initial Access (A01–A04)

| ID | Attack Name | Entry Point | Target | How It Works |
|----|-------------|-------------|--------|--------------|
| **A01** | External Recon | Internet | All edge-facing IPs | Attacker sends thousands of short TCP SYN probes to discover open ports. Signature: many RST responses, very short flow durations (<100ms), high unique destination ports. |
| **A02** | Service Enumeration | Internet | Web Portal, PACS | HTTP path crawling (`/admin`, `/api`, `/login`) to fingerprint application versions. Moderate request bursts with small responses. |
| **A03** | Password Spraying | Internet | VPN Gateway | Low-rate login attempts using common passwords across many usernames. Stays below lockout thresholds. 92% failure rate with slow rotation. |
| **A04** | Brute Force PACS | Internet | PACS Server | High-rate password guessing against the imaging portal. Success probability increases over time (simulates dictionary cracking). |

### Credential Exploitation (A05–A10)

| ID | Attack Name | Entry Point | Target | How It Works |
|----|-------------|-------------|--------|--------------|
| **A05** | Vendor Support Abuse | Compromised VPN | Jump Host → Clinical | Legitimate vendor credentials used at unusual hours. Three-stage: access → pivot into clinical zone → access patient data. |
| **A06** | Default Credentials | Internal | Patient Monitors | Many IoMT devices ship with default admin/admin credentials. Immediate admin session after minimal attempts. |
| **A07** | Hard-coded Credential Abuse | Internal | Ventilators | Firmware contains hard-coded service credentials. Attacker gains SSH access and modifies ventilator configuration. |
| **A08** | Auth Bypass Imaging | Internet/Internal | PACS, DICOM Viewer | Exploits authentication vulnerability — privileged access without prior login sequence. |
| **A09** | Replay Token Attack | Compromised Endpoint | EHR, FHIR Server | Captured session token replayed from a different client context. Access to patient records without valid credentials. |
| **A10** | Cleartext Credential Capture | Internal | Web Portal, Mobile App | Sniffing unencrypted HTTP traffic on the same subnet, then replaying captured credentials. |

### IoMT-Specific Attacks (A11–A12)

| ID | Attack Name | Entry Point | Target | How It Works |
|----|-------------|-------------|--------|--------------|
| **A11** | BLE Telemetry Replay | Near-device | Wearables, BLE GW | Attacker within Bluetooth range captures BLE packets and replays them, causing duplicate or falsified vital signs. |
| **A12** | Firmware Tampering | Internal Privileged | All IoMT Devices | Unauthorized firmware push through the device management server. Large transfers followed by device reboot wave. |

### Data Theft (A13–A16)

| ID | Attack Name | Entry Point | Target | How It Works |
|----|-------------|-------------|--------|--------------|
| **A13** | DICOM Discovery | Compromised WS | PACS, Archive | Spike in DICOM C-FIND queries to enumerate patient studies. Precursor to bulk image theft. |
| **A14** | DICOM Exfiltration | Compromised Radiology | PACS, Viewer, Archive | Sustained large DICOM C-MOVE transfers. Outbound bytes surge to unusual external IP. |
| **A15** | FHIR Bulk Pull | Compromised App Token | FHIR Server | High-rate GET requests with anomalous pagination, pulling thousands of patient records via the REST API. |
| **A16** | HL7 Interface Flood | Compromised Clinical | HL7 Engine, LIS, EHR | Abnormal HL7 message count bursts causing parser errors. Can disrupt lab result delivery. |

### Lateral Movement & Ransomware (A17–A20)

| ID | Attack Name | Entry Point | Target | How It Works |
|----|-------------|-------------|--------|--------------|
| **A17** | East-West Pivot | Compromised IT | Clinical from Enterprise | Sudden SMB/RDP connections from Enterprise IT zone to Clinical/Imaging/IoMT zones. Progressive host compromise. |
| **A18** | Ransomware Staging | Compromised WS | File Shares, AD, Backup | SMB session spike, admin share access, RDP spread. Ransomware payload staged across file shares. |
| **A19** | Backup Deletion | Compromised Admin | Backup Server | Discovery and deletion of backup volumes to prevent ransomware recovery. Drop in routine backup traffic. |
| **A20** | PHI Exfiltration | Compromised Server | File Share, EHR | Large outbound transfer to unusual external destination. Data staged, compressed, then exfiltrated. |

### Denial of Service & Sabotage (A21–A24)

| ID | Attack Name | Entry Point | Target | How It Works |
|----|-------------|-------------|--------|--------------|
| **A21** | PACS DoS | External/Internal | PACS Server | Resource exhaustion via massive DICOM/HTTPS requests. Retransmissions rise, service latency spikes. |
| **A22** | App-Layer Flood | Internet Bot | Web Portal, EHR | High HTTP request rate causing 4xx/5xx error storms. Simulates application-layer DDoS. |
| **A23** | Telemetry Spoofing | Internal MITM | Telemetry Aggregator | Normal packet rate but implausible vital sign value jumps. Could cause false alarms or mask real emergencies. |
| **A24** | Unauthorized Config Change | Compromised Tool | Device Management | Bursts of write/config operations to IoMT devices, causing device behavior drift (e.g., changing alarm thresholds). |

---

## 7. World 1: Mathematical Engine

### How It Works
The mathematical engine uses **probability distributions** and **finite state machines** to simulate network traffic without any actual networking.

1. **Benign Traffic Generation** (`traffic_generator.py`):
   - Uses a **Communication Map** (`NORMAL_COMM_MAP`) defining who talks to whom and at what rate
   - Applies **diurnal patterns**: imaging peaks 8am-6pm, backups run 1am-4am, IoMT telemetry is 24/7
   - Adds **infrastructure noise**: DNS queries, SNMP polling, NTP sync, Syslog forwarding
   - Uses **burst/pause cycles** via overlapping sine functions for organic variability

2. **Attack Injection** (`attack_injector.py`):
   - Each of 24 attacks is a `AttackStateMachine` with multi-stage progression
   - **IP Rotation**: External attackers rotate through 2-6 IPs (simulating proxies/botnets)
   - **Organic Variability**: Flow counts modulated by multi-frequency sine waves + random bursts
   - **Inter-flow Correlation**: State tracks compromised hosts, discovered data, and stage progress

3. **Dataset Assembly** (`dataset_builder.py`):
   - Places each attack TWICE: once in train region (0-80%), once in test (80-100%)
   - **Chronological split**: No random shuffling, preserving temporal dependencies
   - Outputs `train.csv`, `test.csv`, and `full_dataset.csv`

### Output Format
Each row in the CSV contains raw flow metadata:
```csv
ts_start, ts_end, duration, src_ip, dst_ip, src_port, dst_port, proto,
bytes_in, bytes_out, packets_in, packets_out, tcp_flags, zone_src, zone_dst,
device_role_src, device_role_dst, label, attack_type, scenario_id
```

---

## 8. World 2: Docker Orchestration

### How It Works
The Docker orchestrator converts the same hospital topology into a **real, physical containerized environment**.

1. **Infrastructure** (`scripts/docker_orchestrator.py`):
   - Reads `configs/devices/medium_hospital.json`
   - Creates 38 Alpine Linux containers, one per hospital device
   - Creates 6 isolated Docker bridge networks (one per zone)
   - Gateway/Firewall containers get `NET_ADMIN` capability and span all networks

2. **Physical Attack Detonation** (`scripts/docker_attacker.py`):
   - Installs real hacking tools (`nmap`, `hping3`) into the attacker container
   - Installs `tcpdump` on the router to capture cross-zone traffic
   - Executes actual network attacks (port scans, SYN floods) between containers
   - Extracts the resulting `.pcap` file for analysis in Wireshark

### Key Difference from World 1
| Aspect | World 1 (Math) | World 2 (Docker) |
|--------|----------------|-------------------|
| Speed | Millions of flows in seconds | Real-time execution |
| Payload | No binary payload (metadata only) | Real binary TCP/IP packets |
| Scale | 10,000+ devices possible | Limited by Docker host resources |
| Use Case | ML training datasets | DPI analysis, IDS rule testing |
| PCAP | Synthesized (via scapy) | Native (via tcpdump) |

---

## 9. Code Architecture

### `config.py` (639 lines) — The Brain
- Defines 6 `Zone` enums with subnet assignments
- Defines 33 `DeviceRole` enums covering all hospital asset types
- Contains 38 `AssetDef` dataclasses with IP, zone, protocols, criticality
- Registers all 24 `AttackScenario` objects (A01-A24) with multi-stage definitions
- Defines the `NORMAL_COMM_MAP` (27 communication pairs with baseline flow rates)
- Defines `BASE_FLOW_FIELDS` (26 fields), `MEDICAL_METADATA_FIELDS` (16 fields), and `WINDOW_FEATURE_FIELDS` (28+ features)

### `network_model.py` (110 lines) — The Graph
- Wraps `AssetDef` into runtime `Asset` objects
- Builds lookup indices: by name, by role, by zone
- Generates communication pairs from `NORMAL_COMM_MAP` with flow rate scaling

### `traffic_generator.py` (560 lines) — Benign Traffic
- `BenignTrafficGenerator` creates flows from the communication map
- Diurnal modulation per device role (imaging peaks daytime, backups at night)
- Infrastructure noise: DNS, SNMP, NTP, Syslog background traffic
- Web browsing noise from nurse stations and radiology workstations
- Maintenance events: software updates, backup sync, clinician logins, vendor sessions

### `attack_injector.py` (933 lines) — The Weapon
- `AttackStateMachine` with IP rotation pool, session state, and stage tracking
- 24 dedicated generator functions (`_a01_recon` through `_a24_config`)
- Organic variability via multi-frequency sine wave modulation
- Progressive compromise tracking (hosts taken over, data discovered)

### `labeling_engine.py` (222 lines) — The Labeler
- Per-flow labeling with attack_id and scenario_id
- Transition window support (ambiguous 5% boundary around attack start/end)
- Event extraction for 15+ event types (login failures, DICOM bursts, lateral movement, etc.)

### `time_window.py` (184 lines) — Feature Engineering
- Aggregates flows into fixed-size windows (default 5 seconds)
- Computes 28+ aggregate features: flow counts, unique IPs, login metrics, DICOM rates, cross-zone traffic, retransmission rates, patient value anomaly scores

### `dataset_builder.py` (349 lines) — The Orchestrator
- Plans attack slots: each scenario appears twice (train and test)
- Deterministic shuffled ordering for variety
- Chronological 80/20 split with no data leakage
- Outputs comprehensive `dataset_info.json` with full statistics

---

## 10. Known Drawbacks & Limitations

### Critical Drawbacks

| # | Drawback | Impact | Mitigation |
|---|----------|--------|------------|
| 1 | **No Real Payload Content** | World 1 generates flow metadata only — no actual HTTP headers, DICOM payloads, or HL7 message bodies. DPI models cannot train on this data. | Use `pcap_exporter.py` for synthetic payloads, or use World 2 for real packet capture. |
| 2 | **No Dynamic OS Emulation (World 1)** | Devices are mathematical abstractions, not running operating systems. No CPU load, memory usage, or process-level telemetry. | World 2 (Docker) addresses this partially with Alpine Linux containers. |
| 3 | **Single-Profile Hospital Only** | Only `medium_hospital_v1` profile exists (38 devices). No small clinic or large research hospital variant. | Extend `config.py` with additional profiles and device lists. |
| 4 | **Fixed Attack Timing in World 2** | The Docker attacker script (`docker_attacker.py`) currently has only 2 attack modules (recon + DoS). The mathematical engine has 24. | Extend `docker_attacker.py` with additional physical attack modules. |
| 5 | **No Encrypted Traffic Analysis** | TLS/SSL is flagged (`tls_session=1`) but no actual encryption occurs. Cannot train models on encrypted traffic patterns. | Integrate `mitmproxy` or `stunnel` in Docker for real TLS. |

### Code Quality Issues

| # | Issue | File | Details |
|---|-------|------|---------|
| 6 | **Type Checking Errors** | `time_window.py` | `round()` overload and `dict` type assignment errors flagged by Pyre2. Does not affect runtime but indicates imprecise type annotations. |
| 7 | **Import Path Resolution** | `labeling_engine.py`, `time_window.py` | `from config import ...` fails Pyre2 resolution because there is no `__init__.py` or proper package structure. Works at runtime because Python adds CWD to `sys.path`. |
| 8 | **Duplicate CLI Sections** | `README.md` | Steps 3-5 in the CLI section were duplicated (Docker Orchestration and PCAP export listed twice with different path conventions). |
| 9 | **Hard-coded Docker IPs** | `docker_attacker.py` | Target IPs (e.g., `10.0.2.11` for PACS) are hard-coded and may not match the actual Docker compose subnet assignments in `medium_hospital.json`. |
| 10 | **No Error Recovery** | `dataset_builder.py` | If generation crashes mid-way (e.g., out of memory on large durations), there is no checkpoint/resume mechanism. Partial datasets are lost. |

### Architectural Limitations

| # | Limitation | Details |
|---|-----------|---------|
| 11 | **No Multi-Threading** | The dataset builder runs sequentially. For 7-day simulations with 5s windows, this means 120,960 iterations in a single thread. |
| 12 | **Memory-Bound** | All flows are accumulated in a single Python list (`all_flows`) before writing to CSV. Very long simulations (>48h) may exhaust RAM. |
| 13 | **No Streaming Output** | Cannot write flows to disk incrementally. The entire dataset must fit in memory before the chronological sort and split. |
| 14 | **No VLAN Tagging** | Docker bridge networks simulate separate subnets but do not implement 802.1Q VLAN tagging. Real hospital networks use VLANs. |
| 15 | **Alpine Linux Limitations** | Docker containers use Alpine (minimal ~5MB image). Real hospital devices run Windows Embedded, VxWorks, or custom RTOS with very different network stacks. |

---

## 11. Academic References

### Network Intrusion Detection Datasets
1. **Ring, M. et al. (2019).** *A Survey of Network-based Intrusion Detection Data Sets.* Computers & Security, 86, 147-167. [DOI: 10.1016/j.cose.2019.06.005](https://doi.org/10.1016/j.cose.2019.06.005)
2. **Shiravi, A. et al. (2012).** *Toward Developing a Systematic Approach to Generate Benchmark Datasets for Intrusion Detection.* Computers & Security, 31(3), 357-374. [DOI: 10.1016/j.cose.2011.12.012](https://doi.org/10.1016/j.cose.2011.12.012)

### IoT/IoMT Security & Datasets
3. **Neto, E. C. P. et al. (2023).** *CICIoT2023: A Real-Time Dataset and Benchmark for Large-Scale Attacks in IoT Environment.* University of New Brunswick. [Dataset](https://www.unb.ca/cic/datasets/iotdataset-2023.html)
4. **Hamza, A. et al. (2019).** *Detecting Volumetric Attacks on IoT Devices via SDN-Based Monitoring of MUD Activity.* ACM SOSR. [DOI: 10.1145/3314148.3314352](https://doi.org/10.1145/3314148.3314352)

### Docker-based Cyber Ranges
5. **Vykopal, J. et al. (2017).** *KYPO Cyber Range: Design and Use Cases.* ICIW Conference Proceedings.
6. **Vidal, J. M. et al. (2020).** *Building an IoT-Aware Cyber Range.* Validated use of Docker bridges for CPS emulation.

### Hospital Network Architecture
7. **NIST SP 1800-8 (2018).** *Securing Wireless Infusion Pumps in Healthcare Delivery Organizations.* [NIST](https://www.nist.gov/publications/securing-wireless-infusion-pumps-healthcare-delivery-organizations)
8. **IEC 62443.** *Industrial Communication Networks — Network and System Security.* International standard for segmented zone-based network architecture.

### Tsetlin Machine & Low-Power ML
9. **Granmo, O.-C. (2018).** *The Tsetlin Machine — A Game Theoretic Bandit Driven Approach to Optimal Pattern Recognition with Propositional Logic.* arXiv:1804.01508. [Paper](https://arxiv.org/abs/1804.01508)
10. **Hnilov, A. (2025).** *The Fuzzy-Pattern Tsetlin Machine.* arXiv preprint. [Paper](https://arxiv.org/abs/2508.05061)

---

*This guide was generated as part of the IoMT NIDS Simulator v3.0 project documentation.*
