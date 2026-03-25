# 🏥 IoMT Medical NIDS Simulator (v3.0)

**A Production-Grade, Time-Series Network Intrusion Detection Dataset Generator for Healthcare IoT (IoMT) Environments.**

## 📌 Overview
The **IoMT Medical NIDS Simulator** is an advanced event-driven behavioral simulation engine designed for Academic Research and Machine Learning (ML) model training. It overcomes the limitations of older static datasets (like NSL-KDD or CICIDS2017) by dynamically generating **highly realistic, flow-level network traffic** spanning multiple days of "hospital business hours," incorporating complex multi-stage Cyber Kill Chains (MITRE ATT&CK).

Every generated dataset outputs raw Flow Metadata (`Source IP, Dest IP, Port, Protocol, Packets, Bytes, Duration, TCP Flags`) without mathematical aggregation, perfectly mirroring real-world NetFlow or Zeek firewall outputs.

## 🚀 Key Features
- **Deterministic Chronological Splitting:** Generates strict `train.csv` (80%) and `test.csv` (20%) without random shuffling to preserve temporal dependencies.
- **24 Built-In Attack Scenarios (A01–A24):** Simulates APTs, Ransomware, Botnets, BLE Replay, DICOM Exfiltration, HL7 Floods, and Insider Threats targeting critical infrastructure.
- **38 Hospital Devices Across 6 Zones:** CT Scanners, MRI, Patient Monitors, Infusion Pumps, Ventilators, PACS, FHIR, HL7 Engine, and more.
- **Interactive Web Dashboard:** Glassmorphism GUI to control simulations, run the dataset generator, and construct attacks.
- **Dynamic Scenario Builder:** Graphical Form-Based UI for constructing new multi-stage cyber-attacks visually.
- **Interactive Topology Graph:** `vis.js` visualization of the 38 hospital assets segmented across 6 strict security zones.
- **Physical Docker Attack Detonation:** 7 selectable real attack modules executed inside Docker containers with live PCAP capture.
- **Streaming CSV Output:** Memory-efficient incremental disk writes for long simulations.

## 🛠️ Architecture & Technologies
- **Backend:** Pure Python 3 (Zero heavy dependencies) with streaming CSV output.
- **Frontend Dashboard:** HTML5, CSS3, Vanilla ES6 JavaScript (No React/NPM required).
- **Visualization:** HTML5 Canvas, Server-Sent Events (SSE), `vis.js` for Interactive Topology.
- **Docker Mode:** Alpine Linux containers on isolated Docker bridge networks.

---

## 🌍 Two Worlds of Simulation

This framework offers two distinct modes depending on your research needs:

### World 1: Mathematical Engine (Big Data ML Generation)
*Generates millions of deterministic time-series flows in seconds.*
- Pure mathematical state machines — no real networking
- 24 attack scenarios with IP rotation, organic variability, and multi-stage progression
- Diurnal traffic patterns, infrastructure noise, and maintenance events
- Outputs: `train.csv`, `test.csv`, `full_dataset.csv`, `dataset_info.json`

### World 2: Docker Orchestration (Physical Layer Emulation)
*Deploys the topology as 38 real Alpine Linux containers on isolated Docker bridge networks.*
- 6 isolated subnets (Internet Edge, Enterprise IT, Clinical Core, Imaging, IoMT, Third-Party)
- 7 selectable physical attack modules with real NMAP, hping3, and tcpdump
- Gateway/Firewall containers with `NET_ADMIN` capabilities and IP forwarding
- Outputs: `.pcap` files containing real OS-level payload bytes

```
Zone A: Internet Edge (10.0.0.0/24) ── FW ── GW ── External APT 💀
Zone B: Enterprise IT  (10.0.1.0/24) ── AD, DNS, DHCP, EHR, File Share, Backup, SOC
Zone C: Clinical Core  (10.0.2.0/24) ── PACS, FHIR, HL7, Nurse Stations, Device Mgmt
Zone D: Imaging Subnet (10.0.3.0/24) ── CT Scanner, MRI, Ultrasound, Radiology WS
Zone E: IoMT Subnet    (10.0.4.0/24) ── Patient Monitors, Infusion Pumps, Ventilators, Wearables
Zone F: Third-Party    (10.0.5.0/24) ── Vendor VPN, Jump Host
```

---

## 💻 Plug & Play Execution

### Step 1: Generate the Raw ML Dataset (World 1)
Compile a `train.csv` (80%) and `test.csv` (20%) tracking all 24 attack types:
```bash
python main.py --generate-dataset --output ./output_datasets/
```

### Step 2: Start the Interactive Web Dashboard
Explore the Live Engine, view the Topology, or build Custom Scenarios:
```bash
python main.py --web --port 8080
```
*Then open `http://localhost:8080` in your browser.*

### Step 3: Build the Physical Docker Hospital (World 2)
Create a real physical testing environment with 38 containers:
```bash
python scripts/docker_orchestrator.py --topology configs/devices/medium_hospital.json
docker-compose -f docker-compose-hospital.yml up -d
```

### Step 4: Physical Cyber Attack Detonation (World 2)
Once Docker containers are running, physically unleash cyber-attacks. The script installs hacking tools, captures traffic via `tcpdump` on the router, and extracts a `.pcap`:

```bash
# Execute ALL 7 attack modules (full kill-chain)
python scripts/docker_attacker.py --attack all

# Select specific modules (comma-separated)
python scripts/docker_attacker.py --attack recon,dos,brute_force

# Interactive selection menu
python scripts/docker_attacker.py --attack menu
```

**Available Attack Modules:**
| Module | Maps To | Description |
|--------|---------|-------------|
| `recon` | A01 | Aggressive NMAP port/service sweep across IT & Clinical zones |
| `dos` | A21 | SYN Flood (hping3) against the PACS imaging server |
| `brute_force` | A04 | SSH/HTTPS brute-force against AD Server & EHR Frontend |
| `lateral` | A17 | East-west pivot from IT zone into Clinical/Imaging/IoMT |
| `exfil` | A14/A20 | Simulated PHI data exfiltration across zones |
| `hl7_flood` | A16 | HL7 ADT message flood against clinical engine port 2575 |
| `ble_replay` | A11 | BLE telemetry replay attack against IoMT aggregator |

*Output: `output_datasets/physical_attack_sample.pcap` containing real payload traffic.*

### Step 5: Synthesize PCAPs from CSV (World 1 → PCAP)
Convert generated Flow CSV into `.pcap` files for deep packet inspection:
```bash
pip install scapy
python scripts/pcap_exporter.py --input output_datasets/train.csv --output my_dataset.pcap
```

---

## 📂 Project Structure
```
iotm_data/
├── config.py                  # 🧠 Brain: 6 Zones, 38 Devices, 24 Attacks, CommMap
├── network_model.py           # 🏗️ Hospital network graph builder
├── traffic_generator.py       # 🚗 Benign traffic with diurnal patterns
├── attack_injector.py         # 💀 24 attack state machines with IP rotation
├── labeling_engine.py         # 🏷️ Per-flow labeling with transition windows
├── time_window.py             # 📊 5-second aggregate feature windows (28+ features)
├── dataset_builder.py         # 📦 Streaming dataset builder (train/test split)
├── main.py                    # 🚀 CLI entry point
├── gui_web.py                 # 🌐 Web dashboard backend (SSE server)
├── scripts/
│   ├── docker_orchestrator.py # 🐳 JSON topology → docker-compose.yml
│   ├── docker_attacker.py     # 💣 7 selectable physical attack modules
│   └── pcap_exporter.py       # 📡 CSV → .pcap conversion (Scapy)
├── configs/devices/           # Hospital topology JSONs
├── docs/
│   ├── IoMT_NIDS_Complete_Guide.md  # 📖 Complete learning guide (Basic → Advanced)
│   └── visualizations/        # Interactive HTML topology diagrams
└── static/                    # Web dashboard frontend
```

---

## 📖 Documentation

For a comprehensive learning guide covering everything from basics to advanced concepts, see:

**[`docs/IoMT_NIDS_Complete_Guide.md`](docs/IoMT_NIDS_Complete_Guide.md)**

This guide covers:
- All 38 devices — purpose, function, and clinical role
- All 24 attack scenarios — step-by-step kill-chain explanations
- 6-zone hospital routing architecture with router types
- Code architecture walkthrough (file-by-file)
- 15 known drawbacks with mitigation strategies
- Academic references with DOI links

---

## 📚 Academic References

**Foundations of World 1 (Mathematical Flow Generation):**
1. **Ring et al. (2019)** — *A Survey of Network-based Intrusion Detection Data Sets* (Comput. Secur.) — Validates synthesized flow-metadata datasets for modern ML training.
2. **Shiravi et al. (2012)** — *Toward Developing a Systematic Approach to Generate Benchmark Datasets for Intrusion Detection* — Establishes the probabilistic state-machine generation methodology.

**Foundations of World 2 (Docker Orchestration):**
3. **Neto et al. (2023)** — *CICIoT2023: A Real-Time Dataset and Benchmark for Large-Scale Attacks in IoT Environment* — [UNB CIC IoT Dataset 2023](https://www.unb.ca/cic/datasets/iotdataset-2023.html)
4. **Vidal et al. (2020)** — *Building an IoT-Aware Cyber Range with Docker* — Validates Docker bridge networks for CPS emulation.

**Tsetlin Machine & Low-Power ML:**
5. **Granmo, O.-C. (2018)** — *The Tsetlin Machine* — [arXiv:1804.01508](https://arxiv.org/abs/1804.01508)

---

## 📝 License
MIT License. Free for academic and research use.
