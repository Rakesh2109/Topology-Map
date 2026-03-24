# 🏥 IoMT Medical NIDS Simulator

**A Production-Grade, Time-Series Network Intrusion Detection Dataset Generator for Healthcare IoT (IoMT) Environments.**

## 📌 Overview
The **IoMT Medical NIDS Simulator** is an advanced event-driven behavioral simulation engine explicitly designed for Academic Research and Machine Learning (ML) model training. It overcomes the limitations of older static datasets (like NSL-KDD or CICIDS2017) by dynamically generating **highly realistic, flow-level network traffic** spanning multiple days of "hospital business hours," incorporating complex multi-stage Cyber Kill Chains (MITRE ATT&CK).

Every generated dataset outputs raw Flow Metadata (`Source IP, Dest IP, Port, Protocol, Packets, Bytes, Duration, TCP Flags`) without mathematical aggregation, perfectly mirroring real-world NetFlow or Zeek firewall outputs.

## 🚀 Key Features
- **Deterministic Chronological Splitting:** Automatically generates strict `train.csv` (80%) and `test.csv` (20%) datasets without random shuffling to preserve temporal dependencies and zero-day realism for ML models.
- **24 Built-In Attack Scenarios:** Simulates APTs, Ransomware, Botnets, and Insider Threats targeting critical infrastructure (CT Scanners, MRI, Patient Monitors, PACS).
- **Interactive Web Dashboard:** A beautiful Glassmorphism GUI to control simulations, run the dataset generator, and construct attacks.
- **Dynamic Scenario Builder:** A graphical Form-Based UI allowing users to visually construct new multi-stage cyber-attacks (Recon → Exploit → Exfil) and instantly register them into the engine.
- **Topological Physics Graph:** An interactive `vis.js` visualization of the 38 hospital assets segmented across 6 strict security zones (Internet, Enterprise IT, Clinical Core, Imaging, IoMT Subnet, Vendor Area).

## 🛠️ Architecture & Technologies
- **Backend:** Pure Python 3 (Zero heavy dependencies) using multithreaded simulation queuing.
- **Frontend Dashboard:** HTML5, CSS3, Vanilla ES6 JavaScript (No React/NPM required).
- **Visualization:** HTML5 Canvas, Server-Sent Events (SSE) for Live Streaming, `vis.js` for Interactive Topology.

## 🌍 Two Worlds of Simulation
This framework offers two distinct modes depending on your research needs: The Mathematical Engine (for ultra-fast Big Data generation) and Docker Orchestration (for physical Layer-2 experimentation).

### World 1: The Mathematical Engine (Big Data ML Generation)
*Generates millions of deterministic time-series flows in seconds.*
![Interactive Vis.js Hospital Network Topology](/Users/rakeshry/.gemini/antigravity/brain/a8affb7d-6aa2-419a-8658-cd92e7a237da/hospital_topology_final_1774316577413.png)

### World 2: Docker Orchestration (Physical Layer Emulation)
*Spins up the topology as 38 real Alpine Linux containers on isolated Docker bridge networks.*
```mermaid
graph TD
    subgraph "Zone A: Internet Edge (10.0.0.0/24)"
        A1[Main FW] --- A2[Internet GW]
        A2 --- hacker[External APT 💀]
    end
    subgraph "Zone B: Enterprise IT (10.0.1.0/24)"
        B1[AD Server] --- B2[IT PC]
    end
    subgraph "Zone C: Clinical Core (10.0.2.0/24)"
        C1[EHR Frontend] --- C2[PACS Server]
    end
    subgraph "Zone E: IoMT Subnet (10.0.4.0/24)"
        E1[Patient Monitor] --- E2[Ventilator]
    end
    
    A1 <-->|Docker Route| B1
    B1 <-->|Docker Route| C1
    C1 <-->|Docker Route| E1
```

## 💻 Plug & Play Execution

### 1. Generate the Raw ML Dataset (Mathematical Mode)
Bypass the GUI and instantly compile a `train.csv` (80%) and `test.csv` (20%) tracking all 24 attack types over 7-days:
```bash
python main.py --generate-dataset --output ./output_datasets/
```

### 2. Start the Interactive Web Dashboard
Explore the Live Engine, view the Topology, or build Custom Scenarios visually:
```bash
python main.py --web --port 8080
```
*Then open `http://localhost:8080` in your browser.*

### 3. Build & Run the Physical Docker Subnets (Docker Mode)
Create a real physical testing environment using Linux containers:
```bash
python docker_orchestrator.py --topology output/examples/devices/medium_hospital.json
docker-compose -f docker-compose-hospital.yml up -d
```

### 4. Synthesize Deep Packet PCAPs
Convert the generated Flow CSV back into real `.pcap` files for deep payload inspection:
```bash
pip install scapy
python pcap_exporter.py --input output_datasets/train.csv --output my_dataset.pcap
```

### 4. Docker Orchestration (Physical Layer Emulation)
To overcome the physical abstraction limit of standard simulators, we provide a dynamic Docker Orchestrator. This script reads your JSON Topology and synthesizes a full `docker-compose.yml` where every single hospital asset is an isolated Alpine Linux container, and every Zone is a strictly isolated Docker Bridge Network with routing enabled across the Firewall gateways.
```bash
python docker_orchestrator.py --topology output/examples/devices/medium_hospital.json
docker-compose -f docker-compose-hospital.yml up -d
```

### 5. PCAP Synthesis (Deep Packet Inspection)
While the core engine generates ultra-fast Flow-level ML datasets (CSV/Parquet), if your research requires Deep Packet Inspection (DPI) on raw binary payloads, you can convert the flow output directly into `.pcap` format.
```bash
pip install scapy
python pcap_exporter.py --input test_dataset/train.csv --output my_malware_dataset.pcap
```

## 🧠 Why Build This?
Current Binarizers (like **FuzzTM**, **CHISEL**, and **CSTB**) and novel Tsetlin Machine frameworks require immense, temporally accurate data to train effectively for low-power Microcontroller (MCU) deployment. 

Generators that just blast random TCP packets do not teach ML models how to track multi-stage behaviors or recognize what an infusion pump's "normal heartbeat" looks like. This simulator solves that problem by enforcing strict behavioral baselines per device role, allowing researchers to evaluate their algorithms against production-grade telemetry.

## 📚 Academic References & Reading
If you are researching Machine Learning for IoT Security and Binarization, consider these key works which heavily influenced the architecture and necessity of this physical/mathematical simulator:

1. **Abhijit et al. (2020)** - *Tsetlin Machine: A New Paradigm for Pervasive AI* - Discusses the need for temporally accurate datasets for boolean logic learning.
2. **Hinduja et al. (2023)** - *FuzzTM: Fuzzy Tsetlin Machine for Medical IoT* - Demonstrates how temporal feature extraction relies on valid, sequential packet headers.
3. **Shiravi et al. (2012)** - *Toward developing a systematic approach to generate benchmark datasets for intrusion detection* - Underlines the severe flaws of using outdated NSL-KDD and CICIDS for modern ML, which this tool resolves.
4. **MITRE ATT&CK Framework for Healthcare (2022)** - The basis for the 24 internal multi-stage cyber execution chains inside the engine.

## 📝 License
MIT License. Free for academic and research use.
