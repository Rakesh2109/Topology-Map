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

## 💻 Installation & Usage

### 1. Start the Visual Web Dashboard
To launch the interactive GUI on `http://localhost:8080`:
```bash
python main.py --web --port 8080
```
*Features:* Live simulation streaming, interactive topology map, and the dynamic attack Scenario Builder.

### 2. Generate a Complete ML Dataset (Headless Mode)
To bypass the GUI and instantly compile a `train.csv` and `test.csv` simulating all 24 attack types over a 7-day period:
```bash
python main.py --generate-dataset --output ./output_datasets/
```

### 3. Load Custom JSON Scenarios/Topologies
You can feed the engine custom environments or specific attack vectors:
```bash
python main.py --load-devices output/examples/devices/medium_hospital.json --load-scenario output/examples/scenarios/ransomware_pacs.json
```

## 🧠 Why Build This?
Current Binarizers (like **FuzzTM**, **CHISEL**, and **CSTB**) and novel Tsetlin Machine frameworks require immense, temporally accurate data to train effectively for low-power Microcontroller (MCU) deployment. 

Generators that just blast random TCP packets do not teach ML models how to track multi-stage behaviors or recognize what an infusion pump's "normal heartbeat" looks like. This simulator solves that problem by enforcing strict behavioral baselines per device role, allowing researchers to evaluate their algorithms against production-grade telemetry.

## 📝 License
MIT License. Free for academic and research use.
