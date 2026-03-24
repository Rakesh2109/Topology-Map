import json
import os
import argparse

def generate_docker_compose(topology_path, output_path="docker-compose-hospital.yml"):
    """
    Reads the topological JSON and synthesizes a full docker-compose.yml 
    allowing users to run the virtual hospital using true Linux containers 
    on strictly walled Docker Bridge networks.
    """
    print(f"[*] Reading topology from {topology_path}...")
    with open(topology_path, 'r') as f:
        topology = json.load(f)

    compose_lines = [
        "version: '3.8'",
        "services:"
    ]

    zones = topology.get("zones", [])
    devices = topology.get("devices", [])

    # 1. Generate Services (Containers)
    for dev in devices:
        service_name = dev["name"].replace(" ", "_").lower().replace("/", "_").replace("-", "_")
        zone = dev["zone"]
        ip = dev["ip"]

        compose_lines.append(f"  {service_name}:")
        compose_lines.append(f"    image: alpine:latest")
        compose_lines.append(f"    container_name: iomt_{service_name}")
        compose_lines.append(f"    command: tail -f /dev/null")
        compose_lines.append(f"    networks:")
        compose_lines.append(f"      {zone}:")
        compose_lines.append(f"        ipv4_address: {ip}")
        compose_lines.append(f"    labels:")
        compose_lines.append(f"      role: {dev['role']}")
        compose_lines.append(f"      criticality: '{dev['criticality']}'")

        # Routing capability for Firewalls/Gateways
        if dev["role"] in ["gateway", "firewall"]:
            compose_lines.append(f"    cap_add:")
            compose_lines.append(f"      - NET_ADMIN")
            compose_lines.append(f"    sysctls:")
            compose_lines.append(f"      - net.ipv4.ip_forward=1")
            
            # Rebuild the networks section for gateways to span ALL zones
            compose_lines.pop() # remove criticality
            compose_lines.pop() # remove role
            compose_lines.pop() # remove labels obj
            compose_lines.pop() # remove ip
            compose_lines.pop() # remove zone:
            compose_lines.pop() # remove networks:
            
            compose_lines.append(f"    networks:")
            for z in zones:
                z_name = z["name"]
                if z_name == zone:
                    compose_lines.append(f"      {z_name}:")
                    compose_lines.append(f"        ipv4_address: {ip}")
                else:
                    compose_lines.append(f"      {z_name}:")
            compose_lines.append(f"    labels:")
            compose_lines.append(f"      role: {dev['role']}")
            compose_lines.append(f"      criticality: '{dev['criticality']}'")
        
        compose_lines.append("") # newline

    # 2. Generate Networks (VLANs / Subnets)
    compose_lines.append("networks:")
    for zone in zones:
        compose_lines.append(f"  {zone['name']}:")
        compose_lines.append(f"    driver: bridge")
        compose_lines.append(f"    ipam:")
        compose_lines.append(f"      config:")
        compose_lines.append(f"        - subnet: {zone['cidr']}")

    # 3. Write Output
    with open(output_path, 'w') as f:
        f.write("\n".join(compose_lines))

    print(f"[+] SUCCESS! Generated physical Docker OS orchestration.")
    print(f"[+] You can now run: `docker-compose -f {output_path} up -d`")
    print(f"[+] This will launch {len(devices)} Alpine Linux containers operating on {len(zones)} isolated Layer-2 bridge networks!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert IoMT JSON Topology to robust Docker Compose architecture.")
    parser.add_argument("--topology", default="configs/devices/medium_hospital.json", help="Path to topology JSON")
    parser.add_argument("--output", default="docker-compose-hospital.yml", help="Path to output docker-compose file")
    args = parser.parse_args()
    
    generate_docker_compose(args.topology, args.output)
