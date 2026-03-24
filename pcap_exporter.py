import csv
import argparse
import sys

try:
    from scapy.all import IP, TCP, UDP, ICMP, Ether, wrpcap
except ModuleNotFoundError:
    print("[-] Error: 'scapy' is required for PCAP generation.")
    print("[-] Please run: pip install scapy")
    sys.exit(1)

def flow_to_pcap(csv_path, output_pcap="dataset_synthesized.pcap"):
    """
    Reads the Flow-level dataset (train.csv/test.csv) and generates
    a synthetic .pcap file representing those flows.
    For demonstration, this synthesizes one packet per flow representing the 
    total byte length. It applies the correct TCP flags and protocols.
    """
    print(f"[*] Reading Flow Metadata from {csv_path}")
    
    packets = []
    
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                src_ip = row['Src_IP']
                dst_ip = row['Dst_IP']
                src_port = int(row['Src_Port'])
                dst_port = int(row['Dst_Port'])
                proto = int(row['Protocol'])
                tot_bytes = int(row['Total_Bytes'])
                flags = row['TCP_Flags']
                timestamp = float(row['Timestamp'])
                
                # Create IP Layer
                ip_layer = IP(src=src_ip, dst=dst_ip)
                
                # Create Transport Layer
                if proto == 6:  # TCP
                    # Convert string flags "SYN,ACK" to scapy flags
                    scapy_flags = ""
                    if "S" in flags or "SYN" in flags: scapy_flags += "S"
                    if "A" in flags or "ACK" in flags: scapy_flags += "A"
                    if "P" in flags or "PSH" in flags: scapy_flags += "P"
                    if "R" in flags or "RST" in flags: scapy_flags += "R"
                    if "F" in flags or "FIN" in flags: scapy_flags += "F"
                    
                    if not scapy_flags: scapy_flags = "S" # default
                        
                    trans_layer = TCP(sport=src_port, dport=dst_port, flags=scapy_flags)
                elif proto == 17: # UDP
                    trans_layer = UDP(sport=src_port, dport=dst_port)
                elif proto == 1:  # ICMP
                    trans_layer = ICMP()
                else:
                    trans_layer = UDP(sport=src_port, dport=dst_port) # fallback
                
                # Payload Padding (To match total bytes of the flow)
                # Note: Scapy handles ethernet/IP headers which add ~54 bytes
                payload_len = max(0, tot_bytes - 54)
                payload = b"X" * min(payload_len, 1500) # cap at MTU to prevent massive memory spikes per packet
                
                # Synthesize Packet
                pkt = Ether() / ip_layer / trans_layer / payload
                pkt.time = timestamp
                
                packets.append(pkt)
                
            except Exception as e:
                # Malformed row in CSV
                continue
                
    print(f"[*] Synthesized {len(packets)} packets. Writing PCAP to disk...")
    # wrpcap writes the array. For massive datasets, an appended PcapWriter should be used.
    # We use wrpcap for the demonstration script.
    wrpcap(output_pcap, packets)
    print(f"[+] SUCCESS! Wrote synthesized payload captures to {output_pcap}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert IoMT Dataset CSV into synthetic PCAP captures.")
    parser.add_argument("--input", required=True, help="Path to train.csv or test.csv")
    parser.add_argument("--output", default="synthesized_dataset.pcap", help="Output path for the .pcap file")
    args = parser.parse_args()
    
    flow_to_pcap(args.input, args.output)
