from scapy.all import *
import base64
import json

def extract_payloads(pcap_file):
    payloads = []
    
    packets = rdpcap(pcap_file)
    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            try:
                # Try to decode payload as potential JSON
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                try:
                    json_payload = json.loads(payload)
                    if 'cmd' in json_payload:
                        payloads.append(json_payload)
                except json.JSONDecodeError:
                    continue
            except Exception:
                continue
    
    return payloads

def main():
    pcap_file = 'file.pcap'  # Replace with your PCAP file
    payloads = extract_payloads(pcap_file)
    
    for payload in payloads:
        print("Encrypted Command:")
        print(json.dumps(payload, indent=2))
        print("-" * 40)

if __name__ == "__main__":
    main()