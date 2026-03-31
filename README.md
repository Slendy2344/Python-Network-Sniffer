from scapy.all import * 
from scapy.layers.http import HTTPRequest
import argparse

def network_sniffing(interface, filter_protocol=None):
    print("Sniffing on interface")
    def packets(packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            print(f"IP Packet: {src_ip} => {dst_ip}, Protocol: {protocol}")
            
        if packet.haslayer(HTTPRequest):
            method = packet[HTTPRequest].Method.decode()
            host = packet[HTTPRequest].Host.decode()
            path = packet[HTTPRequest].Path.decode()
            print(f"HTTPRequest: {method} {host}{path}")
            
            
        if packet.haslayer(Raw):
            payload = packet[Raw].load[:100]
            print(f"Raw Payload: {payload}")
    sniff (iface=interface, prn=packets, filter=filter_protocol, store=False)

if __name__=="__main__":
    parser = argparse.ArgumentParser(description="Sniff Network Packets.")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff on.")
    parser.add_argument("-f", "--filter", help="BPF Filterfor packet sniffing (optional)...Choose from IP, HTTP, or Raw")
    args = parser.parse_args()
    
try:
    network_sniffing(args.interface, args.filter)
except PermissionError: 
    print("Permission denied, try using sudo.")
except Exception as e:
    print(f"An error has occurered: {e}")
except KeyboardInterrupt:
    print("\nPacket sniffing stopped by user.")
        
        
