from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether

tcp_count = 0
udp_count = 0
icmp_count = 0
other_count = 0

def packet_callback(packet):
    global tcp_count, udp_count, icmp_count, other_count

    if Ether in packet and IP in packet:
        src_mac = packet[Ether].src
        dest_mac = packet[Ether].dst
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst

        if TCP in packet:
            proto_name = "TCP"
            tcp_count += 1
        elif UDP in packet:
            proto_name = "UDP"
            udp_count += 1
        elif ICMP in packet:
            proto_name = "ICMP"
            icmp_count += 1
        else:
            proto_name = "OTHER"
            other_count += 1

        print(f"Protocol: {proto_name}, Src MAC: {src_mac}, Dst MAC: {dest_mac}, "
              f"Src IP: {src_ip}, Dst IP: {dest_ip}, Length: {len(packet)}")

def main():
    timeout_seconds = 20
    print(f"Starting packet capture for {timeout_seconds} seconds...")

    try:
        sniff(prn=packet_callback, timeout=timeout_seconds)
    except PermissionError:
        print("Permission denied. Run as administrator/root.")
        return
    except KeyboardInterrupt:
        print("\nPacket capture stopped.")

    print("\nPacket counts:")
    print(f"TCP: {tcp_count}")
    print(f"UDP: {udp_count}")
    print(f"ICMP: {icmp_count}")
    print(f"Other: {other_count}")

if __name__ == "__main__":
    main()
