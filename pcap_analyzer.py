#!/usr/bin/env python3

import sys
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS


def analyze_pcap(filename):
    print("=" * 50)
    print("        PCAP NETWORK TRAFFIC ANALYZER")
    print("=" * 50)

    try:
        packets = rdpcap(filename)
    except FileNotFoundError:
        print(f"[!] File non trovato: {filename}")
        return
    except Exception as e:
        print(f"[!] Errore durante la lettura del PCAP: {e}")
        return

    print(f"\n[+] File: {filename}")
    print(f"[+] Pacchetti analizzati: {len(packets)}")

    protocols = Counter()
    source_ips = Counter()
    destination_ips = Counter()
    tcp_ports = Counter()
    udp_ports = Counter()

    for packet in packets:

        # ARP
        if packet.haslayer(ARP):
            protocols["ARP"] += 1

        # IP traffic
        if packet.haslayer(IP):

            src = packet[IP].src
            dst = packet[IP].dst

            source_ips[src] += 1
            destination_ips[dst] += 1

            # ICMP
            if packet.haslayer(ICMP):
                protocols["ICMP"] += 1

            # TCP
            elif packet.haslayer(TCP):
                protocols["TCP"] += 1

                sport = packet[TCP].sport
                dport = packet[TCP].dport

                tcp_ports[sport] += 1
                tcp_ports[dport] += 1

            # UDP
            elif packet.haslayer(UDP):
                protocols["UDP"] += 1

                sport = packet[UDP].sport
                dport = packet[UDP].dport

                udp_ports[sport] += 1
                udp_ports[dport] += 1

            else:
                protocols["Other IP"] += 1

        # DNS
        if packet.haslayer(DNS):
            protocols["DNS"] += 1

    # --------------------------------------------------
    # RESULTS
    # --------------------------------------------------

    print("\n" + "-" * 50)
    print("PROTOCOLS")
    print("-" * 50)

    for protocol, count in protocols.most_common():
        print(f"{protocol:<15} {count}")

    print("\n" + "-" * 50)
    print("TOP SOURCE IPs")
    print("-" * 50)

    for ip, count in source_ips.most_common(10):
        print(f"{ip:<20} {count} packets")

    print("\n" + "-" * 50)
    print("TOP DESTINATION IPs")
    print("-" * 50)

    for ip, count in destination_ips.most_common(10):
        print(f"{ip:<20} {count} packets")

    print("\n" + "-" * 50)
    print("TCP PORTS")
    print("-" * 50)

    for port, count in tcp_ports.most_common(10):
        print(f"Port {port:<10} {count} packets")

    print("\n" + "-" * 50)
    print("UDP PORTS")
    print("-" * 50)

    for port, count in udp_ports.most_common(10):
        print(f"Port {port:<10} {count} packets")

    print("\n" + "=" * 50)
    print("Analysis completed.")
    print("=" * 50)


def main():

    if len(sys.argv) != 2:
        print("Usage:")
        print(f"  python3 {sys.argv[0]} traffic.pcapng")
        sys.exit(1)

    filename = sys.argv[1]

    analyze_pcap(filename)


if __name__ == "__main__":
    main()