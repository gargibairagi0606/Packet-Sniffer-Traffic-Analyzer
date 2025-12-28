# Packet Sniffer and Basic Traffic Analyzer

## Overview

This project is a Python-based packet sniffer and traffic analyzer that captures live network packets and analyzes protocol information in real time. It helps in understanding how data flows across a network and how different protocols such as TCP, UDP, and ICMP operate at the transport and network layers.
The tool extracts and displays:
- Source and Destination MAC addresses
- Source and Destination IP addresses
- Protocol type (TCP / UDP / ICMP / Others)
- Packet length
- Total packet count for each protocol type

This experiment is useful for learning network packet structures, protocol fields, and real-time traffic behavior.

## Objectives

- Capture real-time network packets
- Analyze Ethernet, IP, TCP, UDP, and ICMP headers
- Understand packet structure and protocol flow
- Generate statistics for different protocol types

## Project Structure

```
Packet-Sniffer-Traffic-Analyzer/
│
├── packet_sniffer.py
├── README.md
├── .gitignore
└── requirements.txt
```

## Files in the Repository

| File Name	| Description |
| --------  | ------------|
| packet_sniffer.py	| Python program for packet capturing |
| README.md	| Project documentation |
| .gitignore	| Ignores cache, virtual env & build files |
| requirements.txt	| Required dependency (scapy) |

## Requirements

- Python 3.x
- Scapy library
- Administrator / Root privileges

Install the required library using:
```
pip install -r requirements.txt
```

## How it Works

1. The program uses **Scapy's sniff()** function to capture packets.  
2. For each packet, it extracts:
   - Ethernet header: source and destination MAC addresses  
   - IP header: source and destination IP addresses  
   - Protocol: TCP, UDP, ICMP, or other  
   - Packet length  
3. Maintains counters for each protocol type.  
4. After the capture duration or manual stop, it displays **total counts** for each protocol.

## Usage

```bash
python packet_sniffer.py
```
The sniffer runs for a duration of 20 seconds

## Example Output

```
Starting packet capture for 20 seconds...
Protocol: TCP, Src MAC: 40:48:6e:1f:15:f0, Dst MAC: f0:03:8c:3a:46:77, Src IP: 20.42.73.31, Dst IP: 192.168.1.12, Length: 54
Protocol: TCP, Src MAC: 40:48:6e:1f:15:f0, Dst MAC: f0:03:8c:3a:46:77, Src IP: 140.82.113.25, Dst IP: 192.168.1.12, Length: 80
Protocol: UDP, Src MAC: b8:1e:a4:e2:5e:c7, Dst MAC: ff:ff:ff:ff:ff:ff, Src IP: 192.168.1.7, Dst IP: 192.168.1.255, Length: 86

Packet counts:
TCP: 11
UDP: 3
ICMP: 0
Other: 0
```

This project demonstrates how packet sniffing tools operate internally and how raw network data can be parsed to reveal protocol information. It provides practical knowledge of:
- Packet capture mechanisms
- Protocol header analysis
- Network traffic monitoring
- Real-time traffic statistics generation
