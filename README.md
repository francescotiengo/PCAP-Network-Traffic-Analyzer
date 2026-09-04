# PCAP Network Traffic Analyzer

A simple Python tool for analyzing PCAP/PCAPNG files and extracting
network traffic statistics.

This project was developed in a personal networking and cybersecurity
lab using Kali Linux, Cisco equipment, and Wireshark.

## Features

- PCAP/PCAPNG file analysis
- Packet count
- Protocol statistics
- Source IP analysis
- Destination IP analysis
- TCP port statistics
- UDP port statistics

## Lab Environment

The traffic analyzed in this project was generated within my own lab
environment using Kali Linux and Cisco equipment.

Wireshark was used to capture and inspect the network traffic, while
the Python script was used to automatically analyze the captured data.

## Usage

Run the analyzer with the PCAP file:

```bash
python3 pcap_analyzer.py prova1.pcapng
