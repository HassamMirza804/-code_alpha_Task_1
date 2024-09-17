# -*- coding: utf-8 -*-
"""sniffer.ipynb

Automatically generated by Colab.

Original file is located at
    https://colab.research.google.com/drive/1YL5_r7lzn4suYMotYdwf7xf7-QRBpP8c
"""

from scapy.all import sniff, IP

# Define a callback function to process the captured packets
def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Source: {ip_src}, Destination: {ip_dst}, Protocol: {packet[IP].proto}")

# Start sniffing packets
sniff(prn=packet_callback, count=10)  # Adjust count for the number of packets to capture