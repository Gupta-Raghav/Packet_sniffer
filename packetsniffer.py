#!usr/bin/env python3
import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=processed_packet)


def processed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet)


sniff("eth0")
