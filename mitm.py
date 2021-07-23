from scapy.all import *
import threading
import os
import sys

print("Are you run with root previledges? ")
VIP = input("Enter the IP address of the victim: ")
GW = input("Enter the IP address of the gateway: ")
IFACE = input("Enter the name of the interface (ex: eth0): ")