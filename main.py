#!/bin/python3
from scapy import volatile
from scapy.all import *
import netifaces, string, random

#generate random hostname
def getname(N):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))

iface="wlp3s0"

#enter main loop
while True:
    hostname=getname(5)
    hr_addr=str(RandMAC())
    true_mac=get_if_hwaddr(iface)
    #hr_addr=get_if_hwaddr(iface)
    print(f"Sending Package:\n\tEther: {true_mac}\n\tDisguise: {hr_addr}\n\tDest: ff:ff:ff:ff:ff:ff\n\tHostname: {hostname}\n")
    #send DISCOVER package to broadcast with random MAC and hostname
    sendp(
        #build up network frames with code
        Ether(src=true_mac, dst="ff:ff:ff:ff:ff:ff") / \
        IP(src="0.0.0.0", dst="255.255.255.255") / \
        UDP(sport=68, dport=67) / \
        BOOTP(chaddr=hr_addr, flags=0x8000) / \
        DHCP(options = [
            ("message-type", 1),
            ("param_req_list", [1, 3, 6, 15, 121]),
            ("max_dhcp_size",1499),
            ("client_id", 1, hr_addr),
            ("lease_time",10000),
            ("hostname", hostname),
            ("end",'00000000000000')
        ]),
        iface=iface,
        verbose=False,
    )
    #limit the packages as to not overwhelm the DHCP server
    time.sleep(1)
