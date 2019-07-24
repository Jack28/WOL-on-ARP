#!/usr/bin/env python2

# by Felix Bauer
# felix@ai4me.de
# 2015-12-12

from __future__ import print_function
from scapy.all import *
import wol
import datetime
import sys


# whake if someone asks for one of those IPs
dstIPs = dict()
dstIPs["192.168.0.100"]="11:22:33:44:55:66"
dstIPs["192.168.0.120"]="de:ad:be:ef:c0:ff"

# send Magic Packet to NASolocos
def wakeup(macaddr):
  wake=wol.WOL(macaddr,intf="eth0")
  wake.raw()

# send spoofed ARP reply
def sendarpreply(pkt,ipaddr,macaddr):
  # print pkt[Ether].summary()
  # pkt[Ether].src
  reply=Ether(src=macaddr,dst=pkt[Ether].src)/ARP(op=2, pdst=pkt[ARP].psrc, psrc=ipaddr, hwsrc=macaddr)
  sendp(reply)
  # print reply.summary()

# handle ARP packet
def arpcheck(pkt):
  # check if ARP
  if ARP in pkt and pkt[ARP].op in (1,2):
    # check if ARP request
    if pkt[ARP].op == 1: # who-has
      # check if NASolocos is meant
      if pkt[ARP].pdst in dstIPs:
        # print timestamp
        # print(str(datetime.datetime.now()))
        # print pkt.summary()
        print("%s asking for %s" % (pkt.psrc,pkt.pdst), file=sys.stderr)
        wakeup(dstIPs[pkt.pdst])
 #       sendarpreply(pkt,pkt.pdst,dstIPs[pkt.pdst])

if len(sys.argv) > 1:
  for (i,j) in dstIPs: # wrong
    wakeup(i)
  exit()

# listen for ARP packets
sniff(filter="arp",prn=arpcheck,store=0)
