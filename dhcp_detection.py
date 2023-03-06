import sys
import scapy
from scapy.all import *
global reqCnt
global ofrCnt
reqCnt = 0
ofrCnt = 0
def monitorPackets(p):
    if p.haslayer(BOOTP):
        global reqCnt
        global ofrCnt
        opCode = p.getlayer(BOOTP).op
        if opCode == 1:
            reqCnt=reqCnt+1
        elif opCode == 2:
            ofrCnt=ofrCnt+1
        print ("[*] - "+str(reqCnt)+" Requests, "+str(ofrCnt)+" Offers.")
interface="eth0"
print(interface)
sniff(iface=interface,prn=monitorPackets)
