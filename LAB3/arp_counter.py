from scapy.all import *
from colorama import Fore

arpRequestCount = 0
arpReplyCount = 0


def count_arp(pkt):
    global arpRequestCount
    global arpReplyCount
    if (pkt.op == 1):
        arpRequestCount += 1

    if (pkt.op == 2):
        arpReplyCount += 1
    print("============================================")
    print(f"arp request count is: {arpRequestCount}")
    print(f"arp reply count is: {arpReplyCount}")


sniff(count=20, filter='arp', prn=count_arp)

