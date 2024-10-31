from scapy.all import *
from colorama import Fore


def print_pkt(pkt):
    myMACAddress = get_if_hwaddr("myhost-eth0")
    if (pkt.src == myMACAddress):
        print(Fore.GREEN + pkt.summary())
    elif (pkt.dst == myMACAddress):
        print(Fore.BLUE + pkt.summary())
    else:
        print(Fore.MAGENTA + pkt.summary())


sniff(filter='arp', prn=print_pkt)

