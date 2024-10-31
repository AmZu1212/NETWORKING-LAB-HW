from scapy.all import *
from colorama import Fore


def print_pkt(pkt):
    # myMACAddress = get_if_hwaddr("myhost-eth0")
    if (pkt.sniffed_on == "r01-eth1"):
        print(Fore.GREEN + pkt.summary())
    elif (pkt.sniffed_on == "r01-eth2"):
        print(Fore.YELLOW + pkt.summary())
    else:
        print(Fore.MAGENTA + pkt.summary())


sniff(prn=print_pkt, iface=["r01-eth1", "r01-eth2"])

