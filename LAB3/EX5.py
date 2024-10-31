from scapy.all import *
from colorama import Fore

p = sr1(IP(dst="10.69.0.1") / ICMP())

print(f"sequence number: {p[ICMP].seq}")
print(f"identifier: {p[ICMP].id}")

