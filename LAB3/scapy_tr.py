from scapy.all import *
from colorama import Fore
import math
import time

TTL = 1
maxTTL = 7
i = 0

for itr in range(0, maxTTL):
    i += 1
    sentTime = time.time()
    # send a packet. (sr1)
    reply = sr1(IP(dst="10.69.3.100", ttl=TTL) / ICMP(), verbose=0)
    returnTime = time.time()
    RTT = math.floor((returnTime - sentTime) * 1000)
    # if the packet is expired.
    if reply[ICMP].type == 11:
        # add the router to the route list
        print(f"{i}     Packet Dropped. TTL = {TTL}, src = {reply.src}, RTT = {RTT}ms")
    else:  # the packet finally arrived
        print(f"{i}     Packet Reached. TTL = {TTL}, src = {reply.src}, RTT = {RTT}ms")
        # we reach the destination. stop looping and print the route.
        break

    # 1000 ms delay each loop
    time.sleep(1)

    # increment TTL
    TTL += 1


