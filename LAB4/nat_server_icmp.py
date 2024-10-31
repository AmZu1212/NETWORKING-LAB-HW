from scapy.all import *
from colorama import Fore

NATip = "10.69.0.100"
localIface = "middlebox-eth0"
publicIface = "middlebox-eth1"
PRIVATE1ip = "192.168.1.101"


# this is nat_server_icmp.py
def callback(pkt):
    # check if it is an ip packet
    if pkt.haslayer(IP):
        # make sure it wasn't sent by the nat server
        if pkt.getlayer(Ether).src == get_if_hwaddr(localIface):
            # print(Fore.YELLOW + pkt.summary())
            return
        if pkt.getlayer(Ether).src == get_if_hwaddr(publicIface):
            # print(Fore.GREEN + pkt.summary())
            return

        # get a reference to the packet
        NATpkt = pkt[IP]

        # delete the IP checksum
        del NATpkt.getlayer(IP).chksum

        if NATpkt.getlayer(IP).dst == NATip:
            # INCOMING PACKET (public packet entering)
            # change destination ip to private1's ip
            NATpkt.getlayer(IP).dst = PRIVATE1ip
            # send the new package
            send(NATpkt, iface=localIface)
            color = Fore.GREEN
        else:
            # OUTGOING PACKET (local packet exiting)
            # change source ip to the NAT's ip
            NATpkt.getlayer(IP).src = NATip
            # send the new package
            send(NATpkt, iface=publicIface)
            color = Fore.YELLOW

        # print the packets summary
        print(color + NATpkt.summary())
        print(Fore.RESET)


# capture ip packets
sniff(prn=callback, iface=[localIface, publicIface], filter='ip')

