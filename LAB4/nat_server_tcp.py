from scapy.all import *
from colorama import Fore

NATip = "10.69.0.100"
localIface = "middlebox-eth0"
publicIface = "middlebox-eth1"
PRIVATE1ip = "192.168.1.101"
port_to_client_map = {}


# this is nat_server_icmp.py
def callback(pkt):
    # make sure it wasn't sent by the nat server
    if pkt.getlayer(Ether).src == get_if_hwaddr(localIface):
        return
    if pkt.getlayer(Ether).src == get_if_hwaddr(publicIface):
        return

    # check if it is an ip packet
    if pkt.haslayer(IP):
        # get a reference to the packet
        NATpkt = pkt[IP]

        # delete the TCP checksum
        if NATpkt.haslayer(TCP):
            del NATpkt.getlayer(TCP).chksum

        # delete the IP checksum
        del NATpkt.getlayer(IP).chksum

        if NATpkt.getlayer(IP).dst == NATip:
            # INCOMING PACKET (public packet entering)
            # change destination ip to client's ip
            clientPort = NATpkt.getlayer(TCP).dport
            destinationClient = port_to_client_map[clientPort]
            NATpkt.getlayer(IP).dst = destinationClient

            # send the new package
            send(NATpkt, iface=localIface)

            # set print color
            color = Fore.GREEN

        else:
            # OUTGOING PACKET (local packet exiting)
            # get client's port
            clientPort = pkt.getlayer(TCP).sport

            # check if it is a new client
            if not findclient(clientPort):
                # add to the dictionary
                port_to_client_map[clientPort] = pkt.getlayer(IP).src

            # change source ip to the NAT's ip
            NATpkt.getlayer(IP).src = NATip

            # send the new package
            send(NATpkt, iface=publicIface)

            # set print color
            color = Fore.YELLOW

        # print the packets summary
        print(color + NATpkt.summary())

        # reset console color
        print(Fore.RESET)

        # print the dictionary
        print("============= The Dictionary =============")
        for key in port_to_client_map:
            print(f"IP: {port_to_client_map[key]}  -  PORT: {key}")
        print("==========================================")


def findclient(client_port):
    # check if it is a new client
    for key in port_to_client_map:
        if key == client_port:
            return True
    return False


# capture ip packets
sniff(prn=callback, iface=[localIface, publicIface], filter='ip')

