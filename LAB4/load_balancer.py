from scapy.all import *
from colorama import Fore

# LB Hardware
LBip = "10.69.0.100"
localIface = "middlebox-eth0"
publicIface = "middlebox-eth1"

# Workers Hardware
nextWorker = 0  # mod3
workerIPlist = ["192.168.1.101", "192.168.1.102", "192.168.1.103"]
workerPORTlist = [[], [], []]


# this is nat_server_icmp.py
def callback(pkt):
    global nextWorker
    # check this to avoid feedback loops
    if pkt.getlayer(Ether).src == get_if_hwaddr(localIface):
        return
    if pkt.getlayer(Ether).src == get_if_hwaddr(publicIface):
        return

    # check if it is an ip packet
    if not pkt.haslayer(TCP):
        return

    # get a reference to the packet
    LBpkt = pkt[IP]

    # delete the TCP & IP checksum
    del LBpkt[TCP].chksum
    del LBpkt[IP].chksum

    if LBpkt[TCP].dport == 80:
        # INCOMING PACKET (public packet entering)
        clientPort = LBpkt[TCP].sport

        # CHECK IF IT IS AN EXISTING CLIENT
        hostWorker = findclient(clientPort)

        # if host not defined
        if hostWorker == -1:
            # get next worker ip
            nextWorkerIP = workerIPlist[nextWorker]

            # add to worker's list
            workerPORTlist[nextWorker].append(clientPort)

            # UPDATE RR TICKER
            nextWorker = (nextWorker + 1) % 3

        # Already hosted, passthrough
        else:
            nextWorkerIP = workerIPlist[hostWorker]

        # UPDATE DST IP TO CORRECT WORKER
        LBpkt[IP].dst = nextWorkerIP

        # SEND PACKET
        send(LBpkt, iface=localIface)

        # set print color
        color = Fore.GREEN

    else:
        # OUTGOING PACKET (local packet exiting)
        # set src ip to LB's IP
        LBpkt[IP].src = LBip

        # send the new package
        send(LBpkt, iface=publicIface)

        # set print color
        color = Fore.YELLOW

    # print the packets summary
    print(color + LBpkt.summary())

    # reset console color
    print(Fore.RESET)

    # print the dictionary
    print("======================= Worker Load Print ===========================")
    for i, sublist in enumerate(workerPORTlist):
        print(f"========= Private{i + 1}'s Port list =========")
        for port in sublist:
            print(f"{port}")
        print("========================================")

    print("=============================================================")


def findclient(client_port):
    # check if it is a new client
    for hostID, sublist in enumerate(workerPORTlist):
        for port in sublist:
            if port == client_port:
                return hostID
    return -1


# capture ip packets
sniff(prn=callback, iface=[localIface, publicIface], filter='port 80')

