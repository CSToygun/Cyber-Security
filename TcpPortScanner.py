#//Thank you
#//Coded by https://github.com/kaantekiner

from scapy.layers.inet import ICMP, IP, TCP
from scapy.sendrecv import sr1
import socket
import sys, traceback

# build packets
ipPaket = IP()
icmpPAKET = ICMP()
tcpPaket = TCP()

# build attiributes
DestinationIP = "none"
timeOutSeconds = 5

def Start():
    takeDestinationAndTimeout()

def validateIPv4Adress(s):
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True

def takeDestinationAndTimeout():
    print("\n")
    global DestinationIP
    global timeOutSeconds
    DestinationIP = input("Destination IPv4 for check reachability? ")
    try:
        if validateIPv4Adress(DestinationIP):
            socket.inet_aton(DestinationIP)
        else:
            print("Invalid IPv4 Adress")
            takeDestinationAndTimeout()
    except socket.error:
        print("Invalid IPv4 Adress")
        takeDestinationAndTimeout()
    askForTimeout()

def askForTimeout():
    global timeOutSeconds
    timeOutSeconds = input("Timeout?[5] ")
    if timeOutSeconds == "":
        timeOutSeconds = 5
    try:
        timeOutSeconds = int(timeOutSeconds)
    except:
        print("Invalid timeout value, retype an integer")
        askForTimeout()
    assignIpPacketAttiributes()

def assignIpPacketAttiributes():
    global ipPaket
    ipPaket.dst = DestinationIP
    sendPacket()

def sendPacket():
    print("\n")
    print("Sending ICMP Packet To Target(" + str(DestinationIP) + ") with timeout sec " + str(timeOutSeconds))
    Response = sr1(ipPaket / icmpPAKET, timeout=timeOutSeconds, verbose=False)
    if not (Response is None):
        print(ipPaket.dst, "is ONLINE", "\n")
        printOutputs(Response)
    else:
        print("Timeout done, seems target OFFLINE, UNREACHABLE or DO NOT ANSWER ICMP")
        print("\n")
        contuniue = input("You want to contuine?[y/N]")
        if contuniue == "" or contuniue == "N" or contuniue == "n":
            sys.exit(0)
        if contuniue == "Y" or contuniue == "y":
            print("will port scan but not developed yet")

def printOutputs(Response):
    print("ICMP Packet Sended and Response Recieved Successfully")
    print("Full response from target =", Response)
    print("version =", Response.version)
    print("ihl =", Response.ihl)
    print("tos =", Response.tos)
    print("len =", Response.len)
    print("id =", Response.id)
    print("flag =", Response.flags)
    print("frag =", Response.frag)
    print("ttl =", Response.ttl)
    print("proto =", Response.proto)
    print("chksum =", Response.chksum)
    print("src =", Response.src)
    print("dst =", Response.dst)
    detectOS(Response)

def detectOS(Response):
    WentTTL = Response.ttl
    OS = "Unknkown"
    if WentTTL <= 64:
        OS = "Linux"
    else:
        OS = "Windows"
    print("\n", "---- OS Detection ----")
    print("Possible OS =", OS)
    StartPortScanProcess()

def StartPortScanProcess():
    print("\n" + "Starting PORT scan process")
    assignTcpPacketAttiributes()

def assignTcpPacketAttiributes():
    global tcpPaket
    # tcpPaket.sport = RandShort()
    tcpPaket.sport = 800
    tcpPaket.flags = "S"
    timeOutSecondsLocal = 2
    StartPort = int(input("Start Port? "))
    EndPort = int(input("End Port? "))
    PrintClosedQuestion = input("Show closed ones?[y/N]")
    if PrintClosedQuestion == "":
        PrintClosedQuestion = "n"
    print("\n")
    print("Process Started")
    for i in range(StartPort, EndPort + 1):
        tcpPaket.dport = i
        Response = sr1(ipPaket / tcpPaket, timeout=timeOutSecondsLocal, verbose=False)
        if Response is None:
            if PrintClosedQuestion.lower() == "y":
                print("port", tcpPaket.dport, "is CLOSED(unanswered)")
        if Response is not None:
            if Response.haslayer(TCP):
                if Response.getlayer(TCP).flags == 18 or Response.getlayer(TCP).flags == 20:
                    if Response.getlayer(TCP).flags == 18:
                        print("port", tcpPaket.dport, "is OPEN")
                        # complete connection with this RTS and ACK packet to not to DOS:)
                        Send_RTS_ACK = sr1(ipPaket / TCP(sport=tcpPaket.sport, dport=tcpPaket.dport, flags='AR'),
                                           timeout=timeOutSecondsLocal, verbose=False)
                    if Response.getlayer(TCP).flags == 20:
                        if PrintClosedQuestion.lower() == "y":
                            print("port", tcpPaket.dport, "is CLOSED")
                else:
                    if PrintClosedQuestion.lower() == "y":
                        print("port", tcpPaket.dport, "is CLOSED(filtered")
            elif Response.haslayer(ICMP):
                if PrintClosedQuestion.lower() == "y":
                    print("port", tcpPaket.dport, "do not have tcp layer, ICMP response may be FILTERED")
            else:
                if PrintClosedQuestion.lower() == "y":
                    print("port", tcpPaket.dport, "send UNKNOWN response")
                    print("port", Response.summary())
    print("Process done.")
Start()
