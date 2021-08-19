from scapy.all import *
#from scapy.layers.dot11 import *
#from scapy.layers.inet import *
#from scapy.layers.l2 import *

ap_list = []


def packethandler(pkt):
    for layer in pkt.layers():
        print(layer)
    if pkt.haslayer(Dot11Beacon):
        print("Found a Dot11!!!!!!!!!!!!!!!!!!!!!!!!!!")
        if pkt.type == 0 and pkt.subtype == 8:
            if pkt.addr2 not in ap_list:
                ap_list.append(pkt.addr2)
                print("AP MAC: %s with SSID: %s " % (pkt.addr2, pkt.info))
        else:
            print("Packet type = %s, subtype = %s") % (pkt.type, pkt.subtype)
    elif pkt.haslayer(IP):
        print("IP: %s" % pkt[IP].src)
    elif pkt.haslayer(ARP):
        print("ARP: %s" % pkt[ARP].summary)
    elif pkt.haslayer(Ether):
        print("Ether: %s" % pkt[Ether].summary)
    else:
        print("Other: %s" % pkt.summary)


sniff(iface="WiFi 2", prn=packethandler)
