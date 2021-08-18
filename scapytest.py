#!/usr/bin/python

from scapy.all import *
import scapy
import argparse
import os
import sys
from scapy.layers.dot11 import *
from threading import Thread
import time

AP = dict(
    bssid = '02',
    ssid = 'free wifi',
    channel = '4',
    cryto = 'wpa',
    signalStrength = '2',
    riskStatus = 'white'
)

# Initial global lists which will be turned into saved files
apList = []  # Master list of all seen APs
whitelist = []  # User approved APs
blacklist = []  # Definite malicious/bad APs
interface = "WiFi 2"


def get_args():
    print(sys.path)
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Target IP Address/Addresses')
    options = parser.parse_args()

    # Some error checking
    if not options.target:
        parser.error("[-] Please specify an IP Address or Addresses, use --help for more info.")
    return options


def scan():
    #sniff(iface=interface, timeout=2, prn=packet_printer)
    sniff(iface=interface, timeout=5, prn=Packet.summary)


def packet_printer(packet):
    if packet.haslayer(scapy.layers.Dot11.Dot11Beacon):

        mac = packet[Dot11].addr2
        ssid = packet[Dot11].info.decode()

        if packet.addr2 not in apList:
            apList.append(packet[Dot11Beacon].addr2)

        try:
            signalStrength = packet.dBm_AntSignal
        except:
            signalStrength = "N/A"

        otherStats = packet[Dot11Beacon].network_stats()
        channel = otherStats.get("channel")
        encryption = otherStats.get("crypto")

        print("AP MAC: %s with SSID: %s \nSignal strength (dB): %3 \nChannel: %s \nEncryption: %s" %(mac, ssid, signalStrength, channel, encryption))
    else:
        print("Not dot 11 beacon.")
    return


# Helper function for changing the scan channel
def change_channel():
    channel = 1
    while True:
        os.system(f"iwconfig {interface} channel {channel}")
        channel = channel % 14 + 1      # Switches between channels 1 - 15
        time.sleep(1)

# someOptions = get_args()
# print(someOptions)
scan()



def analyse():

    if AP['riskStatus'] == 'white':
        print("She okay.")
        return
    elif AP['riskStatus'] == 'black':
        print("Oh shit we in trouble now")
    elif AP['riskStatus'] == 'grey':
        print("Just some neighbourly wifi action.")

