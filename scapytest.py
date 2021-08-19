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
interface = "WiFi 2"


def user_input():
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


scan()



def analyse():

    suspicionLevel = 'green'
    # Check if AP has already appeared and its current classification
    if AP in apList:
        if AP['riskStatus'] == 'white':
            suspicionLevel = 'green'
            print("She okay.")
            return
        elif AP['riskStatus'] == 'black':
            suspicionLevel = 'red'
            print("Oh shit we in trouble now")
        elif AP['riskStatus'] == 'grey':
            suspicionLevel = 'green'
            print("Just some neighbourly wifi action.")
        elif AP['riskStatus'] == 'unset':
            suspicionLevel = 'yellow'
            print("Seen before but not something we know about.")

    # AP is newly appeared (or reappeared once time expiring storage implemented)
    else:
        suspicionLevel = 'yellow'
        print("Something new.")
        # Adds new AP to master list
        apList.append(AP)

    # Checks for SSID spoofing

    # Checks BSSID for known pentesting tools

    # Checks encryption

    return suspicionLevel
