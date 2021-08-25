#!/usr/bin/python

from scapy.all import *
import argparse
import os
import sys
#from scapy.layers.dot11 import *
from threading import Thread
import pandas
import time

# Initial global lists which will be turned into saved files

# Pandas dataframe that will contain all access points nearby
APlist = pandas.DataFrame(columns=["BSSID", "SSID", "Channel", "Encryption", "Signal Strength (dBm)", "Risk Status"])
APlist.set_index("BSSID", inplace=True)           # Initially set unique identifier of dataframe as BSSID, might need to change this because of BSSID spoofing

# Pandas dataframe for current scan
activeList = pandas.DataFrame(columns=["BSSID", "SSID", "Channel", "Encryption", "Signal Strength (dBm)"])
activeList.set_index("BSSID", inplace=True)

interface = "wlan1"     # Monitor mode scanning interface; needs a method to dynamically determine this in case of changes


def setup():
    os.system('ifconfig wlan1 down')
    try:
        os.system('iw dev wlan1 set type monitor')
    except:
        sys.exit(1)
    os.system('ifconfig wlan1 up')


def user_input():
    print(sys.path)
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Target IP Address/Addresses')
    options = parser.parse_args()

    # Some error checking
    if not options.target:
        parser.error("[-] Please specify an IP Address or Addresses, use --help for more info.")
    return options

# Basic CLI display of APs and details, refreshes at 1Hz
def display():
    while True:
        os.system("clear")
        print(APlist)
        time.sleep(1)


def scan():
    sniff(iface=interface, timeout=5, prn=packet_printer)
    #sniff(iface=interface, timeout=5, prn=Packet.summary)


def packet_printer(packet):
    if packet.haslayer(Dot11Beacon):

        mac = packet[Dot11].addr2
        ssid = packet[Dot11].info.decode()

        try:
            signalStrength = packet.dBm_AntSignal
        except:
            signalStrength = "N/A"

        otherStats = packet[Dot11Beacon].network_stats()
        channel = otherStats.get("channel")
        encryption = otherStats.get("crypto")

        if mac not in activeList:
            activeList.loc[mac] = (ssid, channel, encryption, signalStrength)

        print("AP MAC: %s with SSID: %s \nSignal strength (dB): %s \nChannel: %s \nEncryption: %s" %(mac, ssid, signalStrength, channel, encryption))
    else:
        print("Not dot 11 beacon.")
    return


# Helper function for changing the scan channel
def change_channel():
    channel = 1
    while True:
        os.system("iwconfig wlan1 channel " + channel)
        channel = channel % 14 + 1      # Switches between channels 1 - 15
        time.sleep(1)


def analyse(bssid):
    suspicionLevel = 'green'
    # Check if AP has already appeared and its current classification
    if not APlist.loc[bssid]['New']:
        if APlist.loc[bssid]['Risk Status'] == 'white':
            suspicionLevel = 'green'
            print("She okay.")
            return
        elif APlist.loc[bssid]['Risk Status'] == 'black':
            suspicionLevel = 'red'
            print("Oh shit we in trouble now")
        elif APlist.loc[bssid]['Risk Status'] == 'grey':
            suspicionLevel = 'green'
            print("Just some neighbourly wifi action.")
        elif APlist.loc[bssid]['Risk Status'] == 'unknown':
            suspicionLevel = 'yellow'
            print("Seen before but not something we know about.")

    # AP is newly appeared (or reappeared once time expiring storage implemented)
    else:
        suspicionLevel = 'yellow'
        print("Something new.")
        # Add the newly spotted AP to the AP master list
        APlist.loc[bssid] = (activeList.loc[bssid]['SSID'], activeList.loc[bssid]['Channel'], activeList.loc[bssid]['Encryption'], activeList.loc[bssid]['Signal Strength (dBm)', 'unknown'])

    # Checks for SSID spoofing
    if activeList.loc[bssid]['SSID'] == an ssid from another bssid in APlist

    # Checks BSSID for known pentesting tools

    # Checks encryption

    return suspicionLevel


def save():
    # Saves AP master list

    return


if __name__ == "__main__":
    setup()
    scan()
    for each in activeList:
        analyse(bssid=activeList[each])           # Does this really work? Damn Python is just so *chef's kiss*
    # after scan and analyse, clear active list
    display()
    save()
