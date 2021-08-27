#!/usr/bin/python

# Rogue WiFi Scanner
# Author: Maddie Owen
# Company: Seric Systems

# Description: a Python script to be executed on a Raspberry Pi to automatically discover
# and notify a user of rogue or soft wireless access points nearby.

# Function list:
# setup():
# Takes no parameters
# Checks that all libraries/dependencies are in place,
# updates them, and sets wireless interface to
# monitor mode.

# scan():
# Takes no parameters
# Helper function: packet_printer()
# Performs a 5 second scan of wireless access points within range,
# calling the packet_printer function to process each sniffed packet.
# Outputs: csv of most recent scan, list of discovered APs,
# user message that scan has been completed.

# packet_printer(packet):
# Takes a packet as parameter, as defined by the Scapy library
# Helper function: analyse()
# Handles each packet sniffed by the scan() function. Checks whether
# the packet is of Dot11Beacon type (i.e. from an access point),
# and if so, extracts the relevant packet data and adds the
# access point to the active list.
# Outputs: adds current AP to active list.

# analyse(bssid):
# Takes the bssid (unique identifier) of the AP for analysis as a parameter
# Checks the selected AP from the active list and decides if it is suspect by:
# checking if it is newly appeared, checking the current user set status (whitelist, blacklist)
# identifying if SSID spoofing is occurring, identifying weak or no encryption,
# identifying no authorisation, identifying known hacking tools.
# Outputs: edits the attributes of the master list of APs,
# notifies user of any new suspect APs.

# set_status(bssid, status):
# Takes the BSSID to be changed and the status to change it to as an argument
# Changes risk status of specified AP entry to specified status.
# Outputs: edits the attributes of the master list.

# change_channel():
# Helper function for scan, changes the channel on which the
# network interface is sniffing on.

# user_input():
# Provides the basis for user interaction via the command line.
# In future to be adapted to interact with a web interface.

# display():
# Provides a command line display of currently active APs


from scapy.all import *
import argparse
import os
import sys
from threading import Thread
import pandas
import time

# Initial global lists which will be turned into saved files

# Pandas dataframe that will contain all access points nearby
APlist = pandas.DataFrame(columns=["BSSID", "SSID", "Channel", "Encryption", "Signal Strength (dBm)", "Risk Status"])
APlist.set_index("BSSID",
                 inplace=True)  # Initially set unique identifier of dataframe as BSSID, might need to change this
# because of BSSID spoofing

# Pandas dataframe for current scan
activeList = pandas.DataFrame(columns=["BSSID", "SSID", "Channel", "Encryption", "Signal Strength (dBm)"])
activeList.set_index("BSSID", inplace=True)

interface = "WiFi 2"  # Monitor mode scanning interface; needs a method to dynamically determine this in case of changes
# WiFi 2 for PC, wlan1 for Pi


def setup():
    os.system('ifconfig wlan1 down')
    try:
        os.system('iw dev wlan1 set type monitor')
    except:
        sys.exit(1)
    os.system('ifconfig wlan1 up')


def scan():
    sniff(iface=interface, timeout=10, prn=packet_printer)


def packet_printer(packet):
    if packet.haslayer(Dot11Beacon):

        bssid = packet[Dot11].addr2
        ssid = packet[Dot11].info.decode()

        try:
            signalStrength = packet.dBm_AntSignal
        except:
            signalStrength = "N/A"

        otherStats = packet[Dot11Beacon].network_stats()
        channel = otherStats.get("channel")
        encryption = otherStats.get("crypto")

        if bssid not in activeList:
            activeList.loc[bssid] = (ssid, channel, encryption, signalStrength)

        print("Access point with BSSID: %s\n SSID: %s \nSignal strength (dB): %s \nChannel: %s \nEncryption: %s" % (
            bssid, ssid, signalStrength, channel, encryption))

    return


def change_channel():
    channel = 1
    for x in range(20):
        os.system("iwconfig wlan1 channel " + channel)
        channel = channel % 12 + 1  # Switches between channels 1 - 13
        time.sleep(0.5)


def analyse(bssid):
    suspicionLevel = 'green'
    # Check if AP has already appeared and its current classification
    if bssid in APlist:
        if APlist.loc[bssid]['Risk Status'] == 'white':
            suspicionLevel = 'green'
            print("All okay.")
            return
        elif APlist.loc[bssid]['Risk Status'] == 'black':
            suspicionLevel = 'red'
            print("Danger! This AP has been flagged as malicious.")
        elif APlist.loc[bssid]['Risk Status'] == 'grey':
            suspicionLevel = 'green'
            print("Just some neighbourly wifi action.")
        elif APlist.loc[bssid]['Risk Status'] == 'unknown':
            suspicionLevel = 'yellow'
            print("Seen before but not something we know about.")

    # AP is newly appeared (or reappeared once time expiring storage implemented)
    else:
        suspicionLevel = 'yellow'
        print("A new AP.")

        # A basic check for SSID spoofing
        for each in APlist:
            if activeList.loc[bssid]['SSID'] == APlist.loc[each]['SSID']:
                suspicionLevel = 'red'
                print("SSID spoofing suspected for AP with BSSID %s and SSID %s danger!" % (
                    activeList.loc[bssid], activeList.loc[bssid]['SSID']))

        # Check MAC address for known pentesting tools

        # Check encryption type for soft access points

        # Add the newly spotted AP to the AP master list
        APlist.loc[bssid] = (
            activeList.loc[bssid]['SSID'], activeList.loc[bssid]['Channel'], activeList.loc[bssid]['Encryption'],
            activeList.loc[bssid]['Signal Strength (dBm)', 'unknown'])

    return suspicionLevel


def set_status(bssid, status):
    APlist.loc[bssid]['Risk Status'] = status
    return


def save():
    # Saves AP master list to file
    APlist.to_csv('APmasterlist.csv')
    return


def fetch():
    # Retrieves saved AP master list
    APlist = pandas.read_csv('APmasterlist.csv')
    return


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
    for x in range(10):
        #os.system("clear")
        print(APlist)
        time.sleep(1)


if __name__ == "__main__":

#    setup()  # Set monitor mode
 #   fetch()
    # Start display thread
    APdisplay = Thread(target=display)
    APdisplay.daemon = True
    APdisplay.start()

    # Start channel switcher
 #   channel_switch = Thread(target=change_channel)
 #   channel_switch.daemon = True
 #   channel_switch.start()

    scan()  # Do the sniff!

    for packet in activeList:
        analyse(bssid=activeList[packet])  # Make this something that works

    # After scan, display and analyse, we need to clear active list and save master list

    # clear activeList
    save()
