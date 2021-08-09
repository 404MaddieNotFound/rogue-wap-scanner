#!/usr/bin/python

# Rogue WiFi Scanner, AKA The WAP Hunter
# Author: Maddie Owen
# Company: Seric Systems

# Description: a Python script to be executed on a Raspberry Pi to automatically discover
# and notify a user of rogue or soft wireless access points nearby.

# Function list:
# initialise():
# Takes no parameters
# Checks that all libraries/dependencies are in place,
# updates them, checks wireless interface is available
# and in monitoring mode.

# scan():
# Takes no parameters
# Helper functions: create_current_wap_list(), create_new_wap_list(),
# Performs a scan of the wireless access points within range,
# saves a PCAP and list of WAPs from the scan.
# Outputs: PCAP/csv of most recent scan, list of WAPs discovered,
# user message that scan has been completed.

# detect_rogues():
# Takes no parameters
# Helper functions: notify(),
# Checks each newly detected WAP, and decides if it is suspect by:
# comparing to whitelist, comparing to blacklist, identifying if SSID
# or BSSID spoofing is being used, identifying weak or no encryption,
# identifying no authorisation, identifying known hacking tools.
# Outputs: edits the attributes of the master list of WAPs,
# notifies user of any new suspect WAPs.

# add_to_whitelist(bssid):
# Takes the BSSID to be whitelisted as an argument
# Helper functions:
# Adds device specified by bssid to the whitelist/edits entry in master list.
# Outputs: edits the whitelist/attributes of the master list.

# add_to_blacklist(bssid):
# Takes the BSSID to be blacklisted as an argument
# Helper functions:
# Adds device specified by bssid to the blacklist/edits entry in master list.
# Outputs: edits the blacklist/attributes of the master list.


import sys  # Used for command line arguments
import scapy
import pyrcrack
import asyncio  # Used for asynchronous waiting and command line interaction
from time import sleep, time


############################################
# Main Functions #

# Checks that all libraries/dependencies are in place,
# updates them, finds available wireless interface and
# checks/sets it to monitoring mode.
async def initialise():
    airmon = pyrcrack.AirmonNg()
    print([interface.asdict() for interface in await airmon.interfaces])

    print("All updated and ready to hunt.")


# Performs a scan of the wireless access points within range,
# saves a PCAP and list of WAPs from the scan.
def scan():
    print("Let's hunt.")
    return


# Sorts the good, the bad and the ugly
def detect_rogues():
    print("Found some suspects.")
    return


# Allows a user to add a specific WAP to the
# whitelist of allowed devices.
def add_to_whitelist(bssid):
    print("Added " + bssid + " to whitelist of allowed WAPs.")


# Allows a user to add a specific WAP to the
# blacklist of suspect/insecure devices.
def add_to_blacklist(bssid):
    print("Added " + bssid + " to blacklist of rogue WAPs.")


##########################################
# Helper Functions #

# Helper function for scan();
# Converts the PCAP of the most recent wireless scan
# into a list of WAPs and attributes.
def create_current_wap_list():
    print("Most recently scanned WAPs: ")
    return


# Helper function for scan();
# Compares the master list against the current list,
# creates and saves a list of WAPs which appear on
# current list but not master list.
def create_new_wap_list():
    print("These are all the newly detected WAPs.")
    return


# Helper function for detect_rogues()
# Informs the user of a suspect WAP.
def notify(bssid):
    print("Suspect WAP: " + bssid)
    return

asyncio.run(initialise())





