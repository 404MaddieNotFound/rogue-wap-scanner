import scapy.layers.l2
from scapy.all import *
import argparse
import sys


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
    sniff(iface="WiFi 2", timeout=10)


# someOptions = get_args()
# print(someOptions)
scan()
sniff(timeout=10)
