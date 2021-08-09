#!/usr/bin/python

import os
import sys


def setup():
    os.system('ifconfig wlan1 down')
    try:
        os.system('iw dev wlan1 set type monitor')
    except:
        sys.exit(1)
    os.system('ifconfig wlan1 up')
