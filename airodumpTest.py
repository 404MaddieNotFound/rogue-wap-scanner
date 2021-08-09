#!/usr/bin/python

import os
import sys


# This here is an incredibly bad practice thing to do,
# and should only be done if all else fails.
# It will also need a wait then a ctrl-c to end the airodump,
# then another wait before reading the contents of the recent.csv file.

def airodump():
    os.system('airodump-ng -w recent --output-format csv wlan1')
