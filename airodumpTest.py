import os


# This here is an incredibly bad practice thing to do,
# and should only be done if all else fails.
# Will need to give root permissions also, which will require a sudo su command,
# a wait, then a password. It will also need a wait then a ctrl-c to end the airodump,
# then another wait before reading the contents of the recent.csv file.
import sys


def setup():
    os.system('ifconfig wlan1 down')
    try:
        os.system('iw dev wlan1 set type monitor')
    except:
        sys.exit(1)
    os.system('ifconfig wlan1 up')


def airodump():
    os.system('airodump-ng -w recent --output-format csv wlan1')

