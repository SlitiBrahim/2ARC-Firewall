import time
from Firewall.CapFileReader import CapFileReader
from scapy.all import *

class Firewall:

    def __init__(self):
        self.capFileReader = CapFileReader()

    def sniff(self):

        print("=> Start sniffing on interface " + conf.iface + "...")

        time.sleep(1)

        sniff(prn=lambda x: x.summary())
