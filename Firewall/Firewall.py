import time, os
from Firewall.CapFileReader import CapFileReader
from Firewall.Chain import Chain
from scapy.all import *
from netfilterqueue import NetfilterQueue
import netifaces as nif

class Firewall:

    def __init__(self, chain=Chain()):
        self.capFileReader = CapFileReader()
        self.__chain = Chain()

    def sniff(self):
        print("=> Start sniffing on interface " + conf.iface + "...")
        time.sleep(1)
        # sinff packets and display each one
        sniff(prn=lambda x: x.summary())

    def __pkt_match_rule(self, pkt):

        for rule in set(self.__chain.get_rules()):
            if pkt.src == rule.get_src():
                return rule
            # additionals verifications (protocol, mac, etc...)

    def __process_pkt(self, pkt):

        print("processing packet", pkt)

        # make nfqueue packet as scapy one
        scapy_pkt = IP(pkt.get_payload())
        rule = self.__pkt_match_rule(scapy_pkt)

        if rule:
            if rule.get_action() == "drop":
                print("=> Packet dropped")
                pkt.drop()
            elif rule.get_action() == "accept":
                print("=> Packet accepted")
                pkt.accept()
        else:
            # default policy
            print("[*] No rule matched that packet, accepting it")
            pkt.accept()

    def __process_packets(self):
        nfqueue = NetfilterQueue()
        nfqueue.bind(1, self.__process_pkt)
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            print("You stopped the firewall filtering")
            self.__rm_queue_chain_iptables()

    def __rm_queue_chain_iptables(self):
        print("=> Removing queue chain into iptables")
        # Delete all iptable rules, so delete previous chain queues
        cmd = "sudo iptables -F"
        os.system(cmd) # execute cmd

    def __add_queue_chain_iptables(self):

        # Delete all iptable rules, so delete previous chain queues
        self.__rm_queue_chain_iptables()

        print("=> Adding queue chain into iptables for redirecting packets to queue")
        curr_iface = conf.iface
        # get local ip of current network interface
        local_ip = nif.ifaddresses(curr_iface)[nif.AF_INET][0]['addr']
        # local_ip = "192.168.1.45"
        cmd = "sudo iptables -I INPUT -d " + local_ip + " -j NFQUEUE --queue-num 1"
        os.system(cmd)

    def run(self):

        self.__add_queue_chain_iptables()

        print("=> Running firewall")
        if self.load_chain_from_file():
            print("=> Rules have been loaded")
            print(self.__chain)
            self.__process_packets()
        else:
            print("=> No rules loaded, firewall will accept any packet")
            self.sniff()

    def get_chain(self):
        return self.__chain

    def set_chain(self, chain):
        self.__chain = chain
        self.__chain.persist_in_file()

    def load_chain_from_file(self):
        loaded_rules = self.__chain.parse_file()
        if loaded_rules:
            self.__chain = Chain(loaded_rules)
            return True
        else:
            return False

