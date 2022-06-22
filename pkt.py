#! /usr/bin/env python3

from netfilterqueue import NetfilterQueue
import argparse

from src.terminal import *
from src.packet import *

class Pkt:
    def __init__(self):
        try:
            self.log = log
        except NameError:
            # if in module, we do not care
            self.log = lambda _: None
        
        self.nfq = NetfilterQueue()

    def run(self):
        self.log.succ("Starting")

        self.nfq.bind(1, self.pkt)

        try:
            self.nfq.run()
        except KeyboardInterrupt:
            log.warn("Bye!")
            self.nfq.unbind()

    def pkt(self, packet):
        pinfo = {
            "l3_ipv4_src": "",
            "l3_ipv4_dst": "",
            "l3_ipv4_proto": "",
            "l3_ipv4_ttl": ""#,
            #"l4_tcp"
        }

        ipdata = IP(packet.get_payload())

        self.log.info(f"Got packet from {ipdata.src}")



        packet.accept()

if __name__ == "__main__":
    log = Log()
    log.succ("pkt v1.0.0")

    parser = argparse.ArgumentParser(description='A stateless firewall with yara like rules in python.', allow_abbrev=True)
    parser.add_argument('--verbose', '-v', action='count', default=0, help='Increases verbosity')
    parser.add_argument('--rules', '-r', help='The directory in which the rules are stored', type=str, default='rules/')
    arguments = parser.parse_args()

    _pkt = Pkt()
    _pkt.run()
