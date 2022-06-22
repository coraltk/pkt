#! /usr/bin/env python3

from netfilterqueue import NetfilterQueue
from src.terminal   import *
from src.packet     import *

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
        ipdata = IP(packet.get_payload())

        self.log.info(f"Got packet from {ipdata.src}")

        if ipdata.src == 'really.cool.ip.address':
            packet.drop()
            return

        packet.accept()

if __name__ == "__main__":
    log = Log()

    log.succ("pkt v1.0.0")

    _pkt = Pkt()

    _pkt.run()
