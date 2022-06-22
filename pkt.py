#! /usr/bin/env python3

from netfilterqueue import NetfilterQueue
import argparse, shutil, os

from src.terminal import *
from src.packet import *

class Pkt:
    def __init__(self, verbose):
        try:
            self.log = log
        except NameError:
            # if in module, we do not care
            self.log = lambda _: None

        self.counter = 0
        self.verbose = verbose

        self.nfq = NetfilterQueue()

    def run(self):
        try:
            shutil.rmtree("packets/")
        except OSError:
            log.warn("Failed to remove packets/ directory")
        os.mkdir("packets/")

        self.log.succ("Starting")

        self.nfq.bind(1, self.pkt)

        try:
            self.nfq.run()
        except KeyboardInterrupt:
            log.warn("Bye!")
            self.nfq.unbind()

    def pkt(self, packet):
        self.counter += 1

        pinfo = {
            "l3_ipv4_src": "",
            "l3_ipv4_dst": "",
            "l3_ipv4_proto": "",
            "l3_ipv4_ttl": "",
            "l4_tcp_port_src" : "",
            "l4_tcp_port_dst" : "",
            "l4_tcp_seq" : "",
            "l4_tcp_ack" : "",
            "l4_tcp_res" : "",
            "l4_tcp_flags_urg" : "",
            "l4_tcp_flags_ack" : "",
            "l4_tcp_flags_psh" : "",
            "l4_tcp_flags_rst" : "",
            "l4_tcp_flags_syn" : "",
            "l4_tcp_flags_fin" : ""
        }

        ip = IP(packet.get_payload())
        pinfo["l3_ipv4_src"]   = ip.src
        pinfo["l3_ipv4_dst"]   = ip.dst
        pinfo["l3_ipv4_proto"] = ip.proto
        pinfo["l3_ipv4_ttl"]   = ip.ttl
        
        if self.verbose > 0:
            log.info(f"{ip.src} -> {ip.dst}")

        match ip.proto:
            case "TCP":
                tcp = TCP(ip.data)

                pinfo["l4_tcp_port_src"] = tcp.src_port
                pinfo["l4_tcp_port_dst"] = tcp.dst_port
                pinfo["l4_tcp_seq"] = tcp.seq
                pinfo["l4_tcp_ack"] = tcp.ack
                pinfo["l4_tcp_res"] = tcp.res

                pinfo["l4_tcp_flags_urg"] = tcp.flags["urg"]
                pinfo["l4_tcp_flags_ack"] = tcp.flags["ack"]
                pinfo["l4_tcp_flags_psh"] = tcp.flags["psh"]
                pinfo["l4_tcp_flags_rst"] = tcp.flags["rst"]
                pinfo["l4_tcp_flags_syn"] = tcp.flags["syn"]
                pinfo["l4_tcp_flags_fin"] = tcp.flags["fin"]

                if self.verbose > 1:
                    log.info(f"\tTCP {tcp.src_port} -> {tcp.dst_port}")
                if self.verbose > 2:
                    log.info(f"\tFlags {tcp.flags['syn']} {tcp.flags['ack']} {tcp.flags['psh']} {tcp.flags['urg']} {tcp.flags['fin']} {tcp.flags['rst']}")

        with open(f"packets/{self.counter}.pkt", "w") as fp:
            fp.write("\n".join([f"{x};{pinfo[x]}" for x in pinfo.keys()]))

        packet.accept()

if __name__ == "__main__":
    log = Log()
    log.succ("pkt v1.0.0")

    parser = argparse.ArgumentParser(description='A stateless firewall with yara like rules in python.', allow_abbrev=True)
    parser.add_argument('--verbose', '-v', action='count', default=0, help='Increases verbosity')
    parser.add_argument('--rules', '-r', help='The directory in which the rules are stored', type=str, default='rules/')
    args = parser.parse_args()

    _pkt = Pkt(args.verbose)
    _pkt.run()
