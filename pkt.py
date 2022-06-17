#! /usr/bin/env python3

import socket, struct

class Decoder:
    def __init__(self):
        self.oui = open("lib/oui.txt", "r").read().split('\n')
        self.protos = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }
    
    # format it so it's human readable
    def format_mac(self, mac):
        byte    = map('{:02x}'.format, mac)
        mac_out = ':'.join(byte).upper()
        return mac_out

    # format ipv4 in dotted decimal form
    def format_ipv4(self, ip):
        return '.'.join(map(str, ip))

    def pretty_mac(self, mac):
        formatted = self.format_mac(mac)
        oui       = formatted.replace(':', '')[:6]
        
        if formatted == "FF:FF:FF:FF:FF:FF":
            return "broadcast"

        for i in self.oui:
            if oui in i:
                return i[7:]+":"+formatted[9:]

        return formatted

    # Parse raw ethernet packet
    def ether(self, data):
        dst, src, proto = struct.unpack('! 6s 6s H', data[:14])

        return self.pretty_mac(src), self.pretty_mac(dst), socket.htons(proto), data[14:]

    # Parse raw ipv4 packet
    def ipv4(self, data):
        version_len = data[0]
        version    = version_len >> 4
        header_len = (version_len & 15) * 4
        ttl, proto, src, dst = struct.unpack('!8xBB2x4s4s', data[:20])

        src        = self.format_ipv4(src)
        dst        = self.format_ipv4(dst)
        data_out   = data[header_len:]

        return src, dst, self.protos[proto], ttl, data_out

    def tcp(self, data):
        src_port, dst_port, seq, ack, res = struct.unpack('! H H L L H', data[:14])
        off      = (res >> 22) * 4
        urg      = (res & 32) >> 5
        ack      = (res & 16) >> 4
        psh      = (res & 8) >> 3
        rst      = (res & 4) >> 2
        syn      = (res & 2) >> 1
        fin      = (res & 32)
        data_out = data[off:]
    
        flags = {"urg": urg, "ack": ack, "psh": psh, "rst": rst, "syn": syn, "fin": fin}

        return src_port, dst_port, seq, ack, flags, data_out

    def udp(self, data):
        pass

    def icmp(self, data):
        pass

if __name__ == "__main__":
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    dcd = Decoder()

    while True:
        payload, addr = sock.recvfrom(65535)

        ether = dcd.ether(payload)
        print(f"src {ether[0]}\tdst {ether[1]}")

        if ether[2] == 8: # ipv4
            ip = dcd.ipv4(ether[3])
            
            print(f"\tIPv4: src {ip[0]}\tdst {ip[1]}\tproto {ip[2]}")

            match ip[2]:
                case "TCP":
                    tcp = dcd.tcp(ip[4])

                    print(f"\t\tTCP: src {tcp[0]}\tdst {tcp[1]}\tseq {tcp[2]}")
                case "UDP":
                    udp = dcd.udp(ip[4])
                case "ICMP":
                    icmp = dcd.icmp(ip[4])

        print()
