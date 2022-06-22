import struct

class IP:
    def __init__(self, data):
        self.protos = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }

        version_len = data[0]
        version    = version_len >> 4
        header_len = (version_len & 15) * 4
        self.ttl, proto, src, dst = struct.unpack('!8xBB2x4s4s', data[:20])

        self.src        = self.format_ipv4(src)
        self.dst        = self.format_ipv4(dst)
        self.data       = data[header_len:]
        self.proto      = self.protos[proto]

    def format_ipv4(self, ip):
        return '.'.join(map(str, ip))
