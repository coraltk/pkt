#! /usr/bin/env python3

import socket, struct, os

colors = {
    "red"         : "\x1b[0;31m",
    "green"       : "\x1b[0;32m",
    "blue"        : "\x1b[0;34m",
    "yellow"      : "\x1b[0;33m",
    "light_red"   : "\x1b[1;31m",
    "light_green" : "\x1b[1;32m",
    "light_blue"  : "\x1b[1;34m",
    "light_yellow": "\x1b[1;33m",
    "reset"       : "\x1b[0m"
}

def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

class Decoder:
    def __init__(self):
        self.oui = open("lib/oui.txt", "r").read().split('\n')
        self.protos = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }

        self.icmp_codes = {
            0: "echo reply",
            3: "destination unreachable",
            4: "source quench",
            5: "redirect",
            8: "echo",
            9: "router advertisement",
            10: "router selection",
            11: "time exceeded",
            12: "parameter problem",
            13: "timestamp",
            14: "timestamp reply",
            15: "information request",
            16: "information reply",
            17: "address mask request",
            18: "address mask reply",
            30: "traceroute"
        }

        self.tls_content = {
            20: "change_cipher_spec",
            21: "alert",
            22: "handshake",
            23: "application_data",
            24: "heartbeat",
            25: "tls12_cid",
            26: "ack"
        }
    
    # format it so it's human readable
    def format_mac(self, mac):
        byte    = map('{:02x}'.format, mac)
        mac_out = ':'.join(byte).upper()
        return mac_out

    # format ipv4 in dotted decimal form
    def format_ipv4(self, ip):
        return '.'.join(map(str, ip))

    def format_data(self, data):
        try:
            # for http and other plaintext application layer protocols
            return data.decode('utf-8'), True
        except:
            # TODO: otherwise, we do more parsing
            try:
                tls_ver = data[1:2]
                if tls_ver == b'\x03': # check if it is tls
                    tls = self.tls(data)
                    
                    if tls[0] == 'client_hello':
                        return f"TLS: content_type {tls[0]}\tversion {tls[1]}\tlength {tls[2]}\ncipher suites length {tls[3]}\ncipher suites {tls[4]}", True
                    else:
                        return f"TLS: content_type {tls[0]}\tversion {tls[1]}\tlength {tls[2]}", True
                else:
                    raise Exception
            except Exception as e:
                print(e)
                input()
                return data, False

    def print_data(self, data, indent=2):
        print("\n"+"\t"*indent, end="")
        width = os.get_terminal_size(0).columns

        data, plaintext = self.format_data(data)
        
        if not plaintext:
            data_pt = "".join([chr(char) if chr(char).isprintable() else "." for char in data])
            data_pt = list(chunks(data_pt, 20))
        
        data = [r'\x{:02x}'.format(byte) for byte in data] if not plaintext else data

        if plaintext:
            data = data.replace("\n", "\n"+"\t"*indent)

        i = 0
        for idx, char in enumerate(data):
            print(char, end="")
            if (idx+1) % 20 == 0 and not plaintext:
                try:
                    print(f"\t{colors['light_red']}"+data_pt[i], end=colors['red'])
                    i+=1
                except:pass
                print("\n"+"\t"*indent, end="")
        
        print()

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
        dst, src, proto = struct.unpack('!6s6sH', data[:14])

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
        src_port, dst_port, seq, ack, res = struct.unpack('!HHLLH', data[:14])
        off      = (res >> 12) * 4
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
        src_port, dst_port, size = struct.unpack('!HH2xH', data[:8])
        data_out = data[8:]

        return src_port, dst_port, size, data_out

    def icmp(self, data): # the most painless to decode :) worked first try
        typ, code, chksum = struct.unpack('!BBH', data[:4])
        data_out = data[4:]

        return self.icmp_codes[typ], code, chksum, data_out

    def tls(self, data):
        content_type, version, length = struct.unpack("!B2sh", data[:5])
        
        tls_handshakes = {
            1: "client_hello",
            2: "server_hello"
        }

        tls_versions = {
            b"\x03\x03": "tls1.2,tls1.3",
            b"\x03\x01": "tls1.1"
        }

        version = tls_versions[version]
        content_type = self.tls_content[content_type]

        if content_type != "handshake":
            return content_type, version, length

        # parse handshake
        data = data[5:]

        handshake, length = struct.unpack("!b2xB", data[:4])
        
        handshake = tls_handshakes[handshake]

       

        # we already know the tls version + we dont care about the random value
        data = data[6+32:]

        if handshake == "client_hello":
            session_id_len, cipher_suites_len = struct.unpack("!b32xh", data[:35])
            data = data[35:]
            
            suites = []
            for i in range(0, cipher_suites_len, 2):
                suites.append(struct.unpack("!H", data[i:i+2]))
        
            data = data[cipher_suites_len:]
            compression_length = struct.unpack("!b", data[:1])
            data = data[1+compression_length[0]:]
        
            extensions_length = struct.unpack("!h", data[:2])
            data = data[2:]
            
            i = 0
            while i > extensions_length[0]:
                # get the extension type
                extension_type, extension_length = struct.unpack("!HH", data[i:i+4])
                if extension_type == 0: # sni
                    server_name_length = struct.unpack("!H", data[i+7:i+9])
                    server_name = data[i+9:i+9+server_name_length[0]]
                    
                    print(server_name.decode('utf-8'))
                    input()
                    
                    i+=9+server_name_length[0]

                    continue
                else:
                    i+=extension_length

            return handshake, version, length, int(cipher_suites_len/2), suites
        else:
            pass

        return handshake, version, length

if __name__ == "__main__":
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    dcd = Decoder()

    while True:
        payload, addr = sock.recvfrom(65535)

        ether = dcd.ether(payload)
        print(f"{colors['green']}src {ether[0]}\tdst {ether[1]}")

        if ether[2] == 8: # ipv4
            ip = dcd.ipv4(ether[3])
            
            print(f"IPv4: src {ip[0]}\tdst {ip[1]}\tproto {ip[2]}")

            match ip[2]:
                case "TCP":
                    tcp = dcd.tcp(ip[4])

                    print(f"\t{colors['blue']}TCP: src {tcp[0]}\tdst {tcp[1]}\tseq {tcp[2]} {colors['red']}")
                    dcd.print_data(tcp[5])
                case "UDP":
                    udp = dcd.udp(ip[4])
                    
                    print(f"\t{colors['blue']}UDP: src {udp[0]}\tdst {udp[1]}\tsize {udp[2]} {colors['red']}")
                    dcd.print_data(udp[3])
                case "ICMP":
                    icmp = dcd.icmp(ip[4])

                    print(f"\t{colors['blue']}ICMP: type {colors['yellow']}{icmp[0]}{colors['blue']}\tcode {icmp[1]} {colors['red']}")
                    dcd.print_data(icmp[3])
        print()
