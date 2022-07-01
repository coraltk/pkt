import struct

class IP:
    def __init__(self, data):
        self.protos = {
            1: "ICMP",
            2: "IGMP",
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

class TCP:
    def __init__(self, data):
        self.src_port, self.dst_port, self.seq, self.ack, self.res = struct.unpack('!HHLLH', data[:14])
        off      = (self.res >> 12) * 4
        urg      = (self.res & 32) >> 5
        ack      = (self.res & 16) >> 4
        psh      = (self.res & 8) >> 3
        rst      = (self.res & 4) >> 2
        syn      = (self.res & 2) >> 1
        fin      = (self.res & 32)
        self.data = data[off:]
    
        self.flags = {"urg": urg, "ack": ack, "psh": psh, "rst": rst, "syn": syn, "fin": fin}

class UDP:
    def __init__(self, data):
        self.src_port, self.dst_port, self.size = struct.unpack('!HH2xH', data[:8])
        self.data = data[8:]

class DNS:
    def __init__(self, data):
        opcodes = {
            0: "query",
            1: "iquery OBSOLETE",
            2: "status",
            3: "unassigned opcode",
            4: "notify",
            5: "update",
            6: "dns stateful operations"
        }

        header = struct.unpack("!6H", data[:12])
        self.txid = header[0]
        flags = header[1]
        self.nqueries = header[2]
        self.nanswers = header[3]
        self.nauthority = header[4]
        self.nadditional = header[5]

        self.is_query = flags & 0x8000
        self.opcode = opcodes[flags & 0x7800 >> 11]
        self.trunced = flags & 0x0200 != 0
        
        payload = data[12:]

        if self.is_query:
            queries = []
            for i in range(self.nqueries):
                j = payload.index(0) + 1 + 4
                queries.append(payload[:j])
                payload = payload[j:]

            self.queries = [self.get_domain(query) for query in queries]
        else:
            self.authoritative = (flags & 1024) >> 10
            self.recursion_desired = (flags & 256) >> 8
            self.recursion_available = (flags & 128) >> 7
            self.z = (flags & 64) >> 6
            self.authenticated = (flags & 32) >> 5
            self.non_authenticated_data = (flags & 16) >> 4
            self.reply_code = (flags & 8) >> 3
            
            queries = []
            for i in range(self.nqueries):
                j = payload.index(0) + 1 + 4
                queries.append(payload[:j])
                payload = payload[j:]

            self.queries = [self.get_domain(query) for query in queries]

    def get_domain(self, query):
        # extract domain from a query
        domain = []
        while True:
            l = query[0]
            query = query[1:]
            if l == 0:
                break
            domain.append(query[:l])
            query = query[l:]
        domain = [x.decode("ascii") for x in domain]
        domain = ".".join(domain)
        return domain

class TLS:
    def __init__(self, data):
        content_type, version, length = struct.unpack("!B2sh", data[:5])
        
        tls_handshakes = {
            1: "client_hello",
            2: "server_hello"
        }

        tls_versions = {
            b"\x03\x04": "tls1.3",
            b"\x03\x03": "tls1.2",
            b"\x03\x02": "tls1.1",
            b"\x03\x01": "tls1.0",
        }

        tls_content = {
            20: "change_cipher_spec",
            21: "alert",
            22: "handshake",
            23: "application_data",
            24: "heartbeat",
            25: "tls12_cid",
            26: "ack"
        }

        self.version = tls_versions[version]
        ja3_version = struct.unpack("!H", version)
        self.content_type = tls_content[content_type]
        self.handshake = ""
        self.suites = []
        self.cipher_suites_len = 0.5

        if self.content_type != "handshake":
            return

        # parse handshake
        data = data[5:]

        self.handshake, length, version = struct.unpack("!b2xB2s", data[:6])
        self.version = tls_versions[version]
        ja3_version = struct.unpack("!H", version)

        self.handshake = tls_handshakes[self.handshake]

        # we already know the tls version + we dont care about the random value
        data = data[6+32:]

        if self.handshake == "client_hello":
            session_id_len, self.cipher_suites_len = struct.unpack("!b32xh", data[:35])
            data = data[35:]
            
            self.suites = []
            for i in range(0, self.cipher_suites_len, 2):
                self.suites.append(str(struct.unpack("!H", data[i:i+2])[0]))
        
            data = data[self.cipher_suites_len:]
            self.compression_length = struct.unpack("!b", data[:1])
            data = data[1+self.compression_length[0]:]
        
            self.extensions_length = struct.unpack("!h", data[:2])
            self.data = data[2:]
            
        else:
            pass

class Protocols:
    def __init__(self, parsed_packet, packet_proto):
        lookup = {}

        with open("lib/protos.txt", "r") as f:
            fc = f.readlines()[:-2]
            for i in fc:
                i = i.rstrip()
                parsed = i.split("  ")
                protocol = parsed[0]
                port = parsed[1]
                what = " ".join(parsed[2:])
                lookup[f"{protocol}_{port}"] = what
        
        try:
            src_proto = lookup[f"{packet_proto}_{parsed_packet.src_port}"]
        except Exception as e:
            src_proto = "unknown"
        
        try:
            dst_proto = lookup[f"{packet_proto}_{parsed_packet.dst_port}"]
        except Exception as e:
            dst_proto = "unknown"

        self.protos = f"{src_proto} OR {dst_proto}"
