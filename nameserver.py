import socket
import struct
import threading
import time
import os
import json
from RouteDataPacket import RouteDataPacket
from datetime import datetime
from collections import deque, defaultdict

INTEREST = 0x1
DATA = 0x2
ROUTING_DATA = 0x3
HELLO = 0x4
UPDATE = 0x5
ERROR = 0x6
ROUTE_ACK = 0x7
REDIRECT_NS = 0x8

ACK_FLAG = 0x1
RET_FLAG = 0x2
TRUNC_FLAG = 0x3

# Error codes
FORMAT_ERROR = 0x1
NAME_ERROR = 0x2

_PRINT_LOCK = threading.Lock()

def create_data_packet(seq_num, name, payload, flags=0x0, fragment_num=1, total_fragments=1):
    packet_type = DATA
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    seq_num = seq_num & 0xFF
    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes)

    payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload
    payload_size = len(payload_bytes) & 0xFFFF

    header = struct.pack("!BBBBBH", packet_type_flags, seq_num, name_length, fragment_num, total_fragments, payload_size)
    return header + name_bytes + payload_bytes

def create_interest_packet(seq_num, name, flags=0x0, origin_node="", data_flag=False, visited_domains=None):
    if visited_domains is None:
        visited_domains = []

    packet_type = INTEREST
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    seq_num = seq_num & 0xFF
    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes)

    origin_bytes = origin_node.encode("utf-8")
    origin_length = len(origin_bytes)

    data_flag_byte = b'\x01' if data_flag else b'\x00'

    # ---- Encode visited_domains ----
    vd_count = len(visited_domains) & 0xFF
    vd_bytes = bytes([vd_count])

    for dom in visited_domains:
        dom_b = dom.encode("utf-8")
        vd_bytes += bytes([len(dom_b) & 0xFF]) + dom_b

    # ---- Build packet ----
    header = struct.pack("!BBB", packet_type_flags, seq_num, name_length)
    packet = (
        header +
        name_bytes +
        bytes([origin_length]) +
        origin_bytes +
        data_flag_byte +
        vd_bytes
    )

    return packet

# def create_error_packet(seq_num, name, error_code, origin_node="", flags=0x0, data_flag=False, visited_domains=None):
#     """
#     Build an ERROR packet with origin node info:
#     Header: packet_type&flags (1 byte), seq_num (1 byte),
#             error_code (1 byte), name_length (1 byte)
#     Then: name (variable), origin_length (1 byte), origin_node (variable)
#     """
#     packet_type = ERROR
#     packet_type_flags = (packet_type << 4) | (flags & 0xF)

#     seq_num = seq_num & 0xFF
#     err_code = error_code & 0xFF
#     name_bytes = name.encode("utf-8")
#     name_length = len(name_bytes)

#     origin_bytes = origin_node.encode("utf-8")
#     origin_length = len(origin_bytes)

#     data_flag_byte = b'\x01' if data_flag else b'\x00'

#     # ---- Encode visited_domains ----
#     vd_count = len(visited_domains) & 0xFF
#     vd_bytes = bytes([vd_count])

#     for dom in visited_domains:
#         dom_b = dom.encode("utf-8")
#         vd_bytes += bytes([len(dom_b) & 0xFF]) + dom_b

#     # ---- Build packet ----
#     header = struct.pack("!BBB", packet_type_flags, seq_num, name_length)
#     packet = (
#         header +
#         name_bytes +
#         bytes([origin_length]) +
#         origin_bytes +
#         data_flag_byte +
#         vd_bytes
#     )

#     return packet

def create_error_packet(seq_num, name, error_code, origin_node="", flags=0x0):
    """
    Build an ERROR packet with origin node info:
    Header: packet_type&flags (1 byte), seq_num (1 byte),
            error_code (1 byte), name_length (1 byte)
    Then: name (variable), origin_length (1 byte), origin_node (variable)
    """
    packet_type = ERROR
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    seq_num = seq_num & 0xFF
    err_code = error_code & 0xFF
    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes) & 0xFF
    origin_bytes = origin_node.encode("utf-8")
    origin_length = len(origin_bytes) & 0xFF

    header = struct.pack("!BBBB", packet_type_flags, seq_num, err_code, name_length)
    packet = header + name_bytes + struct.pack("!B", origin_length) + origin_bytes
    return packet

def parse_error_packet(packet):
    if len(packet) < 5:
        raise ValueError("Invalid ERROR packet: too short")

    packet_type_flags, seq_num, err_code, name_length = struct.unpack("!BBBB", packet[:4])
    name_start = 4
    name_end = name_start + name_length
    name = packet[name_start:name_end].decode("utf-8")

    if len(packet) > name_end:
        origin_length = packet[name_end]
        origin_start = name_end + 1
        origin_end = origin_start + origin_length
        origin_node = packet[origin_start:origin_end].decode("utf-8")
    else:
        origin_node = ""

    packet_type = (packet_type_flags >> 4) & 0xF
    flags = packet_type_flags & 0xF

    return {
        "PacketType": packet_type,
        "Flags": flags,
        "SequenceNumber": seq_num,
        "ErrorCode": err_code,
        "Name": name,
        "OriginNode": origin_node
    }

def create_route_data_packet(seq_num, name, payload, flags=0x0):
    packet_type = ROUTING_DATA
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    seq_num = seq_num & 0xFF
    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes)

    # payload should be a dict with at least 'origin_name' and 'path' fields
    if isinstance(payload, dict):
        payload_json = json.dumps(payload)
        payload_bytes = payload_json.encode("utf-8")
    else:
        payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload
    payload_size = len(payload_bytes) & 0xFF

    header = struct.pack("!BBBB", packet_type_flags, seq_num, name_length, payload_size)
    return header + name_bytes + payload_bytes

def parse_interest_packet(packet):
    packet_type_flags, seq_num, name_length = struct.unpack("!BBB", packet[:3])

    name_start = 3
    name_end = name_start + name_length
    name = packet[name_start:name_end].decode("utf-8")

    origin_length = packet[name_end]
    origin_start = name_end + 1
    origin_end = origin_start + origin_length
    origin_node = packet[origin_start:origin_end].decode("utf-8")

    data_flag = bool(packet[origin_end])  # 1 byte after origin

    # ---- Parse visited domains ----
    vd_index = origin_end + 1
    visited_count = packet[vd_index]
    vd_index += 1

    visited_domains = []
    for _ in range(visited_count):
        dom_len = packet[vd_index]
        vd_index += 1
        dom = packet[vd_index:vd_index + dom_len].decode("utf-8")
        vd_index += dom_len
        visited_domains.append(dom)

    # Extract fields
    packet_type = (packet_type_flags >> 4) & 0xF
    flags = packet_type_flags & 0xF

    name_segments = name.strip('/').split('/') if isinstance(name, str) else []
    if name_segments and '.' in name_segments[-1]:
        file_name = name_segments[-1]
        node_name = '/' + '/'.join(name_segments[:-1]) if len(name_segments) > 1 else '/' + name_segments[0]
    else:
        file_name = None
        node_name = '/' + '/'.join(name_segments) if name_segments else name

    return {
        "PacketType": packet_type,
        "Flags": flags,
        "SequenceNumber": seq_num,
        "NameLength": name_length,
        "Name": name,
        "OriginNode": origin_node,
        "DataFlag": data_flag,
        "NodeName": node_name,
        "FileName": file_name,
        "VisitedDomains": visited_domains,
    }

def parse_hello_packet(packet):
    packet_type_flags, name_length = struct.unpack("!BB", packet[:2])
    name = packet[2:2 + name_length].decode("utf-8")
    return {
        "PacketType": (packet_type_flags >> 4) & 0xF,
        "Flags": packet_type_flags & 0xF,
        "NameLength": name_length,
        "Name": name
    }

def create_hello_packet(name):
    packet_type = HELLO
    flags = 0x0 # This is only for NS
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes)

    header = struct.pack("!BB", packet_type_flags, name_length)
    packet = header + name_bytes
    return packet

def parse_update_packet(packet):
    """
    Parses a neighbor UPDATE packet created by create_neighbor_update_packet().
    Returns a dict:
      {
        "PacketType": <int>,
        "Flags": <int>,
        "NodeNames": ["/DLSU/Router1", "/ADMU/Router1"],
        "NeighborNames": ["/DLSU/Andrew", "/DLSU/Gokongwei"]
      }
    """
    try:
        packet_type_flags, node_name_length, info_length = struct.unpack("!BBH", packet[:4])

        # Decode node name
        node_start = 4
        node_end = node_start + node_name_length
        node_name = packet[node_start:node_end].decode("utf-8")

        # Decode update info
        info_start = node_end
        info_end = info_start + info_length
        update_info = packet[info_start:info_end].decode("utf-8")

        # Expected format: "<node_name> | <neighbor_name>"
        if "|" in update_info:
            node_part, neighbor_part = update_info.split("|", 1)
        else:
            # fallback (old format without delimiter)
            parts = update_info.split(maxsplit=1)
            node_part = parts[0] if parts else ""
            neighbor_part = parts[1] if len(parts) > 1 else ""

        # Split by spaces for multi-name support
        node_names = [n.strip() for n in node_part.strip().split() if n.strip()]
        neighbor_names = [n.strip() for n in neighbor_part.strip().split() if n.strip()]

        return {
            "PacketType": (packet_type_flags >> 4) & 0xF,
            "Flags": packet_type_flags & 0xF,
            "Name": node_names,
            "NeighborNames": neighbor_names
        }

    except Exception as e:
        print(f"[NS parse_neighbor_update_packet] Error parsing packet: {e}")
        return None
    
def create_route_ack_packet(seq_num, name, flags=0x0, source_name="", hop_count=0, visited_domains=[]):
    """
    Create a ROUTE_ACK packet.

    Format:
      | packet_type_flags (1B) | seq_num (1B) | info_size (1B) | name_length (1B) |
      | name (variable) | source_name_length (1B) | source_name (variable) | hop_count (1B) |

    - packet_type_flags = (ROUTE_ACK << 4) | (flags & 0xF)
    - hop_count is 1 byte (0–255)
    """
    packet_type = ROUTE_ACK
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    seq_num = seq_num & 0xFF

    name_bytes = name.encode("utf-8")
    name_length = len(name_bytes) & 0xFF

    source_name_bytes = source_name.encode("utf-8")
    source_name_length = len(source_name_bytes) & 0xFF

    # Build visited domains bytes: count (1B) followed by repeated (len(1B)+bytes)
    vd_bytes = b""
    for dom in visited_domains:
        dom_b = dom.encode("utf-8")
        vd_bytes += struct.pack("!B", len(dom_b) & 0xFF) + dom_b
    vd_count = len(visited_domains) & 0xFF

    # info_size counts: source_name_length + hop_count(1) + vd_count(1) + sum(each dom_len+1)
    info_size = source_name_length + 1 + 1 + sum((len(d.encode("utf-8")) & 0xFF) + 1 for d in visited_domains)

    header = struct.pack("!BBBB", packet_type_flags, seq_num, info_size, name_length)
    packet = (
        header
        + name_bytes
        + struct.pack("!B", source_name_length)
        + source_name_bytes
        + struct.pack("!B", hop_count)
        + struct.pack("!B", vd_count)
        + vd_bytes
    )
    return packet

def parse_route_ack_packet(packet):
    """Parse ROUTE_ACK packets sent by nodes confirming a border path."""
    if len(packet) < 4:
        return None

    packet_type_flags, seq_num, info_size, name_length = struct.unpack("!BBBB", packet[:4])
    name_start = 4
    name_end = name_start + name_length
    if len(packet) < name_end:
        return None
    name = packet[name_start:name_end].decode("utf-8")

    idx = name_end
    # source_name_length
    if len(packet) < idx + 1:
        return None
    source_name_length = packet[idx]
    idx += 1
    if len(packet) < idx + source_name_length:
        return None
    source_name = packet[idx:idx + source_name_length].decode("utf-8")
    idx += source_name_length

    # hop_count
    if len(packet) < idx + 1:
        return None
    hop_count = packet[idx]
    idx += 1

    # visited domains
    visited_domains = []
    if len(packet) >= idx + 1:
        vd_count = packet[idx]
        idx += 1
        for _ in range(vd_count):
            if len(packet) < idx + 1:
                break
            dom_len = packet[idx]
            idx += 1
            if len(packet) < idx + dom_len:
                break
            dom = packet[idx:idx + dom_len].decode("utf-8")
            idx += dom_len
            visited_domains.append(dom)

    return {
        "PacketType": (packet_type_flags >> 4) & 0xF,
        "Flags": packet_type_flags & 0xF,
        "SequenceNumber": seq_num,
        "NameLength": name_length,
        "Name": name,
        "SourceName": source_name,
        "HopCount": hop_count,
        "VisitedDomains": visited_domains,
    }

def _top_domain(name):
            if not name:
                return None
            s = name.lstrip("/")
            parts = s.split("/")
            return parts[0] if parts else None

def append_visited_domain(parsed, new_domain):
    """
    Takes a parsed interest packet and appends a new domain
    to its VisitedDomains list if not already present.
    
    Returns the updated list.
    """
    # Extract current visited domains
    visited = list(parsed.get("VisitedDomains", []))

    # Only append if this domain has not been visited yet
    if new_domain not in visited:
        visited.append(new_domain)

    return visited

    # except Exception as e:
    #     print(f"[NS parse_neighbor_update_packet] Error parsing packet: {e}")
    #     return None

def create_redirect_ns_packet(seq_num, dest_name, alt_ns_name, flags=0x0):
    """
    Create a REDIRECT_NS packet to tell an edge node to query a different NameServer.
    
    Format:
      | packet_type_flags (1B) | seq_num (1B) | alt_ns_length (1B) | dest_name_length (1B) |
      | alt_ns_name (variable) | dest_name (variable) |
    """
    packet_type = REDIRECT_NS
    packet_type_flags = (packet_type << 4) | (flags & 0xF)

    seq_num = seq_num & 0xFF
    
    alt_ns_bytes = alt_ns_name.encode("utf-8")
    alt_ns_length = len(alt_ns_bytes) & 0xFF
    
    dest_name_bytes = dest_name.encode("utf-8")
    dest_name_length = len(dest_name_bytes) & 0xFF

    header = struct.pack("!BBBB", packet_type_flags, seq_num, alt_ns_length, dest_name_length)
    packet = header + alt_ns_bytes + dest_name_bytes
    return packet

def parse_redirect_ns_packet(packet):
    """Parse REDIRECT_NS packet sent by NameServer to edge node."""
    if len(packet) < 4:
        raise ValueError("Invalid REDIRECT_NS packet: too short")
    
    packet_type_flags, seq_num, alt_ns_length, dest_name_length = struct.unpack("!BBBB", packet[:4])
    
    alt_ns_start = 4
    alt_ns_end = alt_ns_start + alt_ns_length
    if len(packet) < alt_ns_end:
        raise ValueError("Invalid REDIRECT_NS packet: incomplete alt_ns_name")
    
    alt_ns_name = packet[alt_ns_start:alt_ns_end].decode("utf-8")
    
    dest_name_start = alt_ns_end
    dest_name_end = dest_name_start + dest_name_length
    if len(packet) < dest_name_end:
        raise ValueError("Invalid REDIRECT_NS packet: incomplete dest_name")
    
    dest_name = packet[dest_name_start:dest_name_end].decode("utf-8")
    
    packet_type = (packet_type_flags >> 4) & 0xF
    flags = packet_type_flags & 0xF
    
    return {
        "PacketType": packet_type,
        "Flags": flags,
        "SequenceNumber": seq_num,
        "AlternateNS": alt_ns_name,
        "DestinationName": dest_name,
    }

class NameServer:
    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        if not hasattr(self, 'logs'):
            self.logs = []
        self.logs.append({"timestamp": timestamp, "message": message})

    # --- Statistics helpers (lazy lookup to avoid circular imports) ---
    def _get_global_stats(self):
        try:
            import sys
            # Try common module names first
            for mod_name in ('com', '__main__'):
                mod = sys.modules.get(mod_name)
                if mod and hasattr(mod, 'global_stats'):
                    return getattr(mod, 'global_stats')
            # Fallback: scan loaded modules for any with a global_stats attr
            for m in list(sys.modules.values()):
                try:
                    if hasattr(m, 'global_stats'):
                        return getattr(m, 'global_stats')
                except Exception:
                    continue
        except Exception:
            pass
        return None
    
    def _record_hello(self):
        try:
            gs = self._get_global_stats()
            if not gs:
                return
            gs.record_hello()
        except Exception as e:
            print(f"[STATS ERROR] Failed to record packet: {e}")

    def _record_packet_stat(self, packet):
        try:
            gs = self._get_global_stats()
            if not gs:
                return
            packet_type = (packet[0] >> 4) & 0xF if packet else None
            size_bits = len(packet) * 8 if packet else 0
            gs.record_packet(packet_type, size_bits)
        except Exception as e:
            print(f"[STATS ERROR] Failed to record packet: {e}")

    def _record_hop_stat(self, packet_type):
        """Record a hop for non-HELLO/UPDATE packets"""
        try:
            # Only record hops for packets that are not HELLO or UPDATE (those are initialization)
            if packet_type == INTEREST:
                gs = self._get_global_stats()
                if gs:
                    gs.record_hop()
        except Exception as e:
            print(f"[STATS ERROR] Failed to record hop: {e}")

    def _record_interest_query_stat(self):
        try:
            gs = self._get_global_stats()
            if not gs:
                return
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            self.log(f"[STATS] Recorded INTEREST QUERY timestamp={ts}")
            gs.record_interest_query()
        except Exception as e:
            print(f"[STATS ERROR] Failed to record interest query: {e}")
    
    def _record_interest_stat(self, seq_num, name, timestamp=None):
        try:
            gs = self._get_global_stats()
            if not gs:
                return
            ts = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            self.log(f"[STATS] Recorded INTEREST seq={seq_num} name={name} origin={self.name} timestamp={ts}")
            gs.record_interest(self.name, name, seq_num, ts)
        except Exception as e:
            print(f"[STATS ERROR] Failed to record interest: {e}")

    def _record_update(self):
        """Record an UPDATE packet reception (count at NameServer side)."""
        try:
            gs = self._get_global_stats()
            if not gs:
                return
            gs.record_update()
        except Exception as e:
            print(f"[STATS ERROR] Failed to record update: {e}")

    def __init__(self, ns_name="/DLSU/NameServer1", host="127.0.0.1", port=6000, topo_file="topology.txt"):
        self.ns_name = ns_name
        self.host = host
        self.port = port
        self.topo_file = topo_file

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))

        self.port_to_name = {}
        self.name_to_port = {}
        self.neighbor_table = {}

        self.graph = defaultdict(set)
        #self._load_topology_file(self.topo_file)

        self.running = True
        self.listener_thread = threading.Thread(target=self._listen, daemon=True)
        self.listener_thread.start()

        #self.update_thread = threading.Thread(target=self._periodic_update, daemon=True)
        #self.update_thread.start()

        #print(f"[NS {self.ns_name}] up at {self.host}:{self.port}")
        #print(f"[NS {self.ns_name}] loaded topology with {len(self.graph)} nodes from {self.topo_file}")

        self.pending_interests = {}
        self.pending_ttl = 5.0  # seconds to suppress duplicate ENCAP forwarding

        # Simple PIT at the NameServer: map base interest name -> list of requester UDP addrs
        self.pit = defaultdict(list)

    def _periodic_update(self):
        while self.running:
            domain = self.get_domains_from_name()
            for node in self.graph:
                # Handle nodes with multiple names (space-separated)
                node_names = node.split()
                #print(f"Node Names [{self.ns_name}]: {node_names}")
                for alias in node_names:
                    alias_domain = alias.lstrip('/').split('/')[0] if alias else ''
                    if alias_domain == domain and node != self.ns_name:
                        # Compute next hop for node to reach name server
                        path = self._shortest_path(node, self.ns_name)
                        if path and len(path) > 1:
                            next_hop = path[1]
                        else:
                            next_hop = self.ns_name
                        pkt = create_route_data_packet(seq_num=0, name=self.ns_name, routing_info=path)
                        # Send to node (if port known)
                        if node in self.name_to_port:
                            target_port = self.name_to_port[node]
                            self.sock.sendto(pkt, (self.host, target_port))
                            print(f"[{self.ns_name}] Sent ROUTE packet to {node} (alias: {alias}) at port {target_port} with next hop {next_hop}")
                            self.log(f" Sent ROUTE packet to {node} (alias: {alias}) at port {target_port} with next hop {next_hop}")
            time.sleep(10)

    def _find_pending(self, name, seq=None, origin=None):
        """
        Find a pending interest by name (ENCAP or base).
        Returns (key, entry) if found, else (None, None).
        If seq is provided, also match sequence number.
        If origin is provided, only return a pending entry that matches the same origin.
        This prevents suppressing interests that have the same name but come from different origin nodes.
        """
        # direct lookup
        entry = self.pending_interests.get(name)
        if entry and (seq is None or entry.get("seq_num") == seq):
            if origin is None or entry.get("origin") == origin:
                return name, entry

        # fallback: match base name (strip ENCAP)
        stripped = self._strip_encap(name)
        for k, v in self.pending_interests.items():
            if self._strip_encap(k) == stripped:
                if seq is None or v.get("seq_num") == seq:
                    if origin is None or v.get("origin") == origin:
                        return k, v

        return None, None

    def _remove_pending(self, key):
        """Safely remove a pending interest entry."""
        if key in self.pending_interests:
            del self.pending_interests[key]

    def get_domains_from_name(self):
        for part in self.ns_name.split(" "):
              part = part.lstrip('/')
              top_domain = part.split('/')[0] if part else ''
        return top_domain

    def load_neighbors_from_file(self, filename):
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or ':' not in line:
                        continue
                    node_name, ports_str = line.split(':', 1)
                    node_name = node_name.strip()
                    if node_name == self.ns_name:
                        ports = [p.strip() for p in ports_str.split(',') if p.strip()]
                        for port in ports:
                            try:
                                pkt = create_hello_packet(self.ns_name)
                                try:
                                    self._record_hello()
                                except Exception:
                                    pass
                                self.sock.sendto(pkt, (self.host, int(port)))
                                #print(f"[{self.ns_name}] Sent HELLO packet to {self.host}:{port}")
                            except Exception as e:
                                print(f"[{self.ns_name}] Error sending HELLO packet to {self.host}:{port}: {e}")
                                self.log(f"[{self.ns_name}] Error sending HELLO packet to {self.host}:{port}: {e}")
                        #print(f"[{self.ns_name}] Loaded neighbors from {filename}: {ports}")
        except Exception as e:
            print(f"[{self.ns_name}] Error loading neighbors from {filename}: {e}")           
            self.log(f"[{self.ns_name}] Error loading neighbors from {filename}: {e}")           

    def _load_topology_file(self, path):
        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or ":" not in line:
                        continue
                    node, nbrs = line.split(":", 1)
                    node = node.strip()
                    nbr_list = [n.strip() for n in nbrs.split(",") if n.strip()]
                    for n in nbr_list:
                        self.graph[node].add(n)
                        self.graph[n].add(node)
        except FileNotFoundError:
            print(f"[{self.ns_name}] WARNING: topology file '{path}' not found — start with an empty graph.")
        except Exception as e:
            print(f"[{self.ns_name}] ERROR loading topology: {e}")

    def _listen(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                if not data:
                    continue
                pkt_type = (data[0] >> 4) & 0xF
                
                # Record packet statistics — but skip ROUTE_ACK here;
                # NameServer records ROUTE_ACK when it creates them (avoid double-counting).
                try:
                    if pkt_type != ROUTE_ACK:
                        self._record_packet_stat(data)
                except Exception:
                    pass
                
                # Record hop for non-HELLO/UPDATE packets
                if pkt_type not in [HELLO, UPDATE]:
                    try:
                        self._record_hop_stat(pkt_type)
                    except Exception:
                        pass
                
                if pkt_type == HELLO:
                    self._handle_hello(data, addr)
                elif pkt_type == UPDATE:
                    self._handle_update(data, addr)
                elif pkt_type == INTEREST:
                    self._handle_interest(data, addr)
                elif pkt_type == ROUTE_ACK:
                    self._handle_route_ack(data, addr)
                else:
                    pass
            except Exception as e:
                print(f"[{self.ns_name}] Listener error: {e}")

    def _handle_hello(self, packet, addr):
        parsed = parse_hello_packet(packet)
        node_name = parsed["Name"]
        flags = parsed["Flags"]

        self.port_to_name[addr[1]] = node_name
        self.name_to_port[node_name] = addr[1]

        if flags == ACK_FLAG:
            # Add to neighbor table
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f") #time received
            self.neighbor_table[node_name] = timestamp
            #print(f"[{self.ns_name}] HELLO from {node_name} at {addr} (added as neighbor)")

    def _handle_update(self, packet, addr):
        """
        Handles neighbor UPDATE packets and updates the NS topology.
        Supports multi-name nodes and domain filtering.
        """
        try:
            parsed = parse_update_packet(packet)
            if not parsed:
                print(f"[{self.ns_name}] Failed to parse UPDATE from {addr}")
                self.log(f" Failed to parse UPDATE from {addr}")
                return

            # Only process neighbor update packets (flag 0x2)
            if parsed["Flags"] != 0x2:
                return

            src_nodes = parsed.get("Name", [])
            neighbor_nodes = parsed.get("NeighborNames", [])

            if not src_nodes or not neighbor_nodes:
                print(f"[{self.ns_name}] Ignored UPDATE missing node or neighbor data from {addr}")
                return

            # Normalize node and neighbor lists
            src_nodes = [n.strip() for n in src_nodes if n.strip()]
            neighbor_nodes = [n.strip() for n in neighbor_nodes if n.strip()]

            # --- Check if update belongs to this NS's domain ---
            ns_domain = self.ns_name.strip("/").split("/")[0]  # e.g., "DLSU" from "/DLSU/NameServer1"

            # Determine if at least one of the node's names belongs to this NS's domain
            in_domain = any(
                n.strip("/").split("/")[0] == ns_domain for n in src_nodes
            )

            if not in_domain:
                print(f"[{self.ns_name}] Ignored UPDATE not in domain ({ns_domain}): {' '.join(src_nodes)}")
                return
            
            combined_name = " ".join(src_nodes)

            # Register node-port mapping
            self.port_to_name[addr[1]] = combined_name
            self.name_to_port[combined_name] = addr[1]

            # Ensure node exists in the graph
            if combined_name not in self.graph or not isinstance(self.graph[combined_name], set):
                self.graph[combined_name] = set()

            # Add bidirectional edges
            combined_neighbor = " ".join(neighbor_nodes)

            # Add connection both ways. Only count the UPDATE if it actually
            # changes the topology (prevents duplicate/forwarded UPDATEs from
            # inflating the statistics).
            prev_a = combined_neighbor in self.graph.get(combined_name, set())
            prev_b = combined_name in self.graph.get(combined_neighbor, set())

            self.graph[combined_name].add(combined_neighbor)
            if combined_neighbor not in self.graph:
                self.graph[combined_neighbor] = set()
            self.graph[combined_neighbor].add(combined_name)

            made_change = not (prev_a and prev_b)

            print(f"[{self.ns_name}] UPDATE accepted: {combined_name} ↔ {combined_neighbor}")

            # Count this UPDATE only if it actually modified the graph
            if made_change:
                try:
                    self._record_update()
                except Exception:
                    pass

            # --- Save topology to file ---
            self._write_topology_to_file()

        except Exception as e:
            print(f"[{self.ns_name}] Error handling UPDATE: {e}")

    def _write_topology_to_file(self):
        """
        Writes the current topology graph to '<ns_name>_topology.txt'.
        - Each node (including aliases) appears on its own line, even if neighbor sets are identical.
        - Multi-name (border router) nodes are grouped as one name with spaces (not commas).
        - When border routers appear as neighbors, their full grouped names are shown.
        """
        try:
            safe_name = self.ns_name.replace("/", "_").strip("_")
            filename = f"{safe_name}_topology.txt"
            dirpath = os.path.dirname(filename)
            if dirpath and not os.path.exists(dirpath):
                os.makedirs(dirpath, exist_ok=True)

            # Determine the NS's own domain, e.g., "DLSU" from "/DLSU/NameServer1"
            ns_domain = self.ns_name.strip("/").split("/")[0] if self.ns_name else ""

            # Build alias mapping: each alias points to its full multi-name (border router) group
            alias_map = {}
            for port, aliases_str in getattr(self, "port_to_name", {}).items():
                if isinstance(aliases_str, str):
                    aliases = [a.strip() for a in aliases_str.split() if a.strip()]
                elif isinstance(aliases_str, (list, tuple)):
                    aliases = [a.strip() for a in aliases_str if a.strip()]
                else:
                    continue
                if not aliases:
                    continue
                combined = " ".join(sorted(set(aliases)))
                for a in aliases:
                    alias_map[a] = combined

            def top_level(name):
                segs = name.strip("/").split("/")
                return segs[0] if segs else ""

            lines = []
            written = set()

            for node in sorted(self.graph.keys()):
                if not isinstance(node, str) or not node.startswith("/"):
                    continue
                if node in written:
                    continue

                # Get grouped alias name if exists
                node_group = alias_map.get(node, node)

                # Mark all names in this group as written
                for part in node_group.split():
                    written.add(part)

                # Skip nodes outside this NS's domain
                if not any(top_level(a) == ns_domain for a in node_group.split()):
                    continue

                # Gather all neighbors for this node
                neighbors = self.graph.get(node, set())

                # Replace any alias neighbors with their grouped form
                expanded_neighbors = set()
                for n in neighbors:
                    if not isinstance(n, str) or not n.startswith("/"):
                        continue
                    expanded_neighbors.add(alias_map.get(n, n))

                # Sort for consistent output
                sorted_neighbors = sorted(expanded_neighbors)

                # Build output line
                neighbor_str = ", ".join(sorted_neighbors)
                lines.append(f"{node_group}: {neighbor_str}\n")

            # Write topology file (overwrite existing)
            with open(filename, "w", encoding="utf-8") as f:
                f.writelines(lines)

            print(f"[{self.ns_name}] Topology updated and saved to {filename}")

        except Exception as e:
            print(f"[{self.ns_name}] Error writing topology file: {e}")

    def strip_last_level(self, path):
        """Utility to remove the last level from a hierarchical name."""
        if not path:
            return path
        segments = path.strip('/').split('/')
        if len(segments) > 1:
            return '/' + '/'.join(segments[:-1])
        return path
    
    def _strip_encap(self, name):
        """If name is an ENCAP:<border>|<original>, return the original part; otherwise return name."""
        try:
            if isinstance(name, str) and name.startswith("ENCAP:"):
                rest = name[6:]
                if "|" in rest:
                    return rest.split("|", 1)[1].strip()
        except Exception:
            pass
        return name

    def _handle_interest(self, packet, addr):
        """
        Treat interest as a route request.
        - Source is determined from addr (using HELLO/UPDATE).
        - Name is the destination name.
        - Computes shortest path on graph from topology.txt.
        - Replies with ROUTING_DATA or forwards INTEREST to border router if dest is outside domain.
        """
        # Parse INTEREST safely; if parsing fails, send FORMAT_ERROR back to sender
        try:
            parsed = parse_interest_packet(packet)
        except Exception as e:
            print(f"[{self.ns_name}] Failed to parse INTEREST from {addr}: {e}")
            self.log(f" Failed to parse INTEREST from {addr}: {e}")
            # attempt to extract seq_num if present
            seq_num = packet[1] if len(packet) > 1 else 0
            origin_name = self.port_to_name.get(addr[1], "UNKNOWN")
            # fix later
            err_pkt = create_error_packet(seq_num, origin_name, FORMAT_ERROR, "UNKNOWN")
            try:
                self.sock.sendto(err_pkt, addr)
                print(f"[{self.ns_name}] Sent FORMAT_ERROR to {addr} (origin={origin_name})")
                self.log(f" Sent FORMAT_ERROR to {addr} (origin={origin_name})")
            except Exception as se:
                print(f"[{self.ns_name}] Failed to send FORMAT_ERROR to {addr}: {se}")
                self.log(f" Failed to send FORMAT_ERROR to {addr}: {se}")
            return

        dest_name = parsed["Name"]
        seq_num = parsed["SequenceNumber"]

        src_name = parsed["OriginNode"]
        if not src_name:
            # don't know who this is
            print(f"[{self.ns_name}] INTEREST from unknown {addr}. (No prior HELLO/UPDATE.)")
            self.log(f" INTEREST from unknown {addr}. (No prior HELLO/UPDATE.)")
            src_name = "UNKNOWN"

        # Check if this is a real interest (data_flag=True) or a query (data_flag=False)
        is_real_interest = parsed.get("DataFlag", False)
        kind = "REAL_INTEREST" if is_real_interest else "QUERY"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        print(f"[{self.ns_name}] Received INTEREST ({kind}) from port {addr[1]} at {timestamp} origin={src_name}")
        self.log(f"[{self.ns_name}] Received INTEREST ({kind}) from port {addr[1]} at {timestamp}")

        if kind == "QUERY":
            self._record_interest_query_stat()

        enc_layers = []
        enc_border = None
        enc_name = None

        raw_name = parsed.get("Name", "")

        if isinstance(raw_name, str) and raw_name.startswith("ENCAP:"):
            try:
                # remove leading "ENCAP:" and split to layers
                parts = [p.strip() for p in raw_name[6:].split("|")]

                if len(parts) >= 2:
                    enc_layers = parts[:-1]          # all except last
                    enc_name = parts[-1]             # last = destination
                    if len(parts) >= 2:
                        enc_border = parts[-2]       # second to last = current border hop
            except Exception:
                enc_layers = []
                enc_border = None
                enc_name = None

        # If ENCAP exists, override dest_name
        if enc_name:
            dest_name = enc_name

        # Record a PIT entry at the NameServer for this interest (so we can reply later)
        # Store by base (stripped of ENCAP) name
        base_name = self._strip_encap(parsed.get("Name"))
        # avoid duplicate identical addrs
        if addr not in self.pit[base_name]:
            self.pit[base_name].append(addr)

        print(f"[{self.ns_name}] ROUTE REQ: {src_name} -> {dest_name}")
        self.log(f" ROUTE REQ: {src_name} -> {dest_name}")

        original_name = dest_name
        # destination for routing calculation:
        # - If the requested name exactly matches a node in the topology graph,
        #   treat it as a node-to-node query (do not strip last level).
        # - Otherwise, assume the request includes a file and strip the last level
        #   to derive the node that contains the object.
        if dest_name in self.graph:
            dest_node = dest_name
        else:
            dest_node = self.strip_last_level(dest_name)

        my_top = _top_domain(self.ns_name)
        target_top = _top_domain(dest_node)

        # Check if ANY domain part of dest_node (supporting multi-name nodes) matches local domain
        # For example: "/DLSU/Router1 /ADMU/Router1" should check both DLSU and ADMU
        target_domains = []
        for part in dest_node.split():
            top = _top_domain(part)
            if top:
                target_domains.append(top)
        
        # If ANY target domain is local, treat as local request (do not ENCAP forward)
        is_local_domain = any(d == my_top for d in target_domains) if target_domains else False

        # If the request is for a name outside this NS domain, attempt to forward to a border router
        if not is_local_domain and target_top and my_top and target_top != my_top:
            # find candidate border routers (nodes whose any alias has the target top domain)
            border_candidates = []
            for node in self.graph.keys():
                # node may contain space-separated aliases
                for alias in node.split():
                    if _top_domain(alias) == target_top:
                        border_candidates.append(node)
                        break

            def _find_nearest_border_router():
                nearest = None
                shortest = None
                for node in self.graph.keys():
                    if " " in node:  # border router = multiple aliases
                        path = self._shortest_path(self.ns_name, node)
                        if path and (shortest is None or len(path) < shortest):
                            shortest = len(path)
                            nearest = node
                return nearest

            # Try candidates, find a path and a reachable port along that path (including aliases)
            def _find_port_for_path(path_nodes):
                # Check each hop in the path (after source) for any known port
                # prefer hop nearest to source (path_nodes[1], path_nodes[2], ...)
                for hop in path_nodes[1:]:
                    # try exact mapping for hop (may be a multi-alias string)
                    if hop in self.name_to_port:
                        return self.name_to_port[hop], hop
                    # try aliases
                    for alias in hop.split():
                        if alias in self.name_to_port:
                            return self.name_to_port[alias], alias
                return None, None

            if not border_candidates:
                # As fallback, try to find the nearest border router in general
                nearest_border = _find_nearest_border_router()
                if nearest_border:
                    print(f"[{self.ns_name}] No border routers for domain {target_top}; using nearest border router {nearest_border}")
                    self.log(f" No border routers for domain {target_top}; using nearest border router {nearest_border}")
                    border_candidates.append(nearest_border)

            # Check if origin node is the same as the border router needed for destination
            # If so, redirect the origin to query its alternate NameServer instead
            for candidate in border_candidates:
                # Check if src_name matches the candidate (considering multi-name nodes)
                src_parts = src_name.split()
                candidate_parts = candidate.split()
                
                # If origin and border candidate share the same node identity
                if src_name == candidate or any(p in candidate_parts for p in src_parts):
                    # Find the alternate NameServer for this edge node
                    # An edge node has aliases in multiple domains, so find a domain OTHER than the current NS domain
                    alt_ns = None
                    
                    # Get domains from origin node
                    src_domains = set()
                    for part in src_parts:
                        top = _top_domain(part)
                        if top:
                            src_domains.add(top)
                    
                    # Find a domain that the origin is in, but is NOT the current NS's domain
                    for domain in src_domains:
                        if domain != my_top:
                            # Construct the alternate NS name for this domain
                            alt_ns = f"/{domain}/NameServer1"
                            print(f"[{self.ns_name}] [DEBUG] Found alternate domain: {domain}, constructing alt_ns: {alt_ns}")
                            self.log(f" [DEBUG] Found alternate domain: {domain}, constructing alt_ns: {alt_ns}")
                            break
                    
                    if alt_ns:
                        # Send REDIRECT_NS packet to origin, telling it to query the alternate NS
                        print(f"[{self.ns_name}] REDIRECT: Origin {src_name} is the edge router for domain {target_top}")
                        print(f"[{self.ns_name}] Sending REDIRECT_NS to {src_name} to query {alt_ns} for {dest_name}")
                        self.log(f" REDIRECT: Origin {src_name} is the edge router for domain {target_top}")
                        self.log(f" Sending REDIRECT_NS to {src_name} to query {alt_ns} for {dest_name}")
                        
                        redirect_pkt = create_redirect_ns_packet(seq_num=seq_num, dest_name=dest_name, alt_ns_name=alt_ns)
                        try:
                            self.sock.sendto(redirect_pkt, addr)
                            self._record_packet_stat(redirect_pkt)
                            return
                        except Exception as e:
                            print(f"[{self.ns_name}] Failed to send REDIRECT_NS to {addr}: {e}")
                            self.log(f" Failed to send REDIRECT_NS to {addr}: {e}")
                            return
                    else:
                        print(f"[{self.ns_name}] [DEBUG] No alternate domain found, continuing with normal forwarding")
                        self.log(f" [DEBUG] No alternate domain found, continuing with normal forwarding")

            for candidate in border_candidates:
                # 1) Try path from THIS NS to the candidate (so NS can send to a neighbor it knows)
                path_from_ns = self._shortest_path(self.ns_name, candidate)
                if path_from_ns and len(path_from_ns) > 1:
                    port, resolved_name = _find_port_for_path(path_from_ns)
                    if port:
                        try:
                            # Encapsulate the original destination with the candidate (border) alias.
                            # Format: "ENCAP:<candidate>|<original_name>"
                            # check pending duplicates
                            existing_key, _ = self._find_pending(raw_name, seq=seq_num, origin=src_name)
                            if existing_key:
                                print(f"[{self.ns_name}] Suppressing duplicate ENCAP for {original_name} from {src_name} (seq={seq_num}) — pending already exists")
                                #return
                            # Build new ENCAP chain:
                            # ENCAP:<old_layer1>|<old_layer2>|...|<new_candidate>|<dest_name>
                            else:
                                new_enc_layers = list(enc_layers)      # copy existing stack
                                new_enc_layers.append(candidate)       # append new border
                                final_enc = "ENCAP:" + "|".join(new_enc_layers + [original_name])

                                new_visited_list = append_visited_domain(parsed, my_top)
                                print(f"[{self.ns_name}] New Visited Domains List: {new_visited_list}")
                                enc_pkt = create_interest_packet(seq_num=seq_num, name=final_enc, flags=0x0, origin_node=src_name, data_flag=False, visited_domains=new_visited_list)
                                # Cache pending ENCAP interest so we can reply when ROUTE_ACK arrives
                                # key = (original_name, src_name, seq_num)
                                # self.pending_interests[key] = {"addr": addr, "origin": src_name, "border_router": candidate, "ts": time.time()}
                                # Key is now the full ENCAP name
                                self.pending_interests[parsed["Name"]] = {
                                    "addr": addr,
                                    "origin": src_name,
                                    "border_router": candidate,
                                    "seq_num": seq_num,    # optional, can help with duplicates
                                    "ts": time.time()
                                }
                                # Print the ENCAP-forwarded message and the pending table together
                                with _PRINT_LOCK:
                                    print(f"[{self.ns_name}] ENCAP-FORWARDED INTEREST for {final_enc} -> candidate {candidate} via resolved {resolved_name} (port {port}) [path_from_ns]\n[{self.ns_name}] Current Pending Interests: {self.pending_interests}")
                                    self.log(f" ENCAP-FORWARDED INTEREST for {final_enc} -> candidate {candidate} via resolved {resolved_name} (port {port}) [path_from_ns]\n[{self.ns_name}] Current Pending Interests: {self.pending_interests}")
                                #print(f"[{self.ns_name}] New Visited Domains List: {new_visited_list}")
                                self.sock.sendto(enc_pkt, (self.host, int(port)))
                                return
                        except Exception as e:
                            print(f"[{self.ns_name}] Error forwarding INTEREST to {resolved_name}:{port} - {e}")
                            self.log(f" Error forwarding INTEREST to {resolved_name}:{port} - {e}")

                # 2) Fallback: try path from the original source to the candidate and search ANY hop the NS knows
                path_to_border = self._shortest_path(src_name, candidate)
                if path_to_border:
                    # search entire path (not only hops after src) for any known node/alias
                    port, resolved_name = None, None
                    # Avoid selecting the source (src_name) itself — start from the next hop
                    for hop in path_to_border[1:]:
                        if hop in self.name_to_port:
                            port, resolved_name = self.name_to_port[hop], hop
                            break
                        for alias in hop.split():
                            if alias in self.name_to_port:
                                port, resolved_name = self.name_to_port[alias], alias
                                break
                        if port:
                            break
                    if port:
                        try:
                            existing_key, _ = self._find_pending(raw_name, seq=seq_num, origin=src_name)
                            if existing_key:
                                print(f"[{self.ns_name}] Suppressing duplicate ENCAP for {original_name} from {src_name} (seq={seq_num}) — pending already exists")
                                #return

                            # Build new ENCAP chain:
                            # ENCAP:<old_layer1>|<old_layer2>|...|<new_candidate>|<dest_name>
                            else:
                                new_enc_layers = list(enc_layers)      # copy existing stack
                                new_enc_layers.append(candidate)       # append new border
                                final_enc = "ENCAP:" + "|".join(new_enc_layers + [original_name])
                                new_visited_list = append_visited_domain(parsed, my_top)
                                enc_pkt = create_interest_packet(seq_num=seq_num, name=final_enc, flags=0x0, origin_node=src_name, data_flag=False, visited_domains=new_visited_list)
                                # key = (original_name, src_name, seq_num)
                                # self.pending_interests[key] = {"addr": addr, "origin": src_name, "border_router": candidate, "ts": time.time()}
                                self.pending_interests[parsed["Name"]] = {
                                    "addr": addr,
                                    "origin": src_name,
                                    "border_router": candidate,
                                    "seq_num": seq_num,    # optional, can help with duplicates
                                    "ts": time.time()
                                }
                                with _PRINT_LOCK:
                                    print(f"[{self.ns_name}] ENCAP-FORWARDED INTEREST for {original_name} -> candidate {candidate} via resolved {resolved_name} (port {port}) [path_from_src]\n[{self.ns_name}] Current Pending Interests: {self.pending_interests}")
                                    self.log(f" ENCAP-FORWARDED INTEREST for {original_name} -> candidate {candidate} via resolved {resolved_name} (port {port}) [path_from_src]\n[{self.ns_name}] Current Pending Interests: {self.pending_interests}")
                                self.sock.sendto(enc_pkt, (self.host, int(port)))
                                return
                        except Exception as e:
                            print(f"[{self.ns_name}] Error forwarding INTEREST to {resolved_name}:{port} - {e}")
                            self.log(f" Error forwarding INTEREST to {resolved_name}:{port} - {e}")

                # 3) As fallback, check candidate aliases themselves (direct mapping)
                for alias in candidate.split():
                    if alias in self.name_to_port:
                        try:
                            existing_key, _ = self._find_pending(raw_name, seq=seq_num, origin=src_name)
                            if existing_key:
                                print(f"[{self.ns_name}] Suppressing duplicate ENCAP for {original_name} from {src_name} (seq={seq_num}) — pending already exists")
                                #return

                            # Build new ENCAP chain:
                            # ENCAP:<old_layer1>|<old_layer2>|...|<new_candidate>|<dest_name>
                            else:
                                new_enc_layers = list(enc_layers)      # copy existing stack
                                new_enc_layers.append(candidate)       # append new border
                                final_enc = "ENCAP:" + "|".join(new_enc_layers + [original_name])
                                new_visited_list = append_visited_domain(parsed, my_top)
                                enc_pkt = create_interest_packet(seq_num=seq_num, name=final_enc, flags=0x0, origin_node=src_name, data_flag=False, visited_domains=new_visited_list)
                                # Cache pending ENCAP interest so we can reply when ROUTE_ACK arrives
                                # CHANGED: Store border_router (candidate) in pending_interests for later use in ACK handling
                                # key = (original_name, src_name, seq_num)
                                # self.pending_interests[key] = {"addr": addr, "origin": src_name, "border_router": candidate, "ts": time.time()}
                                self.pending_interests[parsed["Name"]] = {
                                    "addr": addr,
                                    "origin": src_name,
                                    "border_router": candidate,
                                    "seq_num": seq_num,    # optional, can help with duplicates
                                    "ts": time.time()
                                }
                                with _PRINT_LOCK:
                                    print(f"[{self.ns_name}] ENCAP-FORWARDED INTEREST for {original_name} -> candidate alias {alias} (port {self.name_to_port[alias]}) [candidate_alias]\n[{self.ns_name}] Current Pending Interests: {self.pending_interests}")
                                    self.log(f" ENCAP-FORWARDED INTEREST for {original_name} -> candidate alias {alias} (port {self.name_to_port[alias]}) [candidate_alias]\n[{self.ns_name}] Current Pending Interests: {self.pending_interests}")
                                self.sock.sendto(enc_pkt, (self.host, int(self.name_to_port[alias])))
                                return
                        except Exception as e:
                            print(f"[{self.ns_name}] Error forwarding INTEREST to alias {alias} - {e}")
                            self.log(f" Error forwarding INTEREST to alias {alias} - {e}")

            # If we couldn't forward to any border router because there were no known ports on path/candidates
            print(f"[{self.ns_name}] Target domain {target_top} not local and no reachable border port found — continuing resolution attempt.")
            self.log(f" Target domain {target_top} not local and no reachable border port found — continuing resolution attempt.")

        # Normal handling: compute path to destination inside this domain
        else:
            path = self._shortest_path(src_name, dest_node)
            if not path:
                route_name = dest_node
                payload_obj = {"ok": False, "reason": "NameNotFound", "src": src_name, "dest": dest_node}
                payload = json.dumps(payload_obj)
                # resp = create_route_data_packet(seq_num=seq_num, name=original_name, payload=payload, flags=ACK_FLAG)
                # self.sock.sendto(resp, addr)
                # print(f"[{self.ns_name}] No path. Sent DATA(NameNotFound) to {addr}")
                # self.log(f" No path. Sent DATA(NameNotFound) to {addr}")

                err_pkt = create_error_packet(seq_num, original_name, NAME_ERROR, src_name)
                try:
                    self.sock.sendto(err_pkt, addr)
                    print(f"[{self.ns_name}] No path. Sent NAME_ERROR for {original_name} to {addr}")
                    self.log(f" No path. Sent NAME_ERROR for {original_name} to {addr}")
                except Exception as e:
                    print(f"[{self.ns_name}] Failed to send NAME_ERROR to {addr}: {e}")
                    self.log(f" Failed to send NAME_ERROR to {addr}: {e}")
                return

            next_hop = path[1] if len(path) >= 2 else dest_node
            origin_name = parsed["OriginNode"]
            route_payload = {
                "origin_name": origin_name,
                "path": path,
                "dest": original_name,
                "next_hop": next_hop,
                "hop_count": max(0, len(path) - 1) if isinstance(path, (list, tuple)) else 0

            }
            if parsed["Flags"] == 0x1:
                # Compute hop-count from the source border router to destination
                # Prefer the first element in the ENCAP chain as the 'source border'
                source_border = None
                if enc_layers:
                    source_border = enc_layers[0]
                else:
                    source_border = parsed.get("OriginNode") or src_name

                try:
                    border_to_dest_path = self._shortest_path(source_border, dest_node) if source_border else None
                    if border_to_dest_path:
                        hop_count_to_dest = max(0, len(border_to_dest_path) - 1)
                    else:
                        # fallback to path we computed earlier (src_name -> dest_node)
                        hop_count_to_dest = max(0, len(path) - 1) if path else 0
                except Exception:
                    hop_count_to_dest = max(0, len(path) - 1) if path else 0

                # set SourceName to the original source-border router (first ENCAP element) so upstream
                # NameServers can compute distances between border routers correctly.
                ack_src = source_border or enc_border or parsed.get("OriginNode") or src_name
                ack_pkt = create_route_ack_packet(
                            seq_num=seq_num,
                            name=parsed["Name"],
                            flags=0x0,
                            source_name=ack_src,
                            hop_count=hop_count_to_dest,
                            visited_domains=parsed.get("VisitedDomains", [])
                        )
                try:
                    # Record that the NameServer created/sent a ROUTE_ACK
                    self._record_packet_stat(ack_pkt)
                except Exception:
                    pass
                print(f"[{self.ns_name}] Sent ROUTE_ACK for ENCAP name='{enc_name}' (full='{parsed.get('Name')}', hop_count={hop_count_to_dest}) to {addr}")
                self.log(f" Sent ROUTE_ACK for ENCAP name='{enc_name}' (full='{parsed.get('Name')}', hop_count={hop_count_to_dest}) to {addr}")
                self.sock.sendto(ack_pkt, addr)
            else:
                resp = create_route_data_packet(seq_num=seq_num, name=original_name, payload=route_payload, flags=ACK_FLAG)
                self.sock.sendto(resp, addr)
                self._record_packet_stat(resp)
                print(f"[{self.ns_name}] Sent ROUTE (next_hop={next_hop}) to {addr}")
                self.log(f" Sent ROUTE (next_hop={next_hop}) to {addr}")

    def _handle_route_ack(self, packet, addr):
        parsed = parse_route_ack_packet(packet)
        if not parsed:
            print(f"[{self.ns_name}] Failed to parse ROUTE_ACK from {addr}")
            self.log(f" Failed to parse ROUTE_ACK from {addr}")
            return

        dest_name = parsed["Name"]
        seq_num = parsed["SequenceNumber"]

        print(f"[{self.ns_name}] Received ROUTE_ACK for {dest_name} from {addr}")
        self.log(f" Received ROUTE_ACK for {dest_name} from {addr}")

        cleaned_ack_name = dest_name  # default (no ENCAP)
        if isinstance(dest_name, str) and dest_name.startswith("ENCAP:"):
            try:
                parts = [p.strip() for p in dest_name[6:].split("|")]

                # Remove the second-to-last token even when only two tokens remain.
                # Examples:
                # - A|B|C -> remove B -> A|C
                # - A|C   -> remove A -> C
                if len(parts) >= 2:
                    parts.pop(-2)

                # If only a single token remains after reduction, drop the ENCAP: prefix
                if len(parts) == 1:
                    cleaned_ack_name = parts[0]
                else:
                    cleaned_ack_name = "ENCAP:" + "|".join(parts)
                print(f"[{self.ns_name}] Reduced ENCAP for ROUTE_ACK: '{dest_name}' -> '{cleaned_ack_name}'")

                # Overwrite dest_name so downstream forwarding uses the reduced ENCAP
                dest_name = cleaned_ack_name

                # Also update parsed payload for consistent handling
                parsed["Name"] = cleaned_ack_name

            except Exception as e:
                print(f"[{self.ns_name}] ENCAP decode failed for ROUTE_ACK: {e}")

        # Try to find pending using the ack name; if ack contains ENCAP, try the stripped base too.
        found_key, pending = self._find_pending(cleaned_ack_name, seq=seq_num)
        if not pending:
            stripped = self._strip_encap(cleaned_ack_name)
            found_key, pending = self._find_pending(stripped, seq=seq_num)
            print(f"[{self.ns_name}] No pending ENCAP interest for {cleaned_ack_name} (already processed or not tracked)")
            self.log(f" No pending ENCAP interest for {cleaned_ack_name} (already processed or not tracked)")
            #print(f"[{self.ns_name}] Pending Table: {self.pending_interests}")
            return
        # if pending:
        #     print(f"[{self.ns_name}] Found pending ENCAP interest for {cleaned_ack_name}: {pending}")

        # incoming hop count reported by the destination-side NameServer:
        incoming_hops = parsed.get("HopCount", 0) or 0

        origin_node = pending["origin"]
        border_router = pending["border_router"]
        next_hop = pending["addr"][1]  # port of original requester
        
        ns_domain = _top_domain(self.ns_name)
        origin_domain = _top_domain(origin_node)

        # Check if the first element of visited domains matches this NS domain
        visited_domains = parsed["VisitedDomains"]
        print(f"[{self.ns_name}] Visited Domains List from ACK: {visited_domains}")
        is_dom = False
        if visited_domains and visited_domains[0] == ns_domain:
            print(f"[{self.ns_name}] First visited domain matches NS domain: {ns_domain}")
            is_dom = True

        if next_hop and not is_dom:
            try:
                # Compute hops between this NS's border context and the source NameServer's provided source_name (if present)
                extra_hops = 0
                try:
                    src_name_in_ack = parsed.get("SourceName")
                    if src_name_in_ack and border_router:
                        path_between = self._shortest_path(border_router, src_name_in_ack)
                        if path_between:
                            extra_hops = max(0, len(path_between) - 1)
                except Exception:
                    extra_hops = 0

                new_hop_count = int(incoming_hops) + int(extra_hops)

                # Preserve the downstream border-router identity in SourceName so upstream NSs can
                # compute intra-domain distances correctly. Fallback to our recorded border_router or
                # self.ns_name if nothing better is available.
                src_name_field = parsed.get("SourceName") or pending.get("border_router") or self.ns_name
                new_route_ack = create_route_ack_packet(
                    seq_num=seq_num,
                    name=cleaned_ack_name,
                    flags=0x0,
                    source_name=src_name_field,
                    hop_count=new_hop_count,
                    visited_domains=visited_domains
                )
                print(f"[{self.ns_name}] Forwarded ROUTE_ACK → next hop (port {next_hop})")
                self.log(f" Forwarded ROUTE_ACK → next hop (port {next_hop})")

                print(f"[{self.ns_name}] New Visited Domains List: {visited_domains}")
                print(f"[{self.ns_name}] Cleared pending ENCAP interest for {cleaned_ack_name}")
                
                self.sock.sendto(new_route_ack, (self.host, int(next_hop)))
                # remove it
                self.pending_interests.pop(found_key, None)
                return
            except Exception as e:
                print(f"[{self.ns_name}] Error forwarding ACK to:{next_hop} - {e}")
                self.log(f" Error forwarding ACK to:{next_hop} - {e}")
        # if ns_domain != origin_domain:
        #     print(f"[{self.ns_name}] Origin {origin_node} is outside domain {ns_domain}.")
        #     print(f"[{self.ns_name}] Forwarding ROUTE_ACK interdomain based on pending border router path…")

        #     hop_name_resolved = None
        #     if next_hop in self.port_to_name:
        #         hop_name_resolved = self.port_to_name[next_hop]
        #     else:
        #         for alias in next_hop.split():
        #             if alias in self.port_to_name:
        #                 hop_name_resolved = self.port_to_name[alias]
        #                 break

        #     if next_hop:
        #         try:
        #             self.sock.sendto(packet, (self.host, int(next_hop)))
        #             print(f"[{self.ns_name}] Forwarded ROUTE_ACK → next hop (port {next_hop})")
        #         except Exception as e:
        #             print(f"[{self.ns_name}] Error forwarding ACK to:{next_hop} - {e}")
        #     else:
        #         print(f"[{self.ns_name}] No known port for next hop {next_hop}. Cannot forward ACK.")

            # # Compute path to border router (same as ENCAP forwarding)
            # path_to_border = self._shortest_path(self.ns_name, border_router)
            # if not path_to_border or len(path_to_border) < 2:
            #     print(f"[{self.ns_name}] No path to border router {border_router}. Dropping ACK.")
            #     return

            # next_hop = path_to_border[1]

            # # Resolve hop name → port
            # hop_port = None
            # hop_name_resolved = None
            # if next_hop in self.name_to_port:
            #     hop_port = self.name_to_port[next_hop]
            #     hop_name_resolved = next_hop
            # else:
            #     for alias in next_hop.split():
            #         if alias in self.name_to_port:
            #             hop_port = self.name_to_port[alias]
            #             hop_name_resolved = alias
            #             break

            # if hop_port:
            #     try:
            #         self.sock.sendto(packet, (self.host, int(hop_port)))
            #         print(f"[{self.ns_name}] Forwarded ROUTE_ACK → next hop {hop_name_resolved} (port {hop_port})")
            #     except Exception as e:
            #         print(f"[{self.ns_name}] Error forwarding ACK to {hop_name_resolved}:{hop_port} - {e}")
            # else:
            #     print(f"[{self.ns_name}] No known port for next hop {next_hop}. Cannot forward ACK.")
        
        else:
            # original_target should be the base (no ENCAP)
            original_target = self._strip_encap(dest_name)
            print(f"[{self.ns_name}] Preparing ROUTE_DATA reply to {origin_node} for {original_target}, direct to border router: {pending['border_router']}")
            self.log(f" Preparing ROUTE_DATA reply to {origin_node} for {original_target}, direct to border router: {pending['border_router']}")

            # Prefer sending directly to the recorded original requester address if available.
            recorded_addr = pending.get("addr")

            # Build the ROUTE_DATA payload (used in all cases)
            path_from_origin = self._shortest_path(origin_node, border_router) or []
            path_to_origin = self._shortest_path(self.ns_name, origin_node) or []
            first_hop_border = path_from_origin[1] if len(path_from_origin) > 1 else border_router
            first_hop_origin = path_to_origin[1] if len(path_to_origin) > 1 else None
            #print(f"[{self.ns_name}] Computed path_from_origin: {path_from_origin}, path_to_origin: {path_to_origin}")

            # route_payload = {
            #     "origin_name": origin_node,
            #     "path": path_from_origin,
            #     "border_router": border_router,
            #     "dest": original_target,
            #     "next_hop": first_hop_border,
            #     "path_to_origin": path_to_origin,
            #     "note": "ACK confirmed path via border router"
            # }

            # When replying with ROUTE_DATA to the origin, include total hops:
            # total_hops = incoming_hops (distance in destination domain from source-border->dest)
            #            + hops from origin to the border_router (within this domain)
            local_hops = max(0, len(path_from_origin) - 1) if isinstance(path_from_origin, (list, tuple)) else 0
            total_hops = int(incoming_hops) + int(local_hops)

            route_payload = {
                "origin_name": origin_node,
                "path": path_from_origin,
                "dest": original_target,
                "next_hop": first_hop_border,
               "hop_count": total_hops
            }

            resp = create_route_data_packet(
                seq_num=seq_num,
                name=original_target,
                payload=route_payload,
                flags=ACK_FLAG
            )

            # Prefer the recorded UDP endpoint that originally contacted the NS (authoritative)
            # Primary behavior: send ROUTE to the first hop toward the origin (intradomain style)
            if first_hop_origin:
                # resolve a port for the first_hop (handle multi-alias names)
                hop_port = None
                hop_name_resolved = None
                if first_hop_origin in self.name_to_port:
                    hop_port = self.name_to_port[first_hop_origin]
                    hop_name_resolved = first_hop_origin
                else:
                    for alias in first_hop_origin.split():
                        if alias in self.name_to_port:
                            hop_port = self.name_to_port[alias]
                            hop_name_resolved = alias
                            break
                if hop_port:
                    try:
                        target = (self.host, int(hop_port))
                        self.sock.sendto(resp, target)
                        self._record_packet_stat(resp)
                        print(f"[{self.ns_name}] Sent ROUTE (next_hop={first_hop_border}) to {first_hop_origin} neighbor")
                        return
                    except Exception as e:
                        print(f"[{self.ns_name}] Error sending ROUTE to first-hop to {first_hop_origin} going towards origin: {e}")

            # Fallbacks: try name->port for the origin, then the recorded addr as last resort
            origin_port = self.name_to_port.get(origin_node)
            if origin_port:
                try:
                    target = (self.host, int(origin_port))
                    self.sock.sendto(resp, target)
                    self._record_packet_stat(resp)
                    print(f"[{self.ns_name}] Sent ROUTE (next_hop={origin_node}) to {target}")
                    return
                except Exception as e:
                    print(f"[{self.ns_name}] Failed to send ROUTE to origin {origin_node} at port {origin_port}: {e}")

            if recorded_addr:
                try:
                    self.sock.sendto(resp, recorded_addr)
                    self._record_packet_stat(resp)
                    print(f"[{self.ns_name}] Sent ROUTE (fallback) to recorded addr {recorded_addr} for {original_target}")
                    return
                except Exception as e:
                    print(f"[{self.ns_name}] Error sending ROUTE to recorded addr {recorded_addr}: {e}")

            # NEW fallback: consult NameServer PIT entries for the base name and send the ROUTE_DATA to any recorded requesters
            pit_addrs = list(self.pit.get(original_target, []))
            if pit_addrs:
                for a in pit_addrs:
                    try:
                        self.sock.sendto(resp, a)
                        self._record_packet_stat(resp)
                        print(f"[{self.ns_name}] Sent ROUTE_DATA to PIT recorded addr {a} for {original_target}")
                    except Exception as e:
                        print(f"[{self.ns_name}] Failed sending ROUTE_DATA to PIT addr {a}: {e}")
                # clear PIT entries for this name (one-time)
                try:
                    del self.pit[original_target]
                except KeyError:
                    pass
                return

            # --- existing fallback behavior (unchanged) ---
            # Compute path from origin to border router (used by node to install FIB and forward toward border)
            path_from_origin = self._shortest_path(origin_node, border_router)
            if not path_from_origin:
                print(f"[{self.ns_name}] Cannot find path from origin {origin_node} to border router {border_router}")
                return

            # Also compute path from NS to origin, in case we need to forward via first hop
            path_to_origin = self._shortest_path(self.ns_name, origin_node)
            if not path_to_origin or len(path_to_origin) < 2:
                print(f"[{self.ns_name}] Cannot find path to origin {origin_node}")
                return

            first_hop_border = path_from_origin[1] if len(path_from_origin) > 1 else border_router
            first_hop_origin = path_to_origin[1]

            # Build reply payload
            route_payload = {
                "origin_name": origin_node,
                "path": path_from_origin,
                "border_router": border_router,
                "dest": original_target,
                "next_hop": first_hop_border,
                "path_to_origin": path_to_origin,
                "note": "ACK confirmed path via border router",
                "hop_count": max(0, len(path_from_origin) - 1) if isinstance(path_from_origin, (list, tuple)) else 0
            }

            resp = create_route_data_packet(
                seq_num=seq_num,
                name=original_target,
                payload=route_payload,
                flags=ACK_FLAG
            )

            # Prefer sending directly to the origin if we know its port
            origin_port = self.name_to_port.get(origin_node)
            if origin_port:
                try:
                    self.sock.sendto(resp, (self.host, int(origin_port)))
                    self._record_packet_stat(resp)
                    print(f"[{self.ns_name}] Sent ROUTE_DATA directly to origin {origin_node} at port {origin_port}")
                except Exception as e:
                    print(f"[{self.ns_name}] Failed to send ROUTE_DATA to origin {origin_node} at port {origin_port}: {e}")
                return  # do not also send to first_hop_origin

            # Otherwise, forward via the first hop toward the origin
            port = self.name_to_port.get(first_hop_origin)
            if not port:
                print(f"[{self.ns_name}] Cannot find port for first_hop {first_hop_origin} to origin {origin_node}")
                return
            try:
                self.sock.sendto(resp, (self.host, int(port)))
                self._record_packet_stat(resp)
                print(f"[{self.ns_name}] Sent ROUTE_DATA (border_first_hop={first_hop_border}) "
                    f"to first_hop {first_hop_origin} (port {port}) for {original_target} toward origin {origin_node}")
            except Exception as e:
                print(f"[{self.ns_name}] Error sending ROUTE_DATA to first hop {first_hop_origin}: {e}")
            
    def _shortest_path(self, src, dest):
        if src not in self.graph or dest not in self.graph:
            return None
        if src == dest:
            return [src]
        q = deque([src])
        prev = {src: None}
        while q:
            u = q.popleft()
            for v in self.graph[u]:
                if v not in prev:
                    prev[v] = u
                    if v == dest:
                        path = [dest]
                        cur = dest
                        while prev[cur] is not None:
                            cur = prev[cur]
                            path.append(cur)
                        path.reverse()
                        return path
                    q.append(v)
        return None

    def stop(self):
        self.running = False
        try:
            self.sock.sendto(b"", (self.host, self.port))
        except Exception:
            pass
        self.sock.close()

    def dump_state(self):
        """Simple debug helper to print pending interest table and mappings."""
        print(f"[{self.ns_name}] name_to_port: {self.name_to_port}")
        print(f"[{self.ns_name}] port_to_name: {self.port_to_name}")
        print(f"[{self.ns_name}] pending_interests (count={len(self.pending_interests)}):")
        for k, v in self.pending_interests.items():
            print(f"  {k} -> {v}")
    
    def get_neigbors(self):
        return self.neighbor_table

""" if __name__ == "__main__":
    ns = NameServer(ns_name="/DLSU/NameServer1", host="127.0.0.1", port=6000, topo_file="topology.txt")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        ns.stop() """
