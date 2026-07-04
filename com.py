from node import Node
from nameserver import NameServer
import time
import threading
import queue
import random
from datetime import datetime

# Packet Types (4 bits)
INTEREST = 0x1
DATA = 0x2
ROUTING_DATA = 0x3
HELLO = 0x4
UPDATE = 0x5
ERROR = 0x6
ROUTE_ACK = 0x7
REDIRECT_NS = 0x8

# Flag Masks (lower 4 bits)
ACK_FLAG = 0x1
RET_FLAG = 0x2
TRUNC_FLAG = 0x3

# Statistics tracking class
class NetworkStatistics:
    def __init__(self):
        self.lock = threading.Lock()
        self.packet_counts = {
            'INTEREST': 0,
            'INTEREST_QUERY': 0,
            'DATA': 0,
            'ROUTING_DATA': 0,
            'HELLO': 0,
            'UPDATE': 0,
            'ERROR': 0,
            'ROUTE_ACK': 0,
            'REDIRECT_NS': 0
        }
        self.total_data_bits_transferred = 0
        self.total_hops = 0
        self.interest_data_pairs = {}  # {(origin, name, seq): {'interest_time': ts, 'data_time': ts}}
        # start_time is set when the phase actually begins
        self.start_time = None
        self.end_time = None
        # Track payload bits (actual file data) vs control bits (headers/metadata)
        self.payload_bits = 0  # Actual data content
        # Split control bits into data-packet header bits and non-data packet bits
        self.data_control_bits = 0  # header overhead from DATA packets
        self.non_data_bits = 0     # full bits of non-DATA packets (interest, routing, ack, error, etc.)
        # Backwards-compatible alias (kept in case other modules reference it)
        self.control_bits = 0
        # Configuration flag: whether to include HELLO/UPDATE bits in control overhead
        self.include_hello_update_in_control_overhead = False
    
    def record_interest(self, origin_node, name, seq_num, timestamp):
        """Record when an interest packet is sent"""
        with self.lock:
            key = (origin_node, name, seq_num)
            if key not in self.interest_data_pairs:
                self.interest_data_pairs[key] = {}
            self.interest_data_pairs[key]['interest_time'] = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")
            self.packet_counts['INTEREST'] += 1

    def record_interest_hop(self, origin_node, name, seq_num, node_name):
        """Append a node to the interest path for the given interest key."""
        with self.lock:
            key = (origin_node, name, seq_num)
            if key not in self.interest_data_pairs:
                self.interest_data_pairs[key] = {}
            path = self.interest_data_pairs[key].setdefault('interest_path', [])
            path.append(node_name)
    
    def record_interest_query(self):
        """Record when an interest query (data_flag=False) is sent to NameServer"""
        with self.lock:
            self.packet_counts['INTEREST_QUERY'] += 1
    
    def record_data(self, name, seq_num, payload_size, timestamp):
        """Record when a data packet is received and match it with interest"""
        with self.lock:
            # First, count the DATA packet
            self.packet_counts['DATA'] += 1
            self.total_data_bits_transferred += payload_size * 8  # Convert bytes to bits
            
            # Track payload bits (actual data) vs control bits (header overhead)
            # DATA packet header: packet_type_flags(1) + seq_num(1) + name_length(1) + fragment_num(1) + total_fragments(1) + payload_size(1) = 6 bytes
            # Plus name length (variable)
            name_bytes = len(name.encode('utf-8'))
            header_bits = (6 + name_bytes) * 8
            self.payload_bits += payload_size * 8
            # attribute data_control_bits for DATA packet headers
            self.data_control_bits += header_bits
            # keep alias in sync
            self.control_bits = self.data_control_bits + self.non_data_bits
            
            # Try to find and update matching interest records
            # Data packets may come from any origin, so we search for matching name and seq
            timestamp_dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")
            
            for key, times in self.interest_data_pairs.items():
                origin_node, interest_name, interest_seq = key
                # Match by name and sequence number (origin may differ for intermediate nodes)
                if interest_name == name and interest_seq == seq_num:
                    if 'interest_time' in times:
                        times['data_time'] = timestamp_dt

    def record_data_hop(self, name, seq_num, node_name):
        """(removed) previously used to append nodes to a separate data path."""
        # Deprecated: data path tracking removed — keep stub for compatibility.
        return

    
    def record_packet(self, packet_type, size_bits=0, size_bytes=0):
        """Record any packet type (but skip DATA/INTEREST as they're counted separately)"""
        with self.lock:
            packet_names = {
                INTEREST: 'INTEREST',
                DATA: 'DATA',
                ROUTING_DATA: 'ROUTING_DATA',
                HELLO: 'HELLO',
                UPDATE: 'UPDATE',
                ERROR: 'ERROR',
                ROUTE_ACK: 'ROUTE_ACK',
                REDIRECT_NS: 'REDIRECT_NS'
            }
            if packet_type in packet_names:
                packet_name = packet_names[packet_type]
                # Skip double-counting DATA and INTEREST (recorded separately)
                if packet_name not in ['DATA', 'INTEREST', 'HELLO', 'UPDATE']:
                    self.packet_counts[packet_name] += 1
                
                # Track full bits for non-DATA packets
                # Skip HELLO/UPDATE bits if configured to exclude them from control overhead
                should_count_bits = True
                if packet_name in ['HELLO', 'UPDATE'] and not self.include_hello_update_in_control_overhead:
                    should_count_bits = False
                
                if should_count_bits:
                    if size_bytes > 0:
                        self.non_data_bits += size_bytes * 8
                    elif size_bits > 0:
                        self.non_data_bits += size_bits
                # keep alias in sync
                self.control_bits = self.data_control_bits + self.non_data_bits
    
    def set_include_hello_update_in_overhead(self, include=True):
        """Enable/disable HELLO and UPDATE packet bits from control overhead calculation"""
        with self.lock:
            self.include_hello_update_in_control_overhead = include

    def record_hello(self):
        with self.lock:
            self.packet_counts['HELLO'] += 1
    
    def record_update(self):
        with self.lock:
            self.packet_counts['UPDATE'] += 1
    
    def record_hop(self):
        """Record a hop when a node receives a non-HELLO/UPDATE packet"""
        with self.lock:
            self.total_hops += 1
    
    def finalize(self):
        """Mark the end of statistics collection"""
        self.end_time = datetime.now()
    
    def calculate_latencies(self):
        """Calculate latency for each completed interest-data pair.

        Latency is estimated using a hop-based model: 10 milliseconds per hop.
        We use the recorded `interest_path` length (number of hops the interest traversed).
        This function returns latencies in seconds (consistent with previous behavior).
        """
        latencies = []
        with self.lock:
            # Determine completed pairs and estimate hop counts per pair.
            # Prefer explicit per-pair paths if available (interest_path and optional data_path).
            # If only interest_path is present, assume symmetric return path and double it.
            # If no per-pair path info is available, fall back to evenly distributing
            # `self.total_hops` across completed pairs (best-effort).
            completed_pairs = 0
            for key, times in self.interest_data_pairs.items():
                if 'data_time' in times:
                    completed_pairs += 1

            for key, times in self.interest_data_pairs.items():
                if 'data_time' not in times:
                    continue

                interest_path = times.get('interest_path', []) or []
                data_path = times.get('data_path', []) or []

                # If there's exactly one completed pair, prefer using the aggregated
                # `self.total_hops` (this matches single-run totals reported elsewhere).
                if completed_pairs == 1:
                    hop_count = int(self.total_hops)
                elif interest_path and data_path:
                    hop_count = len(interest_path) + len(data_path)
                elif interest_path:
                    # assume return path mirrors interest path
                    hop_count = len(interest_path) * 2
                else:
                    # fall back: distribute total_hops across completed pairs
                    try:
                        hop_count = int(self.total_hops / completed_pairs) if completed_pairs > 0 else 0
                    except Exception:
                        hop_count = 0

                # 10 ms per hop -> convert to seconds
                # Add per-hop jitter: each hop has +/-2ms variation.
                base_seconds = (hop_count * 10) / 1000.0
                # Generate per-hop uniform jitter samples in seconds and sum them.
                jitter_samples = []
                if hop_count > 0:
                    jitter_samples = [random.uniform(-0.002, 0.002) for _ in range(hop_count)]
                variation = sum(jitter_samples)

                # Remove the initialization hop's full delay (10ms plus that hop's jitter)
                # rather than subtracting a fixed 10ms. This removes the exact instance
                # of per-hop jitter associated with the self-send.
                init_remove = (0.01 + jitter_samples[0]) if (hop_count > 0 and len(jitter_samples) > 0) else 0.0

                latency_seconds = base_seconds + variation - init_remove
                # Ensure latency never goes below 0.
                latency_seconds = max(0.0, latency_seconds)
                latencies.append(latency_seconds)
        return latencies
    
    def get_statistics(self):
        """Get comprehensive network statistics"""
        total_time = ((self.end_time - self.start_time).total_seconds() if (self.start_time and self.end_time) else 0)
        latencies = self.calculate_latencies()
        avg_latency = sum(latencies) / len(latencies) if latencies else 0
        max_latency = max(latencies) if latencies else 0
        min_latency = min(latencies) if latencies else 0
        
        # Calculate throughput in bits per second using average latency (actual data transfer time)
        # This is more accurate for single-request scenarios as it excludes waiting/setup time
        throughput_bps = self.total_data_bits_transferred / avg_latency if avg_latency > 0 else 0
        throughput_kbps = throughput_bps / 1000
        
        # Calculate control overhead: data-header bits + all non-data packet bits
        # Control bits = data_control_bits + non_data_bits
        control_bits_combined = self.data_control_bits + self.non_data_bits
        # Control overhead = control_bits / (control_bits + payload_bits) * 100
        total_bits = control_bits_combined + self.payload_bits
        control_overhead_percent = (control_bits_combined / total_bits * 100) if total_bits > 0 else 0
        
        # Count control packets (non-data) for reference
        control_packets = (self.packet_counts['ROUTING_DATA'] +
                          self.packet_counts['ERROR'] +
                          self.packet_counts['HELLO'] + 
                          self.packet_counts['UPDATE'] + 
                          self.packet_counts['ROUTE_ACK'] +
                          self.packet_counts['INTEREST_QUERY'] +
                          self.packet_counts['REDIRECT_NS'])
        
        total_packets = sum(self.packet_counts.values())
        
        return {
            'total_time': total_time,
            'packet_counts': self.packet_counts,
            'total_packets': total_packets,
            'total_data_bits': self.total_data_bits_transferred,
            'total_hops': self.total_hops,
            'throughput_bps': throughput_bps,
            'throughput_kbps': throughput_kbps,
            'avg_latency_ms': avg_latency * 1000,
            'max_latency_ms': max_latency * 1000,
            'min_latency_ms': min_latency * 1000,
            'control_packets': control_packets,
            'control_overhead_percent': control_overhead_percent,
            'completed_pairs': len(latencies),
            'payload_bits': self.payload_bits,
            # expose combined control bits for compatibility
            'control_bits': control_bits_combined,
            'data_control_bits': self.data_control_bits,
            'non_data_bits': self.non_data_bits
        }

# Global statistics instance
class PhaseAwareStats:
    """A wrapper that maintains separate NetworkStatistics objects for
    different phases and delegates recording to the active phase.
    """
    def __init__(self, phase_names=None, default_phase=None):
        phase_names = phase_names or ["initialization", "first_request", "second_request"]
        self.phases = {name: NetworkStatistics() for name in phase_names}
        self.active = default_phase or phase_names[0]
        # mark the active phase start time when stats object is created
        try:
            self.phases[self.active].start_time = datetime.now()
        except Exception:
            pass

    def set_phase(self, phase_name):
        # End previous active phase (if it was started and not yet ended)
        try:
            prev = self.active
            if prev in self.phases:
                prev_st = self.phases[prev]
                if prev_st.start_time is not None and prev_st.end_time is None:
                    prev_st.end_time = datetime.now()
        except Exception:
            pass

        if phase_name not in self.phases:
            self.phases[phase_name] = NetworkStatistics()
        self.active = phase_name
        st = self.phases[phase_name]
        # (re)start the phase timer when the phase is set
        st.start_time = datetime.now()
        st.end_time = None

    def _active(self):
        return self.phases[self.active]

    @property
    def interest_data_pairs(self):
        combined = {}
        for st in self.phases.values():
            if hasattr(st, 'interest_data_pairs') and isinstance(st.interest_data_pairs, dict):
                combined.update(st.interest_data_pairs)
        return combined

    # Delegate methods
    def record_interest(self, origin_node, name, seq_num, timestamp):
        return self._active().record_interest(origin_node, name, seq_num, timestamp)

    def record_interest_query(self):
        return self._active().record_interest_query()

    def record_data(self, name, seq_num, payload_size, timestamp):
        return self._active().record_data(name, seq_num, payload_size, timestamp)

    def record_packet(self, packet_type, size_bits=0, size_bytes=0):
        return self._active().record_packet(packet_type, size_bits=size_bits, size_bytes=size_bytes)

    def record_hop(self):
        return self._active().record_hop()

    def record_interest_hop(self, origin_node, name, seq_num, node_name):
        return self._active().record_interest_hop(origin_node, name, seq_num, node_name)
    

    # Delegate hello/update so nodes can record these directly
    def record_hello(self):
        return self._active().record_hello()

    def record_update(self):
        return self._active().record_update()

    def set_include_hello_update_in_overhead(self, include=True):
        """Enable/disable HELLO and UPDATE packet bits from control overhead calculation"""
        return self._active().set_include_hello_update_in_overhead(include)

    def finalize(self):
        for st in self.phases.values():
            try:
                # only finalize phases that have been started
                if st.start_time is not None and st.end_time is None:
                    st.finalize()
            except Exception:
                pass

    def end_active_phase(self):
        """Explicitly end the currently active phase by setting its end_time."""
        try:
            st = self.phases.get(self.active)
            if st and st.start_time is not None and st.end_time is None:
                st.end_time = datetime.now()
        except Exception:
            pass

    def calculate_latencies(self, phase=None):
        if phase:
            if phase not in self.phases:
                # no records for that phase
                return []
            return self.phases[phase].calculate_latencies()
        # aggregate
        latencies = []
        for st in self.phases.values():
            latencies.extend(st.calculate_latencies())
        return latencies

    def get_statistics(self, phase=None):
        # If a specific phase requested, return that phase's stats
        if phase:
            # if the requested phase doesn't exist (e.g. auto_run shorter than request_count), create an empty phase
            if phase not in self.phases:
                self.phases[phase] = NetworkStatistics()
            return self.phases[phase].get_statistics()

        # Otherwise return combined stats across all phases
        combined = {
            'total_time': 0,
            'packet_counts': {k: 0 for k in self._active().packet_counts.keys()},
            'total_packets': 0,
            'total_data_bits': 0,
            'total_hops': 0,
            'throughput_bps': 0,
            'throughput_kbps': 0,
            'avg_latency_ms': 0,
            'max_latency_ms': 0,
            'min_latency_ms': 0,
            'control_packets': 0,
            'control_overhead_percent': 0,
            'completed_pairs': 0,
            'payload_bits': 0,
            'control_bits': 0,
            'data_control_bits': 0,
            'non_data_bits': 0
        }

        all_latencies = []
        for st in self.phases.values():
            s = st.get_statistics()
            combined['total_time'] += s['total_time']
            for k, v in s['packet_counts'].items():
                combined['packet_counts'][k] = combined['packet_counts'].get(k, 0) + v
            combined['total_packets'] += s['total_packets']
            combined['total_data_bits'] += s['total_data_bits']
            combined['total_hops'] += s['total_hops']
            combined['control_packets'] += s['control_packets']
            combined['payload_bits'] += s.get('payload_bits', 0)
            combined['control_bits'] += s.get('control_bits', 0)
            combined['data_control_bits'] += s.get('data_control_bits', 0)
            combined['non_data_bits'] += s.get('non_data_bits', 0)
            all_latencies.extend(st.calculate_latencies())
            combined['completed_pairs'] += s.get('completed_pairs', 0)

        combined['avg_latency_ms'] = (sum(all_latencies) / len(all_latencies) * 1000) if all_latencies else 0
        combined['max_latency_ms'] = (max(all_latencies) * 1000) if all_latencies else 0
        combined['min_latency_ms'] = (min(all_latencies) * 1000) if all_latencies else 0
        # Use average latency for throughput (measures actual data transfer time, not total elapsed time)
        combined['throughput_bps'] = combined['total_data_bits'] / (combined['avg_latency_ms'] / 1000) if combined['avg_latency_ms'] > 0 else 0
        combined['throughput_kbps'] = combined['throughput_bps'] / 1000
        # Recompute control_bits as the sum of data headers + non-data packet bits
        combined['control_bits'] = combined.get('data_control_bits', 0) + combined.get('non_data_bits', 0)
        # Calculate control overhead using bits: control_bits / (control_bits + payload_bits)
        total_bits_combined = combined['control_bits'] + combined['payload_bits']
        combined['control_overhead_percent'] = (combined['control_bits'] / total_bits_combined * 100) if total_bits_combined > 0 else 0

        return combined


# Global phase-aware statistics instance
global_stats = PhaseAwareStats()

# Export for other modules
__all__ = ['global_stats', 'NetworkStatistics', 'DebugController']

# Configure the number of requests to run
r_count = 1

def load_config(config_file="config.txt"):
    """Load configuration from config.txt file"""
    config = {
        'mode': 'auto',
        'origin_node': '/DLSU/Andrew/PC1',
        'destination_node': '/UP',
        'request_count': 5,
        'request_time': 1,
        'only_start_init': True,
        'random_nodes': True
    }
    
    try:
        with open(config_file, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Parse boolean values
                    if key in ['only_start_init', 'random_nodes']:
                        config[key] = value.lower() == 'true'
                    # Parse numeric values
                    elif key in ['request_count', 'request_time']:
                        try:
                            if key == 'request_count':
                                config[key] = int(value)
                            else:
                                config[key] = float(value)
                        except ValueError:
                            print(f"[WARNING] Invalid {key} value: {value}, using default")
                    # Parse string values
                    else:
                        config[key] = value
        
        print(f"[CONFIG] Loaded configuration from {config_file}")
        print(f"[CONFIG] Mode: {config['mode']}")
        print(f"[CONFIG] Origin: {config['origin_node']}")
        print(f"[CONFIG] Destination: {config['destination_node']}")
        print(f"[CONFIG] Request Count: {config['request_count']}")
        print(f"[CONFIG] Request Time: {config['request_time']}")
        print(f"[CONFIG] Only Start Init: {config['only_start_init']}")
        print(f"[CONFIG] Random Nodes: {config['random_nodes']}\n")
        
        return config
    
    except FileNotFoundError:
        print(f"[WARNING] Config file {config_file} not found, using defaults")
        return config
    except Exception as e:
        print(f"[ERROR] Error loading config: {e}, using defaults")
        return config

def find_node_by_name(nodes, node_name):
    """Find a node object by its name"""
    for node in nodes:
        if hasattr(node, 'name') and node.name == node_name:
            return node
        elif hasattr(node, 'ns_name') and node.ns_name == node_name:
            return node
    
    # If exact match not found, print available nodes for debugging
    print(f"[ERROR] Node '{node_name}' not found!")
    print("[INFO] Available nodes:")
    for node in nodes:
        if hasattr(node, 'name'):
            print(f"  - {node.name}")
        elif hasattr(node, 'ns_name'):
            print(f"  - {node.ns_name}")
    return None

if __name__ == "__main__":
    ns = NameServer(ns_name="/DLSU/NameServer1", host="127.0.0.1", port=5000, topo_file="DLSU_NameServer1_topology.txt")
    admu_ns = NameServer(ns_name="/ADMU/NameServer1", host="127.0.0.1", port=6000, topo_file="ADMU_NameServer1_topology.txt")
    up_ns = NameServer(ns_name="/UP/NameServer1", host="127.0.0.1", port=7000, topo_file="UP_NameServer1_topology.txt")
    
    dpc1 = Node("/DLSU/Andrew/PC1", port=5001)
    andrew = Node("/DLSU/Andrew", port=5002)
    goks = Node("/DLSU/Gokongwei", port=5003)
    henry = Node("/DLSU/Henry", port=5004)
    dlsu = Node("/DLSU", port=5005)
    miguel = Node("/DLSU/Miguel", port=5006)
    dcam1 = Node("/DLSU/Miguel/cam1", port=5007)
    dxa = Node("/DLSU/Router1 /ADMU/Router1", port=5008, isborder=True)
    gonzaga = Node("/ADMU/Gonzaga", port=6001)
    admu = Node("/ADMU", port=6002)
    acam1 = Node("/ADMU/Gonzaga/cam1", port=6003)
    kostka = Node("/ADMU/Kostka", port=6004)
    axu = Node("/ADMU/Router2 /UP/Router1", port=6005, isborder=True)
    up = Node("/UP", port=7001)
    salcedo = Node("/UP/Salcedo", port=7002)
    lara = Node("/UP/Lara", port=7003)
    upc1 = Node("/UP/Salcedo/PC1", port=7004)

    nodes =[dpc1, andrew, goks, henry, dlsu, miguel, dcam1, dxa, 
            gonzaga, admu, acam1, kostka, axu, up, salcedo, lara, upc1, ns, admu_ns, up_ns]

    # load all nodes
    # Start statistics phase for initialization (discovery)
    def single_init(nodes, gs):

        try:
            gs.set_phase("initialization")
        except Exception:
            pass

        for node in nodes:
            # NameServers and Nodes both implement load_neighbors_from_file
            try:
                node.load_neighbors_from_file("neighbors.txt")
            except Exception:
                pass
        # End initialization phase now that neighbor loading is complete
        try:
            gs.end_active_phase()
        except Exception:
            pass
    
    # # keep a short pause for network stabilization, but do not count it in initialization

    # Start periodic discovery reload every 30 seconds.
    # This ensures NameServers and Nodes re-announce and re-learn neighbor ports.
    def periodic_init(nodes, gs):
        def _periodic_discovery_loop(all_nodes, interval=30):
            try:
                gs.set_phase("initialization")
            except Exception:
                pass

            while True:
                for n in all_nodes:
                    try:
                        n.load_neighbors_from_file("neighbors.txt")
                    except Exception:
                        pass
                try:
                    gs.end_active_phase()
                except Exception:
                    pass
                time.sleep(interval)

        discovery_thread = threading.Thread(target=_periodic_discovery_loop, args=(nodes, 30), daemon=True)
        discovery_thread.start()

    # Load configuration from config.txt
    config = load_config("config.txt")
    only_start_init = config['only_start_init']

    if only_start_init:
        single_init(nodes, global_stats)
    else:
        periodic_init(nodes, global_stats)

    time.sleep(1)

    # neighbor tables
    # print("\n--- Neighbor Tables ---")
    # print("dpc1 neighbors:", dpc1.get_neighbors())
    # print("andrew neighbors:", andrew.get_neighbors())
    # print("henry neighbors:", henry.get_neighbors())
    # print("border router neighbors: ", dxa.get_neighbors())
    # print("NameServer neighbors:", ns.get_neigbors())

    # tests buffer and queueing (temp)
    # NPU = 8
    # TOTAL_PACKETS = 50 
    # threads = []

    # print(f"\n[TEST] Starting Buffer and Queueing Test...")
    # print(f"[CONFIG] NPU = {NPU}, Total Packets = {TOTAL_PACKETS}\n")

    # def send_fake_interest(i):
    #     processing_unit = i % NPU
    #     fake_name = f"/UP/UnknownTarget{processing_unit}"
    #     seq_num = 1000 + i
    #     andrew.send_interest(seq_num, fake_name, target=("127.0.0.1", 5003))
    #     print(f"[TEST] Packet {i} handled by NPU {processing_unit}")

    # for i in range(TOTAL_PACKETS):
    #     t = threading.Thread(target=send_fake_interest, args=(i,))
    #     t.start()
    #     threads.append(t)

    # for t in threads:
    #     t.join()

    # print(f"\n[TEST] Sent {TOTAL_PACKETS} Interest packets distributed across {NPU} NPUs.")
    # print("[TEST] Buffer growth and FIFO processing sequence below...\n")

    # time.sleep(5)

    def _ns_for_origin(origin_node):
        """Return the NameServer object for origin based on its top-level domain."""
        try:
            origin_top = origin_node.name.strip('/').split('/', 1)[0]
        except Exception:
            origin_top = "DLSU"
        if origin_top == "DLSU":
            return ns
        if origin_top == "ADMU":
            return admu_ns
        if origin_top == "UP":
            return up_ns
        return ns

    def send_interest_via_ns(origin_node, seq_num, name, data_flag=False):
        """Send an Interest from origin_node toward the NameServer of its domain,
        but actually send to the first-hop neighbor toward that NameServer.
        """
        ns_obj = _ns_for_origin(origin_node)
        target = ("127.0.0.1", ns_obj.port)  # fallback: direct to NS
        try:
            path = ns_obj._shortest_path(origin_node.name, ns_obj.ns_name)
            if path and len(path) > 1:
                first_hop = path[1]
                # prefer origin's own mapping, then NS mapping, then alias splits
                port = None
                if hasattr(origin_node, "name_to_port"):
                    port = origin_node.name_to_port.get(first_hop)
                if not port and hasattr(ns_obj, "name_to_port"):
                    port = ns_obj.name_to_port.get(first_hop)
                if not port:
                    # try alias tokens
                    for candidate in (first_hop.split() if isinstance(first_hop, str) else []):
                        if hasattr(origin_node, "name_to_port") and candidate in origin_node.name_to_port:
                            port = origin_node.name_to_port[candidate]
                            break
                        if hasattr(ns_obj, "name_to_port") and candidate in ns_obj.name_to_port:
                            port = ns_obj.name_to_port[candidate]
                            break
                if port:
                    target = ("127.0.0.1", int(port))
        except Exception:
            # any failure: fall back to direct NS port (already set)
            pass

        origin_node.send_interest(seq_num=seq_num, name=name, target=target, data_flag=data_flag)

    def manual_run(orig, dest, gs, loc_name, r_count): 
        interest_files = {}
        messages = {}
        
        for i in range(1, r_count + 1):
            digit_str = str(i).zfill(5) 
            interest_files[i] = f"{loc_name}/file{digit_str}.txt"
            messages[i] = f"Hifromdst{digit_str} " * 80

        # Send requests dynamically based on r_count
        for i in range(1, r_count + 1):
            dest.add_cs(interest_files[i], messages[i])

            # Reset the received data status before sending each request
            orig.reset_received_data(interest_files[i])

            # switch to current request phase
            try:
                gs.set_phase(f"request{i}")
            except Exception:
                pass
            
            send_interest_via_ns(orig, seq_num=0, name=interest_files[i], data_flag=False)
            
            # Wait until node has received the data packet
            max_wait_time = 10  # seconds
            start_time = time.time()
            while not orig.has_received_data(interest_files[i]):
                if time.time() - start_time > max_wait_time:
                    print(f"[WARNING] Timeout waiting for {orig.name} to receive data for {interest_files[i]}")
                    break
                time.sleep(0.001)

    def auto_run(orig, dest, gs, loc_name, r_time, rand):
        curr_req_timer = time.time()
        ctr = 1
        interest_files = {}
        messages = {}
        max_wait_time = 10  # seconds

        if rand:
            while time.time() - curr_req_timer < float(r_time):
                orig_int, dest_int = random.sample(range(17), 2)
                original = nodes[orig_int]
                destination = nodes[dest_int]
                location_name = destination.name
                
                digit_str = str(ctr).zfill(5)
                interest_files[ctr] = f"{location_name}/file{digit_str}.txt"
                messages[ctr] = f"Hifromdst{digit_str} " * 80

                try:
                    destination.add_cs(interest_files[ctr], messages[ctr])
                except Exception:
                    pass

                try:
                    original.reset_received_data(interest_files[ctr])
                except Exception:
                    pass

                try:
                    gs.set_phase(f"request{ctr}")
                except Exception:
                    pass

                try:
                    send_interest_via_ns(original, seq_num=0, name=interest_files[ctr], data_flag=False)
                    start_time = time.time()
                    while not original.has_received_data(interest_files[ctr]):
                        if time.time() - start_time > max_wait_time:
                            print(f"[WARNING] Timeout waiting for {original.name} to receive data for {interest_files[ctr]}")
                            break
                        time.sleep(0.001)
                except Exception:
                    pass
                
                ctr += 1

        else:
            while time.time() - curr_req_timer < float(r_time):
                digit_str = str(ctr).zfill(5)
                
                interest_files[ctr] = f"{loc_name}/file{digit_str}.txt"
                messages[ctr] = f"Hifromdst{digit_str} " * 80

                try:
                    dest.add_cs(interest_files[ctr], messages[ctr])
                except Exception:
                    pass

                try:
                    orig.reset_received_data(interest_files[ctr])
                except Exception:
                    pass

                try:
                    gs.set_phase(f"request{ctr}")
                except Exception:
                    pass

                try:
                    send_interest_via_ns(orig, seq_num=0, name=interest_files[ctr], data_flag=False)
                    start_time = time.time()
                    while not orig.has_received_data(interest_files[ctr]):
                        if time.time() - start_time > max_wait_time:
                            print(f"[WARNING] Timeout waiting for {orig.name} to receive data for {interest_files[ctr]}")
                            break
                        time.sleep(0.001)
                except Exception:
                    pass
                
                ctr += 1

        return ctr-1

    # Find nodes by name from config (already loaded above)
    original = find_node_by_name(nodes, config['origin_node'])
    destination = find_node_by_name(nodes, config['destination_node'])
    
    if original is None or destination is None:
        print("[ERROR] Could not find origin or destination node. Exiting.")
        exit(1)
    
    location_name = destination.name
    runtime_rand = config['random_nodes']
    request_count = config['request_count']
    request_time = config['request_time']
    mode = config['mode']

    # Run based on mode from config
    if mode.lower() == 'manual':
        print(f"\n[RUN] Starting MANUAL mode: {request_count} requests")
        manual_run(original, destination, global_stats, location_name, request_count)
    else:
        print(f"\n[RUN] Starting AUTO mode: {request_time}s duration")
        request_count = auto_run(original, destination, global_stats, location_name, request_time, runtime_rand)

""" # destination does not exist
print("\n[TEST] Testing error case: destination does not exist")
error_origin = nodes[0]
error_interest_name = "/DLSU/Miguel/cam2/nothing_here.txt"
try:
    global_stats.set_phase("error_test")
except Exception:
    pass
send_interest_via_ns(error_origin, seq_num=0, name=error_interest_name, data_flag=False)
    
max_wait_time = 5
start_time = time.time()
while not error_origin.has_received_data(error_interest_name):
    if time.time() - start_time > max_wait_time:
        print(f"[INFO] No data received for {error_interest_name} (expected - destination doesn't exist)")
        break
    time.sleep(0.1)

# destination exists but file does not
print("\n[TEST] Testing error case: destination exists but file does not")
error_origin2 = nodes[2]
error_interest_name2 = "/DLSU/Miguel/cam1/nothing_here.txt"
try:
    global_stats.set_phase("error_test")
except Exception:
    pass
send_interest_via_ns(error_origin2, seq_num=0, name=error_interest_name2, data_flag=False)
    
max_wait_time = 5
start_time = time.time()
while not error_origin2.has_received_data(error_interest_name2):
    if time.time() - start_time > max_wait_time:
        print(f"[INFO] No data received for {error_interest_name2} (expected - file doesn't exist at destination)")
        break
    time.sleep(0.1) """
    
"""
# destination does not have a filename
print("\n[TEST] Testing error case: destination does not have a filename")
error_origin3 = nodes[0]
error_interest_name3 = "/DLSU/Miguel/cam1"
try:
    global_stats.set_phase("error_test")
except Exception:
    pass
send_interest_via_ns(error_origin3, seq_num=0, name=error_interest_name3, data_flag=False)
    
max_wait_time = 5
start_time = time.time()
while not error_origin3.has_received_data(error_interest_name3):
    if time.time() - start_time > max_wait_time:
        print(f"[INFO] No data received for {error_interest_name3} (expected - no filename provided)")
        break
    time.sleep(0.1)
"""
    # fib tables
    # print("\n--- FIB Tables ---")
    # print("dpc1 FIB:", dpc1.fib)
    # print("andrew FIB:", andrew.fib)
    # print("goks FIB: ", goks.fib)
    # print("henry FIB:", henry.fib)
    # print("dlsu FIB:", dlsu.fib)
    # print("dcam1 FIB", dcam1.fib)
    # print("border router FIB: ", dxa.fib)
    # print("admu FIB: ", admu.fib)
    # print("gonzaga FIB: ", gonzaga.fib)
    # print("acam1 FIB", acam1.fib)
    # print("salcedo FIB", salcedo.fib)

    # print("\n--- PIT Tables ---")
    # print("henry PIT:", henry.pit)
    # print("miguel PIT: ", miguel.pit)
    # print("dlsu PIT:", dlsu.pit)
    # print("goks PIT:", goks.pit)

# DEBUGGING MENU 
class DebugController:
    def print_sorted_logs(self, node_names):
        selected_nodes = [self.nodes[name] for name in node_names if name in self.nodes]
        all_logs = []
        for node in selected_nodes:
            for entry in getattr(node, 'logs', []):
                all_logs.append({"node": getattr(node, 'name', getattr(node, 'ns_name', 'Unknown')), "timestamp": entry["timestamp"], "message": entry["message"]})
        all_logs.sort(key=lambda x: x["timestamp"])
        for log in all_logs:
            print(f"[{log['timestamp']}]: {log['message']}")

    def __init__(self, nodes):
        self.nodes = {}
        for n in nodes:
            if hasattr(n, "name"):
                self.nodes[n.name] = n
            elif hasattr(n, "ns_name"):
                self.nodes[n.ns_name] = n
        self.selected_node = None
        self.command_queue = queue.Queue()


    def list_nodes(self):
        print("\nAvailable Nodes:")
        for n in self.nodes.values():
            node_name = getattr(n, "name", getattr(n, "ns_name", "Unknown"))
            node_port = getattr(n, "port", "N/A")
            print(f"  {node_name}  (port {node_port})")
        print()


    def select_node(self, node_name):
        if node_name in self.nodes:
            self.selected_node = self.nodes[node_name]
            print(f"\n[DEBUG] Zoomed into node: {node_name} (port {self.selected_node.port})")
            if hasattr(self.selected_node, "ns_name"):
                nameserver_debug_menu(self.selected_node)
            else:
                node_debug_menu(self.selected_node)
        else:
            print(f"[DEBUG] Node {node_name} not found.")

    def send_interest(self, origin_name, interest_name, seq_num=0):
        origin = self.nodes.get(origin_name)
        if not origin:
            print(f"[DEBUG] Origin node {origin_name} not found.")
            return

        try:
            send_interest_via_ns(
                origin_node=origin,
                seq_num=seq_num,
                name=interest_name,
                data_flag=False
            )
            print(f"[DEBUG] Sent INTEREST from {origin_name} for {interest_name} (seq={seq_num})")
        except Exception as e:
            print(f"[DEBUG] Failed to send INTEREST: {e}")

    def add_cs(self, node_name, content_name, data_value):
        node = self.nodes.get(node_name)
        if not node:
            print(f"[DEBUG] Node {node_name} not found.")
            return

        try:
            if hasattr(node, "add_cs") and callable(getattr(node, "add_cs")):
                node.add_cs(content_name, data_value)
            else:
                if not hasattr(node, "cs"):
                    node.cs = {}
                node.cs[content_name] = data_value
            print(f"[DEBUG] Added CS entry on {node_name}: {content_name} -> {data_value}")
        except Exception as e:
            print(f"[DEBUG] Failed to add CS entry: {e}")

    def run_test(self, test_id):
        print(f"[DEBUG] Running test case {test_id}...")

        # intra-domain
        if test_id == "1":
            src = self.nodes.get("/DLSU/Andrew/PC1")
            dest = self.nodes.get("/DLSU/Gokongwei")
            if src and dest:
                print("[TEST 1] Sending Interest within DLSU domain...")
                # not sure yet
                try:
                    dest.add_cs("/DLSU/Gokongwei/hello.txt", "Hello from Gokongwei!")
                except Exception:
                    pass
                src.send_interest(
                    seq_num=1,
                    name="/DLSU/Gokongwei/hello.txt",
                    target=("127.0.0.1", dest.port),
                )
            else:
                print("[TEST 1] Nodes not found in registry.")

        # inter-domain
        elif test_id == "2":
            src = self.nodes.get("/DLSU/Andrew/PC1")
            dest = self.nodes.get("/UP/Salcedo/PC1")
            if src and dest:
                print("[TEST 2] Sending Interest across domains (DLSU → UP)...")
                try:
                    dest.add_cs("/UP/Salcedo/PC1/status.txt", "UP Salcedo PC1 is alive")
                except Exception:
                    pass
                src.send_interest(
                    seq_num=10,
                    name="/UP/Salcedo/PC1/status.txt",
                    target=("127.0.0.1", dest.port),
                )
            else:
                print("[TEST 2] Source or destination node not found.")

        # nonexistent node (domain exists)
        elif test_id == "3":
            src = self.nodes.get("/DLSU/Andrew/PC1")
            admu_ns = self.nodes.get("/ADMU/NameServer1")
            if src and admu_ns:
                print("[TEST 3] Sending Interest to nonexistent node in ADMU...")
                src.send_interest(
                    seq_num=20,
                    name="/ADMU/nonexistent_node/hello.pdf",
                    target=("127.0.0.1", admu_ns.port),
                )
            else:
                print("[TEST 3] Source node or ADMU NameServer not found.")

        # nonexistent domain
        elif test_id == "4":
            src = self.nodes.get("/DLSU/Andrew/PC1")
            dlsu_ns = self.nodes.get("/DLSU/NameServer1")
            if src and dlsu_ns:
                print("[TEST 4] Sending Interest to nonexistent domain /XYZ...")
                src.send_interest(
                    seq_num=30,
                    name="/XYZ/UnknownNode/data.txt",
                    target=("127.0.0.1", dlsu_ns.port),
                )
            else:
                print("[TEST 4] Source node or DLSU NameServer not found.")

        # malformed packet
        elif test_id == "5":
            src = self.nodes.get("/DLSU/Andrew/PC1")
            if src:
                print("[TEST 5] Sending malformed packet...")
                import struct
                packet_type = 0x0
                flags = 0x0
                ptf = (packet_type << 4) | (flags & 0xF)
                seq = 0xAA
                name = b"bad"
                name_len = len(name)
                header = struct.pack("!BBB", ptf, seq, name_len)
                payload = header + name + b"\x03" + b"zzz"
                src.sock.sendto(payload, ("127.0.0.1", src.port))
            else:
                print("[TEST 5] Source node not found.")

        else:
            print(f"[DEBUG] Test {test_id} not defined. Use 1-5.")


    def help(self):
        print("""
[DEBUG COMMANDS]
  list                             - show all nodes
  addcs <node> <name> <data>       - add a CS entry
  interest <origin> <name> [seq]   - send Interest
  filter <names...>                - logs for listed nodes
  help                             - show this menu
        """)

    def process_command(self, cmd):
        parts = cmd.strip().split()
        if not parts:
            return False
        match parts[0]:
            case "list":
                self.list_nodes()
            case "select":
                if len(parts) > 1:
                    self.select_node(parts[1])
                else:
                    print("[DEBUG] Usage: select <node_name>")
            case "run":
                if len(parts) > 1:
                    self.run_test(parts[1])
                else:
                    print("[DEBUG] Usage: run <test_id>")
            case "interest":
                # interest <origin_node> <content_name> [seq]
                if len(parts) >= 3:
                    origin_name = parts[1]
                    interest_name = parts[2]
                    try:
                        seq_num = int(parts[3]) if len(parts) > 3 else 0
                    except ValueError:
                        print("[DEBUG] seq_num must be an integer; defaulting to 0.")
                        seq_num = 0
                    self.send_interest(origin_name, interest_name, seq_num)
                else:
                    print("[DEBUG] interest <origin_node_name> <content_name> [seq_num]")
            case "addcs":
                # addcs <node_name> <content_name> <data>
                if len(parts) >= 4:
                    node_name = parts[1]
                    content_name = parts[2]
                    data_value = " ".join(parts[3:])
                    self.add_cs(node_name, content_name, data_value)
                else:
                    print("[DEBUG] addcs <node_name> <content_name> <data>")
            case "help":
                self.help()
            case "exit":
                print("[DEBUG] Exiting debug input thread...")
                self.command_queue.put("exit")
                return True
            case "filter":
                if len(parts) > 1:
                    self.print_sorted_logs(parts[1:])
                else:
                    print("[DEBUG] Usage: filter <node_name> <node_name> ...")
            case _:
                print("[DEBUG] Unknown command. Type 'help' for options.")
        return False


def debug_input_loop(controller):
    controller.help()
    while True:
        cmd = input("> ")
        if controller.process_command(cmd):
            break


# node debug menu
def node_debug_menu(node):
    print(f"\nNode Name/s: {getattr(node, 'name', getattr(node, 'ns_name', 'Unknown'))}")
    print(f"Port: {getattr(node, 'port', 'N/A')}")
    print("[AVAILABLE COMMANDS]")
    print("  view fib")
    print("  view pit")
    print("  view cs")
    print("  view buffer")
    print("  view neighbors")
    print("  view logs")
    print("  back\n")

    while True:
        cmd = input(f"{getattr(node, 'name', 'Node')}> ").strip().lower()
        if cmd == "back":
            print("\n[DEBUG] Returning to global menu...\n")
            break

        elif cmd == "view fib":
            print(f"\n[FIB for {node.name}]")
            print(node.fib if hasattr(node, "fib") else "No FIB table.\n")

        elif cmd == "view pit":
            print(f"\n[PIT for {node.name}]")
            print(node.pit if hasattr(node, "pit") else "No PIT table.\n")

        elif cmd == "view cs":
            print(f"\n[CS for {node.name}]")
            print(node.cs if hasattr(node, 'cs') else "No CS cache.\n")

        elif cmd == "view buffer":
            print(f"\n[BUFFER for {node.name}]")
            if hasattr(node, "buffer"):
                for entry in node.buffer:
                    print(entry)
            else:
                print("No buffer.\n")

        elif cmd == "view neighbors":
            if hasattr(node, "get_neighbors"):
                print(f"\n[Neighbors of {node.name}]")
                print(node.get_neighbors())
            else:
                print("No neighbor table.\n")

        elif cmd == "view logs":
            if hasattr(node, "logs"):
                print(f"\n[Logs for {node.name}]")
                for log in node.logs:
                    print(f"[{log['timestamp']}] {log['message']}")
            else:
                print("No logs found.\n")

        else:
            print("[DEBUG] Unknown command. Type one of: view fib/pit/cs/buffer/neighbors/logs/back")

# nameserver debug menu
def nameserver_debug_menu(ns):
    print(f"\nNameServer: {getattr(ns, 'ns_name', 'Unknown')}")
    print(f"Port: {getattr(ns, 'port', 'N/A')}")
    print("[AVAILABLE COMMANDS]")
    print("  view fib")
    print("  view registry")
    print("  view neighbors")
    print("  back\n")

    while True:
        cmd = input(f"{getattr(ns, 'ns_name', 'NS')}> ").strip().lower()
        if cmd == "back":
            print("\n[DEBUG] Returning to global menu...\n")
            break

        elif cmd == "view fib":
            print(f"\n[FIB for {ns.ns_name}]")
            print(getattr(ns, "fib", "No FIB table.\n"))

        elif cmd == "view registry":
            reg = getattr(ns, "registry", getattr(ns, "registered_nodes", None))
            if reg:
                print(f"\n[Registry for {ns.ns_name}]")
                for name, info in reg.items():
                    print(f"  {name} → {info}")
            else:
                print("No registry or registered nodes.\n")

        elif cmd == "view neighbors":
            if hasattr(ns, "get_neigbors"):
                print(f"\n[Neighbors of {ns.ns_name}]")
                print(ns.get_neigbors())
            else:
                print("No neighbor table.\n")

        else:
            print("[DEBUG] Unknown command. Type one of: view fib/registry/neighbors/back")

controller = DebugController(nodes)

def print_network_statistics():
    global r_count
    """Print comprehensive network statistics"""
    # finalize and collect per-phase stats
    global_stats.finalize()
    phases = ["initialization"] + [f"request{i}" for i in range(1, request_count + 1)]
    phase_stats = {p: global_stats.get_statistics(p) for p in phases}

    # For each phase, compute how many border-interest increments occurred
    # during that phase by scanning border nodes' timestamped logs and
    # applying a 10ms penalty per observed border hop to the phase avg latency.
    try:
        for p in phases:
            s = phase_stats.get(p, {})
            try:
                st_obj = global_stats.phases.get(p)
                if not st_obj or not getattr(st_obj, 'start_time', None):
                    continue
                start = st_obj.start_time
                end = st_obj.end_time or datetime.now()
                border_count = 0
                for n in nodes:
                    if not getattr(n, 'isborder', False):
                        continue
                    logs = getattr(n, 'logs', [])
                    for entry in logs:
                        try:
                            ts = datetime.strptime(entry.get('timestamp', ''), "%Y-%m-%d %H:%M:%S.%f")
                        except Exception:
                            continue
                        if ts >= start and ts <= end and 'border_interest_hops increment' in entry.get('message', ''):
                            border_count += 1
                if border_count > 0:
                    penalty_ms = border_count * 10
                    s['avg_latency_ms'] = s.get('avg_latency_ms', 0.0) + penalty_ms
                    # Adjust per-phase min/max to reflect applied penalty as well
                    s['max_latency_ms'] = s.get('max_latency_ms', 0.0) + penalty_ms
                    s['min_latency_ms'] = s.get('min_latency_ms', 0.0) + penalty_ms
                    # Recompute throughput for the phase after penalty
                    avg_s = s['avg_latency_ms'] / 1000.0 if s['avg_latency_ms'] > 0 else 0
                    s['throughput_bps'] = s.get('total_data_bits', 0) / avg_s if avg_s > 0 else 0
                    s['throughput_kbps'] = s['throughput_bps'] / 1000
                    s['border_hop_penalty'] = border_count
            except Exception:
                continue
    except Exception:
        pass

    # Get base combined stats, but override latency metrics using the
    # already-computed per-phase latencies (now adjusted) to avoid re-sampling jitter.
    combined = global_stats.get_statistics()
    try:
        total_completed = sum((phase_stats[p].get('completed_pairs', 0) for p in phase_stats))
        if total_completed > 0:
            # Weighted average of per-phase average latencies (ms)
            total_latency_ms = sum((phase_stats[p].get('avg_latency_ms', 0.0) * phase_stats[p].get('completed_pairs', 0) for p in phase_stats))
            combined['avg_latency_ms'] = total_latency_ms / total_completed
            # pick extreme values across phases
            phase_maxes = [phase_stats[p].get('max_latency_ms', 0.0) for p in phase_stats if phase_stats[p].get('completed_pairs', 0) > 0]
            phase_mins = [phase_stats[p].get('min_latency_ms', 0.0) for p in phase_stats if phase_stats[p].get('completed_pairs', 0) > 0]
            if phase_maxes:
                combined['max_latency_ms'] = max(phase_maxes)
            if phase_mins:
                combined['min_latency_ms'] = min(phase_mins)
            combined['completed_pairs'] = total_completed
            # Recompute throughput based on the combined avg latency (seconds)
            avg_latency_s = combined['avg_latency_ms'] / 1000.0
            combined['throughput_bps'] = combined['total_data_bits'] / avg_latency_s if avg_latency_s > 0 else 0
            combined['throughput_kbps'] = combined['throughput_bps'] / 1000
    except Exception:
        pass
    # (No combined-level border-hop penalty here — per-phase penalties applied above.)

    print("\n" + "="*80)
    print("NETWORK PERFORMANCE STATISTICS (PER PHASE)")
    print("="*80)

    for p in phases:
        s = phase_stats[p]
        print(f"\n[PHASE] {p}")
        print(f"  Duration:               {s['total_time']:.3f} seconds")
        if s['total_data_bits'] > 0:
            print(f"  Total Data Bits :       {s['total_data_bits']/1000:.1f} kilobits")
        else:
            print(f"  Total Data Bits :       0.000 kilobits")
        print(f"  Total Packets:          {s['total_packets']} packets")
        print(f"    - INTEREST:           {s['packet_counts'].get('INTEREST', 0)}")
        print(f"    - INTEREST_QUERY:     {s['packet_counts'].get('INTEREST_QUERY', 0)}")
        print(f"    - DATA:               {s['packet_counts'].get('DATA', 0)}")
        print(f"    - HELLO:              {s['packet_counts'].get('HELLO', 0)}")
        print(f"    - UPDATE:             {s['packet_counts'].get('UPDATE', 0)}")
        print(f"    - ROUTING_DATA:       {s['packet_counts'].get('ROUTING_DATA', 0)}")
        print(f"    - ROUTE_ACK:          {s['packet_counts'].get('ROUTE_ACK', 0)}")
        print(f"    - ERROR:              {s['packet_counts'].get('ERROR', 0)}")
        print(f"    - REDIRECT_NS:        {s['packet_counts'].get('REDIRECT_NS', 0)}")
        payload_bits = s.get('payload_bits', 0)
        data_control_bits = s.get('data_control_bits', 0)
        non_data_bits = s.get('non_data_bits', 0)
        control_bits = data_control_bits + non_data_bits
        total_bits = payload_bits + control_bits
        if total_bits > 0:
            print(f"  Control Bits :          {control_bits}/{total_bits} ({s['control_overhead_percent']:.2f}% overhead)")
        else:
            print(f"  Control Bits :          0/0 (0.00% overhead)")
        print(f"  Avg Latency:            {s['avg_latency_ms']:.3f} ms")
        print(f"  Throughput:             {s['throughput_kbps']:.3f} Kbps")
        if s['total_hops']==0:
            print(f"  Total Hops:             0 hops")
        else:
            s['total_hops'] -= 1
            print(f"  Total Hops:             {s['total_hops']} hops")
        print(f"  Completed Pairs:        {s.get('completed_pairs', 0)}")
        # Print paths for completed interest-data pairs in this phase
        try:
            st = global_stats.phases.get(p)
            if st and getattr(st, 'interest_data_pairs', None):
                for key, info in st.interest_data_pairs.items():
                    # only show completed pairs
                    if 'interest_time' in info and 'data_time' in info:
                        ipath = info.get('interest_path', [])
                        print(f"  Interest/Data path:     {ipath}")
        except Exception:
            pass

    print("\n" + "="*80)
    print("NETWORK PERFORMANCE STATISTICS (COMBINED)")
    print("="*80)

    print("\n[LATENCY METRICS]")
    print(f"  Average Latency:        {combined['avg_latency_ms']:.3f} ms")
    print(f"  Maximum Latency:        {combined['max_latency_ms']:.3f} ms")
    print(f"  Minimum Latency:        {combined['min_latency_ms']:.3f} ms")
    print(f"  Completed Requests:     {combined['completed_pairs']}")

    print("\n[THROUGHPUT METRICS]")
    print(f"  Total Data Transmitted: {combined['total_data_bits']/1000:.1f} kilobits")
    if combined['avg_latency_ms'] == 0 or combined['completed_pairs'] == 0:
        print(f"  Throughput:             0.000 Kbps")
    else: 
        print(f"  Throughput:             {((combined['total_data_bits']/combined['avg_latency_ms'])/combined['completed_pairs']):.3f} Kbps")
    print(f"  Test Duration:          {combined['total_time']:.3f} seconds")

    print("\n[PACKET TRANSMISSION OVERHEAD]")
    print(f"  Total Packets Sent:     {combined['total_packets']} packets")
    print(f"    - INTEREST:           {combined['packet_counts'].get('INTEREST', 0)}")
    print(f"    - INTEREST_QUERY:     {combined['packet_counts'].get('INTEREST_QUERY', 0)}")
    print(f"    - DATA:               {combined['packet_counts'].get('DATA', 0)}")
    print(f"    - ROUTING_DATA:       {combined['packet_counts'].get('ROUTING_DATA', 0)}")
    print(f"    - HELLO:              {combined['packet_counts'].get('HELLO', 0)}")
    print(f"    - UPDATE:             {combined['packet_counts'].get('UPDATE', 0)}")
    print(f"    - ERROR:              {combined['packet_counts'].get('ERROR', 0)}")
    print(f"    - ROUTE_ACK:          {combined['packet_counts'].get('ROUTE_ACK', 0)}")
    print(f"    - REDIRECT_NS:        {combined['packet_counts'].get('REDIRECT_NS', 0)}")


    print("\n[CONTROL OVERHEAD]")
    print(f"  Control Packets:        {combined['control_packets']} packets")
    total_bits_combined = combined.get('payload_bits', 0) + combined.get('control_bits', 0)
    if total_bits_combined > 0:
        print(f"  Control Bits:           {combined.get('control_bits', 0)}/{total_bits_combined} ({combined['control_overhead_percent']:.2f}% overhead)")
    else:
        print(f"  Control Bits:           0/0 (0.00% overhead)")
    print(f"   - Data header bits:    {combined.get('data_control_bits', 0)} bits")
    print(f"   - Non-DATA packet bits:{combined.get('non_data_bits', 0)} bits")
    print(f"  Data Packet Ratio:      {100 - combined['control_overhead_percent']:.2f}%")

    print("\n[ROUTING HOPS]")
    if combined['total_hops']==0:
        print(f"  Total Hops:             0 hops")
    else:
        print(f"  Total Hops:             {combined['total_hops']-combined['packet_counts'].get('INTEREST')} hops")

    # Border routers: print per-node and total border interest hops
    try:
        border_nodes = [n for n in nodes if getattr(n, 'isborder', False)]
        if border_nodes:
            total_border_hops = 0
            print("\n[BORDER INTEREST HOPS]")
            for bn in border_nodes:
                hops = getattr(bn, 'border_interest_hops', 0)
                total_border_hops += hops
                print(f"  {getattr(bn, 'name', 'unknown')}: {hops} hops")
            print(f"  Total Border Interest Hops: {total_border_hops} hops")
    except Exception:
        pass

    print("\n" + "="*80)

"""
input_thread = threading.Thread(target=debug_input_loop, args=(controller,), daemon=True)
input_thread.start()


# Keep running
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    for node in nodes:
        node.stop()
"""
from gui import LogGUI

# Print statistics before starting GUI
print_network_statistics()

LogGUI(controller).run()
