from Packet import Packet

# Packet Types (4 bits)
INTEREST = 0x1
DATA = 0x2
ROUTING_DATA = 0x3
HELLO = 0x4
UPDATE = 0x5
ERROR = 0x6

class RouteDataPacket(Packet):
    def __init__(self, seq_num, name, flags=0x0, timestamp=None, path=None, raw_routing_info=None, routing_info=None):
        super().__init__(ROUTING_DATA, flags, seq_num, timestamp)
        self.name = name
        self.name_bytes = name.encode("utf-8")
        self.name_length = len(self.name_bytes)
        self.path = path if path is not None else []
        self.raw_routing_info = raw_routing_info if raw_routing_info is not None else ""
        self.routing_info = routing_info
        if routing_info is not None:
            if isinstance(routing_info, str):
                self.routing_info_bytes = routing_info.encode("utf-8")
            else:
                self.routing_info_bytes = routing_info
            self.info_size = len(self.routing_info_bytes)
        else:
            self.routing_info_bytes = b""
            self.info_size = 0

    def __repr__(self):
        return (f"<RouteDataPacket PacketType={self.packet_type} Flags={self.flags} "
                f"SequenceNumber={self.seq_num} InfoSize={self.info_size} "
                f"NameLength={self.name_length} Name={self.name} "
                f"Path={self.path} RawRoutingInfo={self.raw_routing_info} "
                f"Timestamp={self.timestamp}>")