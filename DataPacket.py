from Packet import Packet

# Packet Types (4 bits)
INTEREST = 0x1
DATA = 0x2
ROUTING_DATA = 0x3
HELLO = 0x4
UPDATE = 0x5
ERROR = 0x6

class DataPacket(Packet):
    def __init__(self, seq_num, name, payload, flags=0x0, timestamp=None):
        super().__init__(DATA, flags, seq_num, timestamp)
        self.name = name
        self.name_length = len(name.encode("utf-8"))
        self.payload = payload
        self.payload_size = len(payload.encode("utf-8")) if isinstance(payload, str) else len(payload)

    def __repr__(self):
        type_names = {
            INTEREST: 'INTEREST',
            DATA: 'DATA',
            ROUTING_DATA: 'ROUTING_DATA',
            HELLO: 'HELLO',
            UPDATE: 'UPDATE',
            ERROR: 'ERROR',
        }
        pkt_type_name = type_names.get(self.packet_type, str(self.packet_type))
        return (
            f"<DataPacket\n"
            f"  PacketType={pkt_type_name}\n"
            f"  Flags={self.flags}\n"
            f"  SequenceNumber={self.seq_num}\n"
            f"  PayloadSize={self.payload_size} bytes\n"
            f"  NameLength={self.name_length}\n"
            f"  Name={self.name}\n"
            f"  Timestamp={self.timestamp}\n"
            f">"
        )