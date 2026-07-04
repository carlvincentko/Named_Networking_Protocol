from Packet import Packet

# Packet Types (4 bits)
INTEREST = 0x1
DATA = 0x2
ROUTING_DATA = 0x3
HELLO = 0x4
UPDATE = 0x5
ERROR = 0x6

class InterestPacket(Packet):
    def __init__(self, seq_num, name, flags=0x0, timestamp=None):
        super().__init__(INTEREST, flags, seq_num, timestamp)
        self.name = name
        self.name_length = len(name.encode("utf-8"))

    def __repr__(self):
        return (f"<InterestPacket PacketType={self.packet_type} Flags={self.flags} "
                f"SequenceNumber={self.seq_num} NameLength={self.name_length} "
                f"Name={self.name} Timestamp={self.timestamp}>")