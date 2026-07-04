from datetime import datetime

# Packet Types (4 bits)
INTEREST = 0x1
DATA = 0x2
ROUTING_DATA = 0x3
HELLO = 0x4
UPDATE = 0x5
ERROR = 0x6

class Packet:
    def __init__(self, packet_type, flags, seq_num, timestamp=None):
        self.packet_type = packet_type
        self.flags = flags
        self.seq_num = seq_num
        self.timestamp = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    def __repr__(self):
        return f"<Packet type={self.packet_type} seq={self.seq_num} flags={self.flags} ts={self.timestamp}>"