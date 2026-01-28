# protocol.py
import struct

# Cabeçalho: seq(4) | ack(4) | flags(1) | rwnd(2)
HEADER_FORMAT = "!IIBH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

FLAG_SYN  = 0x01
FLAG_ACK  = 0x02
FLAG_FIN  = 0x04
FLAG_DATA = 0x08
FLAG_KEY  = 0x10 

def make_packet(seq, ack, flags, rwnd=0, payload=b""):
    header = struct.pack(HEADER_FORMAT, seq, ack, flags, rwnd)
    return header + payload

def parse_packet(data):
    header = data[:HEADER_SIZE]
    payload = data[HEADER_SIZE:]
    seq, ack, flags, rwnd = struct.unpack(HEADER_FORMAT, header)
    return seq, ack, flags, rwnd, payload