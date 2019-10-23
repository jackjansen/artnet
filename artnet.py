#!/usr/bin/env python3
import sys
import socket
import struct

MAX_PACKET_SIZE=16384

class ArtNetReceiver:
    
    def __init__(self):
        self.addr = ('', 6454)
        self.sock = socket.socket(socket.SOCK_DGRAM, socket.AF_INET)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.sock.bind(self.addr)
        self.handlers = {
        }
        
    def log(self, msg):
        print(msg, file=sys.stderr)
        
    def run(self):
        while True:
            self.run1()
    
    def run1(self):
        pkt, peer = self.sock.recvfrom(MAX_PACKET_SIZE)
        if len(pkt) < 10:
            self.log(f"{peer[0]}:{peer[1]}: Short packet, len={len(pkt)}")
            return False
        ident, opcode = struct.unpack('<8sh', pkt)
        if ident != b'Art-Net\0':
            self.log(f"{peer[0]}:{peer[1]}: Unknown packet, len={len(pkt)}, data={repr(pkt)}")
            return False
        handler = self.handlers.get(opcode, self.defaultHandler)
        return handler(peer, opcode, pkt)
        
    def defaultHandler(self, peer, opcode, pkt):
        self.log(f"{peer[0]}:{peer[1]}: Unhandled opcode {opcode}. Data={repr(pkt)}")
        
def main():
    a = ArtNetReceiver()
    a.run()
    
if __name__ == '__main__':
    main()
