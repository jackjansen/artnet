#!/usr/bin/env python3
import sys
import socket
import struct

MAX_PACKET_SIZE=16384

class ArtNetReceiver:
    
    def __init__(self):
        self.addr = ('', 6454)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.sock.bind(self.addr)
        self.handlers = {
            0x2000 : self.pollHandler,
            0x2100 : self.pollReplyHandler
        }
        self.dmxPortAddress = 0x1234
        self.dmxShortName = 'pyartnet'
        self.dmxLongName = f'Python Artnet receiver on {socket.gethostname()}'
        
    def log(self, msg):
        print(msg, file=sys.stderr)
        
    def reply(self, addr, opcode, pktData):
        pkt = struct.pack('<8sh', b'Art-Net\0', opcode) + pktData
        self.sock.sendto(pkt, addr)
        
    def findOurIP(self, peer):
        s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s2.connect(peer)
        ourIP, _ = s2.getsockname()
        s2.close()
        return ourIP
    def run(self):
        while True:
            self.run1()
    
    def run1(self):
        pkt, peer = self.sock.recvfrom(MAX_PACKET_SIZE)
        if len(pkt) < 10:
            self.log(f"{peer[0]}:{peer[1]}: Short packet, len={len(pkt)}")
            return False
        ident, opcode = struct.unpack('<8sh', pkt[:10])
        if ident != b'Art-Net\0':
            self.log(f"{peer[0]}:{peer[1]}: Unknown packet, len={len(pkt)}, data={repr(pkt)}")
            return False
        handler = self.handlers.get(opcode, self.defaultHandler)
        return handler(peer, opcode, pkt[10:])
        
    def defaultHandler(self, peer, opcode, pktData):
        self.log(f"{peer[0]}:{peer[1]}: Unhandled opcode {opcode}. Data={repr(pktData)}")
        return False
        
    def pollHandler(self, peer, opcode, pktData):
        protoVersion, flags, prio = struct.unpack('>hbb', pktData)
        self.log(f"{peer[0]}:{peer[1]}: poll(version={protoVersion}, flags={flags}, prio={prio})")
        if protoVersion != 14:
            return False
        ourIP = self.findOurIP(peer)
        ourPort = self.addr[1]
        ourVersion = 1
        ourOEM = 0
        ourUBEA = 0
        ourStatus = 0b00010000
        ourESTA = 0xf07f # 0x7ff0
        ourNodeReport = '#0001 [0000] All is well'
        numPorts = 1
        port0Info = 0b10000000
        ourMac = b'\x08\0x00jack'
        ourStatus2 = 0b00001000
        replyData = struct.pack('!4sBBhhhBBH18s64s64sh4B4B4B4B4Bxxx3xx6s4sBB26x', 
            socket.inet_aton(ourIP), 
            ourPort>>8, 
            ourPort&0xff, 
            ourVersion, 
            self.dmxPortAddress & 0xfff0, 
            ourOEM, 
            ourUBEA, 
            ourStatus, 
            ourESTA, 
            self.dmxShortName.encode('ascii'),
            self.dmxLongName.encode('ascii'),
            ourNodeReport.encode('ascii'),
            numPorts,
            port0Info, 0, 0, 0, # Port types
            0, 0, 0, 0, # Input port status
            0, 0, 0, 0, # Output port status
            0, 0, 0, 0, # Input port addresses
            self.dmxPortAddress & 0xf, 0, 0, 0, # Output port addresses
            ourMac,
            socket.inet_aton(ourIP), # Bind IP address
            0, # Bind index
            ourStatus2
            )
            
        self.reply(peer, 0x2100, replyData)
        return True

    def pollReplyHandler(self, peer, opcode, pktData):
        self.log(f"{peer[0]}:{peer[1]}: ignoring pollReply")
       
def main():
    a = ArtNetReceiver()
    a.run()
    
if __name__ == '__main__':
    main()
