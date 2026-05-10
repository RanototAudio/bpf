#!/usr/bin/env python3
import socket
import struct
import sys

def checksum(data):
    if len(data) % 2 == 1:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def main():
    if len(sys.argv) > 1:
        interface = sys.argv[1]
    else:
        interface = "lo"
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.bind((interface, 0))
    except PermissionError:
        print("Error: Must run as root to use raw sockets.")
        sys.exit(1)

    print(f"Naive packet modifier starting on {interface}...")
    print("This script sniffs for UDP 'hello' and would send a modified 'bye  ' packet.")
    print("Note: Unlike XDP, this cannot easily 'block' the original packet without NFQUEUE.")

    try:
        while True:
            packet, addr = sock.recvfrom(65535)
            
            if len(packet) < 14: continue
            eth_header = packet[:14]
            eth_proto = struct.unpack('!H', eth_header[12:14])[0]
            
            if eth_proto != 0x0800: # Not IPv4
                continue
                
            if len(packet) < 34: continue
            ip_header = packet[14:34]
            iph = struct.unpack('!BBHHHBBHII', ip_header)
            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            protocol = iph[6]
            
            if protocol != 17: # Not UDP
                continue
            udp_start = 14 + iph_length
            if len(packet) < udp_start + 8: continue
            udp_header = packet[udp_start:udp_start+8]
            udph = struct.unpack('!HHHH', udp_header)
            payload_start = udp_start + 8
            payload = packet[payload_start:]
            
            if payload.startswith(b"hello"):
                print(f"Captured 'hello' from {socket.inet_ntoa(struct.pack('!I', iph[8]))}")
                
                new_payload = b"bye  " + payload[5:]
                
    except KeyboardInterrupt:
        print("\nStopping...")

if __name__ == "__main__":
    main()
