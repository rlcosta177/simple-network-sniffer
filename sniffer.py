import socket
from scapy.all import *
from scapy.layers.l2 import Ether

interface = "wlp2s0"

# essentially: it's a raw packet sniffer that captures all packets
# captures packets(layers 2-7) / all info about them(like ip, layer4 protocol etc.) / captures all ethernet frames no matter the protocol(arp, icmp, dhcp etc.)
sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

# binds the socket into a network interface (e.g. eth0(ethernet), wlp2s0(wifi))
sniffer_socket.bind((interface, 0))

try:
    while True:
        # 2^16 | ipv4 length field is 16 bits long. max mtu size is 1518
        #      | udp length field is 16 bits long as well
        #      | layer 7 packets can go up to 8MB, so the are fragmented into smaller sizes
        #      | from 1518-65535.
        #      | so generally, you would use 65535 to capture all the protocols, if you want only
        #      | a specific protocol, change the byte size accordingly
        raw_data, addr = sniffer_socket.recvfrom(65535)

        # format the raw data into human readable text
        packet = Ether(raw_data)

        print(packet.summary())

except KeyboardInterrupt:
    sniffer_socket.close()
