
from random import randint
from socket import inet_ntoa
from struct import pack, unpack
from ipaddress import ip_address, IPv4Address, IPv6Address

PROTOCOLS = {
    'tcp': 6,
    'udp': 17,
}

def generate_ip(version: 4 | 6 = 4) -> str:
    ''' Generates a randome IP address. Defaults to IPv4. To specify IPv6, pass in 6 as the version.'''

    MAX_IPV4 = IPv4Address._ALL_ONES  # 2 ** 32 - 1
    MAX_IPV6 = IPv6Address._ALL_ONES  # 2 ** 128 - 1

    if version == 6:
        return str(IPv6Address(randint(0, MAX_IPV6)))

    return str(IPv4Address(randint(0, MAX_IPV4)))


def validIPAddress(ip: str) -> bool:
    ''' Check if the ip address is valid. Returns "IPv4" or "IPv6" if valid, None otherwise. '''
    try:
        if ip_address(ip).version == 4 or ip_address(ip).version == 6:
            return True
    except ValueError:
        print("Invalid IP address: ", ip)
    
    return None


def create_packet(payload: bytes, source_ip: str, dest_ip: str, source_port: int, dest_port: int, 
                  protocol: str = 'tcp') -> bytes | None:
    ''' Creates a pseudo network layer packet with the payload and source/dest IP addresses. 
        Returns an IPv4 packet with protocol as protocol if successful, None otherwise. '''

    if not validIPAddress(source_ip) or not validIPAddress(dest_ip) or ip_address(source_ip).version != ip_address(dest_ip).version:
        return None
    
    protocol = PROTOCOLS[protocol.lower()] if protocol.lower() in PROTOCOLS.keys() else None

    if not protocol:
        return None
    
    if protocol == PROTOCOLS['tcp']:
        payload = tcp_packet(source_port=source_port, dest_port=dest_port, payload=payload)
    elif protocol == PROTOCOLS['udp']:
        payload = udp_packet(source_port=source_port, dest_port=dest_port, payload=payload)
    
    if ip_address(source_ip).version == 4:
        return ipv4_packet(protocol=protocol, source_ip=source_ip, dest_ip=dest_ip, payload=payload)

    return None


def udp_packet(source_port: int, dest_port: int, payload: bytes) -> bytes:
    ''' Create a UDP packet with the given parameters. '''

    # udp packet header fields
    length = 8 + len(payload) # 8 bytes for header + payload length
    checksum = 0 # checksum; 0 for now

    header = pack("!HHHH", source_port, dest_port, length, checksum)
    return header + payload


def unpack_udp_packet(packet: bytes):
    ''' Unpack a UDP packet and return (src_port, dest_port, payload) '''

    udp_h = unpack("!HHHH", packet[:8])

    src_port = udp_h[0]
    dest_port = udp_h[1]

    return src_port, dest_port, packet[8:]


def unpack_tcp_packet(packet: bytes):
    ''' Unpack a TCP packet and return (src_port, dest_port, payload) '''

    tcp_h = unpack("!HHLLBBHHH", packet[:20])

    src_port = tcp_h[0]
    dest_port = tcp_h[1]

    return src_port, dest_port, packet[20:]


def tcp_packet(source_port: int, dest_port: int, payload: bytes) -> bytes:
    ''' Create a TCP packet with the given parameters. '''

    # tcp packet header fields
    seq_num = randint(0, 65535) # random sequence number
    ack_num = 0 # no ack number as first packet in connection
    data_offset = 5 # 20 bytes constant
    reserved = 0 # reserved bits
    window_size = 8192 # window size
    checksum = 0 # checksum; 0 for now
    urgent_pointer = 0 # no urgent pointer

    header = pack("!HHLLBBHHH", source_port, dest_port, seq_num, ack_num, data_offset, reserved, window_size, checksum, urgent_pointer)
    return header + payload


def ipv4_packet(protocol: int, source_ip: str, dest_ip: str, payload: bytes) -> bytes:
    ''' Create an IPv4 packet with the given parameters. '''

    # ip packet header fields
    ihl = 5 # Internet Header Length; 20 bytes constant
    source_ip = ip_address(source_ip).packed
    dest_ip = ip_address(dest_ip).packed
    tos = 0 # Type of Service; 0 for normal
    ttl = 255 # Time to Live; 255 for maximum
    checksum = 0 # Checksum; 0 for now
    total_length = ihl + len(payload)
    identification = randint(0, 65535)

    header = pack("!BBHHHBBH4s4s", 4, ihl, tos, total_length, identification, ttl, protocol, checksum, source_ip, dest_ip)
    return header + payload


def unpack_ipv4_packet(packet: bytes):
    ''' Unpack an IPv4 packet and return (protocol, src_ip, dest_ip, payload) '''

    ipv4_h = unpack("!BBHHHBBH4s4s", packet[:20])

    protocol = ipv4_h[6]
    src_ip = inet_ntoa(ipv4_h[8])
    dest_ip = inet_ntoa(ipv4_h[9])

    return protocol, src_ip, dest_ip, packet[20:]



