
import random
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
        return str(IPv6Address(random.randint(0, MAX_IPV6)))

    return str(IPv4Address(random.randint(0, MAX_IPV4)))


def validIPAddress(ip: str) -> bool:
    ''' Check if the ip address is valid. Returns "IPv4" or "IPv6" if valid, None otherwise. '''
    try:
        if ip_address(ip).version == 4 or ip_address(ip).version == 6:
            return True
    except ValueError:
        print("Invalid IP address: ", ip)
    
    return None


def create_packet(payload: bytes, source_ip: str, dest_ip: str, protocol: str = 'tcp') -> bytes | None:
    ''' Creates a pseudo network layer packet with the payload and source/dest IP addresses. '''

    if not validIPAddress(source_ip) or not validIPAddress(dest_ip) or ip_address(source_ip).version != ip_address(dest_ip).version:
        return None
    
    protocol = PROTOCOLS[protocol.lower()] if protocol.lower() in PROTOCOLS.keys() else None

    if not protocol:
        return None


    return ipv4_packet_header(version=ip_address(source_ip).version, 
                            protocol=protocol, source_ip=source_ip, dest_ip=dest_ip, payload=payload)


def ipv4_packet_header(version: 4 | 6, protocol: int, source_ip: str, dest_ip: str, payload: bytes) -> bytes:
    ''' Create an IP packet with the given parameters. '''

    # ip packet header fields
    ihl = 5 # Internet Header Length; 20 bytes constant
    source_ip = ip_address(source_ip).packed
    dest_ip = ip_address(dest_ip).packed
    tos = 0 # Type of Service; 0 for normal
    ttl = 255 # Time to Live; 255 for maximum
    checksum = 0 # Checksum; 0 for now
    total_length = ihl + len(payload)
    identification = random.randint(0, 65535)

    header = pack("!BBHHHBBH4s4s", version, ihl, tos, total_length, identification, ttl, protocol, checksum, source_ip, dest_ip)
    return header + payload


def unpack_ipv4_packet(packet: bytes):
    ''' Unpack an IPv4 packet and return (protocol, src_ip, dest_ip, payload) '''

    ipv4_h = unpack("!BBHHHBBH4s4s", packet[:20])

    protocol = ipv4_h[6]
    src_ip = inet_ntoa(ipv4_h[8])
    dest_ip = inet_ntoa(ipv4_h[9])

    return protocol, src_ip, dest_ip, packet[20:]

