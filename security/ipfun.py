import socket
import scapy.all as scapy

def get_ip_from_host(host: str):
    ''' Return (hostname, aliases, ipaddrlist) from host name. Supports ipv4 only.'''
    try:
        ips = socket.gethostbyname_ex(host)
    except socket.gaierror:
        ips = None
    return ips

# print(get_ip_from_host('www.google.com'))
# print(get_ip_from_host('www.manga4life.com'))


def host_traffic():
    ''' Returns the traffic of the host. '''
    packets = scapy.sniff()
    packets.summary()

host_traffic()
