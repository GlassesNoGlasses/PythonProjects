
import random
from ipaddress import ip_address, IPv4Address, IPv6Address

def generate_ip(version: int = 4) -> str:
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
