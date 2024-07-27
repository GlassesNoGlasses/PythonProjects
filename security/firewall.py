import socket
import scapy.all as scapy
import csv
from ipaddress import ip_address, IPv4Address

CSV_FIELDS = ['host', 'aliases', 'ips', 'inbound', 'outbound', 'protocol']


class FirewallConfig():
    
    def __init__(self, csv_file: str, autosave: bool = True) -> None:
        self.config = {}
        self.default = {'inbound': True, 'outbound': True, 'protocol': None}
        self.csv_file = csv_file
        self.autosave = autosave
    
    def validIPAddress(self, ip: str) -> str:
        ''' Check if the ip address is valid. Returns "IPv4" or "IPv6" if valid, None otherwise. '''
        try:
            if ip_address(ip).version == 4:
                return "IPv4"
            elif ip_address(ip).version == 6:
                return "IPv6"
        except ValueError:
            return None
        
        return None
    
    def filter_ips(self, ips: list[str]) -> list[str]:
        ''' Filter out invalid ip addresses. '''
        return [ip for ip in ips if self.validIPAddress(ip)]
    
    def save_config(self) -> None:
        ''' Save the firewall configuration to a csv file. '''

        with open(self.csv_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=CSV_FIELDS)
            writer.writeheader()

            for host, data in self.config.items():
                writer.writerow({'host': host, 'aliases': data['aliases'], 'ips': data['ips'], 'inbound': data['inbound'], 'outbound': data['outbound'], 'protocol': data['protocol']})
    
    def load_config(self) -> bool:
        ''' Load the firewall configuration from a csv file. '''

        try:
            with open(self.csv_file, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    self.config[row['host']] = {'aliases': row['aliases'], 'ips': row['ips'], 'inbound': row['inbound'], 'outbound': row['outbound'], 'protocol': row['protocol']}
        except FileNotFoundError:
            return False
        
        return True

    
    def update_config(self, host: str, aliases: list[str], ips: list[str], inbound: bool = True, 
                      outbound: bool = True, protocol: str | None = None) -> bool:
        ''' Update the configuration. '''

        filtered_ips = self.filter_ips(ips)

        if not filtered_ips:
            return False
        
        self.config[host] = {'aliases': aliases, 'ips': filtered_ips, 'inbound': inbound, 'outbound': outbound, 'protocol': protocol}

        if self.autosave:
            self.save_config()
        
        return True
    
    def delete_config(self, host: str) -> bool:
        ''' Delete a configuration. '''
        if host in self.config:
            del self.config[host]
            return True
        return False


class Firewall():

    def __init__(self, ip_addr = None, auto_save: bool = True, csv_file: str = "./firewall.csv") -> None:

        self.config = FirewallConfig(autosave=auto_save, csv_file=csv_file)
        self.ip_addr = ip_addr if ip_addr else self.get_ip()
        self.csv_file = csv_file
    
    def get_ip():
        ''' Get's the ip address of the host. '''
        return socket.gethostbyname(socket.gethostname())
        
    def get_ip_from_host(host: str):
        ''' Return (hostname, aliases, ipaddrlist) from host name. Supports ipv4 only.'''
        try:
            ips = socket.gethostbyname_ex(host)
        except socket.gaierror:
            ips = None
        return ips

    def add_firewall(self, host: str, aliases: list[str], ips: list[str], inbound: bool = True, 
                     outbound: bool = True, protocol: str | None = None) -> bool:
        ''' Add a firewall rule. '''

        # filter inputs to ensure they are valid
        if not host or not ips:
            return False
        
        # parse invalid inputs to ensure they are valid
        try:
            host = host.strip().split()[0]
            aliases = [aliase.strip().split()[0] for aliase in aliases]
        except AttributeError:
            return False

        return self.config.update_config(host, aliases, ips, inbound, outbound, protocol)
    
    def show_firewalls(self) -> dict:
        ''' Show the firewall configuration. '''
        return self.config.config


def main():
    firewall = Firewall()
    print(firewall.ip_addr)
    print(firewall.get_ip_from_host('www.google.com'))
    print(firewall.get_ip_from_host('www.manga4life.com'))

