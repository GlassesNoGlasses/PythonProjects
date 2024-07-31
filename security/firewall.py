import socket
import scapy.all as scapy
import pandas as pd
import numpy as np
from ipaddress import ip_address

CSV_FIELDS = ['host', 'aliases', 'ips', 'inbound', 'outbound', 'protocol']

class FirewallConfig():
    
    def __init__(self, csv_file: str, autosave: bool = True) -> None:
        self.config = pd.DataFrame(columns=CSV_FIELDS)
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

        self.config.to_csv(self.csv_file, columns=CSV_FIELDS, index=False)

    
    def load_config(self, csv: str) -> bool:
        ''' Load the firewall configuration from a csv file. '''

        self.config = pd.read_csv(csv)

        if (self.config.empty):
            return False
        
        return True


    def update_config(self, host: str, aliases: list[str], ips: list[str], inbound: bool = True, 
                      outbound: bool = True, protocol: str | None = None) -> bool:
        ''' Update the configuration. '''

        filtered_ips = self.filter_ips(ips)

        if not filtered_ips:
            return False
        
        next_index = 0 if pd.isnull(self.config.index.max()) else self.config.index.max() + 1

        self.config.loc[next_index] = [host, aliases, filtered_ips, inbound, outbound, protocol]
        print(self.config)
        
        if self.autosave:
            self.save_config()
        
        return True
    
    def delete_config(self, host: str) -> None:
        ''' Delete a configuration. '''

        self.config = self.config.drop(host)

        if self.autosave:
            self.save_config()
    
    def show_config(self, count: None | int = None) -> dict:
        ''' Show the configuration. '''

        print(self.config.head(count)) if count else print(self.config)


class Firewall():

    def __init__(self, ip_addr: str = "0.0.0.0", auto_save: bool = True, csv_file: str = "./firewall.csv") -> None:

        self.config = FirewallConfig(autosave=auto_save, csv_file=csv_file)
        self.ip_addr = ip_addr
        self.csv_file = csv_file
    

    def get_ip_from_host(self, host: str):
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
    google, google_aliases, google_ips = firewall.get_ip_from_host('www.google.com')
    manga4life, manga4life_aliases, manga4life_ips = firewall.get_ip_from_host('www.manga4life.com')

    firewall.add_firewall(google, google_aliases, google_ips)
    firewall.add_firewall(manga4life, manga4life_aliases, manga4life_ips)

    firewall.show_firewalls()

main()

