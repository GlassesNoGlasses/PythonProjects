import socket
import scapy.all as scapy
import pandas as pd
from ipaddress import ip_address

# csv file config
CSV_FIELDS = ['host', 'aliases', 'ips', 'inbound', 'outbound', 'protocol']

# load respective scapy layers
scapy.load_layer("http")
scapy.load_layer("tls")
scapy.load_layer("dns")

class FirewallConfig():
    
    def __init__(self, csv_path: str, ip_addr: str, autosave: bool = True) -> None:
        # user's ip address
        self.ip_addr = ip_addr

        # store configuration of the firewall
        self.config = pd.DataFrame(columns=CSV_FIELDS)

        # cache frequent ip addresses for inbound/outbound allowance
        self.cache = {'inbound': [], 'outbound': []}

        # default settings for the firewall
        self.default = {'inbound': True, 'outbound': True, 'protocol': None}

        # csv file path to save configuration
        self.csv_path = csv_path

        # autosave configuration; defaults to true
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

        self.config.to_csv(self.csv_path, columns=CSV_FIELDS, index=False)

    
    def load_config(self, csv: str) -> bool:
        ''' Load the firewall configuration from a csv file. '''

        self.config = pd.read_csv(csv)

        if (self.config.empty):
            return False
        
        return True


    def update_config(self, host: str, aliases: list[str], ips: list[str], inbound: bool, 
                      outbound: bool, protocol: str | None) -> bool:
        ''' Update the configuration. '''

        filtered_ips = self.filter_ips(ips)
        index = -1

        if not filtered_ips or not host:
            return False

        inbound = inbound if inbound else self.default['inbound']
        outbound = outbound if outbound else self.default['outbound']
        protocol = protocol if protocol else self.default['protocol']
        
        # existing host in the configuration
        if host in self.config['host'].values:
            index = self.config[self.config['host'] == host].index.values[0]
        else:
            index = 0 if pd.isnull(self.config.index.max()) else self.config.index.max() + 1
        
        # add to config
        self.config.loc[index, CSV_FIELDS] = [host, aliases, filtered_ips, inbound, outbound, protocol]

        # add to cache
        self.cache['inbound'] += filtered_ips if inbound else []
        self.cache['outbound'] += filtered_ips if outbound else []
        
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


    def packet_filter(self, packet) -> bool:
        ''' Filter packets. '''

        # want only tcp/udp packets for network traffic
        is_traffic = packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP)

        if (not is_traffic):
            return False

        # filter packets based on current machines ip address src/dst
        sip = packet[IPv6].src if (IPv6 in packet) else packet[IP].src
        dip = packet[IPv6].dst if (IPv6 in packet) else packet[IP].dst

        is_user = sip == self.ip_addr or dip == self.ip_addr

        # print("Packet is allowed.") if is_traffic and is_user else print("Packet is blocked.")

        return is_traffic and is_user



    def packet_prn(self, packet) -> None:
        ''' Perform actions on packets. '''

        if packet.haslayer(scapy.IP):
            sip = packet[IPv6].src if (IPv6 in packet) else packet[IP].src
            dip = packet[IPv6].dst if (IPv6 in packet) else packet[IP].dst

            if sip in self.cache['inbound']:
                print(f"Packet from {sip} is blocked.")
                return
            elif dip in self.config['outbound']:
                print(f"Packet to {dip} is blocked.")
                return
            else:
                print(f"Packet from {sip} to {dip} is allowed.")
                return
        
        print("Packet is allowed.")
        return


class Firewall():

    def __init__(self, ip_addr = None, auto_save: bool = True, csv_path: str = "./firewall.csv") -> None:
        # fetch the ip address of the current machine
        ip_addr = ip_addr if ip_addr else self.initialize_ip()

        # initialize config
        self.fw_config = FirewallConfig(autosave=auto_save, csv_path=csv_path, ip_addr=ip_addr)
    
    
    def initialize_ip(self) -> str:
        ''' Initialize and fetch for the current machine's ip address. '''

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()

        return ip
    

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

        return self.fw_config.update_config(host, aliases, ips, inbound, outbound, protocol)
    
    def show_firewall(self) -> dict:
        ''' Show the firewall configuration. '''

        self.fw_config.show_config()
    

    def run(self, count: int | None = None) -> None:
        ''' Run the firewall. '''
        
        capture = scapy.sniff(lfilter=self.fw_config.packet_filter, count=count, prn=self.fw_config.packet_prn)
        capture.show()

def main():
    firewall = Firewall()
    print(firewall.fw_config.ip_addr)
    google, google_aliases, google_ips = firewall.get_ip_from_host('www.google.com')
    manga4life, manga4life_aliases, manga4life_ips = firewall.get_ip_from_host('www.manga4life.com')

    # firewall.add_firewall(google, google_aliases, google_ips)
    # firewall.add_firewall(manga4life, manga4life_aliases, manga4life_ips)
    # firewall.add_firewall(google, google_aliases, google_ips, protocol='tcp')


    # firewall.show_firewall()
    firewall.run(count=10)

main()

