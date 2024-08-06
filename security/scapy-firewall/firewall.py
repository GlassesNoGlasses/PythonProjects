import socket
import scapy.all as scapy
import pandas as pd
from ast import literal_eval
from ipaddress import ip_address

# csv file config
CSV_FIELDS = ['host', 'aliases', 'ips', 'inbound', 'outbound', 'protocol']

# load respective scapy layers
scapy.load_layer("http")
scapy.load_layer("tls")
scapy.load_layer("dns")

# protocols
PROTOCOLS = {
    'tcp': scapy.TCP, 
    'udp': scapy.UDP, 
    'icmp': scapy.ICMP, 
    'dns': scapy.DNS,
    "all": True,
}

class FirewallConfig():
    
    def __init__(self, csv_path: str, ip_addr: str, autosave: bool = True) -> None:
        # user's ip address
        self.ip_addr = ip_addr

        # store configuration of the firewall
        self.config = pd.DataFrame(columns=CSV_FIELDS)

        # blocked_cache frequent ip addresses for inbound/outbound allowance
        self.blocked_cache = {'inbound': [], 'outbound': []}

        # default settings for the firewall
        self.default = {'inbound': True, 'outbound': True, 'protocol': 'all'}

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
        
        # convert string of lists to literal lists
        self.config.loc[:, 'ips'] = self.config['ips'].apply(literal_eval)
        self.config.loc[:, 'aliases'] = self.config['aliases'].apply(literal_eval)

        # update blocked_cache
        self.blocked_cache['inbound'] = self.config[self.config['inbound'] == False]['ips']
        self.blocked_cache['outbound'] = self.config[self.config['outbound'] == False]['ips']
        
        return True


    def update_config(self, host: str, aliases: list[str], ips: list[str], inbound: bool, 
                      outbound: bool, protocol: str | None) -> bool:
        ''' Update the configuration. '''

        filtered_ips = self.filter_ips(ips)
        index = -1

        if not filtered_ips or not host:
            return False

        # set default values
        inbound = inbound if inbound is not None else self.default['inbound']
        outbound = outbound if outbound is not None else self.default['outbound']
        protocol = PROTOCOLS[protocol] if protocol and protocol.lower() in PROTOCOLS.keys() else self.default['protocol']
        
        # existing host in the configuration
        if host in self.config['host'].values:
            index = self.config[self.config['host'] == host].index.values[0]
        else:
            index = 0 if pd.isnull(self.config.index.max()) else self.config.index.max() + 1
        
        # add to config
        self.config.loc[index, CSV_FIELDS] = [host, aliases, filtered_ips, inbound, outbound, protocol]

        # add to blocked_cache
        self.blocked_cache['inbound'] += filtered_ips if not inbound else []
        self.blocked_cache['outbound'] += filtered_ips if not outbound else []
        
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

        if (not packet.haslayer(scapy.IP)):
            return False

        # filter packets based on current machines ip address src/dst
        sip = packet[IPv6].src if (IPv6 in packet) else packet[IP].src
        dip = packet[IPv6].dst if (IPv6 in packet) else packet[IP].dst

        in_firewall = sip in self.blocked_cache['inbound'] or dip in self.blocked_cache['outbound']
        is_user = sip == self.ip_addr or dip == self.ip_addr

        if not in_firewall or not is_user:
            return False
        
        protocol = self.config[self.config['ips'].isin([sip, dip])]['protocol'].values[0]

        if protocol == 'all':
            is_traffic = True
        else:
            is_traffic = packet.haslayer(protocol) if protocol and protocol in PROTOCOLS.keys() else False

        return is_traffic



    def packet_prn(self, packet) -> None:
        ''' Perform actions on packets from blocked inbound/outpound configs. '''

        print("ERROR: Packet blocked by firewall.")
        print(packet.show())


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
    

    def run(self, count: int | None = None, write: bool = True) -> None:
        ''' Run the firewall. '''
        
        capture = scapy.sniff(lfilter=self.fw_config.packet_filter, count=count, prn=self.fw_config.packet_prn)

        if write:
            scapy.wrpcap("firewall.pcap", capture)
        

def main():
    firewall = Firewall()
    print("RUNNIN ON IP: ", firewall.fw_config.ip_addr)
    google, google_aliases, google_ips = firewall.get_ip_from_host('www.google.com')
    manga4life, manga4life_aliases, manga4life_ips = firewall.get_ip_from_host('www.manga4life.com')
    asura, asura_aliases, asura_ips = firewall.get_ip_from_host('asuracomic.net')

    # firewall.add_firewall(google, google_aliases, google_ips)
    firewall.add_firewall(manga4life, manga4life_aliases, manga4life_ips, outbound=False, inbound=False)
    firewall.add_firewall(google, google_aliases, google_ips, inbound=False, outbound=False, protocol='tcp')
    firewall.add_firewall(asura, asura_aliases, asura_ips, inbound=False, outbound=False, protocol='tcp')

    firewall.show_firewall()
    firewall.run(count=10)

main()

