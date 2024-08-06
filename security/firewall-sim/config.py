
import pandas as pd


class FirewallSimConfig():

    def __init__(self, csv_path: str, protocols: list[str]) -> None:
        ''' Initialize the firewall simulator configuration. '''

        self.columns = ['src_ip', 'dst_ip', 'inbound', 'outbound' 'protocol']
        self.config = pd.DataFrame(columns=self.columns)
        self.protocols = protocols
        self.csv_path = csv_path
    

    def save_config(self) -> None:
        ''' Save the firewall configuration to a csv file. '''

        self.config.to_csv(self.csv_path, columns=self.columns, index=False)
    

    def load_config(self) -> bool:
        ''' Load the firewall configuration from a csv file. '''

        self.config = pd.read_csv(self.csv_path)

        if (self.config.empty):
            return False
        
        return True
    

    def add_config(self, src_ip: str, dst_ip: str, inbound: bool, outbound: bool, protocol: str) -> bool:
        ''' Add a new configuration. '''

        if not src_ip or not dst_ip or protocol not in self.protocols:
            return False
        
        # check if the configuration already exists
        if not self.config[(self.config['src_ip'] == src_ip) & (self.config['dst_ip'] == dst_ip)].empty:
            return False

        self.config.loc[len(self.config)] = [src_ip, dst_ip, inbound, outbound, protocol]
        
        return True
    

    def update_config(self, src_ip: str, dst_ip: str, inbound: bool, outbound: bool, protocol: str) -> bool:
        ''' Update an existing configuration. Add the config if it doesn't exist. '''

        if not src_ip or not dst_ip or protocol not in self.protocols:
            return False
        
        # check if the configuration exists
        index = self.config[(self.config['src_ip'] == src_ip) & (self.config['dst_ip'] == dst_ip)].index

        if index.empty:
            return self.add_config(src_ip, dst_ip, inbound, outbound, protocol)
        
        self.config.loc[index, ['inbound', 'outbound', 'protocol']] = [inbound, outbound, protocol]
        
        return True
    

    def remove_config(self, src_ip: str, dst_ip: str) -> bool:
        ''' Remove a configuration. '''

        if not src_ip or not dst_ip:
            return False
        
        index = self.config[(self.config['src_ip'] == src_ip) & (self.config['dst_ip'] == dst_ip)].index

        if index.empty:
            return True
        
        self.config.drop(index, inplace=True)
        
        return True
    

    def verify_access(self, src_ip: str, dst_ip: str, protocol: str) -> bool:
        ''' Verify if the source IP has access to the destination IP. '''

        if not src_ip or not dst_ip or protocol not in self.protocols:
            return False
        
        # check if the configuration exists
        config = self.config[(self.config['src_ip'] == src_ip) & (self.config['dst_ip'] == dst_ip) & (self.config['protocol'] == protocol)]

        if config.empty:
            return False
        
        return config['inbound'].values[0] and config['outbound'].values[0]
