
import pandas as pd


class FirewallSimConfig():

    def __init__(self, csv_path: str, protocols: list[str]) -> None:
        ''' Initialize the firewall simulator configuration. '''

        # columns: source IP, destination IP, protocol, access
        self.columns = ['source_ip', 'dest_ip', 'protocol', 'access']
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
    

    def get_config(self, source_ip: str, dest_ip: str, protocol: str) -> pd.DataFrame:
        ''' Get the firewall configuration. '''

        return self.config[(self.config['source_ip'] == source_ip) & (self.config['dest_ip'] == dest_ip) & (self.config['protocol'] == protocol)]
    

    def add_rule(self, source_ip: str, dest_ip: str, protocol: str, access: bool = False) -> bool:
        ''' Add a new configuration. '''

        if not source_ip or not dest_ip or protocol not in self.protocols:
            return False
        
        # check if the configuration already exists
        if not self.get_config(source_ip, dest_ip, protocol).empty:
            return False

        self.config.loc[len(self.config)] = [source_ip, dest_ip, protocol, access]
        
        return True
    

    def update_rule(self, source_ip: str, dest_ip: str, protocol: str, access: bool) -> bool:
        ''' Update an existing configuration. Add the config if it doesn't exist. '''

        if not source_ip or not dest_ip or protocol not in self.protocols:
            return False
        
        # check if the configuration exists
        config = self.get_config(source_ip, dest_ip, protocol)

        if config.empty:
            return self.add_rule(source_ip, dest_ip, protocol, access)
        
        self.config.loc[config.index, 'access'] = access
        
        return True
    

    def remove_rule(self, source_ip: str, dest_ip: str, protocol) -> bool:
        ''' Remove a configuration. '''

        if not source_ip or not dest_ip:
            return False
        
        config = self.get_config(source_ip, dest_ip, protocol)

        if config.empty:
            return False
        
        self.config.drop(config.index, inplace=True)
        
        return True
    

    def is_protocol_allowed(self, source_ip: str, dest_ip: str, protocol: str) -> bool:
        ''' Verify if the source IP has access to the destination IP. '''

        if not source_ip or not dest_ip or protocol not in self.protocols:
            return False
        
        # check if the configuration exists
        config = self.get_config(source_ip, dest_ip, protocol)

        if config.empty:
            return False
        
        return config['access'].values[0]
