
import socket
import logging
import threading
import time
from random import getrandbits
from helper import *
from config import FirewallSimConfig


class FirewallSim():

    def __init__(self, host_ip: str = "127.0.0.1", port: int = 4444) -> None:
        ''' Initialize the firewall simulator. Optionally can specify a host/port to instantiate.'''

        self.config = FirewallSimConfig("firewall_config.csv", list(PROTOCOLS.keys()))
        self.host_ip: str = host_ip
        self.port: int = port
        self.senders: dict[str, socket.socket] = {}

        # start host socket
        try:
            self.host = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.host.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # reuse address if left in TIME_WAIT state
        except PermissionError as e:
            print(f"Error binding host socket: {e}")
            return
            

    def instantiate_senders(self, num_senders: int = 3, sender_ips: list[str] | None = []) -> None:
        ''' Instantiate num_senders number of sender sockets. Optionally, pass in a list of sender IPs to use. 
            If no sender IPs are passed in, the simulator will generate random IPs. '''
        
        try:
            if num_senders < 1:
                raise ValueError("Number of senders must be greater than 0.")
            
            if not sender_ips:
                sender_ips = [generate_ip() for _ in range(num_senders)]
            elif len(sender_ips) != num_senders or len(sender_ips) != len(set(sender_ips)):
                raise ValueError("Number of sender IPs must match the number of senders and be unique.")
            else:
                for ip in sender_ips:
                    if not validIPAddress(ip):
                        raise ValueError(f'Invalid IP address given: {ip}')
            
            for ip in sender_ips:
                sender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.senders[ip] = sender

                # add rules for each sender; defaults to false
                for protocol in self.config.protocols:
                    access = bool(getrandbits(1))
                    self.config.add_rule(self.host_ip, ip, protocol, access)
                    self.config.add_rule(ip, self.host_ip, protocol, access)
        except ValueError as e:
            print(f"Error instantiating senders IPs: {e}")
            self.cleanup_senders()
            return
        
    
    def cleanup_senders(self) -> None:
        ''' Cleanup the sender sockets. '''

        print("Cleaning up sender sockets...")

        for sender in self.senders.values():
            try:
                sender.shutdown(socket.SHUT_RDWR)
                sender.close()
            except OSError as e:
                print(f"Error closing sender socket: {e}")
        
        self.senders = {}
        print("Finished cleaning up sender sockets.")

    
    def shutdown(self) -> None:
        ''' Cleanup the host and sender sockets. '''

        print("Cleaning up...")

        try:
            self.host.shutdown(socket.SHUT_RDWR)
            self.host.close()

            self.cleanup_senders()
        except OSError as e:
            print(f"Error closing sockets: {e}")

        print("All sockets closed.")
        exit()

    
    def summary(self) -> None:
        ''' Show the current senders and host information. '''

        print("Host IP: ", self.host_ip)
        print("Host Port: ", self.port)
        print("Senders: ", self.senders)
        self.config.summary()


    def run(self, num_senders: int = 3, sender_ips: list[str] | None = []) -> None:
        ''' Start the simulation. Optionally, specify the number of packets to send. '''

        # set up host to listen for packets
        self.host.bind((self.host_ip, self.port)) # bind host socket to host_ip/port
        self.instantiate_senders(num_senders, sender_ips)
        self.summary()
        
        print("[START]: Starting simulation...")

        try:
            # start senders
            for sender in self.senders.keys():
                thread = threading.Thread(target=start_sender, args=(self.senders[sender], sender, self.port, self.host_ip))
                thread.daemon = True
                thread.start()
 
            # start listening for packets
            self.host.listen(len(self.senders))

            while True:
                conn, addr = self.host.accept()

                host = threading.Thread(target=host_new_connection, args=(conn, addr, self.config))
                host.setDaemon = True
                host.start()
            
        except KeyboardInterrupt:
            print("\n[END]: Exiting simulation...")
            self.shutdown()
            exit()
        
        except Exception as e:
            print(f"Error receiving packet: {e}")
            exit()
        

def send_packet(sender: socket.socket, source_ip: str, dest_ip: str, port: int, payload: bytes) -> None:
    ''' Send a packet with payload payload from the sender to dest_ip. dest_ip defaults to the host IP. '''

    if not validIPAddress(dest_ip) or not validIPAddress(source_ip):
        print("Invalid source/dest IP addresses.")

    logging.info(f"[{source_ip}] Sending packet to {dest_ip}...")
    packet = create_packet(payload, source_ip, dest_ip, source_port=port, dest_port=port, protocol='tcp')

    try:
        sender.sendall(packet)
    except InterruptedError as e:
        print(f"Packet sending interrupted: {e}")
        return
    except OSError as e:
        print(f"[Error] Sending packet: {e}")
        return


def host_new_connection(conn: socket, addr, config: FirewallSimConfig) -> None:
    ''' Accept a new connection from a sender. '''

    if not conn or not addr:
        print("[HOST] Invalid connection or address.")
        return

    with conn:
        while True:
            data = conn.recv(1024)
            if not data:
                break

            protocol, src_ip, dest_ip, payload = unpack_ipv4_packet(data)
            logging.info(f"[HOST] {src_ip} {protocol} > {dest_ip}")
            allowed = config.is_protocol_allowed(src_ip, dest_ip, protocol)
            print(f"ACCESS FROM {src_ip} to HOST: ", allowed)

            if config.is_protocol_allowed(src_ip, dest_ip, protocol):
                logging.info(f"[Firewall] Packet is Allowed: {src_ip} can access {dest_ip} via {protocol}")

                if protocol == 6:
                    # tcp packet
                    src_port, dest_port, payload = unpack_tcp_packet(payload)
                    logging.info(f"[HOST] TCP: {src_port} > {dest_port} with payload: {payload.decode()}")
                    conn.sendall(b'[TCP] Allowed Access')
                elif protocol == 17:
                    # udp packet
                    src_port, dest_port, payload = unpack_udp_packet(payload)
                    logging.info(f"[HOST] UDP: {src_port} > {dest_port} with payload: {payload.decode()}")
                    conn.sendall(b'[UDP] Allowed Access')
        
                conn.sendall(b"Allowed Access by Firewall")
            else:
                logging.info(f"[Firewall] Blocked: IP {src_ip} blocked from accessing {dest_ip} via {protocol}")
                conn.sendall(b"Blocked by firewall")


def start_sender(sender: socket.socket, source_ip: str, port: int, dest_ip: str, interval: float = 5.0) -> None:
    ''' Start the sender to send packets to dest_ip. Specify the interval in seconds; defaults to 1s. '''

    if not validIPAddress(source_ip) or not validIPAddress(dest_ip):
        print(f"Invalid source/dest IP address. Source: {source_ip}, Dest: {dest_ip}.")
        return


    try:
        # connect to host
        print(f"Creating Client with IP: {source_ip}...")
        sender.connect((dest_ip, port))
        print(f"{source_ip} connected to HOST {dest_ip}...")

        payload = b"Hello from " + source_ip.encode()

        starttime = time.monotonic()

        # send packets at interval
        while True:
            logging.info(f"[{source_ip}] Sending packet to {dest_ip}...")
            
            send_packet(sender, source_ip, dest_ip, port, payload)
            data = sender.recv(1024)

            logging.info(f"[{source_ip}] Received from HOST: {data.decode()}")

            time.sleep(interval - ((time.monotonic() - starttime) % interval))

    except Exception as e:
        print(f"[Error] Starting Thread Packet: {e}")
        return



if __name__ == '__main__':
    logging.basicConfig(filemode='w', filename='firewall.log', level=logging.INFO)

    sim = FirewallSim()

    logging.info("Starting firewall simulation...")
    sim.run()
    logging.info("Ending firewall simulation")

    pass
