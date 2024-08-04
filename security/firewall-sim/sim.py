
import socket
import logging
import threading
from helper import generate_ip, validIPAddress


class FirewallSim():

    def __init__(self, host_ip: str = "10.10.10.10", port: int = 8080) -> None:
        ''' Initialize the firewall simulator. Optionally can specify a host/port to instantiate.'''

        self.host_ip = host_ip
        self.port = port
        self.senders = {}

        # start host socket
        self.host = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.host.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # reuse address if left in TIME_WAIT state
        self.host.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) # include IP headers
        self.host.bind((host_ip, port)) # bind host socket to host_ip/port

    
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
                sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sender.bind((ip, self.port))
                self.senders[ip] = sender
        except ValueError as e:
            print(f"Error instantiating senders IPs: {e}")
            self.cleanup_senders()
            return
        
    
    def cleanup_senders(self) -> None:
        ''' Cleanup the sender sockets. '''

        print("Cleaning up sender sockets...")

        for sender in self.senders:
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
            self.host.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            self.host.shutdown(socket.SHUT_RDWR)
            self.host.close()

            self.cleanup_senders()
        except OSError as e:
            print(f"Error closing sockets: {e}")

        print("All sockets closed.")

    def run(self) -> None:
        ''' Start the simulation. '''

        print("[START]: Starting simulation...")

        self.host.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        try:
            # start senders
            for sender in self.senders.keys():
                thread = threading.Thread(target=start_sender, args=(self.senders[sender], sender, self.port, self.host_ip))
                thread.setDaemon(True)
                thread.start()
 
            # start listening for packets
            while True:
                packet, addr = self.host.recvfrom(65565)
                print(f"Received packet from {addr}: {packet}")
        except KeyboardInterrupt:
            print("\n[END]: Simulation ended...")
            self.shutdown()
            return


def send_packet(sender: socket.socket, port: int, dest_ip: str, payload) -> None:
    ''' Send a packet with payload payload from the sender to dest_ip. dest_ip defaults to the host IP. '''

    if not validIPAddress(dest_ip):
        print("Invalid destination IP address.")

    try:
        sender.sendto(payload, (dest_ip, port))
    except InterruptedError as e:
        print(f"Packet sending interrupted: {e}")
        return
    except OSError as e:
        print(f"Error sending packet: {e}")
        return
    

def start_sender(sender: socket.socket, source_ip: str, port: int, dest_ip: str, interval: int = 1000) -> None:
    ''' Start the sender to send packets to dest_ip. Specify the interval in milliseconds; defaults to 1000ms. '''

    if not validIPAddress(source_ip) or not validIPAddress(dest_ip):
        print(f"Invalid source/dest IP address. Source: {source_ip}, Dest: {dest_ip}.")
        return

    print(f"Creating Client with IP: {source_ip}...")
    payload = b"Hello from " + source_ip.encode()

    try:
        send_packet(sender, port, dest_ip, payload)

    except KeyboardInterrupt:
        print(f"\n Exiting Client {source_ip}...")
        return
    except Exception as e:
        print(f"Error sending packet: {e}")
        return



if __name__ == '__main__':
    logger = logging.basicConfig(filemode='w', filename='firewall.log', level=logging.INFO)
    pass
