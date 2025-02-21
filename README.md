# cyber-checkpoint
import socket
import scapy.all as scapy

def scan_ports(target, ports):
    print(f"Scanning {target} for open ports...")
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
                print(f"Port {port} is open")
            s.close()
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    return open_ports

def scan_network(ip_range):
    print(f"Scanning network: {ip_range}")
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        devices.append({'ip': element[1].psrc, 'mac': element[1].hwsrc})
        print(f"IP: {element[1].psrc}, MAC: {element[1].hwsrc}")
    return devices

def main():
    target = input("Enter the target IP address: ")
    ports = range(1, 1025)  # Scanning common ports
    open_ports = scan_ports(target, ports)
    print("Open Ports:", open_ports)
    
    network = input("Enter network range to scan (e.g., 192.168.1.0/24): ")
    scan_network(network)

if __name__ == "__main__":
    main()
