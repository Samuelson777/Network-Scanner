from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    # Create an ARP request
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send the packet and receive responses
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def display_devices(devices):
    print("Available devices in the network:")
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t{device['mac']}")

def main():
    ip_range = input("Enter the IP range to scan (e.g., 192.168.1.1/24): ")
    devices = scan_network(ip_range)
    display_devices(devices)

if __name__ == "__main__":
    main()