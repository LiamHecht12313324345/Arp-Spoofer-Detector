import sys
import struct
import socket

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str)
    return mac_addr

def ethernet_head(raw_data):
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    proto = socket.htons(prototype)
    data = raw_data[14:]
    return dest_mac, src_mac, proto, data

def arp_head(raw_data):
    # The ARP packet structure consists of several fields
    hardware_type, protocol_type, hardware_size, protocol_size, opcode = struct.unpack('! H H B B H', raw_data[:8])
    
    # Check if it's an ARP request or reply based on the opcode
    arp_operation = "ARP Request" if opcode == 1 else "ARP Reply"
    
    sender_mac = get_mac_addr(raw_data[8:14])
    sender_ip = get_ip(raw_data[14:18])
    target_mac = get_mac_addr(raw_data[18:24])
    target_ip = get_ip(raw_data[24:28])
    
    return hardware_type, protocol_type, hardware_size, protocol_size, arp_operation, sender_mac, sender_ip, target_mac, target_ip

def get_ip(addr):
    return '.'.join(map(str, addr))

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip

def get_ip_from_mac(mac_address):
    try:
        print("inside get mac")
        print(mac_address)
        # Use ARP to resolve the MAC address of an IP address
        ip_address = socket.gethostbyaddr(mac_address)[0]
        print(ip_address)
        return ip_address
    except (socket.herror, socket.gaierror):
        return None




